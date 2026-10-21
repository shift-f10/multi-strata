#include "secure_frontend/generation_run.hpp"

#include "secure_frontend/utf8_stream_decoder.hpp"

#include <algorithm>
#include <string>
#include <variant>

namespace secure_frontend {
namespace {

using Clock = std::chrono::steady_clock;

std::chrono::milliseconds left_until(const Clock::time_point deadline) {
  const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
  return left.count() > 0 ? left : std::chrono::milliseconds(0);
}

// Longest prefix of valid UTF-8 `text` of at most `limit` bytes ending on a code-point boundary.
std::size_t code_point_prefix(const std::string_view text, std::size_t limit) {
  if (limit >= text.size()) return text.size();
  while (limit > 0U && (static_cast<unsigned char>(text[limit]) & 0xC0U) == 0x80U) --limit;
  return limit;
}

enum class StopCause { none, timeout, bytes, cancel, undecodable };

}  // namespace

GenerationRunResult drive_generation(EngineProtocolClient& protocol, const TokenByteDecoder& decoder,
                                     const GenerationRunLimits& limits, GenerationObserver& observer) {
  GenerationRunResult result;
  Utf8StreamDecoder utf8;
  std::size_t released = 0;
  StopCause cause = StopCause::none;
  const auto generation_deadline = Clock::now() + limits.generation_timeout;
  Clock::time_point drain_deadline{};
  auto last_tick = Clock::now();

  // false: STOP could not be written (the protocol is abandoned).
  const auto send_stop = [&](const StopCause why) {
    cause = why;
    // Shutdown (R-H): the drain is bounded by min(stop_drain, kShutdownDrainBudget), as M1's loop did.
    const bool shutting = why == StopCause::cancel && result.cancel == RunCancel::shutting_down;
    drain_deadline = Clock::now() + (shutting ? std::min(limits.stop_drain_timeout, limits.shutdown_drain) : limits.stop_drain_timeout);
    // Ruling t5-stopcause: the SP2 kill-reason contract (KillReason::client_stop_drain_failed
    // follows stop_cause() == client_cancelled) survives the shared loop.
    const EngineStopCause stop_cause = why == StopCause::cancel && result.cancel == RunCancel::client_gone
                                           ? EngineStopCause::client_cancelled
                                           : EngineStopCause::generation_timeout;
    if (protocol.stop(stop_cause).has_value()) {
      protocol.abandon();
      return false;
    }
    return true;
  };
  // Releases decoded text within the byte cap; on reaching it, cuts on a code
  // point and (while the engine still generates) sends STOP.
  const auto release = [&](std::string text) {
    if (cause != StopCause::none || text.empty()) return true;
    if (released + text.size() > limits.max_generated_bytes) {
      text.resize(code_point_prefix(text, limits.max_generated_bytes - released));
      result.bytes_capped = true;
      if (!text.empty()) {
        released += text.size();
        observer.on_text(text);
      }
      if (!protocol.generating()) {
        cause = StopCause::bytes;
        return true;
      }
      return send_stop(StopCause::bytes);
    }
    released += text.size();
    observer.on_text(text);
    return true;
  };

  for (;;) {
    if (cause == StopCause::none && Clock::now() >= generation_deadline) {
      result.timed_out = true;
      if (!send_stop(StopCause::timeout)) return result;  // engine_unavailable
    }
    if (cause != StopCause::none && Clock::now() >= drain_deadline) {
      protocol.abandon();  // the engine ignored STOP: SP2 drain_failed
      return result;       // engine_unavailable
    }
    const auto budget = std::min(limits.slice, left_until(cause == StopCause::none ? generation_deadline : drain_deadline));
    auto event = protocol.next_event(std::max(budget, std::chrono::milliseconds(1)));
    bool progress = false;
    bool idle_slice = false;
    if (const auto* failure = std::get_if<EngineProtocolError>(&event)) {
      if (failure->code != EngineProtocolErrorCode::timeout) {
        result.end = failure->code == EngineProtocolErrorCode::engine_error || failure->code == EngineProtocolErrorCode::fatal_engine_line
                         ? RunEnd::engine_error
                         : RunEnd::engine_unavailable;
        return result;
      }
      idle_slice = true;
    } else if (const auto* token = std::get_if<TokenEvent>(&event)) {
      ++result.completion_tokens;
      if (limits.max_tokens != 0U && result.completion_tokens > limits.max_tokens) {
        protocol.abandon();  // more tokens than GEN allowed: not trusted further (M1: engine_error)
        result.end = RunEnd::engine_error;
        return result;
      }
      if (cause == StopCause::none) {
        const auto bytes = decoder.bytes_for(token->id);
        const bool ok = std::holds_alternative<std::string>(bytes) ? release(utf8.push(std::get<std::string>(bytes)))
                                                                   : send_stop(StopCause::undecodable);
        if (!ok) return result;  // engine_unavailable
      }
    } else if (std::holds_alternative<ProgressEvent>(event)) {
      progress = true;
    } else {
      const auto& done = std::get<DoneEvent>(event);
      if (cause == StopCause::none) (void)release(utf8.finish(done.finish != "stop"));
      if (done.finish == "nonfinite") {
        result.end = RunEnd::engine_error;
        return result;
      }
      switch (cause) {
        case StopCause::none: result.end = done.finish == "stop" ? RunEnd::stop : RunEnd::length; break;
        case StopCause::timeout:
        case StopCause::bytes: result.end = RunEnd::length; break;
        case StopCause::cancel: result.end = RunEnd::cancelled; break;
        case StopCause::undecodable: result.end = RunEnd::undecodable; break;
      }
      return result;
    }
    const auto now = Clock::now();
    if (progress || idle_slice || now - last_tick >= limits.slice) {
      last_tick = now;
      const RunCancel cancel = observer.on_tick(progress);
      if (cancel != RunCancel::none && cause == StopCause::none) {
        result.cancel = cancel;
        if (!send_stop(StopCause::cancel)) return result;  // engine_unavailable
      }
    }
  }
}

}  // namespace secure_frontend

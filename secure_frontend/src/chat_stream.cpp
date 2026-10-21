#include "secure_frontend/chat_stream.hpp"

#include "secure_frontend/api_constants.hpp"

#include <optional>
#include <string>

namespace secure_frontend {
namespace {

using Clock = std::chrono::steady_clock;

// Holds decoded text and renders events only when the sink can take one
// without blocking: the engine is read at engine speed (spec §2.7).
// Ruling t8-unused: this task's observer reads only the sink and identity;
// carrying settings/shutting_down members it would not read trips
// -Wunused-private-field under clang (-Werror) — Tasks 11/12 add them back
// where they are read.
class StreamObserver final : public GenerationObserver {
 public:
  StreamObserver(StreamSink& sink, const SseIdentity& identity) : sink_(sink), identity_(identity) {}

  void on_text(const std::string_view text) override { pending_ += text; }

  RunCancel on_tick(bool /*progress*/) override {
    flush_ready();
    return RunCancel::none;
  }

  // Sends content events while the sink is writable now.
  void flush_ready() {
    while (!pending_.empty() && sink_.writable(std::chrono::milliseconds(0))) send_one();
  }

  // Waits (in poll slices) until the sink can take an event; false on deadline or gone.
  bool wait_writable(const Clock::time_point until) {
    while (!sink_.writable(api_constants::kStreamPollSlice)) {
      if (Clock::now() >= until || sink_.client_gone()) return false;
    }
    return true;
  }

  bool flush_all(const Clock::time_point until) {
    while (!pending_.empty()) {
      if (!wait_writable(until)) return false;
      send_one();
    }
    return true;
  }

  bool send(const std::string_view event, const Clock::time_point until) { return wait_writable(until) && sink_.send_event(event); }

 private:
  void send_one() {
    const std::size_t size = next_delta_size(pending_);
    (void)sink_.send_event(render_content_event(identity_, std::string_view(pending_).substr(0, size)));
    pending_.erase(0, size);
  }

  StreamSink& sink_;
  const SseIdentity& identity_;
  std::string pending_;  // decoded text, bounded by limits.chat.max_generated_bytes
};

}  // namespace

ChatStreamOutcome run_chat_stream(StreamSink& sink, EngineProtocolClient& protocol, const TokenByteDecoder& decoder,
                                  const SseIdentity& identity, const ChatStreamSettings& settings,
                                  const std::function<bool()>& shutting_down, const GenerationEnded& generation_ended) {
  ChatStreamOutcome outcome;
  (void)shutting_down;  // the cancel/shutdown arms land in Tasks 11 and 14
  StreamObserver observer(sink, identity);
  (void)sink.send_headers(make_sse_head());
  (void)sink.send_event(render_role_event(identity));
  const GenerationRunResult run = drive_generation(protocol, decoder, settings.run, observer);
  generation_ended(run);  // the Lease is gone from here on: the next generation may start
  outcome.end = run.end;
  if (run.timed_out) outcome.log_code = "generation_timeout";
  if (run.end != RunEnd::stop && run.end != RunEnd::length) return outcome;  // other ends: Tasks 11, 13, 14
  const auto until = Clock::now() + settings.tail_deadline;
  if (!observer.flush_all(until)) return outcome;
  if (!observer.send(render_final_event(identity, run.end == RunEnd::stop ? "stop" : "length"), until)) return outcome;
  if (settings.include_usage && !observer.send(render_usage_event(identity, settings.prompt_tokens, run.completion_tokens), until)) return outcome;
  if (!observer.send(kSseDoneEvent, until) || !observer.wait_writable(until)) return outcome;
  sink.finish();
  outcome.terminal_chunk_sent = sink.writable(std::chrono::milliseconds(0));
  return outcome;
}

}  // namespace secure_frontend

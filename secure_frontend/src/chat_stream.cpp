#include "secure_frontend/chat_stream.hpp"

#include "secure_frontend/api_constants.hpp"

#include <optional>
#include <string>

namespace secure_frontend {
namespace {

using Clock = std::chrono::steady_clock;

// How long a sub-16 KiB delta may be held mid-stream before it goes out anyway
// (ruling t11-age). Well under the 2 s STOP bounds of the DOS-02 cancel tests.
constexpr auto kPartialFlushHold = std::chrono::milliseconds(500);

// Holds decoded text and renders events only when the sink can take one
// without blocking: the engine is read at engine speed (spec §2.7).
// Ruling t8-unused: members are carried only where they are read (clang
// -Wunused-private-field under -Werror).
class StreamObserver final : public GenerationObserver {
 public:
  StreamObserver(StreamSink& sink, const SseIdentity& identity, const ChatStreamSettings& settings)
      : sink_(sink), identity_(identity), settings_(settings) {}

  void on_text(const std::string_view text) override {
    if (pending_.empty()) pending_since_ = Clock::now();
    pending_ += text;
  }

  RunCancel on_tick(bool /*progress*/) override {
    if (sink_.client_gone()) return gone_reason();
    flush_ready();
    if (sink_.client_gone()) return gone_reason();
    // Keepalive (spec §3.2): only while nothing is pending and the sink takes
    // it now — a comment never queues behind or interleaves with content.
    if (pending_.empty() && Clock::now() - last_activity_ >= settings_.keepalive && sink_.writable(std::chrono::milliseconds(0))) {
      (void)sink_.send_event(kSseKeepAliveComment);
      last_activity_ = Clock::now();
    }
    return RunCancel::none;
  }

  // Ruling t11-age (reconciles t10-coalesce with Task 11's cancellation tests):
  // a tick sends a FULL 16 KiB delta whenever one is available, and a PARTIAL
  // delta only after it has waited kPartialFlushHold — so a reading client gets
  // timely deltas (DOS-02 disconnect tests: 3 content chunks on a 4 KiB stream)
  // while a never-reading client sees full deltas only (the ≤ 80-event DOS-02
  // bound holds deterministically: pending crosses 16 KiB long before the hold
  // expires). Partial tails always flush in flush_all. blocked_since_ tracks
  // how long output was refused (write_stall vs client_gone).
  void flush_ready() {
    for (;;) {
      if (!sink_.writable(std::chrono::milliseconds(0))) {
        if (!blocked_since_) blocked_since_ = Clock::now();
        return;
      }
      blocked_since_.reset();
      if (pending_.size() >= api_constants::kMaxDeltaTextBytes) {
        send_one();
        continue;
      }
      if (!pending_.empty() && Clock::now() - pending_since_ >= kPartialFlushHold) {
        send_one();
        continue;
      }
      return;
    }
  }

  // write_stall when output was refused for the whole stall window, else client_gone (§8 log codes).
  [[nodiscard]] RunCancel gone_reason() const {
    return blocked_since_ && Clock::now() - *blocked_since_ >= settings_.write_stall ? RunCancel::write_stall : RunCancel::client_gone;
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
    last_activity_ = Clock::now();
  }

  StreamSink& sink_;
  const SseIdentity& identity_;
  const ChatStreamSettings& settings_;
  std::string pending_;  // decoded text, bounded by limits.chat.max_generated_bytes
  Clock::time_point pending_since_{};
  std::optional<Clock::time_point> blocked_since_;
  // Constructed after the role chunk is queued, so the keepalive timer starts there (Task 12).
  Clock::time_point last_activity_{Clock::now()};
};

}  // namespace

ChatStreamOutcome run_chat_stream(StreamSink& sink, EngineProtocolClient& protocol, const TokenByteDecoder& decoder,
                                  const SseIdentity& identity, const ChatStreamSettings& settings,
                                  const std::function<bool()>& shutting_down, const GenerationEnded& generation_ended) {
  ChatStreamOutcome outcome;
  (void)shutting_down;  // the shutdown arm lands in Task 14
  (void)sink.send_headers(make_sse_head());
  (void)sink.send_event(render_role_event(identity));
  StreamObserver observer(sink, identity, settings);  // after the role chunk: the keepalive timer starts here
  const GenerationRunResult run = drive_generation(protocol, decoder, settings.run, observer);
  generation_ended(run);  // the Lease is gone from here on: the next generation may start
  outcome.end = run.end;
  if (run.timed_out) outcome.log_code = "generation_timeout";
  if (run.end == RunEnd::cancelled && (run.cancel == RunCancel::client_gone || run.cancel == RunCancel::write_stall)) {
    outcome.log_code = run.cancel == RunCancel::write_stall ? "write_stall" : "client_gone";
    return outcome;  // nothing more is written to a gone client (spec §2.6)
  }
  const auto until = Clock::now() + settings.tail_deadline;
  if (run.end == RunEnd::engine_error || run.end == RunEnd::engine_unavailable || run.end == RunEnd::undecodable) {
    const ApiError code = run.end == RunEnd::engine_error ? ApiError::engine_error
                              : run.end == RunEnd::engine_unavailable ? ApiError::engine_unavailable
                                                                      : ApiError::internal_error;
    outcome.log_code = api_error_row(code).code;
    if (!observer.flush_all(until) || !observer.send(render_error_event(code), until) || !observer.send(kSseDoneEvent, until) ||
        !observer.wait_writable(until)) {
      return outcome;
    }
    sink.finish();
    outcome.terminal_chunk_sent = sink.writable(std::chrono::milliseconds(0));
    return outcome;
  }
  if (run.end != RunEnd::stop && run.end != RunEnd::length) return outcome;  // shutdown: Task 14
  if (!observer.flush_all(until)) return outcome;
  if (!observer.send(render_final_event(identity, run.end == RunEnd::stop ? "stop" : "length"), until)) return outcome;
  if (settings.include_usage && !observer.send(render_usage_event(identity, settings.prompt_tokens, run.completion_tokens), until)) return outcome;
  if (!observer.send(kSseDoneEvent, until) || !observer.wait_writable(until)) return outcome;
  sink.finish();
  outcome.terminal_chunk_sent = sink.writable(std::chrono::milliseconds(0));
  return outcome;
}

}  // namespace secure_frontend

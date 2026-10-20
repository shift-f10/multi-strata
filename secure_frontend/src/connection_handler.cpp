#include "secure_frontend/connection_handler.hpp"

#include "secure_frontend/api_constants.hpp"
#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/http_wire.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace secure_frontend {
namespace {
using Clock = std::chrono::steady_clock;

bool stopping(const WorkerSignals& signals) { return signals.shutting_down != nullptr && signals.shutting_down->load(); }

// Ruling R-H: once shutdown has begun, a write may take at most kShutdownDrainBudget.
Clock::time_point write_deadline(const ConnectionLimits& limits, const WorkerSignals& signals) {
  return Clock::now() + (stopping(signals) ? api_constants::kShutdownDrainBudget : limits.response_write_deadline);
}

// One 20 ms slice: poll, then a non-blocking recv when readable.
IoResult read_slice(const NativeSocket socket, char* buffer, const std::size_t size) {
  PollEntry entry{socket, true, false};
  const int ready = poll_sockets(std::span<PollEntry>{&entry, 1U}, api_constants::kStreamPollSlice);
  if (ready < 0) return {IoStatus::failed};
  if (ready == 0) return {IoStatus::would_block};
  return recv_some(socket, buffer, size);
}

// P7-P8 for a complete response: bounded send, then half-close and drain (SP0 S4).
ConnectionResult respond_complete(const NativeSocket socket, const HttpResponse& response, const ConnectionLimits& limits,
                                  const WorkerSignals& signals, const ConnectionOutcome outcome, ConnectionResult result) {
  result.status = response.status;
  result.code = response.log_code;
  const std::string wire = serialize_response(response, std::chrono::system_clock::now());
  const WriteOutcome written = send_all_bounded(socket, wire, limits.write_stall, write_deadline(limits, signals), signals.shutting_down);
  if (written == WriteOutcome::complete) {
    result.bytes_out = wire.size();
    result.outcome = outcome;
    half_close_and_drain(socket);
  } else {
    result.outcome = written == WriteOutcome::stalled ? ConnectionOutcome::client_gone : ConnectionOutcome::transport_error;
  }
  return result;
}

// M1 placeholder: minimal blocking implementation used only by
// stream_handler_dispatch_writes_head_chunks_and_terminal_chunk. M2 Task 10 replaces it with the
// non-blocking ChunkedStreamSink (spec §2.7: a slow reader must never stall the engine-reading loop)
// and adds `virtual void set_log_code(std::string_view)` to StreamSink plus `bool streamed{false}` on
// ConnectionResult/RequestLogRecord. Do not add buffering or stall accounting here.
class SocketStreamSink final : public StreamSink {
 public:
  SocketStreamSink(const NativeSocket socket, const ConnectionLimits& limits, const WorkerSignals& signals,
                   std::optional<std::string> allow_origin)
      : socket_(socket), limits_(limits), signals_(signals), allow_origin_(std::move(allow_origin)) {}
  bool send_headers(const HttpHead& head) override {
    if (headers_sent_ || failed_) return false;
    HttpHead with_cors = head;
    if (allow_origin_.has_value()) {
      with_cors.headers.emplace_back("Access-Control-Allow-Origin", *allow_origin_);
      with_cors.headers.emplace_back("Vary", "Origin");
    }
    status_ = head.status;
    headers_sent_ = true;
    return write(serialize_head(with_cors, std::chrono::system_clock::now()));
  }
  bool send_event(const std::string_view bytes) override {
    if (!headers_sent_ || failed_ || finished_) return false;
    if (bytes.empty()) return true;   // a zero-size chunk would end the body
    char size[24];
    const int n = std::snprintf(size, sizeof(size), "%zx\r\n", bytes.size());
    std::string chunk(size, static_cast<std::size_t>(n));
    chunk.append(bytes);
    chunk.append("\r\n");
    return write(chunk);
  }
  bool writable(const std::chrono::milliseconds timeout) override {
    PollEntry entry{socket_, false, true};
    return !failed_ && poll_sockets(std::span<PollEntry>{&entry, 1U}, timeout) > 0 && entry.writable && !entry.failed;
  }
  bool client_gone() override { return failed_ || probe_peer(socket_) == PeerState::gone; }
  void finish() override {
    if (headers_sent_ && !failed_ && !finished_) finished_ = write("0\r\n\r\n");
  }
  [[nodiscard]] int status() const noexcept { return status_; }
  [[nodiscard]] std::size_t bytes() const noexcept { return bytes_; }
  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] bool finished() const noexcept { return finished_; }

 private:
  bool write(const std::string_view bytes) {
    const WriteOutcome outcome = send_all_bounded(socket_, bytes, limits_.write_stall, write_deadline(limits_, signals_), signals_.shutting_down);
    if (outcome != WriteOutcome::complete) { failed_ = true; return false; }
    bytes_ += bytes.size();
    return true;
  }
  NativeSocket socket_;
  const ConnectionLimits& limits_;
  const WorkerSignals& signals_;
  std::optional<std::string> allow_origin_;
  int status_{0};
  std::size_t bytes_{0};
  bool headers_sent_{false};
  bool failed_{false};
  bool finished_{false};
};

}  // namespace

ConnectionResult deliver_route_result(const NativeSocket socket, RouteResult result, const RouteDecision& decision,
                                      const ConnectionLimits& limits, const WorkerSignals& signals) {
  ConnectionResult connection{};
  connection.outcome = ConnectionOutcome::responded;
  connection.route = decision.route;
  if (auto* complete = std::get_if<HttpResponse>(&result)) {
    // Task 6a carry: kNoResponseStatus is never serialized; the client is gone (spec §2.6).
    if (complete->status == kNoResponseStatus) {
      connection.status = 0;
      connection.code = complete->log_code.empty() ? std::string_view{"client_gone"} : complete->log_code;
      connection.outcome = ConnectionOutcome::client_gone;
      return connection;
    }
    return respond_complete(socket, *complete, limits, signals, ConnectionOutcome::responded, connection);
  }
  SocketStreamSink sink(socket, limits, signals, decision.allow_origin);
  try {
    std::get<StreamHandler>(result)(sink);
  } catch (...) {
    // A throwing handler is handled below: before its head it becomes a fixed
    // 500; after it, the stream is cut (no terminal chunk).
  }
  // No head written (a throw, or a handler that wrote nothing): a fixed 500.
  if (sink.status() == 0 && !sink.failed()) {
    return respond_complete(socket, make_error_response(ApiError::internal_error), limits, signals,
                            ConnectionOutcome::responded, connection);
  }
  connection.status = sink.status();
  connection.bytes_out = sink.bytes();
  if (sink.finished()) {
    half_close_and_drain(socket);
    connection.outcome = ConnectionOutcome::responded;
  } else {
    connection.outcome = sink.failed() ? ConnectionOutcome::client_gone : ConnectionOutcome::transport_error;
  }
  return connection;
}

ConnectionResult serve_connection(const NativeSocket socket, RequestRouter& router, const ConnectionLimits& limits,
                                  const WorkerSignals& signals, const Clock::time_point accepted_at) {
  ConnectionResult result{};
  result.outcome = ConnectionOutcome::responded;
  const auto evicted = [&signals] { return signals.abort != nullptr && signals.abort->load(); };
  const auto respond = [&](const HttpResponse& response, const ConnectionOutcome outcome) {
    return respond_complete(socket, response, limits, signals, outcome, result);
  };

  // P1: header. 414/431 as soon as known; 408 at the header deadline.
  std::string buffer;
  std::array<char, api_constants::kRecvChunk> chunk{};
  HeadScanResult scan{HeadScan::need_more};
  for (;;) {
    scan = scan_request_head(buffer, limits.head);
    if (scan.state == HeadScan::line_too_long) return respond(make_error_response(ApiError::request_line_too_long), ConnectionOutcome::responded);
    if (scan.state == HeadScan::header_too_large) return respond(make_error_response(ApiError::header_too_large), ConnectionOutcome::responded);
    if (scan.state == HeadScan::complete) break;
    if (evicted()) { result.outcome = ConnectionOutcome::evicted; return result; }
    if (stopping(signals)) { result.outcome = ConnectionOutcome::shutdown; return result; }
    if (Clock::now() >= accepted_at + limits.header_deadline) {
      return respond(make_error_response(ApiError::request_timeout), ConnectionOutcome::timed_out);
    }
    const IoResult r = read_slice(socket, chunk.data(), chunk.size());
    if (r.status == IoStatus::closed || r.status == IoStatus::failed) { result.outcome = ConnectionOutcome::client_gone; return result; }
    if (r.status == IoStatus::done) buffer.append(chunk.data(), r.bytes);
  }
  if (signals.on_header_complete && !signals.on_header_complete()) { result.outcome = ConnectionOutcome::evicted; return result; }

  // P2: parse and authorize (CPU only), before any body byte is read on purpose.
  const HeadParseResult parsed = parse_request_head(std::string_view{buffer}.substr(0, scan.head_bytes), limits.head);
  if (const auto* error = std::get_if<ApiError>(&parsed)) return respond(make_error_response(*error), ConnectionOutcome::responded);
  const RequestHead& head = std::get<RequestHead>(parsed);
  RouteDecision decision;
  try {
    decision = router.authorize(head);
  } catch (...) {
    return respond(make_error_response(ApiError::internal_error), ConnectionOutcome::responded);
  }
  result.route = decision.route;
  if (decision.early.has_value()) return respond(*decision.early, ConnectionOutcome::responded);
  std::string body = buffer.substr(scan.head_bytes);
  if (body.size() > decision.body_limit) return respond(make_error_response(ApiError::invalid_request), ConnectionOutcome::responded);
  // Review Focus 3: the interim 100 only while no body byte has arrived.
  if (decision.expect_continue && decision.body_limit > 0U && body.empty()) {
    if (send_all_bounded(socket, kContinueResponse, limits.write_stall, write_deadline(limits, signals), signals.shutting_down) != WriteOutcome::complete) {
      result.outcome = ConnectionOutcome::client_gone;
      return result;
    }
  }

  // P3: body (authenticated clients only), bounded by the request deadline.
  while (body.size() < decision.body_limit) {
    if (stopping(signals)) { result.outcome = ConnectionOutcome::shutdown; return result; }
    if (Clock::now() >= accepted_at + limits.request_deadline) {
      return respond(make_error_response(ApiError::request_timeout), ConnectionOutcome::timed_out);
    }
    // One byte more than still owed, so a stray byte is seen without a second read.
    const IoResult r = read_slice(socket, chunk.data(), std::min(chunk.size(), decision.body_limit - body.size() + 1U));
    if (r.status == IoStatus::closed || r.status == IoStatus::failed) { result.outcome = ConnectionOutcome::client_gone; return result; }
    if (r.status == IoStatus::done) body.append(chunk.data(), r.bytes);
    if (body.size() > decision.body_limit) return respond(make_error_response(ApiError::invalid_request), ConnectionOutcome::responded);
  }
  // Bytes that arrived with the request beyond Content-Length: 400. EOF is not an error
  // (a GET half-close still gets its answer: socket_server_responds_after_client_half_close).
  if (bytes_pending(socket)) return respond(make_error_response(ApiError::invalid_request), ConnectionOutcome::responded);

  // P4-P6: route; P7-P8: deliver.
  const RequestContext context{.client_gone = [socket] { return probe_peer(socket) == PeerState::gone; },
                               .shutting_down = signals.shutting_down};
  RouteResult routed{make_error_response(ApiError::internal_error)};
  try {
    routed = router.handle(head, body, decision, context);
  } catch (...) {
    routed = make_error_response(ApiError::internal_error);
  }
  return deliver_route_result(socket, std::move(routed), decision, limits, signals);
}

}  // namespace secure_frontend

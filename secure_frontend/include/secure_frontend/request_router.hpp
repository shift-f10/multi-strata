#pragma once

#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/http_request_head.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace secure_frontend {

enum class RouteId { health, models, model, chat, other };

struct RouteEntry final {
  std::string_view method;
  std::string_view path;
  bool prefix;   // /v1/models/<id>: the rest of the target is the id
  RouteId id;
};

// The one route table (spec §3.6); auth and EXT tests iterate it.
inline constexpr std::array<RouteEntry, 4> kRouteTable{{
    {"GET", "/health", false, RouteId::health},
    {"GET", "/v1/models", false, RouteId::models},
    {"GET", "/v1/models/", true, RouteId::model},
    {"POST", "/v1/chat/completions", false, RouteId::chat},
}};

struct RouteDecision final {
  std::optional<HttpResponse> early;      // set: answer now, the body is never read
  bool expect_continue{false};
  std::size_t body_limit{0};              // bytes the body stage reads (= Content-Length)
  RouteId route{RouteId::other};
  std::optional<std::string> allow_origin;
};

struct RequestContext final {
  std::function<bool()> client_gone;                // chat only; empty = never gone
  const std::atomic<bool>* shutting_down{nullptr};  // null = never
};

// A router returns this status when the client is gone and nothing may be written (spec §2.6).
inline constexpr int kNoResponseStatus = 0;

// Streaming seam (spec §3.11). M1 declares it and dispatches it in the connection
// handler (deliver_route_result, Task 8b); M2 produces StreamHandlers.
struct HttpHead final {
  int status;
  std::vector<std::pair<std::string, std::string>> headers;   // never Content-Length; a stream sets its own framing headers
};

// Implemented by the connection handler over one accepted socket. Every write is
// bounded by limits.http.write_stall_ms on progress (and by kShutdownDrainBudget
// once shutdown has begun); false = the client is gone or the write failed.
struct StreamSink {
  virtual bool send_headers(const HttpHead& head) = 0;           // status line, Date, Connection: close, security headers,
                                                                // head.headers, plus the decision's CORS headers
  virtual bool send_event(std::string_view bytes) = 0;           // one HTTP/1.1 chunk carrying exactly `bytes`
  virtual bool writable(std::chrono::milliseconds timeout) = 0;  // the socket can take more bytes within `timeout`
  virtual bool client_gone() = 0;                                // EOF, reset, or any byte after the body (probe_peer)
  virtual void finish() = 0;                                     // [DONE] already sent -> terminal chunk "0\r\n\r\n"
  // §8 log-only code of the stream (a fixed literal); M2. Default: ignored.
  virtual void set_log_code(std::string_view /*code*/) {}
  virtual ~StreamSink() = default;
};
using StreamHandler = std::function<void(StreamSink&)>;
using RouteResult = std::variant<HttpResponse, StreamHandler>;

class RequestRouter {
 public:
  virtual ~RequestRouter() = default;
  // Spec §4.1 steps 3-8; CPU only; runs before any body byte is read.
  [[nodiscard]] virtual RouteDecision authorize(const RequestHead& head) = 0;
  // Runs after exactly decision.body_limit body bytes were read.
  [[nodiscard]] virtual RouteResult handle(const RequestHead& head, std::string_view body, const RouteDecision& decision,
                                           const RequestContext& context) = 0;
};

// In-memory seam over one complete request: scan, parse, authorize, body
// length check (mismatch or extra bytes: 400), handle. A StreamHandler needs a
// socket, so the seam answers it with a fixed 500 internal_error.
[[nodiscard]] HttpResponse handle_http_request(std::string_view request, RequestRouter& router, const HeadLimits& limits);

}  // namespace secure_frontend

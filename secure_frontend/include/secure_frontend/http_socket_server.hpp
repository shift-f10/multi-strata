#pragma once

#include "secure_frontend/config.hpp"
#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/config_defaults.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace secure_frontend {

// Listener and parser bounds. request_deadline covers reading the whole
// request (header and body) from accept(); the response send gets the
// remaining budget, but never less than one second. Derived from
// FrontendConfig by http_socket_server_limits().
struct HttpSocketServerLimits final {
  std::chrono::milliseconds request_deadline{config_defaults::kRequestDeadlineMs};  // header+body, total
  std::size_t max_request_bytes{static_cast<std::size_t>(config_defaults::kMaxRequestBytes)};
  std::size_t max_header_bytes{static_cast<std::size_t>(config_defaults::kMaxHeaderBytes)};
  std::size_t max_headers{static_cast<std::size_t>(config_defaults::kMaxHeaders)};
  std::size_t max_request_line_bytes{static_cast<std::size_t>(config_defaults::kMaxRequestLineBytes)};
  int backlog{static_cast<int>(config_defaults::kListenerBacklog)};
};

// A deliberately small, synchronous listener for the authenticated HTTP
// boundary. It only accepts TCP clients; it never creates outbound sockets or
// resolves DNS names. The configured bind host must therefore be an IP
// literal. Each serve_one call handles at most one complete bounded request.
class HttpSocketServer final {
 public:
  [[nodiscard]] static std::optional<HttpSocketServer> bind(const Config& listener_config,
                                                              HttpPolicy policy,
                                                              BearerTokenValidator validator,
                                                              RequestDispatcher dispatcher,
                                                              std::string* error,
                                                              HttpSocketServerLimits limits = {});
  HttpSocketServer(HttpSocketServer&&) noexcept;
  HttpSocketServer& operator=(HttpSocketServer&&) noexcept;
  ~HttpSocketServer();

  HttpSocketServer(const HttpSocketServer&) = delete;
  HttpSocketServer& operator=(const HttpSocketServer&) = delete;

  // Returns false for a transport failure. HTTP policy failures are sent as
  // normal HTTP responses and return true. This API is intentionally one-shot
  // so callers can bound concurrency and apply their own lifecycle policy.
  [[nodiscard]] bool serve_one(std::string* error);
  [[nodiscard]] std::uint16_t port() const;
  // True once accept() failed because the listening socket itself is broken
  // (not a socket, invalid, or networking not initialised); callers should
  // stop serving. Client errors, peer resets, network errors and resource
  // exhaustion never set it.
  [[nodiscard]] bool listener_failed() const noexcept;
  // Thread-safe. Makes a blocked serve_one() return and every later call fail
  // with listener_failed(): POSIX shutdown(2) wakes accept() and stops new
  // connections; Windows closes the socket. A serve_one() already handling a
  // client returns too, without a response: the client socket is shut down
  // (never closed here) and the request read re-checks the shutdown at least
  // every 100 ms, so an idle or slow peer cannot hold the caller. Used by the
  // orderly shutdown (SP2 C4).
  void shutdown_listener() noexcept;

 private:
  struct State;
  explicit HttpSocketServer(std::unique_ptr<State> state);
  std::unique_ptr<State> state_;
};

}  // namespace secure_frontend

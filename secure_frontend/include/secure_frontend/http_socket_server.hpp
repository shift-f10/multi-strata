#pragma once

#include "secure_frontend/config.hpp"
#include "secure_frontend/http_request_handler.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace secure_frontend {

// Listener bounds. request_deadline covers reading the whole request (header
// and body) from accept(); the response send gets the remaining budget, but
// never less than one second. SP1 replaces this with typed configuration.
struct HttpSocketServerLimits final {
  std::chrono::milliseconds request_deadline{std::chrono::seconds(30)};  // header+body, total
  std::size_t max_request_bytes{64U * 1024U};
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

 private:
  struct State;
  explicit HttpSocketServer(std::unique_ptr<State> state);
  std::unique_ptr<State> state_;
};

}  // namespace secure_frontend

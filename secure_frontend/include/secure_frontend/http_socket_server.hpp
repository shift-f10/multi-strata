#pragma once

#include "secure_frontend/config.hpp"
#include "secure_frontend/http_request_handler.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace secure_frontend {

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
                                                              std::string* error);
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

 private:
  struct State;
  explicit HttpSocketServer(std::unique_ptr<State> state);
  std::unique_ptr<State> state_;
};

}  // namespace secure_frontend

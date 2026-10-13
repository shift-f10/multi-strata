#pragma once

#include "secure_frontend/http_policy.hpp"

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace secure_frontend {

// The validator owns any secret material. It is called only after request
// syntax and Host/Origin policy have been accepted, and should compare the
// supplied token in constant time (constant_time_token_equals is provided for
// that purpose). It must return false on any token-source error.
using BearerTokenValidator = std::function<bool(std::string_view)>;

struct HttpResponse final {
  int status;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;

  [[nodiscard]] std::optional<std::string_view> header_value(std::string_view name) const;
};

using RequestDispatcher = std::function<HttpResponse(std::string_view method,
                                                     std::string_view target,
                                                     std::string_view body)>;

// Compares all available bytes without an early content mismatch exit. This
// helper is for opaque bearer tokens; callers should keep the expected token
// outside long-lived configuration objects.
[[nodiscard]] bool constant_time_token_equals(std::string_view candidate,
                                              std::string_view expected);

// Parses one complete, bounded HTTP/1.1 message in memory. This deliberately
// does not open sockets, making policy enforcement portable and testable. The
// dispatcher is reached only after Host/Origin policy and bearer
// authentication have succeeded. The raw body is a non-owning view into the
// already bounded request buffer and is valid only for the synchronous
// dispatcher invocation; dispatchers that retain it must make their own copy.
[[nodiscard]] HttpResponse handle_http_request(std::string_view request,
                                                const HttpPolicy& policy,
                                                const BearerTokenValidator& validate_bearer_token,
                                                const RequestDispatcher& dispatch_request);

}  // namespace secure_frontend

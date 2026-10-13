#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace secure_frontend {

// All values in these allowlists are serialized HTTP header values. They are
// deliberately compared byte-for-byte: callers must configure every accepted
// spelling, including any non-default port.
struct HttpPolicy final {
  std::vector<std::string> allowed_hosts;
  std::vector<std::string> same_origin_origins;
  std::vector<std::string> cors_allowed_origins;
  bool cors_enabled{false};
};

enum class HttpPolicyError {
  missing_host,
  duplicate_host,
  invalid_host,
  untrusted_host,
  duplicate_origin,
  invalid_origin,
  untrusted_origin,
};

struct HttpPolicyDecision final {
  bool allowed;
  std::optional<HttpPolicyError> error;
  // Present only for a configured cross-origin request when CORS is enabled.
  std::optional<std::string> access_control_allow_origin;
};

[[nodiscard]] bool is_valid_host_header(std::string_view value);
[[nodiscard]] bool is_valid_origin_header(std::string_view value);

// Each vector contains every instance of its respective HTTP field. Supplying
// more than one Host or Origin field is rejected rather than coalesced.
[[nodiscard]] HttpPolicyDecision validate_http_request_headers(
    const HttpPolicy& policy, const std::vector<std::string_view>& hosts,
    const std::vector<std::string_view>& origins);

}  // namespace secure_frontend

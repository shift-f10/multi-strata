#pragma once

#include "secure_frontend/http_request_handler.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace secure_frontend {

// Spec §7.2. Every client-visible error is one of these rows; the message is
// a compile-time literal and never contains request, config or engine data.
enum class ApiError {
  invalid_request, invalid_json, unsupported_parameter, extension_disabled, context_length_exceeded,
  invalid_api_key, forbidden, not_found, model_not_found, method_not_allowed, request_timeout, length_required,
  request_too_large, request_line_too_long, unsupported_media_type, expectation_failed, header_too_large,
  internal_error, server_busy, engine_unavailable, engine_error, server_shutting_down, http_version_not_supported,
};

struct ApiErrorRow final {
  ApiError error;
  int status;
  std::string_view type;
  std::string_view code;
  std::string_view message;
};

[[nodiscard]] std::span<const ApiErrorRow> api_error_table() noexcept;
[[nodiscard]] const ApiErrorRow& api_error_row(ApiError error) noexcept;
// The fixed key lists of spec §3.1 (unsupported_parameter and extension_disabled).
[[nodiscard]] bool is_fixed_param_key(std::string_view key) noexcept;

struct ErrorOptions final {
  std::string_view param{};             // used only for unsupported_parameter / extension_disabled, and only a fixed key
  std::optional<int> retry_after{};     // engine_unavailable: 5 or none (spec §3.8)
  std::string_view allow{};             // method_not_allowed
};

// {"error":{"message":"<fixed>","type":"<type>","param":null|"<key>","code":"<code>"}}\n
[[nodiscard]] std::string render_error_body(ApiError error, std::string_view param = {});
[[nodiscard]] HttpResponse make_error_response(ApiError error, const ErrorOptions& options = {});
// Spec §3.8: engine_unavailable carries Retry-After 5 unless recovery=exhausted.
[[nodiscard]] std::optional<int> engine_retry_after(std::string_view recovery) noexcept;

}  // namespace secure_frontend

#include "secure_frontend/api_errors.hpp"

#include "secure_frontend/api_constants.hpp"
#include "secure_frontend/json.hpp"

#include <algorithm>
#include <array>

namespace secure_frontend {
namespace {

constexpr std::array<ApiErrorRow, 23> kTable{{
    {ApiError::invalid_request, 400, "invalid_request_error", "invalid_request", "The request is malformed or not supported."},
    {ApiError::invalid_json, 400, "invalid_request_error", "invalid_json", "The request body is not valid JSON within the allowed limits."},
    {ApiError::unsupported_parameter, 400, "invalid_request_error", "unsupported_parameter", "This parameter is not supported by this server."},
    {ApiError::extension_disabled, 400, "invalid_request_error", "extension_disabled", "Tools, functions and extensions are disabled on this server."},
    {ApiError::context_length_exceeded, 400, "invalid_request_error", "context_length_exceeded", "The prompt exceeds the model context or the configured prompt limit."},
    {ApiError::invalid_api_key, 401, "authentication_error", "invalid_api_key", "Missing or invalid API key."},
    {ApiError::forbidden, 403, "permission_error", "forbidden", "The request origin or host is not allowed."},
    {ApiError::not_found, 404, "invalid_request_error", "not_found", "Not found."},
    {ApiError::model_not_found, 404, "invalid_request_error", "model_not_found", "The requested model is not served here."},
    {ApiError::method_not_allowed, 405, "invalid_request_error", "method_not_allowed", "Method not allowed."},
    {ApiError::request_timeout, 408, "invalid_request_error", "request_timeout", "The request was not received in time."},
    {ApiError::length_required, 411, "invalid_request_error", "length_required", "A Content-Length body is required; chunked bodies are not accepted."},
    {ApiError::request_too_large, 413, "invalid_request_error", "request_too_large", "The request body is too large."},
    {ApiError::request_line_too_long, 414, "invalid_request_error", "request_line_too_long", "The request line is too long."},
    {ApiError::unsupported_media_type, 415, "invalid_request_error", "unsupported_media_type", "Send application/json."},
    {ApiError::expectation_failed, 417, "invalid_request_error", "expectation_failed", "Unsupported Expect header."},
    {ApiError::header_too_large, 431, "invalid_request_error", "header_too_large", "The request header is too large."},
    {ApiError::internal_error, 500, "server_error", "internal_error", "Internal error."},
    {ApiError::server_busy, 503, "server_error", "server_busy", "The server is busy; retry later."},
    {ApiError::engine_unavailable, 503, "server_error", "engine_unavailable", "The local engine is not available."},
    {ApiError::engine_error, 503, "server_error", "engine_error", "The local engine could not complete the request."},
    {ApiError::server_shutting_down, 503, "server_error", "server_shutting_down", "The server is shutting down."},
    {ApiError::http_version_not_supported, 505, "invalid_request_error", "http_version_not_supported", "Only HTTP/1.1 is supported."},
}};

constexpr std::array<std::string_view, 21> kFixedParamKeys{
    "n", "presence_penalty", "frequency_penalty", "logit_bias", "stop", "logprobs", "top_k", "min_p", "top_logprobs",
    "response_format", "content", "stream", "tools", "tool_choice", "functions", "function_call", "parallel_tool_calls",
    "mcp_servers", "role",
    // SP5 M1 Task 12 (C-9): the fixed §7.2 key the image gate names — caps, shapes and
    // unfetchable URLs all refuse through this one literal.
    "image_url",
    // Session log step 14: a profile without per-request thinking refuses reasoning_effort by name.
    "reasoning_effort"};

}  // namespace

std::span<const ApiErrorRow> api_error_table() noexcept { return kTable; }

const ApiErrorRow& api_error_row(const ApiError error) noexcept {
  return *std::find_if(kTable.begin(), kTable.end(), [error](const ApiErrorRow& row) { return row.error == error; });
}

bool is_fixed_param_key(const std::string_view key) noexcept {
  return std::find(kFixedParamKeys.begin(), kFixedParamKeys.end(), key) != kFixedParamKeys.end();
}

std::string render_error_body(const ApiError error, const std::string_view param) {
  const ApiErrorRow& row = api_error_row(error);
  const bool named = (error == ApiError::unsupported_parameter || error == ApiError::extension_disabled) &&
                     is_fixed_param_key(param);
  std::string body{"{\"error\":{\"message\":"};
  append_json_string(&body, row.message);
  body.append(",\"type\":");
  append_json_string(&body, row.type);
  body.append(",\"param\":");
  if (named) append_json_string(&body, param); else body.append("null");
  body.append(",\"code\":");
  append_json_string(&body, row.code);
  body.append("}}\n");
  return body;
}

HttpResponse make_error_response(const ApiError error, const ErrorOptions& options) {
  const ApiErrorRow& row = api_error_row(error);
  HttpResponse response{.status = row.status,
                        .headers = {{"Content-Type", "application/json; charset=utf-8"}},
                        .body = render_error_body(error, options.param),
                        .log_code = row.code};
  if (error == ApiError::invalid_api_key) response.headers.emplace_back("WWW-Authenticate", "Bearer");
  if (error == ApiError::server_busy) response.headers.emplace_back("Retry-After", std::to_string(api_constants::kRetryAfterBusyS));
  if (error == ApiError::engine_error) response.headers.emplace_back("x-should-retry", "false");
  if (error == ApiError::engine_unavailable && options.retry_after.has_value()) {
    response.headers.emplace_back("Retry-After", std::to_string(*options.retry_after));
  }
  if (error == ApiError::method_not_allowed && !options.allow.empty()) response.headers.emplace_back("Allow", std::string{options.allow});
  return response;
}

std::optional<int> engine_retry_after(const std::string_view recovery) noexcept {
  if (recovery == "exhausted") return std::nullopt;
  return api_constants::kRetryAfterEngineS;
}

}  // namespace secure_frontend

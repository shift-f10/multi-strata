#include "secure_frontend/api_constants.hpp"
#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/http_request_head.hpp"
#include "secure_frontend/http_wire.hpp"
#include "support/test_support.hpp"

#include <chrono>
#include <iostream>
#include <string>
#include <string_view>
#include <variant>

namespace {
int failures = 0;
void expect(bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}
using secure_frontend::ApiError;

// Spec §7.2, copied row by row: status, type, code, message.
struct ExpectedRow { ApiError error; int status; const char* type; const char* code; const char* message; };
constexpr ExpectedRow kExpected[] = {
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
};

void err_every_code_renders_fixed_body() {
  expect(secure_frontend::api_error_table().size() == std::size(kExpected), "the table has exactly the 23 rows of spec §7.2");
  for (const auto& row : kExpected) {
    const std::string body = std::string{"{\"error\":{\"message\":\""} + row.message + "\",\"type\":\"" + row.type +
                             "\",\"param\":null,\"code\":\"" + row.code + "\"}}\n";
    expect(secure_frontend::render_error_body(row.error) == body, std::string{"body of "} + row.code);
    const auto response = secure_frontend::make_error_response(row.error);
    expect(response.status == row.status, std::string{"status of "} + row.code);
    expect(response.body == body, std::string{"response body of "} + row.code);
    expect(response.header_value("Content-Type") == std::optional<std::string_view>{"application/json; charset=utf-8"},
           std::string{"content type of "} + row.code);
    expect(response.log_code == row.code, std::string{"log code of "} + row.code);
  }
  const auto unauthorized = secure_frontend::make_error_response(ApiError::invalid_api_key);
  expect(unauthorized.header_value("WWW-Authenticate") == std::optional<std::string_view>{"Bearer"}, "401 carries WWW-Authenticate: Bearer");
  const auto busy = secure_frontend::make_error_response(ApiError::server_busy);
  expect(busy.header_value("Retry-After") == std::optional<std::string_view>{"1"}, "server_busy carries Retry-After: 1");
  const auto engine_error = secure_frontend::make_error_response(ApiError::engine_error);
  expect(engine_error.header_value("x-should-retry") == std::optional<std::string_view>{"false"}, "engine_error carries x-should-retry: false");
  const auto starting = secure_frontend::make_error_response(ApiError::engine_unavailable, {.retry_after = 5});
  expect(starting.header_value("Retry-After") == std::optional<std::string_view>{"5"}, "engine_unavailable can carry Retry-After: 5");
  const auto exhausted = secure_frontend::make_error_response(ApiError::engine_unavailable);
  expect(!exhausted.header_value("Retry-After").has_value(), "engine_unavailable without retry_after carries none");
  const auto method = secure_frontend::make_error_response(ApiError::method_not_allowed, {.allow = "GET"});
  expect(method.header_value("Allow") == std::optional<std::string_view>{"GET"}, "405 carries Allow");
}

void err_param_is_key_only() {
  const std::string tools = secure_frontend::render_error_body(ApiError::extension_disabled, "tools");
  expect(tools.find("\"param\":\"tools\"") != std::string::npos, "a fixed extension key is named in param");
  const std::string stream = secure_frontend::render_error_body(ApiError::unsupported_parameter, "stream");
  expect(stream.find("\"param\":\"stream\"") != std::string::npos, "a fixed unsupported key is named in param");
  const std::string unknown = secure_frontend::render_error_body(ApiError::unsupported_parameter, "secret\"value");
  expect(unknown.find("\"param\":null") != std::string::npos && unknown.find("secret") == std::string::npos,
         "a key outside the fixed lists is never reflected");
  const std::string other_code = secure_frontend::render_error_body(ApiError::invalid_request, "tools");
  expect(other_code.find("\"param\":null") != std::string::npos, "param is null for every other code");
  for (const auto key : {"n", "presence_penalty", "frequency_penalty", "logit_bias", "stop", "logprobs", "top_k", "min_p",
                         "top_logprobs", "response_format", "content", "stream", "tools", "tool_choice", "functions",
                         "function_call", "parallel_tool_calls", "mcp_servers", "role"}) {
    expect(secure_frontend::is_fixed_param_key(key), std::string{"fixed key "} + key);
  }
  expect(!secure_frontend::is_fixed_param_key("model") && !secure_frontend::is_fixed_param_key(""), "other keys are not fixed");
}

void wire_response_has_security_headers_and_date() {
  using namespace std::chrono;
  const auto now = system_clock::time_point{seconds{1791963785}};   // 2026-10-14 07:43:05 UTC
  expect(secure_frontend::imf_fixdate(now) == "Wed, 14 Oct 2026 07:43:05 GMT", "IMF-fixdate");
  expect(secure_frontend::imf_fixdate(system_clock::time_point{seconds{951782400}}) == "Tue, 29 Feb 2000 00:00:00 GMT",
         "IMF-fixdate on a leap day");
  secure_frontend::HttpResponse response{.status = 200, .headers = {{"Content-Type", "application/json; charset=utf-8"},
                                                                    {"X-Bad", "a\r\nInjected: 1"}, {"Server", "leak"}},
                                         .body = "{}\n"};
  const std::string wire = secure_frontend::serialize_response(response, now);
  expect(wire.rfind("HTTP/1.1 200 OK\r\n", 0) == 0, "status line");
  for (const auto line : {"Date: Wed, 14 Oct 2026 07:43:05 GMT\r\n", "Connection: close\r\n", "Content-Length: 3\r\n",
                          "Cache-Control: no-store\r\n", "X-Content-Type-Options: nosniff\r\n",
                          "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n",
                          "Referrer-Policy: no-referrer\r\n", "Cross-Origin-Resource-Policy: same-origin\r\n",
                          "Content-Type: application/json; charset=utf-8\r\n"}) {
    expect(wire.find(line) != std::string::npos, std::string{"header line "} + line);
  }
  expect(wire.find("Injected") == std::string::npos, "a header value with CR/LF is dropped");
  expect(wire.find("Server:") == std::string::npos, "no Server header is ever written");
  expect(wire.size() >= 3U && wire.substr(wire.size() - 7U) == "\r\n\r\n{}\n", "body follows the blank line");
  const secure_frontend::HttpResponse no_content{.status = 204, .headers = {}, .body = ""};
  const std::string empty = secure_frontend::serialize_response(no_content, now);
  expect(empty.rfind("HTTP/1.1 204 No Content\r\n", 0) == 0 && empty.find("Content-Length") == std::string::npos,
         "204 has no Content-Length");
  for (const int status : {400, 401, 403, 404, 405, 408, 411, 413, 414, 415, 417, 431, 500, 503, 505}) {
    expect(!secure_frontend::reason_phrase(status).empty() && secure_frontend::reason_phrase(status) != "Unknown",
           "reason phrase for " + std::to_string(status));
  }
  expect(secure_frontend::kContinueResponse == "HTTP/1.1 100 Continue\r\n\r\n", "interim 100 response");
}
constexpr secure_frontend::HeadLimits kLimits{.max_request_line_bytes = 4096, .max_header_bytes = 16384,
                                              .max_headers = 64, .max_request_bytes = 65536};

std::variant<secure_frontend::RequestHead, ApiError> head_of(const std::string& text) {
  const auto scan = secure_frontend::scan_request_head(text, kLimits);
  if (scan.state == secure_frontend::HeadScan::line_too_long) return ApiError::request_line_too_long;
  if (scan.state == secure_frontend::HeadScan::header_too_large) return ApiError::header_too_large;
  if (scan.state != secure_frontend::HeadScan::complete) return ApiError::internal_error;   // "incomplete" marker for tests
  return secure_frontend::parse_request_head(std::string_view{text}.substr(0, scan.head_bytes), kLimits);
}
bool is_error(const std::variant<secure_frontend::RequestHead, ApiError>& r, ApiError e) {
  return std::holds_alternative<ApiError>(r) && std::get<ApiError>(r) == e;
}
const std::string kHost = "Host: 127.0.0.1:8080\r\n";

void dos01_request_line_over_limit_is_414() {
  const std::string long_target(4100, 'a');
  expect(is_error(head_of("GET /" + long_target + " HTTP/1.1\r\n" + kHost + "\r\n"), ApiError::request_line_too_long),
         "a complete head with a request line over 4096 bytes is 414");
  const auto partial = secure_frontend::scan_request_head("GET /" + long_target, kLimits);
  expect(partial.state == secure_frontend::HeadScan::line_too_long, "414 is known before the line ends");
  const auto short_partial = secure_frontend::scan_request_head("GET /abc", kLimits);
  expect(short_partial.state == secure_frontend::HeadScan::need_more, "a short partial line needs more bytes");
}

void dos01_header_block_over_limit_is_431() {
  std::string head = "GET /health HTTP/1.1\r\n" + kHost;
  while (head.size() < 16500U) head += "X-Fill: " + std::string(100, 'f') + "\r\n";
  expect(secure_frontend::scan_request_head(head, kLimits).state == secure_frontend::HeadScan::header_too_large,
         "431 is known before the blank line arrives");
  expect(is_error(head_of(head + "\r\n"), ApiError::header_too_large), "a complete head over 16384 bytes is 431");
}

void dos01_too_many_headers_is_431() {
  std::string head = "GET /health HTTP/1.1\r\n" + kHost;
  for (int i = 0; i < 64; ++i) head += "X-" + std::to_string(i) + ": v\r\n";
  expect(is_error(head_of(head + "\r\n"), ApiError::header_too_large), "65 fields are 431");
  std::string ok = "GET /health HTTP/1.1\r\n" + kHost;
  for (int i = 0; i < 63; ++i) ok += "X-" + std::to_string(i) + ": v\r\n";
  expect(std::holds_alternative<secure_frontend::RequestHead>(head_of(ok + "\r\n")), "64 fields are accepted");
}

void dos01_transfer_encoding_variants_are_411() {
  for (const std::string te : {"Transfer-Encoding: chunked\r\n", "Transfer-Encoding: Chunked\r\n", "Transfer-Encoding:  chunked\r\n",
                               "Transfer-Encoding: gzip, chunked\r\n", "transfer-encoding: identity\r\n",
                               "Transfer-Encoding: chunked\r\nContent-Length: 2\r\n"}) {
    expect(is_error(head_of("POST /v1/chat/completions HTTP/1.1\r\n" + kHost + te + "\r\n"), ApiError::length_required),
           "411 for " + te);
  }
  expect(is_error(head_of("POST /v1/chat/completions HTTP/1.1\r\n" + kHost + "Transfer-Encoding : chunked\r\n\r\n"),
                  ApiError::invalid_request), "space before the colon is 400");
}

void dos01_content_length_variants() {
  const auto post = [](const std::string& cl) { return head_of("POST /v1/chat/completions HTTP/1.1\r\n" + kHost + cl + "\r\n"); };
  expect(is_error(post("Content-Length: 2\r\nContent-Length: 2\r\n"), ApiError::invalid_request), "duplicate");
  expect(is_error(post("Content-Length: +1\r\n"), ApiError::invalid_request), "sign");
  expect(is_error(post("Content-Length: 0x10\r\n"), ApiError::invalid_request), "hex");
  expect(is_error(post("Content-Length: 12345678901\r\n"), ApiError::invalid_request), "11 digits");
  expect(is_error(post("Content-Length: \r\n"), ApiError::invalid_request), "empty");
  expect(is_error(post("Content-Length: 70000\r\n"), ApiError::request_too_large), "over the whole-request limit is 413");
  expect(is_error(post(""), ApiError::length_required), "POST without Content-Length is 411");
  expect(is_error(head_of("GET /health HTTP/1.1\r\n" + kHost + "Content-Length: 1\r\n\r\n"), ApiError::invalid_request),
         "GET with a body is 400");
  const auto ok = post("Content-Length: 0000000002\r\n");
  expect(std::holds_alternative<secure_frontend::RequestHead>(ok) && std::get<secure_frontend::RequestHead>(ok).content_length == 2U,
         "ten digits with leading zeros are accepted");
  // Mismatch and bytes after the body are body-stage rules: see the in-memory seam of Task 6a.
}

void head_request_line_and_header_syntax() {
  expect(is_error(head_of("GET /health HTTP/1.0\r\n" + kHost + "\r\n"), ApiError::http_version_not_supported), "1.0 is 505");
  expect(is_error(head_of("GET /health HTTP/2.0\r\n" + kHost + "\r\n"), ApiError::http_version_not_supported), "2.0 is 505");
  expect(is_error(head_of("GET /health HTTP/1.2\r\n" + kHost + "\r\n"), ApiError::invalid_request), "other versions are 400");
  expect(is_error(head_of("GET  /health HTTP/1.1\r\n" + kHost + "\r\n"), ApiError::invalid_request), "double space");
  for (const std::string target : {"/a?b", "/a#b", "/a%2e", "/a\\b", "*", "http://x/", "/a\x7f"}) {
    expect(is_error(head_of("GET " + target + " HTTP/1.1\r\n" + kHost + "\r\n"), ApiError::invalid_request), "target " + target);
  }
  expect(is_error(head_of("G(T /health HTTP/1.1\r\n" + kHost + "\r\n"), ApiError::invalid_request), "method token");
  expect(is_error(head_of("GET /health HTTP/1.1\r\n" + kHost + " folded\r\n\r\n"), ApiError::invalid_request), "obs-fold");
  expect(is_error(head_of("GET /health HTTP/1.1\r\n" + kHost + "X: a\nY: b\r\n\r\n"), ApiError::invalid_request), "bare LF");
  expect(is_error(head_of("GET /health HTTP/1.1\r\n" + kHost + std::string("X: a\0b\r\n\r\n", 10)), ApiError::invalid_request), "NUL");
  expect(is_error(head_of("GET /health HTTP/1.1\r\n" + kHost + "X: caf\xc3\xa9\r\n\r\n"), ApiError::invalid_request), "non-ASCII value");
  expect(is_error(head_of("POST /v1/chat/completions HTTP/1.1\r\n" + kHost + "Content-Length: 2\r\nExpect: foo\r\n\r\n"),
                  ApiError::expectation_failed), "Expect: foo is 417");
  const auto cont = head_of("POST /v1/chat/completions HTTP/1.1\r\n" + kHost + "Content-Length: 2\r\nExpect: 100-Continue\r\n\r\n");
  expect(std::holds_alternative<secure_frontend::RequestHead>(cont) && std::get<secure_frontend::RequestHead>(cont).expect_continue,
         "Expect: 100-continue is recognised case-insensitively");
  const auto parsed = head_of("DELETE /v1/models HTTP/1.1\r\n" + kHost + "Origin: http://127.0.0.1:8080\r\n\r\n");
  expect(std::holds_alternative<secure_frontend::RequestHead>(parsed), "any token method parses (405 comes after auth)");
  if (const auto* head = std::get_if<secure_frontend::RequestHead>(&parsed)) {
    expect(head->method == "DELETE" && head->target == "/v1/models", "method and target");
    expect(head->values("HOST").size() == 1U && head->values("origin").front() == "http://127.0.0.1:8080", "values()");
  }
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"err_every_code_renders_fixed_body", err_every_code_renders_fixed_body},
      {"err_param_is_key_only", err_param_is_key_only},
      {"wire_response_has_security_headers_and_date", wire_response_has_security_headers_and_date},
      {"dos01_request_line_over_limit_is_414", dos01_request_line_over_limit_is_414},
      {"dos01_header_block_over_limit_is_431", dos01_header_block_over_limit_is_431},
      {"dos01_too_many_headers_is_431", dos01_too_many_headers_is_431},
      {"dos01_transfer_encoding_variants_are_411", dos01_transfer_encoding_variants_are_411},
      {"dos01_content_length_variants", dos01_content_length_variants},
      {"head_request_line_and_header_syntax", head_request_line_and_header_syntax},
  }, failures);
}

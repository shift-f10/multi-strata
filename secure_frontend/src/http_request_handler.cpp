#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/secret_bytes.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

namespace secure_frontend {
namespace {

struct ParsedRequest final {
  std::string_view method;
  std::string_view target;
  std::string_view body;
  std::vector<std::string_view> hosts;
  std::vector<std::string_view> origins;
  std::vector<std::string_view> authorizations;
  std::vector<std::string_view> content_lengths;
  std::vector<std::string_view> preflight_methods;
  std::vector<std::string_view> preflight_headers;
  bool has_transfer_encoding{false};
  std::size_t body_size{0};
};

bool ascii_case_equal(std::string_view left, std::string_view right) {
  if (left.size() != right.size()) return false;
  for (std::size_t index = 0; index < left.size(); ++index) {
    const char a = left[index];
    const char b = right[index];
    const char lowered_left = a >= 'A' && a <= 'Z' ? static_cast<char>(a + ('a' - 'A')) : a;
    const char lowered_right = b >= 'A' && b <= 'Z' ? static_cast<char>(b + ('a' - 'A')) : b;
    if (lowered_left != lowered_right) return false;
  }
  return true;
}

bool is_token(std::string_view value) {
  if (value.empty()) return false;
  for (const unsigned char character : value) {
    const bool alphanumeric = (character >= '0' && character <= '9') ||
                              (character >= 'A' && character <= 'Z') ||
                              (character >= 'a' && character <= 'z');
    if (!alphanumeric && character != '!' && character != '#' && character != '$' && character != '%' &&
        character != '&' && character != '\'' && character != '*' && character != '+' && character != '-' &&
        character != '.' && character != '^' && character != '_' && character != '`' && character != '|' &&
        character != '~') {
      return false;
    }
  }
  return true;
}

bool is_safe_header_value(std::string_view value) {
  return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return (character >= 0x20U && character <= 0x7eU) || character == '\t';
  });
}

std::string_view trim_optional_whitespace(std::string_view value) {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1U);
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1U);
  return value;
}

bool parse_decimal(std::string_view value, std::size_t* result) {
  if (value.empty()) return false;
  std::size_t parsed = 0;
  for (const char character : value) {
    if (character < '0' || character > '9') return false;
    const std::size_t digit = static_cast<std::size_t>(character - '0');
    if (parsed > (std::numeric_limits<std::size_t>::max() - digit) / 10U) return false;
    parsed = (parsed * 10U) + digit;
  }
  *result = parsed;
  return true;
}

bool parse_request(std::string_view request, ParsedRequest* parsed, const HttpParserLimits& limits) {
  if (request.empty() || request.size() > limits.max_request_bytes) return false;
  const std::size_t headers_end = request.find("\r\n\r\n");
  if (headers_end == std::string_view::npos || headers_end + 4U > limits.max_header_bytes) return false;
  if (request.find('\n') != std::string_view::npos && request.find("\r\n") == std::string_view::npos) return false;
  const std::string_view header_block = request.substr(0, headers_end);
  const std::size_t line_end = header_block.find("\r\n");
  if (line_end == std::string_view::npos || line_end > limits.max_request_line_bytes) return false;
  const std::string_view request_line = header_block.substr(0, line_end);
  const std::size_t first_space = request_line.find(' ');
  const std::size_t second_space = first_space == std::string_view::npos ? std::string_view::npos
                                                                          : request_line.find(' ', first_space + 1U);
  if (first_space == std::string_view::npos || second_space == std::string_view::npos ||
      request_line.find(' ', second_space + 1U) != std::string_view::npos ||
      request_line.substr(second_space + 1U) != "HTTP/1.1") return false;
  parsed->method = request_line.substr(0, first_space);
  const std::string_view target = request_line.substr(first_space + 1U, second_space - first_space - 1U);
  if (!is_token(parsed->method) || target.empty() || target.front() != '/' ||
      std::any_of(target.begin(), target.end(), [](unsigned char character) { return character <= 0x20U || character == 0x7fU; })) return false;
  if (parsed->method != "GET" && parsed->method != "POST" && parsed->method != "OPTIONS") return false;
  parsed->target = target;

  std::size_t start = line_end + 2U;
  std::size_t header_count = 0;
  while (start < header_block.size()) {
    const std::size_t separator = header_block.find("\r\n", start);
    const std::size_t end = separator == std::string_view::npos ? header_block.size() : separator;
    const std::string_view line = header_block.substr(start, end - start);
    const std::size_t colon = line.find(':');
    if (colon == std::string_view::npos || !is_token(line.substr(0, colon))) return false;
    const std::string_view raw_value = line.substr(colon + 1U);
    if (!is_safe_header_value(raw_value)) return false;
    const std::string_view value = trim_optional_whitespace(raw_value);
    if (value.empty()) return false;
    if (++header_count > limits.max_headers) return false;
    const std::string_view name = line.substr(0, colon);
    if (ascii_case_equal(name, "host")) parsed->hosts.push_back(value);
    if (ascii_case_equal(name, "origin")) parsed->origins.push_back(value);
    if (ascii_case_equal(name, "authorization")) parsed->authorizations.push_back(value);
    if (ascii_case_equal(name, "content-length")) parsed->content_lengths.push_back(value);
    if (ascii_case_equal(name, "transfer-encoding")) parsed->has_transfer_encoding = true;
    if (ascii_case_equal(name, "access-control-request-method")) parsed->preflight_methods.push_back(value);
    if (ascii_case_equal(name, "access-control-request-headers")) parsed->preflight_headers.push_back(value);
    if (separator == std::string_view::npos) break;
    start = end + 2U;
  }
  parsed->body_size = request.size() - headers_end - 4U;
  parsed->body = request.substr(headers_end + 4U);
  if (parsed->has_transfer_encoding || parsed->content_lengths.size() > 1U) return false;
  if (!parsed->content_lengths.empty()) {
    std::size_t content_length = 0;
    if (!parse_decimal(parsed->content_lengths.front(), &content_length) || content_length != parsed->body_size) return false;
  } else if (parsed->body_size != 0U) {
    return false;
  }
  return true;
}

HttpResponse response(int status, std::string body) {
  return {.status = status, .headers = {{"Content-Type", "text/plain; charset=utf-8"}}, .body = std::move(body)};
}

HttpResponse bad_request() { return response(400, "Bad Request\n"); }
HttpResponse unauthorized() { return response(401, "Unauthorized\n"); }
HttpResponse forbidden() { return response(403, "Forbidden\n"); }
HttpResponse service_unavailable() { return response(503, "Service Unavailable\n"); }

void append_cors_headers(HttpResponse* response, const OriginDecision& decision) {
  if (decision.allow_origin.has_value()) {
    response->headers.emplace_back("Access-Control-Allow-Origin", *decision.allow_origin);
    response->headers.emplace_back("Vary", "Origin");
  }
}

// Temporary (removed in Task 6a, which rewrites this file): the preflight
// fields as a RequestHead so evaluate_preflight decides the preflight.
RequestHead preflight_head(const ParsedRequest& parsed) {
  RequestHead head;
  head.method = std::string{parsed.method};
  head.target = std::string{parsed.target};
  for (const std::string_view value : parsed.origins) head.fields.push_back({"Origin", std::string{value}});
  for (const std::string_view value : parsed.preflight_methods) {
    head.fields.push_back({"Access-Control-Request-Method", std::string{value}});
  }
  for (const std::string_view value : parsed.preflight_headers) {
    head.fields.push_back({"Access-Control-Request-Headers", std::string{value}});
  }
  return head;
}

}  // namespace

std::optional<std::string_view> HttpResponse::header_value(std::string_view name) const {
  for (const auto& [header_name, value] : headers) {
    if (ascii_case_equal(header_name, name)) return value;
  }
  return std::nullopt;
}

bool constant_time_token_equals(std::string_view candidate, std::string_view expected) {
  return detail::fixed_window_equals(candidate, expected, nullptr);
}

HttpResponse handle_http_request(std::string_view request, const HttpPolicy& policy,
                                 const BearerTokenValidator& validate_bearer_token,
                                 const RequestDispatcher& dispatch_request, const HttpParserLimits& limits) {
  ParsedRequest parsed;
  if (!parse_request(request, &parsed, limits)) return bad_request();
  // Temporary Task 3 shim over the new policy API (Task 6a rewrites this file).
  const PolicyVerdict host_verdict = check_host(policy, parsed.hosts);
  if (host_verdict != PolicyVerdict::allowed) return host_verdict == PolicyVerdict::malformed ? bad_request() : forbidden();
  if (auto preflight = evaluate_preflight(policy, preflight_head(parsed))) return std::move(*preflight);
  const OriginDecision policy_decision = check_origin(policy, parsed.origins);
  if (policy_decision.verdict != PolicyVerdict::allowed) return forbidden();

  if (parsed.authorizations.size() != 1U) return parsed.authorizations.size() > 1U ? bad_request() : unauthorized();
  constexpr std::string_view kBearerPrefix = "Bearer ";
  const std::string_view authorization = parsed.authorizations.front();
  if (!authorization.starts_with(kBearerPrefix) || authorization.size() == kBearerPrefix.size()) return unauthorized();
  const std::string_view token = authorization.substr(kBearerPrefix.size());
  bool authorized = false;
  try {
    authorized = validate_bearer_token && validate_bearer_token(token);
  } catch (...) {
    authorized = false;
  }
  if (!authorized) return unauthorized();

  if (!dispatch_request) return service_unavailable();
  HttpResponse response = service_unavailable();
  try {
    response = dispatch_request(parsed.method, parsed.target, parsed.body);
  } catch (...) {
    response = service_unavailable();
  }
  append_cors_headers(&response, policy_decision);
  return response;
}

}  // namespace secure_frontend

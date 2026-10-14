#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/token_verifier.hpp"
#include "support/test_support.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

namespace {

int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

// The new policy has no CORS switch: a configured cors_origins entry is the
// switch (pre-flight P10). The flag is kept so call sites stay unchanged until
// Task 6b ports these cases to the router.
secure_frontend::HttpPolicy policy(bool /*cors_enabled*/ = false) {
  return secure_frontend::make_http_policy(*secure_frontend::parse_listener_address("127.0.0.1"), 8080, {},
                                           {"https://console.example.test"});
}

secure_frontend::BearerTokenValidator validator() {
  return [](std::string_view candidate) {
    return secure_frontend::constant_time_token_equals(candidate, "test-token");
  };
}

secure_frontend::RequestDispatcher dispatcher() {
  return [](std::string_view method, std::string_view target, std::string_view) {
    if (method == "GET" && target == "/health") {
      return secure_frontend::HttpResponse{
          .status = 200,
          .headers = {{"Content-Type", "application/json; charset=utf-8"}},
          .body = "{\"status\":\"ok\"}\n"};
    }
    return secure_frontend::HttpResponse{
        .status = 404,
        .headers = {{"Content-Type", "application/json; charset=utf-8"}},
        .body = "{\"error\":\"Not Found\"}\n"};
  };
}

void passes_the_bounded_raw_body_to_an_authorized_dispatcher() {
  std::string received_method;
  std::string received_target;
  std::string received_body;
  const auto response = secure_frontend::handle_http_request(
      "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
      "Authorization: Bearer test-token\r\nContent-Length: 16\r\n\r\n"
      "{\"message\":\"hi\"}",
      policy(), validator(),
      [&received_method, &received_target, &received_body](std::string_view method, std::string_view target,
                                                            std::string_view body) {
        received_method.assign(method);
        received_target.assign(target);
        received_body.assign(body);
        return secure_frontend::HttpResponse{.status = 201, .headers = {}, .body = "created"};
      });
  expect(response.status == 201, "authorized POST should reach the dispatcher");
  expect(received_method == "POST", "dispatcher should receive the parsed method");
  expect(received_target == "/v1/chat/completions", "dispatcher should receive the parsed target");
  expect(received_body == "{\"message\":\"hi\"}", "dispatcher should receive the exact bounded body");
}

void accepts_authorized_request() {
  const auto response = secure_frontend::handle_http_request(
      "GET /health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAuthorization: Bearer test-token\r\n\r\n",
      policy(), validator(), dispatcher());
  expect(response.status == 200, "valid request should reach the dispatcher");
  expect(response.body == "{\"status\":\"ok\"}\n", "success response should come from the routed API");
}

void rejects_malformed_and_ambiguous_messages() {
  for (const std::string request : {
           "GET / HTTP/1.1\nHost: 127.0.0.1:8080\n\n",
           "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nHost: evil.test\r\nAuthorization: Bearer test-token\r\n\r\n",
           "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAuthorization: Bearer test-token\r\nTransfer-Encoding: chunked\r\n\r\n",
           "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAuthorization: Bearer test-token\r\nContent-Length: 2\r\n\r\nx",
       }) {
    const auto response = secure_frontend::handle_http_request(request, policy(), validator(), dispatcher());
    expect(response.status == 400, "ambiguous or malformed HTTP must be rejected with generic 400");
  }
}

void requires_one_well_formed_bearer_token() {
  for (const std::string request : {
           "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
           "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAuthorization: Basic dGVzdA==\r\n\r\n",
           "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAuthorization: Bearer wrong\r\n\r\n",
           "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAuthorization: Bearer test-token\r\nAuthorization: Bearer test-token\r\n\r\n",
       }) {
    const auto response = secure_frontend::handle_http_request(request, policy(), validator(), dispatcher());
    expect(response.status == 401 || response.status == 400,
           "missing, invalid, or duplicate authorization must never be accepted");
  }
}

void fails_closed_before_calling_validator_for_untrusted_origin() {
  bool called = false;
  const auto response = secure_frontend::handle_http_request(
      "GET / HTTP/1.1\r\nHost: evil.test\r\nAuthorization: Bearer test-token\r\n\r\n", policy(),
      [&called](std::string_view) { called = true; return true; }, dispatcher());
  expect(response.status == 403, "untrusted host should be forbidden");
  expect(!called, "untrusted request must not expose a token to the validator");
}

void emits_cors_only_for_policy_approved_origin() {
  const auto response = secure_frontend::handle_http_request(
      "GET /health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nOrigin: https://console.example.test\r\nAuthorization: Bearer test-token\r\n\r\n",
      policy(true), validator(), dispatcher());
  expect(response.status == 200, "configured CORS origin should be accepted");
  expect(response.header_value("Access-Control-Allow-Origin") == "https://console.example.test",
         "approved CORS origin must be emitted exactly");

  const auto same_origin = secure_frontend::handle_http_request(
      "GET /health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nOrigin: http://127.0.0.1:8080\r\nAuthorization: Bearer test-token\r\n\r\n",
      policy(true), validator(), dispatcher());
  expect(!same_origin.header_value("Access-Control-Allow-Origin").has_value(),
         "same-origin requests must not receive CORS headers");
}

void handles_policy_approved_preflight_without_exposing_an_endpoint() {
  const auto response = secure_frontend::handle_http_request(
      "OPTIONS /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nOrigin: https://console.example.test\r\nAccess-Control-Request-Method: POST\r\n\r\n",
      policy(true), validator(), dispatcher());
  expect(response.status == 204, "CORS preflight is not an authenticated API endpoint");
  expect(response.header_value("Access-Control-Allow-Origin") == "https://console.example.test",
         "preflight must only emit policy-approved CORS");

  const auto unsupported_method = secure_frontend::handle_http_request(
      "OPTIONS /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nOrigin: https://console.example.test\r\nAccess-Control-Request-Method: DELETE\r\n\r\n",
      policy(true), validator(), dispatcher());
  expect(unsupported_method.status == 403, "preflight must reject methods outside the CORS allowlist");
}

void constant_time_helper_matches_only_equal_tokens() {
  expect(secure_frontend::constant_time_token_equals("same", "same"), "equal tokens should match");
  expect(!secure_frontend::constant_time_token_equals("same", "different"), "unequal tokens should not match");
  expect(!secure_frontend::constant_time_token_equals("same", "sam"), "prefixes should not match");
  expect(!secure_frontend::constant_time_token_equals("", ""), "an empty expected token never matches");
}

void auth03_router_uses_verifier() {
  secure_frontend::SecretBytes secret;
  (void)secret.assign("router-token-0123456789abcdefghijklmnopqrs");
  const auto verifier = std::make_shared<const secure_frontend::TokenVerifier>(std::move(secret));
  const auto validator = secure_frontend::make_bearer_validator(verifier);
  bool dispatched = false;
  const secure_frontend::RequestDispatcher record = [&dispatched](std::string_view, std::string_view, std::string_view) {
    dispatched = true;
    return secure_frontend::HttpResponse{.status = 200, .headers = {}, .body = "ok"};
  };
  const auto request = [](const std::string& token) {
    return "GET /health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAuthorization: Bearer " + token + "\r\n\r\n";
  };
  const auto good = secure_frontend::handle_http_request(request("router-token-0123456789abcdefghijklmnopqrs"), policy(),
                                                         validator, record);
  expect(good.status == 200 && dispatched, "the verifier's token is accepted through the handler");
  dispatched = false;
  const auto prefix = secure_frontend::handle_http_request(request("router-token-0123456789abcdefghijklmnopqr"), policy(),
                                                           validator, record);
  expect(prefix.status == 401 && !dispatched, "a prefix is rejected and the dispatcher never runs");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"accepts_authorized_request", accepts_authorized_request},
      {"passes_the_bounded_raw_body_to_an_authorized_dispatcher", passes_the_bounded_raw_body_to_an_authorized_dispatcher},
      {"rejects_malformed_and_ambiguous_messages", rejects_malformed_and_ambiguous_messages},
      {"requires_one_well_formed_bearer_token", requires_one_well_formed_bearer_token},
      {"fails_closed_before_calling_validator_for_untrusted_origin", fails_closed_before_calling_validator_for_untrusted_origin},
      {"emits_cors_only_for_policy_approved_origin", emits_cors_only_for_policy_approved_origin},
      {"handles_policy_approved_preflight_without_exposing_an_endpoint", handles_policy_approved_preflight_without_exposing_an_endpoint},
      {"constant_time_helper_matches_only_equal_tokens", constant_time_helper_matches_only_equal_tokens},
      {"auth03_router_uses_verifier", auth03_router_uses_verifier},
  }, failures);
}

#include "secure_frontend/http_policy.hpp"
#include "support/test_support.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

secure_frontend::HttpPolicy test_policy() {
  return {.allowed_hosts = {"127.0.0.1:8080", "[::1]:8080"},
          .same_origin_origins = {"http://127.0.0.1:8080", "http://[::1]:8080"},
          .cors_allowed_origins = {"https://console.example.test"},
          .cors_enabled = false};
}

void accepts_exact_host_without_browser_origin() {
  const auto policy = test_policy();
  const auto decision = secure_frontend::validate_http_request_headers(
      policy, {"127.0.0.1:8080"}, {});
  expect(decision.allowed, "an exact configured Host without Origin should be accepted");
  expect(!decision.access_control_allow_origin.has_value(), "default policy must not emit CORS");
}

void rejects_ambiguous_or_untrusted_host() {
  const auto policy = test_policy();
  for (const auto& hosts : {std::vector<std::string_view>{},
                           std::vector<std::string_view>{"127.0.0.1:8080", "evil.test"},
                           std::vector<std::string_view>{"evil.test"},
                           std::vector<std::string_view>{"127.0.0.1:8080\r\nevil.test"},
                           std::vector<std::string_view>{"[::1"}}) {
    const auto decision = secure_frontend::validate_http_request_headers(policy, hosts, {});
    expect(!decision.allowed, "missing, duplicate, malformed, and untrusted Hosts must be rejected");
  }
}

void requires_an_exact_same_origin() {
  const auto policy = test_policy();
  const auto allowed = secure_frontend::validate_http_request_headers(
      policy, {"127.0.0.1:8080"}, {"http://127.0.0.1:8080"});
  expect(allowed.allowed, "configured same origin should be accepted");
  expect(!allowed.access_control_allow_origin.has_value(), "same origin must not need CORS");

  for (const auto origin : {"null", "HTTP://127.0.0.1:8080", "http://127.0.0.1",
                            "http://127.0.0.1:8080/", "http://evil.127.0.0.1:8080"}) {
    const auto rejected = secure_frontend::validate_http_request_headers(
        policy, {"127.0.0.1:8080"}, {origin});
    expect(!rejected.allowed, "lookalike or non-exact Origin must be rejected: " + std::string(origin));
    expect(!rejected.access_control_allow_origin.has_value(), "rejected origin must not receive CORS");
  }
}

void rejects_duplicate_or_malformed_origin() {
  const auto policy = test_policy();
  for (const auto& origins : {std::vector<std::string_view>{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
                             std::vector<std::string_view>{"http://127.0.0.1:8080\n"},
                             std::vector<std::string_view>{"https://user@console.example.test"},
                             std::vector<std::string_view>{"https://console.example.test/path"}}) {
    const auto decision = secure_frontend::validate_http_request_headers(policy, {"127.0.0.1:8080"}, origins);
    expect(!decision.allowed, "duplicate or malformed Origin must be rejected");
  }
}

void permits_only_configured_cors_origin_when_enabled() {
  auto policy = test_policy();
  policy.cors_enabled = true;
  const auto allowed = secure_frontend::validate_http_request_headers(
      policy, {"127.0.0.1:8080"}, {"https://console.example.test"});
  expect(allowed.allowed, "exact configured CORS origin should be accepted");
  expect(allowed.access_control_allow_origin == std::optional<std::string>{"https://console.example.test"},
         "CORS response must use the configured exact origin");

  const auto rejected = secure_frontend::validate_http_request_headers(
      policy, {"127.0.0.1:8080"}, {"https://console.example.test:443"});
  expect(!rejected.allowed, "default-port variant must not match the configured origin");
  expect(!rejected.access_control_allow_origin.has_value(), "untrusted origin must not be reflected");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"accepts_exact_host_without_browser_origin", accepts_exact_host_without_browser_origin},
      {"rejects_ambiguous_or_untrusted_host", rejects_ambiguous_or_untrusted_host},
      {"requires_an_exact_same_origin", requires_an_exact_same_origin},
      {"rejects_duplicate_or_malformed_origin", rejects_duplicate_or_malformed_origin},
      {"permits_only_configured_cors_origin_when_enabled", permits_only_configured_cors_origin_when_enabled},
  }, failures);
}

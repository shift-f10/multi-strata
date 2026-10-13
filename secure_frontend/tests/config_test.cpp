#include "secure_frontend/config.hpp"
#include "support/test_support.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <variant>

namespace {

int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

const secure_frontend::Config* config_from(const secure_frontend::ConfigValidation& result) {
  return std::get_if<secure_frontend::Config>(&result);
}

const secure_frontend::ConfigError* error_from(const secure_frontend::ConfigValidation& result) {
  return std::get_if<secure_frontend::ConfigError>(&result);
}

void defaults_to_loopback() {
  const auto result = secure_frontend::validate_config(
      {.host = std::nullopt, .port = std::nullopt, .api_key = std::string{"test-key"}});
  const auto* config = config_from(result);
  expect(config != nullptr, "default configuration should be accepted");
  if (config != nullptr) {
    expect(config->host == "127.0.0.1", "default host should be IPv4 loopback");
    expect(config->port == 8080, "default port should be 8080");
    expect(config->is_loopback, "default host should be loopback");
    expect(config->has_api_key, "validated configuration should record API key presence");
    expect(!config->allow_remote, "remote listening should default to disabled");
  }
}

void requires_key_for_loopback() {
  const auto result = secure_frontend::validate_config(
      {.host = std::string{"::1"}, .port = 9000, .api_key = std::nullopt});
  const auto* error = error_from(result);
  expect(error != nullptr, "loopback bind without a key should be rejected");
  if (error != nullptr) {
    expect(error->code == secure_frontend::ConfigErrorCode::api_key_required,
           "loopback bind should report the API key error");
  }
}

void requires_explicit_opt_in_for_remote_host() {
  const auto result = secure_frontend::validate_config(
      {.host = std::string{"192.0.2.10"}, .port = 8080, .api_key = std::string{"test-key"}});
  const auto* error = error_from(result);
  expect(error != nullptr, "remote bind without an explicit opt-in should be rejected");
  if (error != nullptr) {
    expect(error->code == secure_frontend::ConfigErrorCode::remote_not_enabled,
           "remote bind should report the explicit opt-in error");
  }
}

void requires_key_after_remote_opt_in() {
  const auto result = secure_frontend::validate_config(
      {.host = std::string{"192.0.2.10"}, .port = 8080, .api_key = std::nullopt, .allow_remote = true});
  const auto* error = error_from(result);
  expect(error != nullptr && error->code == secure_frontend::ConfigErrorCode::api_key_required,
         "remote opt-in must still require an API key");
}

void accepts_remote_host_with_opt_in_and_key() {
  const auto result = secure_frontend::validate_config(
      {.host = std::string{"192.0.2.10"}, .port = 65535, .api_key = std::string{"test-key"},
       .allow_remote = true});
  const auto* config = config_from(result);
  expect(config != nullptr, "remote bind with a nonempty key should be accepted");
  if (config != nullptr) {
    expect(!config->is_loopback, "remote IPv4 should not be classified as loopback");
    expect(config->allow_remote, "validated remote configuration should retain opt-in");
  }
}

void requires_separate_opt_in_for_wildcard_host() {
  const auto rejected = secure_frontend::validate_config(
      {.host = std::string{"0.0.0.0"}, .port = 8080, .api_key = std::string{"test-key"},
       .allow_remote = true});
  const auto* error = error_from(rejected);
  expect(error != nullptr && error->code == secure_frontend::ConfigErrorCode::wildcard_bind_not_enabled,
         "wildcard bind must not share the regular remote opt-in");

  const auto accepted = secure_frontend::validate_config(
      {.host = std::string{"::"}, .port = 8080, .api_key = std::string{"test-key"},
       .allow_remote = true, .allow_wildcard_bind = true});
  const auto* config = config_from(accepted);
  expect(config != nullptr && config->allow_wildcard_bind,
         "wildcard bind should require and retain its dedicated opt-in");
}

void rejects_invalid_ports() {
  for (const auto port : {0U, 65536U, 70000U}) {
    const auto result = secure_frontend::validate_config(
        {.host = std::nullopt, .port = port, .api_key = std::string{"test-key"}});
    const auto* error = error_from(result);
    expect(error != nullptr && error->code == secure_frontend::ConfigErrorCode::invalid_port,
           "out-of-range TCP port should be rejected");
  }
}

void rejects_invalid_hosts_and_blank_remote_keys() {
  for (const auto host : {"", "0.0.0.0/0", "bad host", "[::1]", "example..com", "-bad.example"}) {
    const auto result = secure_frontend::validate_config(
        {.host = std::string{host}, .port = std::nullopt, .api_key = std::string{"test-key"}});
    const auto* error = error_from(result);
    expect(error != nullptr && error->code == secure_frontend::ConfigErrorCode::invalid_host,
           "invalid host should be rejected: " + std::string{host});
  }

  const auto result = secure_frontend::validate_config(
      {.host = std::string{"service.internal"}, .port = std::nullopt, .api_key = std::string{" \t\n"},
       .allow_remote = true});
  const auto* error = error_from(result);
  expect(error != nullptr && error->code == secure_frontend::ConfigErrorCode::api_key_required,
         "blank API key must not permit remote binding");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"defaults_to_loopback", defaults_to_loopback},
      {"requires_key_for_loopback", requires_key_for_loopback},
      {"requires_explicit_opt_in_for_remote_host", requires_explicit_opt_in_for_remote_host},
      {"requires_key_after_remote_opt_in", requires_key_after_remote_opt_in},
      {"accepts_remote_host_with_opt_in_and_key", accepts_remote_host_with_opt_in_and_key},
      {"requires_separate_opt_in_for_wildcard_host", requires_separate_opt_in_for_wildcard_host},
      {"rejects_invalid_ports", rejects_invalid_ports},
      {"rejects_invalid_hosts_and_blank_remote_keys", rejects_invalid_hosts_and_blank_remote_keys},
  }, failures);
}

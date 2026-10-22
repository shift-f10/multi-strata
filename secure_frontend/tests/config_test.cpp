#include "secure_frontend/config.hpp"
#include "support/test_support.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
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
      {.host = std::string{"192.0.2.10"}, .port = std::nullopt, .api_key = std::string{" \t\n"},
       .allow_remote = true});
  const auto* error = error_from(result);
  expect(error != nullptr && error->code == secure_frontend::ConfigErrorCode::api_key_required,
         "blank API key must not permit remote binding");
}

// NET-03 / defect (a): every spelling of the unspecified address is a wildcard bind.
const char* const kWildcardSpellings[] = {"0.0.0.0", "::", "::0", "0::0", "0:0:0:0:0:0:0:0", "::0.0.0.0",
                                          "::ffff:0.0.0.0", "0000:0000:0000:0000:0000:0000:0000:0000"};

void net03_wildcard_spellings_need_wildcard_opt_in() {
  for (const char* host : kWildcardSpellings) {
    const auto without = secure_frontend::validate_config(
        {.host = std::string{host}, .port = 8080, .api_key = std::string{"k"}});
    const auto* error = error_from(without);
    expect(error != nullptr && error->code == secure_frontend::ConfigErrorCode::remote_not_enabled,
           std::string{"wildcard without any opt-in must be rejected: "} + host);
    const auto with_both = secure_frontend::validate_config(
        {.host = std::string{host}, .port = 8080, .api_key = std::string{"k"}, .allow_remote = true,
         .allow_wildcard_bind = true});
    const auto* config = config_from(with_both);
    expect(config != nullptr && !config->is_loopback, std::string{"wildcard with both opt-ins is accepted: "} + host);
    if (config != nullptr) {
      expect(config->host == "0.0.0.0" || config->host == "::",
             std::string{"a wildcard binds its canonical text, got "} + config->host);
    }
  }
}

void net03_remote_opt_in_alone_rejects_wildcard() {
  for (const char* host : kWildcardSpellings) {
    const auto result = secure_frontend::validate_config(
        {.host = std::string{host}, .port = 8080, .api_key = std::string{"k"}, .allow_remote = true});
    const auto* error = error_from(result);
    expect(error != nullptr && error->code == secure_frontend::ConfigErrorCode::wildcard_bind_not_enabled,
           std::string{"--allow-remote alone must not allow a wildcard bind: "} + host);
  }
}

void net01_loopback_spellings_classified_from_bytes() {
  const std::pair<const char*, const char*> cases[] = {
      {"127.0.0.1", "127.0.0.1"}, {"127.1.2.3", "127.1.2.3"}, {"::1", "::1"},
      {"0:0:0:0:0:0:0:1", "::1"}, {"0000::0001", "::1"}, {"::ffff:127.0.0.1", "127.0.0.1"}};
  for (const auto& [host, canonical] : cases) {
    const auto result = secure_frontend::validate_config(
        {.host = std::string{host}, .port = 8080, .api_key = std::string{"k"}});
    const auto* config = config_from(result);
    expect(config != nullptr && config->is_loopback, std::string{"loopback spelling must need no opt-in: "} + host);
    if (config != nullptr) expect(config->host == canonical, std::string{"canonical loopback text for "} + host);
  }
}

void net02_hostname_rejected_before_bind() {
  for (const char* host : {"example.com", "service.internal", "my-pc", "localhost.", "localhost.localdomain",
                           "ip6-localhost", "LOCALHOST.example"}) {
    const auto result = secure_frontend::validate_config(
        {.host = std::string{host}, .port = 8080, .api_key = std::string{"k"}, .allow_remote = true});
    const auto* error = error_from(result);
    expect(error != nullptr && error->code == secure_frontend::ConfigErrorCode::invalid_host,
           std::string{"hostnames are rejected at validation, not at bind(): "} + host);
  }
}

void net01_localhost_maps_to_ipv4_loopback() {
  for (const char* host : {"localhost", "LocalHost", "LOCALHOST"}) {
    const auto result = secure_frontend::validate_config(
        {.host = std::string{host}, .port = 8080, .api_key = std::string{"k"}});
    const auto* config = config_from(result);
    expect(config != nullptr && config->is_loopback && config->host == "127.0.0.1",
           std::string{"localhost maps to 127.0.0.1 without a resolver: "} + host);
  }
}

// listener.loopback_without_key (owner decision 2026-10-21): the one keyless listener needs
// the explicit opt-in AND a loopback address; a remote or wildcard bind always needs the key.
void keyless_listener_needs_opt_in_and_loopback() {
  for (const char* host : {"127.0.0.1", "::1", "localhost", "127.0.0.2"}) {
    const auto result = secure_frontend::validate_config(
        {.host = std::string{host}, .port = 8080, .api_key = std::nullopt, .allow_loopback_without_key = true});
    const auto* config = config_from(result);
    expect(config != nullptr && config->is_loopback && !config->has_api_key && config->loopback_without_key,
           std::string{"a loopback bind with the opt-in runs keyless: "} + host);
  }
  const auto keyed = secure_frontend::validate_config(
      {.host = std::string{"127.0.0.1"}, .port = 8080, .api_key = std::string{"k"}, .allow_loopback_without_key = true});
  expect(config_from(keyed) != nullptr && config_from(keyed)->has_api_key && !config_from(keyed)->loopback_without_key,
         "a key, when there is one, is still required (the opt-in never drops a configured key)");
  const auto remote = secure_frontend::validate_config({.host = std::string{"192.0.2.10"}, .port = 8080, .api_key = std::nullopt,
                                                        .allow_remote = true, .allow_loopback_without_key = true});
  expect(error_from(remote) != nullptr && error_from(remote)->code == secure_frontend::ConfigErrorCode::api_key_required,
         "a remote bind never runs keyless, opt-in or not");
  for (const char* wildcard : {"0.0.0.0", "::"}) {
    const auto open = secure_frontend::validate_config({.host = std::string{wildcard}, .port = 8080, .api_key = std::nullopt,
                                                        .allow_remote = true, .allow_wildcard_bind = true,
                                                        .allow_loopback_without_key = true});
    expect(error_from(open) != nullptr && error_from(open)->code == secure_frontend::ConfigErrorCode::api_key_required,
           std::string{"a wildcard bind never runs keyless: "} + wildcard);
  }
  const auto no_opt_in = secure_frontend::validate_config({.host = std::string{"127.0.0.1"}, .port = 8080, .api_key = std::nullopt});
  expect(error_from(no_opt_in) != nullptr && error_from(no_opt_in)->code == secure_frontend::ConfigErrorCode::api_key_required,
         "without the opt-in a loopback bind still needs the key");
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
      {"net03_wildcard_spellings_need_wildcard_opt_in", net03_wildcard_spellings_need_wildcard_opt_in},
      {"net03_remote_opt_in_alone_rejects_wildcard", net03_remote_opt_in_alone_rejects_wildcard},
      {"net01_loopback_spellings_classified_from_bytes", net01_loopback_spellings_classified_from_bytes},
      {"net02_hostname_rejected_before_bind", net02_hostname_rejected_before_bind},
      {"net01_localhost_maps_to_ipv4_loopback", net01_localhost_maps_to_ipv4_loopback},
      {"keyless_listener_needs_opt_in_and_loopback", keyless_listener_needs_opt_in_and_loopback},
  }, failures);
}

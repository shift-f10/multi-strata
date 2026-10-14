#include "support/server_fixture.hpp"
#include "support/test_support.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}
using secure_frontend_test::contains;
using secure_frontend_test::ServerFixture;

std::vector<std::string> with(std::vector<std::string> base, const std::vector<std::string>& extra) {
  base.insert(base.end(), extra.begin(), extra.end());
  return base;
}

std::vector<std::string> without_port(std::vector<std::string> flags) {
  for (std::size_t i = 0; i + 1 < flags.size(); ++i) {
    if (flags[i] == "--port") { flags.erase(flags.begin() + static_cast<long>(i), flags.begin() + static_cast<long>(i) + 2); break; }
  }
  return flags;
}

void cli_config_file_and_flags_share_validator() {
  ServerFixture f;
  auto literals = f.base_literals();
  literals["listener.port"] = "0";
  f.write_config(literals);
  const auto from_file = f.run({"--check", "--config", f.config.string()});
  const auto from_flag = f.run(with(without_port(f.base_flags()), {"--check", "--port", "0"}));
  const std::string expected = "listener.port: must be between 1 and 65535";
  expect(from_file.exit_code != 0 && contains(from_file.err, expected), "file value is validated: " + from_file.err);
  expect(from_flag.exit_code != 0 && contains(from_flag.err, expected), "flag value is validated: " + from_flag.err);
}

void cli_flag_overrides_file_and_is_reported() {
  ServerFixture f;
  f.write_config(f.base_literals());
  const std::string other_port = std::to_string(f.port == 65535 ? 65534 : f.port + 1);
  const auto result = f.run({"--check", "--config", f.config.string(), "--port", other_port});
  expect(result.exit_code == 0, "a valid file plus a flag passes --check: " + result.err);
  expect(contains(result.out, "listener.port = " + other_port), "the flag wins: " + result.out);
  expect(contains(result.out, "listener.port: the command line overrides the config file"),
         "the override is reported, never silent: " + result.out);
}

void cli_check_prints_no_token() {
  ServerFixture f;
  f.write_config(f.base_literals());
  const auto before = secure_frontend_test::snapshot_tree(f.dir);
  const auto result = f.run({"--check", "--config", f.config.string()});
  expect(result.exit_code == 0, "--check on a valid config exits 0: " + result.err);
  expect(secure_frontend_test::snapshot_tree(f.dir) == before, "--check has no side effects below the fixture");
  expect(contains(result.out, "token.source = \"env:SF_TEST_TOKEN\""), "the token source is shown as metadata");
  expect(contains(result.out, "token: available (value not shown)"), "--check confirms the token is readable");
  expect(!contains(result.out, secure_frontend_test::kTestToken) && !contains(result.err, secure_frontend_test::kTestToken),
         "--check never prints the token");
}

void cli_unknown_option_does_not_echo_value() {
  ServerFixture f;
  const std::string secret = "sk-PASTED-SECRET-0123456789";
  const auto equals_form = f.run({"--token=" + secret});
  expect(equals_form.exit_code != 0 && contains(equals_form.err, "unknown option: --token"), "flag name is echoed");
  expect(!contains(equals_form.err, secret), "the value after = is never echoed");
  const auto bare = f.run(with(f.base_flags(), {secret}));
  expect(bare.exit_code != 0 && !contains(bare.err, secret), "a stray argument is never echoed: " + bare.err);
  const auto long_flag = f.run({"--" + std::string(200, 'x')});
  expect(long_flag.exit_code != 0 && !contains(long_flag.err, std::string(65, 'x')), "at most 64 bytes are echoed");
  const auto missing = f.run({"--port"});
  expect(missing.exit_code != 0 && contains(missing.err, "missing value for --port"), "known flag without value");
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"cli_config_file_and_flags_share_validator", cli_config_file_and_flags_share_validator},
      {"cli_flag_overrides_file_and_is_reported", cli_flag_overrides_file_and_is_reported},
      {"cli_check_prints_no_token", cli_check_prints_no_token},
      {"cli_unknown_option_does_not_echo_value", cli_unknown_option_does_not_echo_value},
  }, failures);
}

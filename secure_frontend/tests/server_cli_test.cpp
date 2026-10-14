#include "secure_frontend/token_reader.hpp"
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

void cli_check_has_no_side_effects() {
  ServerFixture f;
  auto literals = f.base_literals();
  literals["roots.logs"] = secure_frontend_test::json_literal((f.dir / "logs").string());
  literals["roots.cache"] = secure_frontend_test::json_literal((f.dir / "cache").string());
  f.write_config(literals);
  const auto before = secure_frontend_test::snapshot_tree(f.dir);
  const auto checked = f.run({"--check", "--config", f.config.string()});
  expect(checked.exit_code == 0, "--check accepts absent-but-creatable logs/cache roots: " + checked.err);
  expect(secure_frontend_test::snapshot_tree(f.dir) == before, "--check created, wrote, renamed or removed nothing");
  expect(!std::filesystem::exists(f.dir / "logs") && !std::filesystem::exists(f.dir / "cache"), "--check created no root");
  secure_frontend_test::ChildProcess server;
  expect(f.start(server, {"--config", f.config.string()}), "serve starts: " + server.stderr_text());
  expect(std::filesystem::is_directory(f.dir / "logs") && std::filesystem::is_directory(f.dir / "cache"),
         "serve creates both roots before it listens");
#if !defined(_WIN32)
  struct stat st {};
  stat((f.dir / "logs").c_str(), &st);
  expect((st.st_mode & 0777) == 0700, "serve creates them 0700");
#endif
}

std::vector<std::string> init_flags(const ServerFixture& f, const std::filesystem::path& config) {
  return {"init", "--config", config.string(), "--models-root", f.models.string(), "--tokenizer-pack",
          f.tokenizer.string(), "--engine", f.engine.string(), "--model-id", "qwen-local", "--port", std::to_string(f.port)};
}

void init_writes_config_and_token_then_server_starts() {
  ServerFixture f;
  const auto config = f.dir / "fresh" / "config.json";
  const auto init = f.run(init_flags(f, config));
  expect(init.exit_code == 0, "init succeeds: " + init.err);
  expect(std::filesystem::exists(config) && std::filesystem::exists(f.dir / "fresh" / "token"), "config and token written");
  const auto source = std::get<secure_frontend::SecretSource>(secure_frontend::make_protected_file_secret_source("token"));
  auto token = secure_frontend::read_token(source, f.dir / "fresh");
  const auto* value = std::get_if<secure_frontend::SecretBytes>(&token);
  expect(value != nullptr && value->size() == 43U, "a generated 43-character token is readable");
  if (value == nullptr) return;
  expect(!contains(init.out, value->view()) && !contains(init.err, value->view()), "init never prints the token");
  secure_frontend_test::ChildProcess server;
  expect(f.start(server, {"--config", config.string()}), "the server starts from the written config alone: " + server.stderr_text());
  const auto response = f.request("GET", "/health", "Bearer " + std::string{value->view()});
  expect(response.rfind("HTTP/1.1 200", 0) == 0, "the generated token authenticates: " + response.substr(0, 16));
}

void init_refuses_to_overwrite_without_force() {
  ServerFixture f;
  const auto config = f.dir / "fresh" / "config.json";
  expect(f.run(init_flags(f, config)).exit_code == 0, "first init");
  const std::string config_before = secure_frontend_test::read_file(config);
  const std::string token_before = secure_frontend_test::read_file(f.dir / "fresh" / "token");
  const auto again = f.run(init_flags(f, config));
  expect(again.exit_code != 0 && contains(again.err, "already exists"), "a second init without --force fails: " + again.err);
  expect(secure_frontend_test::read_file(config) == config_before &&
             secure_frontend_test::read_file(f.dir / "fresh" / "token") == token_before,
         "nothing was changed");
  auto forced = init_flags(f, config);
  forced.insert(forced.begin() + 1, "--force");
  expect(f.run(forced).exit_code == 0, "--force succeeds");
  expect(secure_frontend_test::read_file(f.dir / "fresh" / "token") != token_before, "--force rotates the token");
}

void init_force_refuses_a_non_regular_config_target() {
  ServerFixture f;
  const auto config = f.dir / "fresh" / "config.json";
  expect(f.run(init_flags(f, config)).exit_code == 0, "first init");
  const std::string token_before = secure_frontend_test::read_file(f.dir / "fresh" / "token");
  const auto occupied = f.dir / "fresh" / "occupied";
  secure_frontend_test::make_private_directory(occupied);
  auto forced = init_flags(f, occupied);
  forced.insert(forced.begin() + 1, "--force");
  const auto result = f.run(forced);
  expect(result.exit_code != 0 && contains(result.err, "not a regular file"),
         "--force against a directory fails before writing: " + result.err);
  expect(secure_frontend_test::read_file(f.dir / "fresh" / "token") == token_before, "the token was not rotated");
  expect(std::filesystem::is_directory(occupied), "the directory is left in place");
}

void init_failure_creates_nothing() {
  ServerFixture f;
  const auto before = secure_frontend_test::snapshot_tree(f.dir);
  auto flags = init_flags(f, f.dir / "never" / "config.json");
  flags.back() = "0";  // --port 0 is invalid
  const auto result = f.run(flags);
  expect(result.exit_code != 0 && contains(result.err, "listener.port"), "an invalid option fails init: " + result.err);
  expect(!std::filesystem::exists(f.dir / "never"), "no config directory was created");
  expect(secure_frontend_test::snapshot_tree(f.dir) == before, "nothing below the scratch tree changed");
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"cli_config_file_and_flags_share_validator", cli_config_file_and_flags_share_validator},
      {"cli_flag_overrides_file_and_is_reported", cli_flag_overrides_file_and_is_reported},
      {"cli_check_prints_no_token", cli_check_prints_no_token},
      {"cli_check_has_no_side_effects", cli_check_has_no_side_effects},
      {"cli_unknown_option_does_not_echo_value", cli_unknown_option_does_not_echo_value},
      {"init_writes_config_and_token_then_server_starts", init_writes_config_and_token_then_server_starts},
      {"init_refuses_to_overwrite_without_force", init_refuses_to_overwrite_without_force},
      {"init_force_refuses_a_non_regular_config_target", init_force_refuses_a_non_regular_config_target},
      {"init_failure_creates_nothing", init_failure_creates_nothing},
  }, failures);
}

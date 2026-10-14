#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/server_cli.hpp"
#include "secure_frontend/token_reader.hpp"
#include "support/server_fixture.hpp"
#include "support/test_support.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <string_view>
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

void auth04_empty_token_rejected_on_loopback() {
  ServerFixture f;
  const auto marker = f.dir / "engine-started";
  const auto flags = with(f.base_flags(), {"--engine-arg", "--marker=" + marker.string()});
  for (const char* value : {"", "   "}) {
    const auto result = secure_frontend_test::run_to_completion(
        secure_frontend_test::ProcessSpec{f.server_executable, flags, {{secure_frontend_test::kTestTokenVariable, value}}});
    expect(result.exit_code != 0 && contains(result.err, "Unable to read API token"),
           std::string{"an empty or blank token stops the loopback server: \""} + value + "\"");
  }
  secure_frontend_test::write_file(f.secret / "token", "");
  std::vector<std::string> file_flags = f.base_flags();
  for (std::size_t i = 0; i + 1 < file_flags.size(); ++i) {
    if (file_flags[i] == "--token-env") { file_flags[i] = "--token-file"; file_flags[i + 1] = "token"; }
  }
  file_flags.insert(file_flags.end(), {"--secret-root", f.secret.string(), "--engine-arg", "--marker=" + marker.string()});
  const auto empty_file = f.run(file_flags);
  expect(empty_file.exit_code != 0 && contains(empty_file.err, "Unable to read API token"), "an empty token file too");
  expect(!std::filesystem::exists(marker), "the engine never started");
  expect(!secure_frontend_test::can_connect(f.port), "and nothing listens");
}

// Every "--name" token in `text` (the name ends at a byte outside [a-z0-9-]).
std::set<std::string> option_names_in(std::string_view text) {
  std::set<std::string> names;
  for (std::size_t at = text.find("--"); at != std::string_view::npos; at = text.find("--", at + 2)) {
    std::size_t end = at + 2;
    while (end < text.size() && ((text[end] >= 'a' && text[end] <= 'z') || (text[end] >= '0' && text[end] <= '9') ||
                                 text[end] == '-')) {
      ++end;
    }
    if (end > at + 2) names.emplace(text.substr(at, end - at));
  }
  return names;
}

// Every STRATA_[A-Z0-9_]+ name in `text`.
void strata_names_in(std::string_view text, std::set<std::string>* names) {
  for (std::size_t at = text.find("STRATA_"); at != std::string_view::npos; at = text.find("STRATA_", at + 7)) {
    std::size_t end = at + 7;
    while (end < text.size() && ((text[end] >= 'A' && text[end] <= 'Z') || (text[end] >= '0' && text[end] <= '9') ||
                                 text[end] == '_')) {
      ++end;
    }
    if (end > at + 7) names->emplace(text.substr(at, end - at));
  }
}

void auth04_no_switch_disables_auth() {
  constexpr std::array kForbidden{"auth", "insecure", "unauth", "dev", "anonymous", "disable", "no_token", "no-token"};
  const auto forbidden_in = [&kForbidden](const std::string& text) {
    return std::any_of(kForbidden.begin(), kForbidden.end(),
                       [&text](const char* word) { return text.find(word) != std::string::npos; });
  };
  // Derived from the schema and the usage text, so a key or flag added later is examined by name.
  std::set<std::string> flags = option_names_in(secure_frontend::server_usage());
  std::set<std::string> strata_names;
  strata_names_in(secure_frontend::server_usage(), &strata_names);
  for (const auto& key : secure_frontend::config_schema()) {
    const std::string path{key.path};
    expect(!forbidden_in(path), "no config key can switch off authentication: " + path);
    for (const auto& flag : option_names_in(key.flag)) flags.insert(flag);
    for (const std::string_view text : {key.path, key.flag, key.description, key.default_string}) {
      strata_names_in(text, &strata_names);
    }
    if (key.type == secure_frontend::ConfigValueType::boolean) {
      expect(path == "listener.allow_remote" || path == "listener.allow_wildcard_bind",
             "the only switches are the two bind opt-ins: " + path);
    }
  }
  expect(flags.count("--allow-remote") == 1U && flags.count("--token-env") == 1U && flags.count("--check") == 1U,
         "the flag sweep sees the schema's and the usage text's options");
  for (const auto& flag : flags) expect(!forbidden_in(flag), "no option can switch off authentication: " + flag);
  expect(strata_names.count("STRATA_ENGINE_READY_S") == 1U, "the STRATA_* sweep is seeded from the schema text");
  ServerFixture f;
  for (const char* flag : {"--no-auth", "--insecure", "--dev", "--disable-auth", "--allow-unauthenticated", "--auth=none"}) {
    const auto result = f.run(with(f.base_flags(), {flag}));
    expect(result.exit_code != 0 && contains(result.err, "unknown option"), std::string{"no such option: "} + flag);
  }
  // Upstream's STRATA_* knobs are never read (product spec §4); set them all and probe without a token.
  auto environment = f.environment();
  // The schema-derived names plus guesses at knobs that could exist upstream.
  for (const char* name : {"STRATA_API_KEY", "STRATA_NO_AUTH", "STRATA_DEV", "STRATA_INSECURE", "STRATA_DEBUG", "STRATA_AUTH"}) {
    strata_names.emplace(name);
  }
  for (const auto& name : strata_names) environment.emplace_back(name, name == "STRATA_API_KEY" ? "" : "1");
  secure_frontend_test::ChildProcess server;
  expect(server.start(secure_frontend_test::ProcessSpec{f.server_executable, f.base_flags(), environment}), "server spawned");
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  while (!secure_frontend_test::can_connect(f.port) && std::chrono::steady_clock::now() < deadline &&
         !server.wait_for(std::chrono::milliseconds(50)).has_value()) {
  }
  const auto response = f.request("GET", "/v1/models", "");
  expect(response.rfind("HTTP/1.1 401", 0) == 0, "no environment variable disables authentication");
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
      {"auth04_empty_token_rejected_on_loopback", auth04_empty_token_rejected_on_loopback},
      {"auth04_no_switch_disables_auth", auth04_no_switch_disables_auth},
  }, failures);
}

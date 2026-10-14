#include "secure_frontend/config_file.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "support/config_json.hpp"
#include "support/test_support.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

namespace {
int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}
using secure_frontend::ConfigIssueCode;
using secure_frontend::ConfigValueType;
using secure_frontend_test::ConfigFixture;
using secure_frontend_test::render_config_json;

secure_frontend::ConfigValidationResult validate_text(const std::string& text, const std::filesystem::path& dir) {
  auto draft = secure_frontend::parse_config_text(text, dir);
  if (auto* errors = std::get_if<secure_frontend::ConfigErrors>(&draft)) return *errors;
  return secure_frontend::validate(std::get<secure_frontend::FrontendConfigDraft>(draft));
}

bool has_issue(const secure_frontend::ConfigValidationResult& result, const std::string& key, const ConfigIssueCode code) {
  const auto* errors = std::get_if<secure_frontend::ConfigErrors>(&result);
  return errors != nullptr && std::any_of(errors->begin(), errors->end(), [&](const auto& issue) {
           return issue.key_path == key && issue.code == code;
         });
}

std::string issues_of(const secure_frontend::ConfigValidationResult& result) {
  std::string text;
  if (const auto* errors = std::get_if<secure_frontend::ConfigErrors>(&result)) {
    for (const auto& issue : *errors) text += secure_frontend::format_issue(issue) + "; ";
  }
  return text;
}

std::string valid_sample(const secure_frontend::ConfigKey& key) {
  switch (key.type) {
    case ConfigValueType::integer: return std::to_string(key.minimum);
    case ConfigValueType::boolean: return "false";
    case ConfigValueType::string_array: return "[]";
    case ConfigValueType::string: return key.default_string.empty() ? "\"x\"" : "\"" + std::string{key.default_string} + "\"";
  }
  return "null";
}

std::vector<std::string> wrong_type_samples(const ConfigValueType type) {
  switch (type) {
    case ConfigValueType::integer: return {"\"8080\"", "true", "[1]", "null"};
    case ConfigValueType::boolean: return {"1", "\"true\"", "null"};
    case ConfigValueType::string: return {"1", "true", "[\"x\"]", "{}"};
    case ConfigValueType::string_array: return {"\"x\"", "[1]", "{}", "true"};
  }
  return {};
}

void typed_config_accepts_minimal_file_and_applies_defaults() {
  ConfigFixture f;
  const auto result = validate_text(f.document(), f.dir);
  const auto* validated = std::get_if<secure_frontend::ValidatedConfig>(&result);
  expect(validated != nullptr, "the minimal config must validate: " + issues_of(result));
  if (validated == nullptr) return;
  const auto& c = validated->get();
  expect(c.listener.host.canonical_text() == "127.0.0.1" && c.listener.port == 8080U && !c.listener.allow_remote &&
             !c.listener.allow_wildcard_bind && c.listener.backlog == 16U, "listener defaults");
  expect(c.limits.http.request_deadline == std::chrono::milliseconds(30000) && c.limits.http.max_request_bytes == 65536U &&
             c.limits.http.max_header_bytes == 16384U && c.limits.http.max_headers == 64U &&
             c.limits.http.max_request_line_bytes == 4096U, "http limit defaults");
  expect(c.limits.chat.max_body_bytes == 49152U && c.limits.chat.max_messages == 128U &&
             c.limits.chat.max_completion_tokens == 4096U && c.limits.chat.default_max_tokens == 256U, "chat defaults");
  expect(c.limits.engine.ready_timeout == std::chrono::seconds(900), "ready_timeout defaults to 900 s");
  expect(c.limits.concurrency.max_concurrent_requests == 1U, "one request at a time until SP3");
  expect(c.token.kind() == secure_frontend::SecretSourceKind::protected_file && c.token.location() == "token",
         "token.source defaults to file:token");
  expect(c.engine.profile == secure_frontend::EngineProfile::qwen && c.engine.model_id.value() == "qwen-local",
         "engine defaults");
}

void cfg01_unknown_key_rejected() {
  ConfigFixture f;
  std::vector<std::string> unknown{"bogus", "listener.bogus", "limits.bogus", "limits.http.bogus", "limits.chat.bogus",
                                   "limits.engine.bogus", "limits.concurrency.bogus", "roots.bogus", "token.bogus",
                                   "engine.bogus"};
  for (const auto& key : secure_frontend::config_schema()) unknown.push_back(std::string{key.path} + "_typo");
  for (const auto& path : unknown) {
    auto literals = f.literals;
    literals[path] = "1";
    const auto result = validate_text(render_config_json(literals), f.dir);
    expect(has_issue(result, path, ConfigIssueCode::unknown_key), "unknown key must be rejected by name: " + path);
  }
}

void cfg01_duplicate_key_rejected() {
  ConfigFixture f;
  for (const auto& key : secure_frontend::config_schema()) {
    auto literals = f.literals;
    const std::string path{key.path};
    if (!literals.contains(path)) literals[path] = valid_sample(key);
    const auto result = validate_text(render_config_json(literals, path), f.dir);
    expect(has_issue(result, "config file", ConfigIssueCode::duplicate_key), "duplicate must be rejected: " + path);
  }
  // A member name containing '.' never aliases a nested key: the nested form
  // plus the flat dotted spelling of the same key must not be "last wins".
  const auto with_extra_member = [](std::string document, const std::string& member) {
    document.insert(document.size() - 1U, "," + member);
    return document;
  };
  for (const auto& key : secure_frontend::config_schema()) {
    auto literals = f.literals;
    const std::string path{key.path};
    if (!literals.contains(path)) literals[path] = valid_sample(key);
    const auto text = with_extra_member(render_config_json(literals),
                                        secure_frontend_test::json_literal(path) + ":" + valid_sample(key));
    const auto result = validate_text(text, f.dir);
    const bool rejected = path.find('.') == std::string::npos
                              ? has_issue(result, "config file", ConfigIssueCode::duplicate_key)
                              : has_issue(result, path, ConfigIssueCode::unknown_key);
    expect(rejected && std::holds_alternative<secure_frontend::ConfigErrors>(result),
           "nested plus dotted spelling must be rejected: " + path);
  }
  // A flat dotted top-level key alone is not a nested key either.
  {
    auto literals = f.literals;
    literals.erase("engine.model_id");
    const auto result = validate_text(with_extra_member(render_config_json(literals), "\"engine.model_id\":\"qwen-local\""), f.dir);
    expect(has_issue(result, "engine.model_id", ConfigIssueCode::unknown_key), "flat dotted top-level key rejected");
  }
  {
    const auto result = validate_text(with_extra_member(f.document(), "\"listener.port\":9000"), f.dir);
    expect(has_issue(result, "listener.port", ConfigIssueCode::unknown_key), "flat dotted listener.port rejected");
  }
  // Dotted section names and empty names, at any depth.
  for (const auto& [member, issue_path] :
       std::vector<std::pair<std::string, std::string>>{
           {"\"limits\":{\"http\":{\"max_headers\":10}},\"limits.http\":{\"max_headers\":20}", "limits.http"},
           {"\"limits\":{\"http.max_headers\":20}", "limits.http.max_headers"},
           {"\"\":1", ""},
           {"\"listener\":{\"\":1}", "listener."}}) {
    const auto result = validate_text(with_extra_member(f.document(), member), f.dir);
    expect(has_issue(result, issue_path, ConfigIssueCode::unknown_key), "dotted or empty member name rejected: " + member);
  }
}

void cfg01_type_confusion_rejected() {
  ConfigFixture f;
  for (const auto& key : secure_frontend::config_schema()) {
    const std::string path{key.path};
    for (const auto& sample : wrong_type_samples(key.type)) {
      auto literals = f.literals;
      literals[path] = sample;
      const auto result = validate_text(render_config_json(literals), f.dir);
      expect(has_issue(result, path, ConfigIssueCode::wrong_type), "type confusion " + sample + " for " + path);
    }
    if (key.type == ConfigValueType::integer) {
      for (const char* number : {"8080.0", "1e3"}) {
        auto literals = f.literals;
        literals[path] = number;
        const auto result = validate_text(render_config_json(literals), f.dir);
        expect(has_issue(result, "config file", ConfigIssueCode::malformed_document),
               std::string{"a float is never coerced: "} + number + " for " + path);
      }
    }
  }
}

void cfg01_missing_required_rejected() {
  ConfigFixture f;
  std::vector<std::string> required{"schema_version"};
  for (const auto& key : secure_frontend::config_schema()) if (key.required) required.emplace_back(key.path);
  expect(required.size() == 5U, "schema_version, roots.models, roots.tokenizer_pack, engine.executable, engine.model_id");
  for (const auto& path : required) {
    auto literals = f.literals;
    literals.erase(path);
    const auto result = validate_text(render_config_json(literals), f.dir);
    expect(has_issue(result, path, ConfigIssueCode::missing_required), "missing required key: " + path);
  }
}

void cfg01_out_of_range_rejected() {
  ConfigFixture f;
  for (const auto& key : secure_frontend::config_schema()) {
    if (key.type != ConfigValueType::integer) continue;
    for (const auto value : {key.minimum - 1, key.maximum + 1}) {
      auto literals = f.literals;
      literals[std::string{key.path}] = std::to_string(value);
      const auto result = validate_text(render_config_json(literals), f.dir);
      expect(has_issue(result, std::string{key.path}, ConfigIssueCode::out_of_range),
             "out of range " + std::to_string(value) + " for " + std::string{key.path});
    }
  }
}

void typed_config_cross_field_rules() {
  ConfigFixture f;
  const auto with = [&](std::map<std::string, std::string> extra) {
    auto literals = f.literals;
    for (auto& [k, v] : extra) literals[k] = v;
    return validate_text(render_config_json(literals), f.dir);
  };
  expect(has_issue(with({{"limits.http.max_request_bytes", "8192"}, {"limits.http.max_header_bytes", "16384"}}),
                   "limits.http.max_header_bytes", ConfigIssueCode::conflicting_values), "header > request");
  expect(has_issue(with({{"limits.http.max_header_bytes", "2048"}, {"limits.http.max_request_line_bytes", "4096"}}),
                   "limits.http.max_request_line_bytes", ConfigIssueCode::conflicting_values), "line > header");
  expect(has_issue(with({{"limits.chat.max_body_bytes", "262144"}}), "limits.chat.max_body_bytes",
                   ConfigIssueCode::conflicting_values), "body > request - header");
  expect(has_issue(with({{"limits.chat.default_max_tokens", "5000"}}), "limits.chat.default_max_tokens",
                   ConfigIssueCode::conflicting_values), "default_max_tokens > max_completion_tokens");
  expect(has_issue(with({{"engine.profile", "\"glm53\""}}), "engine.args", ConfigIssueCode::missing_required),
         "glm53 needs at least one engine argument");
  expect(has_issue(with({{"engine.args", "[\"--native\",\"x\"]"}}), "engine.args", ConfigIssueCode::invalid_value),
         "the SP0 deny-list applies to engine.args");
  expect(has_issue(with({{"listener.host", "\"192.0.2.10\""}}), "listener.host", ConfigIssueCode::remote_not_enabled),
         "remote needs listener.allow_remote");
  expect(has_issue(with({{"listener.host", "\"::0\""}, {"listener.allow_remote", "true"}}), "listener.host",
                   ConfigIssueCode::wildcard_bind_not_enabled), "wildcard needs its own opt-in");
  expect(has_issue(with({{"token.source", "\"cmd:echo\""}}), "token.source", ConfigIssueCode::invalid_value),
         "token.source is env:NAME or file:PATH");
  expect(has_issue(with({{"roots.models", "\"relative/models\""}}), "roots.models", ConfigIssueCode::invalid_value),
         "roots must be absolute");
}

void typed_config_errors_never_contain_values() {
  ConfigFixture f;
  auto literals = f.literals;
  const std::string secret_like = "sk-PASTED-SECRET-0123456789";
  literals["listener.host"] = secure_frontend_test::json_literal(secret_like);
  literals["token.source"] = secure_frontend_test::json_literal("env:" + secret_like + "!");
  literals["engine.model_id"] = secure_frontend_test::json_literal(secret_like + "/x");
  const auto text = issues_of(validate_text(render_config_json(literals), f.dir));
  expect(!text.empty() && text.find(secret_like) == std::string::npos, "issues name keys, never values: " + text);
}

#if !defined(_WIN32)
// Spec §3.2/§4: roots.secret defaults to the config file's folder only for a
// file: token. An env: token reads nothing below a secret root, so a loose
// config folder must not fail validation.
void cfg02_env_token_ignores_config_folder_permissions() {
  ConfigFixture f;
  auto literals = f.literals;
  literals.erase("roots.secret");
  literals["token.source"] = secure_frontend_test::json_literal("env:SF_UNUSED_TOKEN");
  chmod(f.dir.c_str(), 0775);
  const auto result = validate_text(render_config_json(literals), f.dir);
  expect(std::holds_alternative<secure_frontend::ValidatedConfig>(result),
         "env token with a 0775 config folder is valid: " + issues_of(result));
  if (const auto* config = std::get_if<secure_frontend::ValidatedConfig>(&result)) {
    expect(!config->get().roots.secret.has_value(), "no secret root is opened for an env token");
  }
}

void cfg02_file_token_default_secret_root_reports_one_issue() {
  ConfigFixture f;
  auto literals = f.literals;
  literals.erase("roots.secret");
  literals["token.source"] = secure_frontend_test::json_literal("file:token");
  chmod(f.dir.c_str(), 0775);
  const auto result = validate_text(render_config_json(literals), f.dir);
  const auto* errors = std::get_if<secure_frontend::ConfigErrors>(&result);
  expect(errors != nullptr, "file token with a 0775 config folder is rejected");
  if (errors == nullptr) return;
  const auto count = std::count_if(errors->begin(), errors->end(),
                                   [](const auto& issue) { return issue.key_path == "roots.secret"; });
  expect(count == 1, "exactly one roots.secret issue: " + issues_of(result));
  expect(has_issue(result, "roots.secret", ConfigIssueCode::invalid_value), "the issue is invalid_value");
  const std::string text = issues_of(result);
  expect(text.find("roots.secret: is unset, so it defaults to the config file's folder, which is not usable: ") !=
             std::string::npos,
         "the reason reads as one sentence: " + text);
  expect(text.find(f.dir.string()) == std::string::npos, "the reason never contains the path: " + text);
  chmod(f.dir.c_str(), 0700);
  const auto ok = validate_text(render_config_json(literals), f.dir);
  const auto* valid = std::get_if<secure_frontend::ValidatedConfig>(&ok);
  expect(valid != nullptr && valid->get().roots.secret.has_value(),
         "a private config folder is the file token's secret root: " + issues_of(ok));
}
#endif

bool untrusted(const std::variant<secure_frontend::FrontendConfigDraft, secure_frontend::ConfigErrors>& result) {
  const auto* errors = std::get_if<secure_frontend::ConfigErrors>(&result);
  return errors != nullptr && !errors->empty() && errors->front().key_path == "config file" &&
         errors->front().code == secure_frontend::ConfigIssueCode::file_untrusted;
}

#if !defined(_WIN32)
void cfg01_group_writable_config_rejected() {
  ConfigFixture f;
  const auto file = f.dir / "config.json";
  secure_frontend_test::write_file(file, f.document(), 0664);
  expect(untrusted(secure_frontend::read_config_file(file)), "a group-writable config file is rejected");
  chmod(file.c_str(), 0644);
  expect(std::holds_alternative<secure_frontend::FrontendConfigDraft>(secure_frontend::read_config_file(file)),
         "0644 is fine: the config is not secret");
  const auto shared = secure_frontend_test::make_scratch_directory();
  secure_frontend_test::write_file(shared / "config.json", f.document(), 0600);
  chmod(shared.c_str(), 0777);
  expect(untrusted(secure_frontend::read_config_file(shared / "config.json")),
         "a config in a directory others can write is rejected (they could swap it)");
  std::filesystem::create_symlink(file, f.dir / "linked.json");
  expect(untrusted(secure_frontend::read_config_file(f.dir / "linked.json")), "a symlinked config file is rejected");
}
#else
void cfg01_config_with_everyone_write_ace_rejected() {
  ConfigFixture f;
  const auto file = f.dir / "config.json";
  secure_frontend_test::write_file(file, f.document());
  expect(std::holds_alternative<secure_frontend::FrontendConfigDraft>(secure_frontend::read_config_file(file)),
         "a config with the inherited user ACL is accepted");
  expect(secure_frontend_test::grant_everyone_write(file), "test setup: add an Everyone write ACE");
  expect(untrusted(secure_frontend::read_config_file(file)), "a config Everyone can write is rejected");
}
#endif

void cfg02_logs_and_cache_roots_are_created_private() {
  ConfigFixture f;
  auto literals = f.literals;
  literals["roots.logs"] = secure_frontend_test::json_literal((f.dir / "logs").string());
  literals["roots.cache"] = secure_frontend_test::json_literal((f.dir / "cache").string());
  const auto result = validate_text(render_config_json(literals), f.dir);
  const auto* validated = std::get_if<secure_frontend::ValidatedConfig>(&result);
  expect(validated != nullptr, "absent logs/cache roots under a private parent validate: " + issues_of(result));
  expect(!std::filesystem::exists(f.dir / "logs") && !std::filesystem::exists(f.dir / "cache"),
         "validate() creates nothing (--check has no side effects)");
  if (validated == nullptr) return;
  expect(secure_frontend::create_runtime_roots(validated->get()).empty(), "serve/init create the missing roots");
  expect(std::filesystem::is_directory(f.dir / "logs") && std::filesystem::is_directory(f.dir / "cache"), "both exist");
#if !defined(_WIN32)
  struct stat st {};
  stat((f.dir / "logs").c_str(), &st);
  expect((st.st_mode & 0777) == 0700, "created 0700");
#endif
  expect(secure_frontend::create_runtime_roots(validated->get()).empty(), "existing private roots are accepted again");
#if !defined(_WIN32)
  const auto shared = f.dir / "shared";
  secure_frontend_test::make_private_directory(shared);
  chmod(shared.c_str(), 0777);
  literals["roots.logs"] = secure_frontend_test::json_literal((shared / "logs").string());
  expect(has_issue(validate_text(render_config_json(literals), f.dir), "roots.logs", ConfigIssueCode::invalid_value),
         "an absent root whose parent others can write is rejected at validation");
  expect(!std::filesystem::exists(shared / "logs"), "and nothing was created");
#endif
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"typed_config_accepts_minimal_file_and_applies_defaults", typed_config_accepts_minimal_file_and_applies_defaults},
      {"cfg01_unknown_key_rejected", cfg01_unknown_key_rejected},
      {"cfg01_duplicate_key_rejected", cfg01_duplicate_key_rejected},
      {"cfg01_type_confusion_rejected", cfg01_type_confusion_rejected},
      {"cfg01_missing_required_rejected", cfg01_missing_required_rejected},
      {"cfg01_out_of_range_rejected", cfg01_out_of_range_rejected},
      {"typed_config_cross_field_rules", typed_config_cross_field_rules},
      {"typed_config_errors_never_contain_values", typed_config_errors_never_contain_values},
      {"cfg02_logs_and_cache_roots_are_created_private", cfg02_logs_and_cache_roots_are_created_private},
#if !defined(_WIN32)
      {"cfg02_env_token_ignores_config_folder_permissions", cfg02_env_token_ignores_config_folder_permissions},
      {"cfg02_file_token_default_secret_root_reports_one_issue", cfg02_file_token_default_secret_root_reports_one_issue},
      {"cfg01_group_writable_config_rejected", cfg01_group_writable_config_rejected},
#else
      {"cfg01_config_with_everyone_write_ace_rejected", cfg01_config_with_everyone_write_ace_rejected},
#endif
  }, failures);
}

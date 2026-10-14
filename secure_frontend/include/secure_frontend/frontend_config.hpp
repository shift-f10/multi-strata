#pragma once

#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/secret_source.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace secure_frontend {

enum class ConfigValueType { boolean, integer, string, string_array };

// One row per configuration key: the single source of truth for the JSON
// reader, the command line, --check output and the README key table.
struct ConfigKey final {
  std::string_view path;
  ConfigValueType type;
  bool required;
  std::int64_t minimum;          // integer keys
  std::int64_t maximum;
  std::int64_t default_integer;
  bool default_boolean;
  std::string_view default_string;  // empty = no default
  std::string_view flag;            // strata-secure-server option(s) for the README; empty = file only
  std::string_view description;
};

[[nodiscard]] std::span<const ConfigKey> config_schema() noexcept;
[[nodiscard]] const ConfigKey* find_config_key(std::string_view path) noexcept;
// True for an object path that prefixes at least one key ("limits", "limits.http").
[[nodiscard]] bool is_config_section(std::string_view path) noexcept;
[[nodiscard]] std::string_view type_reason(ConfigValueType type) noexcept;
// The README key table (secure_frontend/README.md, between the config-keys
// markers); a test fails when they differ.
[[nodiscard]] std::string render_config_schema_markdown();

enum class ConfigSource { file, command_line };
using ConfigDraftValue = std::variant<bool, std::int64_t, std::string, std::vector<std::string>>;
struct ConfigDraftEntry final {
  ConfigDraftValue value;
  ConfigSource source;
};

// Parsing produces this mutable draft. A key absent from `entries` is "not
// set"; values are stored exactly as written (no coercion) for validate().
struct FrontendConfigDraft final {
  std::map<std::string, ConfigDraftEntry, std::less<>> entries;
  std::optional<std::filesystem::path> config_directory;
  std::vector<std::string> overridden_by_command_line;
};

enum class ConfigIssueCode {
  malformed_document, unknown_key, duplicate_key, wrong_type, missing_required, out_of_range, invalid_value,
  conflicting_values, remote_not_enabled, wildcard_bind_not_enabled, file_unavailable, file_untrusted,
};

// key_path names a key ("limits.http.max_request_bytes") or "config file";
// reason is fixed text. Neither ever contains a configured value.
struct ConfigIssue final {
  std::string key_path;
  ConfigIssueCode code;
  std::string reason;
};
using ConfigErrors = std::vector<ConfigIssue>;
[[nodiscard]] std::string format_issue(const ConfigIssue& issue);

enum class EngineProfile { qwen, glm53 };

class ModelId final {
 public:
  [[nodiscard]] const std::string& value() const noexcept { return value_; }

 private:
  friend std::optional<ModelId> make_model_id(std::string_view text);
  explicit ModelId(std::string value) : value_(std::move(value)) {}
  std::string value_;
};
[[nodiscard]] std::optional<ModelId> make_model_id(std::string_view text);

struct ListenerConfig final {
  IpAddress host;
  std::uint16_t port;
  bool allow_remote;
  bool allow_wildcard_bind;
  std::uint32_t backlog;
};
struct HttpLimits final {
  std::chrono::milliseconds request_deadline;
  std::uint32_t max_request_bytes;
  std::uint32_t max_header_bytes;
  std::uint32_t max_headers;
  std::uint32_t max_request_line_bytes;
};
struct ChatLimits final {
  std::uint32_t max_body_bytes;
  std::uint32_t max_messages;
  std::uint32_t max_message_bytes;
  std::uint32_t max_prompt_tokens;
  std::uint32_t max_completion_tokens;
  std::uint32_t default_max_tokens;
  std::uint32_t max_generated_bytes;
};
struct EngineLimits final {
  std::chrono::seconds ready_timeout;
  std::chrono::seconds generation_timeout;
  std::chrono::seconds stop_drain_timeout;
};
struct ConcurrencyLimits final {
  std::uint32_t max_concurrent_requests;
};
struct Limits final {
  HttpLimits http;
  ChatLimits chat;
  EngineLimits engine;
  ConcurrencyLimits concurrency;
};
struct Roots final {
  CanonicalRoot models;
  CanonicalRoot tokenizer_pack;
  std::optional<CanonicalRoot> secret;
  // Canonical paths that may not exist yet: validate() only checks them
  // (check_creatable_root); create_runtime_roots() creates them for serve/init.
  std::optional<std::filesystem::path> logs;
  std::optional<std::filesystem::path> cache;
  // roots.state: absolute only; validate() never touches the filesystem. serve
  // requires it and checks it is an existing owner-only directory (spec §3.9).
  std::optional<std::filesystem::path> state{};
};
struct EngineLaunch final {
  EngineProfile profile;
  CanonicalFile executable;
  ModelId model_id;
  std::vector<std::string> args;
  std::vector<std::filesystem::path> lib_dirs{};  // engine.lib_dirs, each absolute
  std::vector<unsigned> gpus{};                   // engine.gpu, parsed by parse_gpu_list (empty: unset)
  bool allow_new_privileges{false};               // engine.allow_new_privileges (Linux: no PR_SET_NO_NEW_PRIVS)
};

class ValidatedConfig;
class FrontendConfig final {
 public:
  const ListenerConfig listener;
  const Limits limits;
  const Roots roots;
  const SecretSource token;  // metadata only: env name or relative file path (CFG-06)
  const EngineLaunch engine;

 private:
  friend std::variant<ValidatedConfig, std::vector<ConfigIssue>> validate(const FrontendConfigDraft& draft);
  FrontendConfig(ListenerConfig listener_value, Limits limits_value, Roots roots_value, SecretSource token_value,
                 EngineLaunch engine_value)
      : listener(std::move(listener_value)), limits(limits_value), roots(std::move(roots_value)),
        token(std::move(token_value)), engine(std::move(engine_value)) {}
};

// Immutable after validation; subsystems derive their limits from it once.
class ValidatedConfig final {
 public:
  [[nodiscard]] const FrontendConfig& get() const noexcept { return *config_; }
  [[nodiscard]] std::shared_ptr<const FrontendConfig> shared() const noexcept { return config_; }

 private:
  friend std::variant<ValidatedConfig, std::vector<ConfigIssue>> validate(const FrontendConfigDraft& draft);
  explicit ValidatedConfig(std::shared_ptr<const FrontendConfig> config) : config_(std::move(config)) {}
  std::shared_ptr<const FrontendConfig> config_;
};

using ConfigValidationResult = std::variant<ValidatedConfig, ConfigErrors>;

// Collects every issue (all keys, all rules) before returning.
[[nodiscard]] ConfigValidationResult validate(const FrontendConfigDraft& draft);
// "key = value" per schema key in schema order. Holds no secret by construction.
[[nodiscard]] std::string describe(const FrontendConfig& config);
// The listener primitive HttpSocketServer::bind takes.
[[nodiscard]] Config listener_config(const FrontendConfig& config);
// The only filesystem side effect of a configuration: creates a missing
// roots.logs / roots.cache (0700 / private DACL) and checks an existing one.
// Called by serve and init, never by validate() or --check.
[[nodiscard]] ConfigErrors create_runtime_roots(const FrontendConfig& config);

}  // namespace secure_frontend

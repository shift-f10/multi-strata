#pragma once

#include "secure_frontend/acquire_url.hpp"
#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/sampling_params.hpp"
#include "secure_frontend/secret_source.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace secure_frontend {

enum class ConfigValueType { boolean, integer, string, string_array, decimal };

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
  // SP5 M1 Task 4 (decimal rows): bounds below; default_decimal NaN = "unset"
  // (the row stays absent); minimum_exclusive models the pin's open bounds.
  // Defaults keep every pre-Task-4 positional row valid under -Werror.
  double minimum_decimal = 0.0;
  double maximum_decimal = 0.0;
  double default_decimal = std::numeric_limits<double>::quiet_NaN();
  bool minimum_exclusive = false;
};

[[nodiscard]] std::span<const ConfigKey> config_schema() noexcept;
[[nodiscard]] const ConfigKey* find_config_key(std::string_view path) noexcept;
// SP3 addendum: per-key extras kept beside SP1's positional rows.
struct ConfigKeyExtension final {
  std::string_view path;
  std::size_t max_entries;                         // string_array: most entries (0 = unbounded)
  bool (*entry_valid)(std::string_view) noexcept;  // string_array: per-entry grammar (nullptr = any)
  std::string_view entry_reason;                   // fixed reason when an entry fails entry_valid
  std::string_view derived_default;                // non-empty: default derived from other keys (README / --check text)
};
[[nodiscard]] const ConfigKeyExtension* find_config_key_extension(std::string_view path) noexcept;
// True for an object path that prefixes at least one key ("limits", "limits.http").
[[nodiscard]] bool is_config_section(std::string_view path) noexcept;
[[nodiscard]] std::string_view type_reason(ConfigValueType type) noexcept;
// The README key table (secure_frontend/README.md, between the config-keys
// markers); a test fails when they differ.
[[nodiscard]] std::string render_config_schema_markdown();

enum class ConfigSource { file, command_line };
using ConfigDraftValue = std::variant<bool, std::int64_t, std::string, std::vector<std::string>, double>;
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
  excluded_key,
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
  std::vector<std::string> cors_origins;  // SP3 §4.4: exact origins, each is_valid_cors_origin
  std::vector<std::string> host_aliases;  // SP3 §4.3: extra exact Host values, each is_valid_host_alias
};
struct HttpLimits final {
  std::chrono::milliseconds request_deadline;
  std::uint32_t max_request_bytes;
  std::uint32_t max_header_bytes;
  std::uint32_t max_headers;
  std::uint32_t max_request_line_bytes;
  std::chrono::milliseconds header_deadline;          // SP3 §5.1
  std::chrono::milliseconds write_stall;
  std::chrono::milliseconds response_write_deadline;
  std::chrono::milliseconds stream_keepalive;
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
// SP3 §5.1: an absent queue / per-remote key takes its value derived from the
// worker count (the *_derived flags record that for --check).
struct ConcurrencyLimits final {
  std::uint32_t max_concurrent_requests;
  std::uint32_t max_queued_generations;
  std::chrono::milliseconds queue_timeout;
  std::uint32_t max_connections_per_remote_address;
  bool queue_derived;
  bool remote_cap_derived;
};
[[nodiscard]] std::uint32_t derived_max_queued_generations(std::uint32_t workers) noexcept;
[[nodiscard]] std::uint32_t derived_max_connections_per_remote_address(std::uint32_t workers) noexcept;
struct Limits final {
  HttpLimits http;
  ChatLimits chat;
  EngineLimits engine;
  ConcurrencyLimits concurrency;
};
// SP3 §8: logging.requests (one stderr line per request when true).
struct LoggingConfig final {
  bool requests;
};
struct Roots final {
  CanonicalRoot models;
  std::optional<CanonicalRoot> tokenizer_pack;  // --expert only (SP4 §4.9 d)
  std::optional<CanonicalRoot> secret;
  // Canonical paths that may not exist yet: validate() only checks them
  // (check_creatable_root); create_runtime_roots() creates them for serve/init.
  std::optional<std::filesystem::path> logs;
  std::optional<std::filesystem::path> cache;
  // roots.state: absolute only; validate() never touches the filesystem. serve
  // requires it and checks it is an existing owner-only directory (spec §3.9).
  std::optional<std::filesystem::path> state{};
};
// SP5 M1 Task 5 (parity rows reasoning_*): the pin's config family. Kinds and defaults at
// frontend_config.cpp's rows; the pin keeps these as service-object values (serve/server.py:8015,
// :8102-8104, :8120-8136), except effort_position, which composes an engine argument (:2836-2856).
enum class ReasoningEffort { none, low, medium, high };      // clean_shared_defaults :7341-7343
enum class LoopRecovery { off, stop, recover };              // :8129-8136 (false | "stop" | "recover")
enum class EffortPosition { start, end };                    // :2841-2843
enum class AnthropicThinking { model, on_request };          // :8102-8104
struct ReasoningConfig final {
  std::optional<ReasoningEffort> effort;                     // unset: no config-level level (pin None)
  std::int64_t budget_tokens = 0;                            // 0 = no budget (pin default)
  bool close_retry = false;                                  // #1053 opt-in
  LoopRecovery loop_recovery = LoopRecovery::off;            // #728 opt-in
  EffortPosition effort_position = EffortPosition::start;
  AnthropicThinking anthropic_thinking = AnthropicThinking::model;
};

struct EngineLaunch final {
  std::optional<EngineProfile> profile;  // --expert only; a managed model's manifest sets it (SP4 §4.9 c)
  CanonicalFile executable;
  ModelId model_id;
  std::vector<std::string> args;
  std::vector<std::filesystem::path> lib_dirs{};  // engine.lib_dirs, each absolute
  std::vector<unsigned> gpus{};                   // engine.gpu, parsed by parse_gpu_list (empty: unset)
  bool allow_new_privileges{false};               // engine.allow_new_privileges (Linux: no PR_SET_NO_NEW_PRIVS)
  bool fit_max_tokens{true};                      // engine.fit_max_tokens (pin :3485: false answers 400 over room)
  // SP5 M1 Task 6 (parity rows lazy_load / idle_unload_s / mtp; runconfig.py:35-38): the
  // lifecycle family. mtp is on unless explicitly false (draft_layer.py is_off).
  bool lazy_load{false};                          // engine.lazy_load: the first request loads the engine
  std::chrono::seconds idle_unload{0};            // engine.idle_unload_s (0: never, the pin default)
  bool mtp{true};                                 // engine.mtp: false strips the draft layer at every start
};

// SP4 §3.9. pull.downloader is only a syntactically absolute path here; the
// file rules run lazily when a transferring verb or doctor --downloader runs
// (a recorded CFG-01 exception: a box without curl can still serve and import).
struct PullSettings final {
  std::filesystem::path downloader;
  std::optional<ProxySetting> proxy;
  bool allow_private_addresses;
  std::uint64_t max_total_bytes;
  std::chrono::seconds max_duration;
  std::chrono::seconds stall_timeout;
  std::chrono::seconds connect_timeout;
};

// Linux /usr/bin/curl; Windows GetSystemDirectoryW() + "\curl.exe". Empty (so
// not absolute, and refused when a transfer runs) if Windows cannot report its
// system directory.
[[nodiscard]] std::filesystem::path default_downloader_path();

class ValidatedConfig;
class FrontendConfig final {
 public:
  const ListenerConfig listener;
  const Limits limits;
  const Roots roots;
  const SecretSource token;  // metadata only: env name or relative file path (CFG-06)
  const EngineLaunch engine;
  const PullSettings pull;
  const LoggingConfig logging;  // SP3 §8
  const SamplingDefaults sampling;  // SP5 M1 Task 4: defaults.sampling.*
  const ReasoningConfig reasoning;  // SP5 M1 Task 5: reasoning.*

 private:
  friend std::variant<ValidatedConfig, std::vector<ConfigIssue>> validate(const FrontendConfigDraft& draft);
  FrontendConfig(ListenerConfig listener_value, Limits limits_value, Roots roots_value, SecretSource token_value,
                 EngineLaunch engine_value, PullSettings pull_value, LoggingConfig logging_value,
                 SamplingDefaults sampling_value, ReasoningConfig reasoning_value)
      : listener(std::move(listener_value)), limits(limits_value), roots(std::move(roots_value)),
        token(std::move(token_value)), engine(std::move(engine_value)), pull(std::move(pull_value)),
        logging(logging_value), sampling(std::move(sampling_value)), reasoning(reasoning_value) {}
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

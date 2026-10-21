#include "secure_frontend/frontend_config.hpp"

#include "secure_frontend/config_defaults.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/json.hpp"
#include "secure_frontend/model_inventory.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <charconv>
#include <limits>
#include <set>
#include <string>
#include <utility>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#endif

namespace secure_frontend {
namespace {
namespace d = config_defaults;
using T = ConfigValueType;

// SP5 M1 Task 4: a decimal row with this default has no default — an absent
// entry stays unset (never sent to the engine).
constexpr double kUnsetDecimal = std::numeric_limits<double>::quiet_NaN();

// Shortest round-trip decimal text (shared by issue messages and --check).
std::string decimal_text(const double value) {
  char buffer[32];
  const auto [end, ec] = std::to_chars(buffer, buffer + sizeof(buffer), value);
  return ec == std::errc{} ? std::string{buffer, end} : std::string{"?"};
}

constexpr std::array<ConfigKey, 43 + 7 + 3 + 9 + 7 + 3> kSchema{{
    {"schema_version", T::integer, false, 1, 1, d::kSchemaVersion, false, "", "",
     "Config format version; must be 1. Required in a config file."},
    {"listener.host", T::string, false, 0, 0, 0, false, "127.0.0.1", "--host",
     "Bind address: an IPv4/IPv6 literal or localhost. Other hostnames are rejected (never resolved)."},
    {"listener.port", T::integer, false, 1, 65535, d::kListenerPort, false, "", "--port", "TCP port."},
    {"listener.allow_remote", T::boolean, false, 0, 0, 0, false, "", "--allow-remote",
     "Required for every non-loopback address."},
    {"listener.allow_wildcard_bind", T::boolean, false, 0, 0, 0, false, "", "--allow-wildcard-bind",
     "Also required for 0.0.0.0, :: and every other spelling of the unspecified address."},
    {"listener.backlog", T::integer, false, 1, 4096, d::kListenerBacklog, false, "", "", "listen() backlog."},
    {"listener.cors_origins", T::string_array, false, 0, 0, 0, false, "", "",
     "Exact browser origins allowed CORS: http:// or https://, a lower-case host, an optional port, no path; never * or null; at most 16."},
    {"listener.host_aliases", T::string_array, false, 0, 0, 0, false, "", "",
     "Extra exact Host values (host or host:port) clients use; required when the bind is a wildcard; at most 16."},
    {"limits.http.request_deadline_ms", T::integer, false, 1, 3'600'000, d::kRequestDeadlineMs, false, "", "",
     "Total time to read one request, header and body."},
    {"limits.http.max_request_bytes", T::integer, false, 4096, 16'777'216, d::kMaxRequestBytes, false, "", "",
     "Largest request (header and body) the listener and parser accept."},
    {"limits.http.max_header_bytes", T::integer, false, 1024, 65'536, d::kMaxHeaderBytes, false, "", "",
     "Largest header block; at most limits.http.max_request_bytes."},
    {"limits.http.max_headers", T::integer, false, 8, 256, d::kMaxHeaders, false, "", "", "Most header fields."},
    {"limits.http.max_request_line_bytes", T::integer, false, 256, 16'384, d::kMaxRequestLineBytes, false, "", "",
     "Longest request line; at most limits.http.max_header_bytes."},
    {"limits.http.header_deadline_ms", T::integer, false, 1, 3'600'000, d::kHeaderDeadlineMs, false, "", "",
     "Time from accept to the end of the request header; at most limits.http.request_deadline_ms."},
    {"limits.http.write_stall_ms", T::integer, false, 100, 300'000, d::kWriteStallMs, false, "", "",
     "Longest send without progress before the client is treated as gone."},
    {"limits.http.response_write_deadline_ms", T::integer, false, 1'000, 3'600'000, d::kResponseWriteDeadlineMs, false, "", "",
     "Time to send a whole complete response, or a stream's tail after DONE; at least limits.http.write_stall_ms."},
    {"limits.http.stream_keepalive_ms", T::integer, false, 1'000, 300'000, d::kStreamKeepaliveMs, false, "", "",
     "SSE comment interval while no content flows (streaming)."},
    {"limits.chat.max_body_bytes", T::integer, false, 1, 16'777'216, d::kChatMaxBodyBytes, false, "", "",
     "Largest chat request body; at most max_request_bytes minus max_header_bytes."},
    {"limits.chat.max_messages", T::integer, false, 1, 128, d::kChatMaxMessages, false, "", "",
     "Most messages in one chat request."},
    {"limits.chat.max_message_bytes", T::integer, false, 1, 65'536, d::kChatMaxMessageBytes, false, "", "",
     "Largest single message content."},
    {"limits.chat.max_prompt_tokens", T::integer, false, 1, 262'144, d::kChatMaxPromptTokens, false, "", "",
     "Largest tokenized prompt sent to the engine."},
    {"limits.chat.max_completion_tokens", T::integer, false, 1, 16'384, d::kChatMaxCompletionTokens, false, "", "",
     "Largest max_tokens a request may ask for."},
    {"limits.chat.default_max_tokens", T::integer, false, 0, 16'384, d::kChatDefaultMaxTokens, false, "", "",
     "max_tokens when a request omits it; 0 = auto: min(max_completion_tokens, context - prompt - 8); at most limits.chat.max_completion_tokens."},
    {"limits.chat.max_generated_bytes", T::integer, false, 1, 16'777'216, d::kChatMaxGeneratedBytes, false, "", "",
     "Largest generated text returned."},
    {"limits.engine.ready_timeout_s", T::integer, false, 1, 86'400, d::kEngineReadyTimeoutS, false, "", "",
     "How long the supervisor waits for the engine's READY after each start; a miss kills and restarts it (upstream STRATA_ENGINE_READY_S)."},
    {"limits.engine.generation_timeout_s", T::integer, false, 1, 86'400, d::kEngineGenerationTimeoutS, false, "", "",
     "Total time for one generation before STOP."},
    {"limits.engine.stop_drain_timeout_s", T::integer, false, 1, 600, d::kEngineStopDrainTimeoutS, false, "", "",
     "Time to drain to DONE after STOP before the engine is marked failed."},
    {"limits.concurrency.max_concurrent_requests", T::integer, false, 1, 256, d::kMaxConcurrentRequests, false, "", "",
     "Worker threads: connections read or answered at once; 1 = serial."},
    {"limits.concurrency.max_queued_generations", T::integer, false, 0, 254, 0, false, "", "",
     "Chats waiting behind the running generation; 0 when max_concurrent_requests is 1, otherwise at most max_concurrent_requests - 2."},
    {"limits.concurrency.queue_timeout_ms", T::integer, false, 1'000, 3'600'000, d::kQueueTimeoutMs, false, "", "",
     "Longest wait for the engine before 503 server_busy."},
    {"limits.concurrency.max_connections_per_remote_address", T::integer, false, 1, 256, 0, false, "", "",
     "Workers one non-loopback address may hold; at most max_concurrent_requests. Loopback is exempt."},
    {"roots.models", T::string, true, 0, 0, 0, false, "", "--models-root",
     "Absolute directory of .gguf files. The root itself may be a symlink; nothing below it may be."},
    {"roots.tokenizer_pack", T::string, false, 0, 0, 0, false, "", "--tokenizer-pack",
     "Absolute tokenizer directory; only with strata-secure-server --expert (a managed model brings its own)."},
    {"roots.secret", T::string, false, 0, 0, 0, false, "", "--secret-root",
     "Absolute directory holding the token file. Default: the config file's directory."},
    {"roots.logs", T::string, false, 0, 0, 0, false, "", "", "Absolute log directory (created 0700; unused in SP1)."},
    {"roots.cache", T::string, false, 0, 0, 0, false, "", "",
     "Absolute cache directory (created 0700); when set, it holds the engine's CUDA cache in its cuda subdirectory."},
    {"roots.state", T::string, false, 0, 0, 0, false, "", "--state-dir",
     "Absolute, existing owner-only directory for engine state: the engine's cwd, per-generation temp and (without roots.cache) the CUDA cache. Required to serve."},
    {"token.source", T::string, false, 0, 0, 0, false, "file:token", "--token-file, --token-env",
     "file:<relative path below roots.secret> or env:<NAME>. Metadata only; the token is never in the config."},
    {"engine.profile", T::string, false, 0, 0, 0, false, "", "--profile",
     "qwen or glm53; only with --expert (a managed model's manifest sets it)."},
    {"engine.executable", T::string, true, 0, 0, 0, false, "", "--engine",
     "Absolute path of the engine; a regular file not writable by group or others."},
    {"engine.model_id", T::string, true, 0, 0, 0, false, "", "--model-id",
     "Default model reference name[:tag] from the model index (or, with --expert, an inventory ID)."},
    {"engine.args", T::string_array, false, 0, 0, 0, false, "", "--engine-arg (repeatable)",
     "Extra engine arguments; frontend-owned and unsupported flags are rejected."},
    {"engine.lib_dirs", T::string_array, false, 0, 0, 0, false, "", "--engine-lib-dir (repeatable)",
     "Absolute library directories for the engine (default: the engine executable's directory)."},
    {"engine.gpu", T::string, false, 0, 0, 0, false, "", "--gpu",
     "GPU device indices for the engine, e.g. 0 or 0,1 (distinct, 0-255, at most 16); rendered as the engine's --gpu argument (strata family: no GPU variable). Not supported with engine.profile glm53."},
    {"engine.allow_new_privileges", T::boolean, false, 0, 0, 0, false, "", "--allow-new-privileges",
     "Linux: do not set PR_SET_NO_NEW_PRIVS on the engine (default: set). Only for hosts whose NVIDIA driver must run setuid nvidia-modprobe to create /dev/nvidia-uvm on first use."},
    {"pull.downloader", T::string, false, 0, 0, 0, false, "", "",
     "Absolute path of curl for pull/update. Default /usr/bin/curl (Windows: System32\\curl.exe). Validated when a "
     "transfer or doctor --downloader runs, never at serve start."},
    {"pull.proxy", T::string, false, 0, 0, 0, false, "", "",
     "http://host:port or https://host:port; absent = --noproxy *. No credentials. Environment proxies are never read."},
    {"pull.allow_private_addresses", T::boolean, false, 0, 0, 0, false, "", "",
     "Allow sources that resolve to private or special-use addresses."},
    {"pull.max_total_bytes", T::integer, false, 1048576, 17592186044416, 1099511627776, false, "", "",
     "Largest manifest total a pull accepts (bytes)."},
    {"pull.max_duration_s", T::integer, false, 60, 604800, 172800, false, "", "", "Time budget for a whole pull run."},
    {"pull.stall_timeout_s", T::integer, false, 10, 3600, 120, false, "", "", "Abort a transfer slower than 1024 B/s for this long."},
    {"pull.connect_timeout_s", T::integer, false, 1, 300, 30, false, "", "", "TCP/TLS connect timeout per request."},
    {"logging.requests", T::boolean, false, 0, 0, 0, false, "", "",
     "One line per request to stderr: route, status, code, time, bytes, loopback or remote; never paths, headers, tokens or text."},
    // SP5 M1 Task 4 (parity row `sampling`): bounds copied from the pin —
    // clean_shared_defaults (serve/server.py:7331-7367) and the wire conditions
    // (serve/server.py:1360-1394). Unset rows are never sent. The 2.0 caps,
    // the 8192 window cap and the 32-bit seed cap are added security bounds (C-1).
    {"defaults.sampling.temperature", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default temperature (pin: 0..2); unset keeps the engine default.", 0.0, 2.0, kUnsetDecimal, false},
    {"defaults.sampling.top_p", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default top_p (pin: 0 < top_p <= 1); unset keeps the engine default.", 0.0, 1.0, kUnsetDecimal, true},
    {"defaults.sampling.top_k", T::integer, false, 1, 64, -1, false, "", "",
     "Request default top_k candidates (pin: an integer 1..64); unset keeps the engine default.", 0.0, 0.0, kUnsetDecimal, false},
    {"defaults.sampling.min_p", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default min_p (pin wire: only 0 < min_p <= 1 is sent; 0 stays off).", 0.0, 1.0, kUnsetDecimal, false},
    {"defaults.sampling.presence_penalty", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default presence penalty (0 off; cap 2 added, C-1).", 0.0, 2.0, kUnsetDecimal, false},
    {"defaults.sampling.repetition_penalty", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default repetition penalty (pin wire: only != 1.0 is sent; cap 2 added, C-1).", 0.0, 2.0, kUnsetDecimal, true},
    {"defaults.sampling.frequency_penalty", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default frequency penalty (0 off; cap 2 added, C-1).", 0.0, 2.0, kUnsetDecimal, false},
    {"defaults.sampling.penalty_last_n", T::integer, false, 0, 8192, -1, false, "", "",
     "Penalty window; unset means the pin default of 64 when any penalty is on (cap added, C-1).", 0.0, 0.0, kUnsetDecimal, false},
    {"defaults.sampling.seed", T::integer, false, 1, 4294967295, -1, false, "", "",
     "Request default sampling seed (pin: a positive integer; 32-bit cap added, C-1).", 0.0, 0.0, kUnsetDecimal, false},
    // SP5 M1 Task 5 (parity rows reasoning_* / fit_max_tokens): kinds and defaults copied from the
    // pin — effort clean_shared_defaults serve/server.py:7341-7343; budget_tokens :8120-8127 and
    // reasoning_budget :3794-3807 (a whole number, 0 = no budget; the 0..4294967295 bounds are ADDED
    // security bounds, C-1); close_retry :8015; loop_recovery :8129-8136 (the pin also takes bools,
    // the typed row names the three words); effort_position :2841-2843; anthropic_thinking
    // :8102-8104; fit_max_tokens :3485-3488 read at :7996 (false answers 400 over the room, :4536).
    {"reasoning.effort", T::string, false, 0, 0, 0, false, "", "",
     "Thinking level for requests that name none: none, low, medium or high (pin levels); unset names none."},
    {"reasoning.budget_tokens", T::integer, false, 0, 4294967295, 0, false, "", "",
     "Default thinking budget in tokens (0 = none, the pin default); bounds added, C-1."},
    {"reasoning.close_retry", T::boolean, false, 0, 0, 0, false, "", "",
     "Close an unfinished thinking block once when the reply ends inside it (pin opt-in, off)."},
    {"reasoning.loop_recovery", T::string, false, 0, 0, 0, false, "off", "",
     "A reasoning loop ends the reply (off, the pin default), stops (stop) or continues once (recover)."},
    {"reasoning.effort_position", T::string, false, 0, 0, 0, false, "start", "",
     "Where a non-default effort sits in the prompt: start (the pin default) or end; end adds the engine's --tail-role-token."},
    {"reasoning.anthropic_thinking", T::string, false, 0, 0, 0, false, "model", "",
     "Thinking default for /v1/messages-shaped clients: model (the pin default) or on_request."},
    {"engine.fit_max_tokens", T::boolean, false, 0, 0, 0, true, "", "",
     "Fit an over-room max_tokens to the context room (true, the pin default); false answers the §7.2 400 instead."},
    // SP5 M1 Task 6 (parity rows lazy_load / idle_unload_s / mtp): runconfig.py:38 "Start
    // without loading the model; the first request loads it (text only)"; :35 "0 or empty:
    // never" (whole seconds; the 86400 cap is ADDED, C-1); :36 + strata_control/
    // draft_layer.py is_off: the draft layer is on unless an explicit false.
    {"engine.lazy_load", T::boolean, false, 0, 0, 0, false, "", "",
     "Start with the engine unloaded; the first request loads it (the pin's lazy_load, text only)."},
    {"engine.idle_unload_s", T::integer, false, 0, 86400, 0, false, "", "",
     "Seconds without a request before the engine is unloaded (0: never, the pin default); cap added, C-1."},
    {"engine.mtp", T::boolean, false, 0, 0, 0, true, "", "",
     "Draft layer (MTP): on unless explicitly false; false drops --mtp/--spec-min-p/--batch-mtp at every start."},
}};

void add(ConfigErrors& errors, std::string key, const ConfigIssueCode code, std::string reason) {
  errors.push_back(ConfigIssue{std::move(key), code, std::move(reason)});
}

// Reads one key with its schema type, range and default; records issues.
class DraftReader final {
 public:
  DraftReader(const FrontendConfigDraft& draft, ConfigErrors& errors) : draft_(draft), errors_(errors) {}

  std::int64_t integer(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) return key.default_integer;
    const auto* value = std::get_if<std::int64_t>(&entry->value);
    if (value == nullptr) return wrong_type(key), key.default_integer;
    if (*value < key.minimum || *value > key.maximum) {
      add(errors_, std::string{path}, ConfigIssueCode::out_of_range,
          "must be between " + std::to_string(key.minimum) + " and " + std::to_string(key.maximum));
      return key.default_integer;
    }
    return *value;
  }
  bool boolean(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) return key.default_boolean;
    const auto* value = std::get_if<bool>(&entry->value);
    if (value == nullptr) return wrong_type(key), key.default_boolean;
    return *value;
  }
  std::optional<std::string> string(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) {
      if (key.default_string.empty()) return std::nullopt;
      return std::string{key.default_string};
    }
    const auto* value = std::get_if<std::string>(&entry->value);
    if (value == nullptr) return wrong_type(key), std::nullopt;
    return *value;
  }
  std::vector<std::string> strings(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) return {};
    const auto* value = std::get_if<std::vector<std::string>>(&entry->value);
    if (value == nullptr) return wrong_type(key), std::vector<std::string>{};
    return *value;
  }
  // SP5 M1 Task 4: an optional integer row (default_integer outside the range
  // = unset); range-checked when present.
  std::optional<std::int64_t> optional_integer(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) return std::nullopt;
    const auto* value = std::get_if<std::int64_t>(&entry->value);
    if (value == nullptr) return wrong_type(key), std::nullopt;
    if (*value < key.minimum || *value > key.maximum) {
      add(errors_, std::string{path}, ConfigIssueCode::out_of_range,
          "must be between " + std::to_string(key.minimum) + " and " + std::to_string(key.maximum));
      return std::nullopt;
    }
    return *value;
  }
  // SP5 M1 Task 4: a decimal row; integers are accepted (JSON "1" is a valid
  // number); the NaN default means "unset".
  std::optional<double> decimal(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) {
      if (std::isnan(key.default_decimal)) return std::nullopt;
      return key.default_decimal;
    }
    double value = 0.0;
    if (const auto* i = std::get_if<std::int64_t>(&entry->value)) value = static_cast<double>(*i);
    else if (const auto* dp = std::get_if<double>(&entry->value)) value = *dp;
    else return wrong_type(key), std::nullopt;
    if (value < key.minimum_decimal || value > key.maximum_decimal ||
        (key.minimum_exclusive && value == key.minimum_decimal)) {
      add(errors_, std::string{path}, ConfigIssueCode::out_of_range,
          (key.minimum_exclusive ? "must be greater than " : "must be at least ") + decimal_text(key.minimum_decimal) +
          (key.minimum_exclusive ? " and at most " : " and at most ") + decimal_text(key.maximum_decimal));
      return std::nullopt;
    }
    return value;
  }
  bool present(const std::string_view path) const { return draft_.entries.find(path) != draft_.entries.end(); }

 private:
  const ConfigDraftEntry* lookup(const ConfigKey& key) {
    const auto it = draft_.entries.find(key.path);
    if (it != draft_.entries.end()) return &it->second;
    if (key.required) add(errors_, std::string{key.path}, ConfigIssueCode::missing_required, "is required");
    return nullptr;
  }
  void wrong_type(const ConfigKey& key) {
    add(errors_, std::string{key.path}, ConfigIssueCode::wrong_type, std::string{type_reason(key.type)});
  }
  const FrontendConfigDraft& draft_;
  ConfigErrors& errors_;
};

std::optional<CanonicalRoot> canonical_root(DraftReader& read, ConfigErrors& errors, const std::string_view path) {
  const auto text = read.string(path);
  if (!text.has_value()) return std::nullopt;
  auto opened = open_root(path_from_utf8(*text));
  if (auto* error = std::get_if<PathError>(&opened)) {
    add(errors, std::string{path}, ConfigIssueCode::invalid_value, error->message);
    return std::nullopt;
  }
  return std::get<CanonicalRoot>(std::move(opened));
}

// roots.logs / roots.cache: checked, never created, during validation.
std::optional<std::filesystem::path> creatable_root(DraftReader& read, ConfigErrors& errors, const std::string_view path) {
  const auto text = read.string(path);
  if (!text.has_value()) return std::nullopt;
  auto checked = check_creatable_root(path_from_utf8(*text));
  if (auto* error = std::get_if<PathError>(&checked)) {
    add(errors, std::string{path}, ConfigIssueCode::invalid_value, error->message);
    return std::nullopt;
  }
  return std::get<std::filesystem::path>(std::move(checked));
}

// roots.state: absolute, non-empty, no NUL. No filesystem access here, so
// --check stays side-effect free; serve checks it is an existing owner-only
// directory before anything is spawned.
std::optional<std::filesystem::path> absolute_path(DraftReader& read, ConfigErrors& errors, const std::string_view path) {
  const auto text = read.string(path);
  if (!text.has_value()) return std::nullopt;
  if (text->empty() || text->find('\0') != std::string::npos || !path_from_utf8(*text).is_absolute()) {
    add(errors, std::string{path}, ConfigIssueCode::invalid_value, "must be an absolute directory");
    return std::nullopt;
  }
  return path_from_utf8(*text);
}

std::optional<SecretSource> token_source(const std::string& text) {
  if (text.rfind("env:", 0) == 0) {
    auto result = make_environment_secret_source(std::string_view{text}.substr(4));
    if (auto* source = std::get_if<SecretSource>(&result)) return std::move(*source);
    return std::nullopt;
  }
  if (text.rfind("file:", 0) == 0) {
    auto result = make_protected_file_secret_source(std::string_view{text}.substr(5));
    if (auto* source = std::get_if<SecretSource>(&result)) return std::move(*source);
  }
  return std::nullopt;
}

std::string json_quoted(const std::string_view text) {
  std::string out;
  append_json_string(&out, text);
  return out;
}

}  // namespace

std::filesystem::path default_downloader_path() {
#if defined(_WIN32)
  // Pre-flight F-32: a failure or a directory longer than the buffer never
  // yields the relative "curl.exe"; the buffer grows to the reported size once.
  std::wstring system(MAX_PATH, L'\0');
  for (int attempt = 0; attempt < 2; ++attempt) {
    const UINT length = GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
    if (length == 0) return {};
    if (length < system.size()) {
      system.resize(length);
      const std::filesystem::path directory(system);
      if (!directory.is_absolute()) return {};
      return directory / L"curl.exe";
    }
    system.assign(length, L'\0');  // length includes the terminator when the buffer was too small
  }
  return {};
#else
  return std::filesystem::path{"/usr/bin/curl"};
#endif
}

std::span<const ConfigKey> config_schema() noexcept { return kSchema; }

const ConfigKey* find_config_key(const std::string_view path) noexcept {
  for (const auto& key : kSchema) if (key.path == path) return &key;
  return nullptr;
}

namespace {
constexpr std::array<ConfigKeyExtension, 4> kSchemaExtensions{{
    {"listener.cors_origins", static_cast<std::size_t>(config_defaults::kMaxListEntries), &is_valid_cors_origin,
     "each entry must be http:// or https://, a lower-case host, an optional port and no path; * and null are not allowed", ""},
    {"listener.host_aliases", static_cast<std::size_t>(config_defaults::kMaxListEntries), &is_valid_host_alias,
     "each entry must be a host or host:port", ""},
    {"limits.concurrency.max_queued_generations", 0U, nullptr, "", "derived: min(4, max(0, workers-2))"},
    {"limits.concurrency.max_connections_per_remote_address", 0U, nullptr, "", "derived: min(4, workers)"},
}};

// Reads a string-array row and applies its SP3 bounds; any failure records one
// fixed issue naming the key and yields an empty list.
std::vector<std::string> read_bounded_strings(DraftReader& read, ConfigErrors& errors, const std::string_view path) {
  std::vector<std::string> values = read.strings(path);
  const ConfigKeyExtension* extension = find_config_key_extension(path);
  if (extension == nullptr) return values;
  if (extension->max_entries != 0U && values.size() > extension->max_entries) {
    add(errors, std::string{path}, ConfigIssueCode::out_of_range,
        "must have at most " + std::to_string(extension->max_entries) + " entries");
    return {};
  }
  std::set<std::string> seen;
  for (const auto& value : values) {
    if (extension->entry_valid != nullptr && !extension->entry_valid(value)) {
      add(errors, std::string{path}, ConfigIssueCode::invalid_value, std::string{extension->entry_reason});
      return {};
    }
    if (!seen.insert(value).second) {
      add(errors, std::string{path}, ConfigIssueCode::invalid_value, "must not repeat an entry");
      return {};
    }
  }
  return values;
}

bool has_issue_for(const ConfigErrors& errors, const std::string_view path) {
  return std::any_of(errors.begin(), errors.end(), [path](const ConfigIssue& issue) { return issue.key_path == path; });
}
}  // namespace

const ConfigKeyExtension* find_config_key_extension(const std::string_view path) noexcept {
  for (const auto& extension : kSchemaExtensions) if (extension.path == path) return &extension;
  return nullptr;
}

std::uint32_t derived_max_queued_generations(const std::uint32_t workers) noexcept {
  const std::uint32_t spare = workers > 2U ? workers - 2U : 0U;
  return std::min<std::uint32_t>(static_cast<std::uint32_t>(config_defaults::kDerivedQueueCap), spare);
}

std::uint32_t derived_max_connections_per_remote_address(const std::uint32_t workers) noexcept {
  return std::min<std::uint32_t>(static_cast<std::uint32_t>(config_defaults::kDerivedRemoteCap), workers);
}

bool is_config_section(const std::string_view path) noexcept {
  return std::any_of(kSchema.begin(), kSchema.end(), [path](const ConfigKey& key) {
    return key.path.size() > path.size() && key.path.substr(0, path.size()) == path && key.path[path.size()] == '.';
  });
}

std::string_view type_reason(const ConfigValueType type) noexcept {
  switch (type) {
    case ConfigValueType::boolean: return "must be true or false";
    case ConfigValueType::integer: return "must be an integer";
    case ConfigValueType::string: return "must be a string";
    case ConfigValueType::string_array: return "must be an array of strings";
    case ConfigValueType::decimal: return "must be a number";
  }
  return "has the wrong type";
}

std::string render_config_schema_markdown() {
  std::string out = "| Key | Type | Default | Range | Option | Meaning |\n| --- | --- | --- | --- | --- | --- |\n";
  for (const auto& key : kSchema) {
    std::string type;
    std::string fallback;
    std::string range = "-";
    switch (key.type) {
      case ConfigValueType::boolean:
        type = "boolean";
        fallback = key.default_boolean ? "`true`" : "`false`";
        break;
      case ConfigValueType::integer:
        type = "integer";
        fallback = (key.default_integer < key.minimum || key.default_integer > key.maximum)
                       ? "unset"
                       : "`" + std::to_string(key.default_integer) + "`";
        if (const auto* ext = find_config_key_extension(key.path); ext != nullptr && !ext->derived_default.empty()) {
          fallback = "`" + std::string{ext->derived_default} + "`";
        }
        range = std::to_string(key.minimum) + "-" + std::to_string(key.maximum);
        break;
      case ConfigValueType::string:
        type = "string";
        fallback = !key.default_string.empty() ? "`" + std::string{key.default_string} + "`"
                   : key.required             ? "required"
                                              : "unset";
        break;
      case ConfigValueType::string_array:
        type = "string array";
        fallback = "`[]`";
        break;
      case ConfigValueType::decimal:
        type = "number";
        fallback = std::isnan(key.default_decimal) ? "unset" : "`" + decimal_text(key.default_decimal) + "`";
        range = (key.minimum_exclusive ? ">" : "") + decimal_text(key.minimum_decimal) + "-" +
                decimal_text(key.maximum_decimal);
        break;
    }
    const std::string option = key.flag.empty() ? "-" : "`" + std::string{key.flag} + "`";
    out += "| `" + std::string{key.path} + "` | " + type + " | " + fallback + " | " + range + " | " + option + " | " +
           std::string{key.description} + " |\n";
  }
  return out;
}

std::string format_issue(const ConfigIssue& issue) { return issue.key_path + ": " + issue.reason; }

std::optional<ModelId> make_model_id(const std::string_view text) {
  const auto colon = text.find(':');
  const auto name = text.substr(0, colon);
  const bool ok = std::holds_alternative<std::string>(validate_model_id(name)) &&
                  (colon == std::string_view::npos ||
                   std::holds_alternative<std::string>(validate_model_id(text.substr(colon + 1))));
  if (!ok) return std::nullopt;
  return ModelId{std::string{text}};
}

ConfigValidationResult validate(const FrontendConfigDraft& draft) {
  ConfigErrors errors;
  for (const auto& [path, entry] : draft.entries) {
    if (find_config_key(path) == nullptr) add(errors, path, ConfigIssueCode::unknown_key, "unknown key");
  }
  DraftReader read(draft, errors);
  if (draft.config_directory.has_value() && !read.present("schema_version")) {
    add(errors, "schema_version", ConfigIssueCode::missing_required, "is required in a config file");
  }
  (void)read.integer("schema_version");

  // listener
  const std::string host_text = read.string("listener.host").value_or("127.0.0.1");
  const auto port = read.integer("listener.port");
  const bool allow_remote = read.boolean("listener.allow_remote");
  const bool allow_wildcard = read.boolean("listener.allow_wildcard_bind");
  const auto backlog = read.integer("listener.backlog");
  const auto host = parse_listener_address(host_text);
  if (!host.has_value()) {
    add(errors, "listener.host", ConfigIssueCode::invalid_value,
        "must be an IP literal or localhost; hostnames are never resolved");
  } else if (host->scope() != AddressScope::loopback && !allow_remote) {
    add(errors, "listener.host", ConfigIssueCode::remote_not_enabled,
        "a non-loopback address needs listener.allow_remote (--allow-remote)");
  } else if (host->scope() == AddressScope::wildcard && !allow_wildcard) {
    add(errors, "listener.host", ConfigIssueCode::wildcard_bind_not_enabled,
        "a wildcard address also needs listener.allow_wildcard_bind (--allow-wildcard-bind)");
  }
  // SP3 §4.3/§4.4: a wildcard bind trusts only the configured Host aliases.
  std::vector<std::string> cors_origins = read_bounded_strings(read, errors, "listener.cors_origins");
  std::vector<std::string> host_aliases = read_bounded_strings(read, errors, "listener.host_aliases");
  if (host.has_value() && host->scope() == AddressScope::wildcard && host_aliases.empty() &&
      !has_issue_for(errors, "listener.host_aliases")) {
    add(errors, "listener.host_aliases", ConfigIssueCode::invalid_value,
        "must name at least one Host value when the bind is a wildcard");
  }

  // limits
  const auto deadline_ms = read.integer("limits.http.request_deadline_ms");
  const auto max_request = read.integer("limits.http.max_request_bytes");
  const auto max_header = read.integer("limits.http.max_header_bytes");
  const auto max_headers = read.integer("limits.http.max_headers");
  const auto max_line = read.integer("limits.http.max_request_line_bytes");
  const auto header_deadline_ms = read.integer("limits.http.header_deadline_ms");
  const auto write_stall_ms = read.integer("limits.http.write_stall_ms");
  const auto response_deadline_ms = read.integer("limits.http.response_write_deadline_ms");
  const auto keepalive_ms = read.integer("limits.http.stream_keepalive_ms");
  const bool log_requests = read.boolean("logging.requests");
  // SP5 M1 Task 4: defaults.sampling.* (unset rows stay unset).
  SamplingDefaults sampling_defaults{
      read.decimal("defaults.sampling.temperature"), read.decimal("defaults.sampling.top_p"),
      read.decimal("defaults.sampling.min_p"), read.decimal("defaults.sampling.presence_penalty"),
      read.decimal("defaults.sampling.repetition_penalty"), read.decimal("defaults.sampling.frequency_penalty"),
      read.optional_integer("defaults.sampling.top_k"), read.optional_integer("defaults.sampling.penalty_last_n"),
      read.optional_integer("defaults.sampling.seed")};
  // SP5 M1 Task 5: reasoning.* (pin vocabularies; the string rows carry the pin's defaults).
  ReasoningConfig reasoning;
  if (const auto text = read.string("reasoning.effort")) {
    if (*text == "none") reasoning.effort = ReasoningEffort::none;
    else if (*text == "low") reasoning.effort = ReasoningEffort::low;
    else if (*text == "medium") reasoning.effort = ReasoningEffort::medium;
    else if (*text == "high") reasoning.effort = ReasoningEffort::high;
    else add(errors, "reasoning.effort", ConfigIssueCode::invalid_value, "must be none, low, medium or high");
  }
  reasoning.budget_tokens = read.integer("reasoning.budget_tokens");
  reasoning.close_retry = read.boolean("reasoning.close_retry");
  if (const auto text = read.string("reasoning.loop_recovery")) {
    if (*text == "off") reasoning.loop_recovery = LoopRecovery::off;
    else if (*text == "stop") reasoning.loop_recovery = LoopRecovery::stop;
    else if (*text == "recover") reasoning.loop_recovery = LoopRecovery::recover;
    else add(errors, "reasoning.loop_recovery", ConfigIssueCode::invalid_value, "must be off, stop or recover");
  }
  if (const auto text = read.string("reasoning.effort_position")) {
    if (*text == "start") reasoning.effort_position = EffortPosition::start;
    else if (*text == "end") reasoning.effort_position = EffortPosition::end;
    else add(errors, "reasoning.effort_position", ConfigIssueCode::invalid_value, "must be start or end");
  }
  if (const auto text = read.string("reasoning.anthropic_thinking")) {
    if (*text == "model") reasoning.anthropic_thinking = AnthropicThinking::model;
    else if (*text == "on_request") reasoning.anthropic_thinking = AnthropicThinking::on_request;
    else add(errors, "reasoning.anthropic_thinking", ConfigIssueCode::invalid_value, "must be model or on_request");
  }
  const bool fit_max_tokens = read.boolean("engine.fit_max_tokens");
  // SP5 M1 Task 6 (parity rows lazy_load / idle_unload_s / mtp, runconfig.py:35-38):
  // lifecycle family reads; mtp is on unless an explicit false (draft_layer.py is_off).
  const bool lazy_load = read.boolean("engine.lazy_load");
  const std::int64_t idle_unload_s = read.integer("engine.idle_unload_s");
  const bool mtp = read.boolean("engine.mtp");
  const auto max_body = read.integer("limits.chat.max_body_bytes");
  const auto max_messages = read.integer("limits.chat.max_messages");
  const auto max_message = read.integer("limits.chat.max_message_bytes");
  const auto max_prompt = read.integer("limits.chat.max_prompt_tokens");
  const auto max_completion = read.integer("limits.chat.max_completion_tokens");
  const auto default_max = read.integer("limits.chat.default_max_tokens");
  const auto max_generated = read.integer("limits.chat.max_generated_bytes");
  const auto ready_s = read.integer("limits.engine.ready_timeout_s");
  const auto generation_s = read.integer("limits.engine.generation_timeout_s");
  const auto drain_s = read.integer("limits.engine.stop_drain_timeout_s");
  const auto concurrent = read.integer("limits.concurrency.max_concurrent_requests");
  // SP3 §5.1: a derived value is used only when the key is absent; an explicit
  // value is validated as written and never adjusted.
  const auto workers = static_cast<std::uint32_t>(concurrent);
  const bool queue_set = read.present("limits.concurrency.max_queued_generations");
  const auto queued = queue_set ? read.integer("limits.concurrency.max_queued_generations")
                                : static_cast<std::int64_t>(derived_max_queued_generations(workers));
  const auto queue_timeout_ms = read.integer("limits.concurrency.queue_timeout_ms");
  const bool cap_set = read.present("limits.concurrency.max_connections_per_remote_address");
  const auto remote_cap = cap_set ? read.integer("limits.concurrency.max_connections_per_remote_address")
                                  : static_cast<std::int64_t>(derived_max_connections_per_remote_address(workers));
  if (max_header > max_request) {
    add(errors, "limits.http.max_header_bytes", ConfigIssueCode::conflicting_values,
        "must not exceed limits.http.max_request_bytes");
  }
  if (max_line > max_header) {
    add(errors, "limits.http.max_request_line_bytes", ConfigIssueCode::conflicting_values,
        "must not exceed limits.http.max_header_bytes");
  }
  if (max_body > max_request - max_header) {
    add(errors, "limits.chat.max_body_bytes", ConfigIssueCode::conflicting_values,
        "must not exceed limits.http.max_request_bytes minus limits.http.max_header_bytes");
  }
  if (default_max > max_completion) {
    add(errors, "limits.chat.default_max_tokens", ConfigIssueCode::conflicting_values,
        "must not exceed limits.chat.max_completion_tokens");
  }
  if (header_deadline_ms > deadline_ms) {
    add(errors, "limits.http.header_deadline_ms", ConfigIssueCode::conflicting_values,
        "must not exceed limits.http.request_deadline_ms");
  }
  if (response_deadline_ms < write_stall_ms) {
    add(errors, "limits.http.response_write_deadline_ms", ConfigIssueCode::conflicting_values,
        "must be at least limits.http.write_stall_ms");
  }
  if (concurrent == 1 && queued != 0) {
    add(errors, "limits.concurrency.max_queued_generations", ConfigIssueCode::conflicting_values,
        "must be 0 when limits.concurrency.max_concurrent_requests is 1");
  } else if (concurrent >= 2 && queued + 2 > concurrent) {
    add(errors, "limits.concurrency.max_queued_generations", ConfigIssueCode::conflicting_values,
        "plus 2 must not exceed limits.concurrency.max_concurrent_requests");
  }
  if (remote_cap > concurrent) {
    add(errors, "limits.concurrency.max_connections_per_remote_address", ConfigIssueCode::conflicting_values,
        "must not exceed limits.concurrency.max_concurrent_requests");
  }

  // roots: each is opened once, here, and held open by the FrontendConfig.
  const auto models = canonical_root(read, errors, "roots.models");
  const auto tokenizer = canonical_root(read, errors, "roots.tokenizer_pack");
  auto secret = canonical_root(read, errors, "roots.secret");
  const auto logs = creatable_root(read, errors, "roots.logs");
  const auto cache = creatable_root(read, errors, "roots.cache");
  const auto state = absolute_path(read, errors, "roots.state");

  // token. An unset roots.secret defaults to the config file's folder, and only
  // for a file: token: an env: token reads nothing below a secret root (spec
  // §3.2, §4), so that folder is not opened or checked for it.
  const std::string source_text = read.string("token.source").value_or("file:token");
  auto token = token_source(source_text);
  if (!token.has_value()) {
    add(errors, "token.source", ConfigIssueCode::invalid_value,
        "must be env:NAME ([A-Za-z_][A-Za-z0-9_]{0,127}) or file:RELATIVE-PATH below roots.secret");
  } else if (token->kind() == SecretSourceKind::protected_file && !read.present("roots.secret")) {
    if (!draft.config_directory.has_value()) {
      add(errors, "roots.secret", ConfigIssueCode::missing_required, "is required when token.source is file:…");
    } else {
      auto opened = open_root(*draft.config_directory);
      if (auto* root = std::get_if<CanonicalRoot>(&opened)) {
        secret = std::move(*root);
      } else {
        add(errors, "roots.secret", ConfigIssueCode::invalid_value,
            "is unset, so it defaults to the config file's folder, which is not usable: " +
                std::get<PathError>(opened).message);
      }
    }
  }

  // engine
  std::optional<EngineProfile> profile;
  if (const auto text = read.string("engine.profile")) {
    if (*text == "qwen") profile = EngineProfile::qwen;
    else if (*text == "glm53") profile = EngineProfile::glm53;
    else add(errors, "engine.profile", ConfigIssueCode::invalid_value, "must be qwen or glm53");
  }
  std::optional<CanonicalFile> executable;
  if (const auto text = read.string("engine.executable")) {
    auto opened = open_executable(path_from_utf8(*text));
    if (auto* error = std::get_if<PathError>(&opened)) {
      add(errors, "engine.executable", ConfigIssueCode::invalid_value, error->message);
    } else {
      executable = std::get<CanonicalFile>(std::move(opened));
    }
  }
  const auto model_text = read.string("engine.model_id");
  std::optional<ModelId> model_id = model_text ? make_model_id(*model_text) : std::nullopt;
  if (model_text.has_value() && !model_id.has_value()) {
    add(errors, "engine.model_id", ConfigIssueCode::invalid_value,
        "must be name or name:tag, each 1-128 characters of [A-Za-z0-9._-], starting with a letter or digit");
  }
  const auto args = read.strings("engine.args");
  const auto arguments_profile = profile.value_or(EngineProfile::qwen) == EngineProfile::glm53
                                     ? EngineArgumentsProfile::lighttransport_glm53
                                     : EngineArgumentsProfile::strata_0143;
  if (const auto rejected = validate_engine_user_arguments(arguments_profile, args)) {
    add(errors, "engine.args", ConfigIssueCode::invalid_value, rejected->message);
  }
  if (profile == EngineProfile::glm53 && args.empty()) {
    add(errors, "engine.args", ConfigIssueCode::missing_required, "--profile glm53 requires at least one --engine-arg");
  }
  // Each entry is one directory: the platform's list separator would split
  // LD_LIBRARY_PATH (':') or PATH (';') into extra, unvalidated entries.
#if defined(_WIN32)
  constexpr char kListSeparator = ';';
#else
  constexpr char kListSeparator = ':';
#endif
  std::vector<std::filesystem::path> lib_dirs;
  for (const auto& text : read.strings("engine.lib_dirs")) {
    if (text.empty() || text.find('\0') != std::string::npos || text.find(kListSeparator) != std::string::npos ||
        !path_from_utf8(text).is_absolute()) {
      add(errors, "engine.lib_dirs", ConfigIssueCode::invalid_value, "every entry must be an absolute directory");
      break;
    }
    lib_dirs.push_back(path_from_utf8(text));
  }
  std::vector<unsigned> gpus;
  if (const auto gpu_text = read.string("engine.gpu")) {
    if (const auto parsed = parse_gpu_list(*gpu_text)) {
      if (profile == EngineProfile::glm53) {
        add(errors, "engine.gpu", ConfigIssueCode::conflicting_values, "is not supported with engine.profile glm53");
      } else {
        gpus = *parsed;
      }
    } else {
      add(errors, "engine.gpu", ConfigIssueCode::invalid_value,
          "must be a comma-separated list of distinct device indices 0-255, at most 16");
    }
  }
  const bool allow_new_privileges = read.boolean("engine.allow_new_privileges");

  // pull (SP4 §3.9)
  std::filesystem::path downloader = default_downloader_path();
  if (const auto text = read.string("pull.downloader")) {
    const auto candidate = path_from_utf8(*text);
    if (!candidate.is_absolute()) add(errors, "pull.downloader", ConfigIssueCode::invalid_value, "must be an absolute path");
    else downloader = candidate;
  }
  std::optional<ProxySetting> proxy;
  if (const auto text = read.string("pull.proxy")) {
    auto parsed = parse_proxy(*text);
    if (std::holds_alternative<UrlProblem>(parsed)) {
      add(errors, "pull.proxy", ConfigIssueCode::invalid_value,
          "must be http://host:port or https://host:port without credentials, path or query");
    } else {
      proxy = std::get<ProxySetting>(std::move(parsed));
    }
  }
  const bool allow_private = read.boolean("pull.allow_private_addresses");
  const auto max_total = read.integer("pull.max_total_bytes");
  const auto max_duration = read.integer("pull.max_duration_s");
  const auto stall = read.integer("pull.stall_timeout_s");
  const auto connect = read.integer("pull.connect_timeout_s");

  if (!errors.empty() || !host || !models || !token || !executable || !model_id) {
    if (errors.empty()) add(errors, "config file", ConfigIssueCode::invalid_value, "is incomplete");
    return errors;
  }
  const auto u32 = [](const std::int64_t v) { return static_cast<std::uint32_t>(v); };
  ListenerConfig listener{*host, static_cast<std::uint16_t>(port), allow_remote, allow_wildcard, u32(backlog),
                          std::move(cors_origins), std::move(host_aliases)};
  const Limits limits{
      HttpLimits{std::chrono::milliseconds(deadline_ms), u32(max_request), u32(max_header), u32(max_headers), u32(max_line),
                 std::chrono::milliseconds(header_deadline_ms), std::chrono::milliseconds(write_stall_ms),
                 std::chrono::milliseconds(response_deadline_ms), std::chrono::milliseconds(keepalive_ms)},
      ChatLimits{u32(max_body), u32(max_messages), u32(max_message), u32(max_prompt), u32(max_completion), u32(default_max),
                 u32(max_generated)},
      EngineLimits{std::chrono::seconds(ready_s), std::chrono::seconds(generation_s), std::chrono::seconds(drain_s)},
      ConcurrencyLimits{u32(concurrent), u32(queued), std::chrono::milliseconds(queue_timeout_ms), u32(remote_cap), !queue_set,
                        !cap_set}};
  Roots roots{*models, tokenizer, secret, logs, cache, state};
  EngineLaunch engine{profile, *executable, std::move(*model_id), args, std::move(lib_dirs), std::move(gpus), allow_new_privileges,
                      fit_max_tokens, lazy_load, std::chrono::seconds(idle_unload_s), mtp};
  return ValidatedConfig{std::shared_ptr<const FrontendConfig>(
      new FrontendConfig(std::move(listener), limits, std::move(roots), std::move(*token), std::move(engine),
                         PullSettings{std::move(downloader), std::move(proxy), allow_private,
                                      static_cast<std::uint64_t>(max_total), std::chrono::seconds(max_duration),
                                      std::chrono::seconds(stall), std::chrono::seconds(connect)},
                         LoggingConfig{log_requests}, std::move(sampling_defaults), reasoning))};
}

std::string describe(const FrontendConfig& c) {
  std::string out;
  const auto line = [&out](const std::string_view key, const std::string& value) {
    out.append(key).append(" = ").append(value).push_back('\n');
  };
  const auto root_text = [](const CanonicalRoot& root) { return json_quoted(path_to_utf8(root.path())); };
  const auto root_or_unset = [&root_text](const std::optional<CanonicalRoot>& root) {
    return root.has_value() ? root_text(*root) : std::string{"(unset)"};
  };
  const auto path_or_unset = [](const std::optional<std::filesystem::path>& p) {
    return p.has_value() ? json_quoted(path_to_utf8(*p)) : std::string{"(unset)"};
  };
  line("schema_version", "1");
  line("listener.host", json_quoted(c.listener.host.canonical_text()));
  line("listener.port", std::to_string(c.listener.port));
  line("listener.allow_remote", c.listener.allow_remote ? "true" : "false");
  line("listener.allow_wildcard_bind", c.listener.allow_wildcard_bind ? "true" : "false");
  line("listener.backlog", std::to_string(c.listener.backlog));
  const auto list_text = [](const std::vector<std::string>& values) {
    std::string text = "[";
    for (std::size_t i = 0; i < values.size(); ++i) text += (i ? "," : "") + json_quoted(values[i]);
    return text + "]";
  };
  line("listener.cors_origins", list_text(c.listener.cors_origins));
  line("listener.host_aliases", list_text(c.listener.host_aliases));
  line("limits.http.request_deadline_ms", std::to_string(c.limits.http.request_deadline.count()));
  line("limits.http.max_request_bytes", std::to_string(c.limits.http.max_request_bytes));
  line("limits.http.max_header_bytes", std::to_string(c.limits.http.max_header_bytes));
  line("limits.http.max_headers", std::to_string(c.limits.http.max_headers));
  line("limits.http.max_request_line_bytes", std::to_string(c.limits.http.max_request_line_bytes));
  line("limits.http.header_deadline_ms", std::to_string(c.limits.http.header_deadline.count()));
  line("limits.http.write_stall_ms", std::to_string(c.limits.http.write_stall.count()));
  line("limits.http.response_write_deadline_ms", std::to_string(c.limits.http.response_write_deadline.count()));
  line("limits.http.stream_keepalive_ms", std::to_string(c.limits.http.stream_keepalive.count()));
  line("limits.chat.max_body_bytes", std::to_string(c.limits.chat.max_body_bytes));
  line("limits.chat.max_messages", std::to_string(c.limits.chat.max_messages));
  line("limits.chat.max_message_bytes", std::to_string(c.limits.chat.max_message_bytes));
  line("limits.chat.max_prompt_tokens", std::to_string(c.limits.chat.max_prompt_tokens));
  line("limits.chat.max_completion_tokens", std::to_string(c.limits.chat.max_completion_tokens));
  line("limits.chat.default_max_tokens", std::to_string(c.limits.chat.default_max_tokens));
  line("limits.chat.max_generated_bytes", std::to_string(c.limits.chat.max_generated_bytes));
  line("limits.engine.ready_timeout_s", std::to_string(c.limits.engine.ready_timeout.count()));
  line("limits.engine.generation_timeout_s", std::to_string(c.limits.engine.generation_timeout.count()));
  line("limits.engine.stop_drain_timeout_s", std::to_string(c.limits.engine.stop_drain_timeout.count()));
  const auto& cc = c.limits.concurrency;
  line("limits.concurrency.max_concurrent_requests", std::to_string(cc.max_concurrent_requests));
  line("limits.concurrency.max_queued_generations",
       std::to_string(cc.max_queued_generations) + (cc.queue_derived ? " (derived)" : ""));
  line("limits.concurrency.queue_timeout_ms", std::to_string(cc.queue_timeout.count()));
  line("limits.concurrency.max_connections_per_remote_address",
       std::to_string(cc.max_connections_per_remote_address) + (cc.remote_cap_derived ? " (derived)" : ""));
  line("roots.models", root_text(c.roots.models));
  line("roots.tokenizer_pack", root_or_unset(c.roots.tokenizer_pack));
  line("roots.secret", root_or_unset(c.roots.secret));
  line("roots.logs", path_or_unset(c.roots.logs));
  line("roots.cache", path_or_unset(c.roots.cache));
  line("roots.state", path_or_unset(c.roots.state));
  line("token.source", json_quoted((c.token.kind() == SecretSourceKind::environment_variable ? "env:" : "file:") +
                              c.token.location()));
  line("engine.profile", !c.engine.profile                              ? std::string{"(unset)"}
                         : *c.engine.profile == EngineProfile::glm53 ? std::string{"\"glm53\""}
                                                                     : std::string{"\"qwen\""});
  line("engine.executable", json_quoted(path_to_utf8(c.engine.executable.path())));
  line("engine.model_id", json_quoted(c.engine.model_id.value()));
  std::string args = "[";
  for (const auto& arg : c.engine.args) args += (args.size() > 1U ? "," : "") + json_quoted(arg);
  line("engine.args", args + "]");
  std::string libs = "[";
  for (const auto& directory : c.engine.lib_dirs) libs += (libs.size() > 1U ? "," : "") + json_quoted(path_to_utf8(directory));
  line("engine.lib_dirs", libs + "]");
  std::string gpu_list;
  for (const unsigned device : c.engine.gpus) gpu_list += (gpu_list.empty() ? "" : ",") + std::to_string(device);
  line("engine.gpu", gpu_list.empty() ? std::string{"(unset)"} : json_quoted(gpu_list));
  line("engine.allow_new_privileges", c.engine.allow_new_privileges ? "true" : "false");
  line("pull.downloader", json_quoted(path_to_utf8(c.pull.downloader)));
  line("pull.proxy", c.pull.proxy ? json_quoted(render_proxy(*c.pull.proxy)) : std::string{"(unset)"});
  line("pull.allow_private_addresses", c.pull.allow_private_addresses ? "true" : "false");
  line("pull.max_total_bytes", std::to_string(c.pull.max_total_bytes));
  line("pull.max_duration_s", std::to_string(c.pull.max_duration.count()));
  line("pull.stall_timeout_s", std::to_string(c.pull.stall_timeout.count()));
  line("pull.connect_timeout_s", std::to_string(c.pull.connect_timeout.count()));
  line("logging.requests", c.logging.requests ? "true" : "false");
  // SP5 M1 Task 4: the defaults.sampling.* rows; an unset row stays unset and
  // is never sent (the engine keeps its own default).
  const auto decimal_or_unset = [](const std::optional<double>& value) {
    return value.has_value() ? decimal_text(*value) : std::string{"(unset)"};
  };
  const auto integer_or_unset = [](const std::optional<std::int64_t>& value) {
    return value.has_value() ? std::to_string(*value) : std::string{"(unset)"};
  };
  line("defaults.sampling.temperature", decimal_or_unset(c.sampling.temperature));
  line("defaults.sampling.top_p", decimal_or_unset(c.sampling.top_p));
  line("defaults.sampling.min_p", decimal_or_unset(c.sampling.min_p));
  line("defaults.sampling.presence_penalty", decimal_or_unset(c.sampling.presence_penalty));
  line("defaults.sampling.repetition_penalty", decimal_or_unset(c.sampling.repetition_penalty));
  line("defaults.sampling.frequency_penalty", decimal_or_unset(c.sampling.frequency_penalty));
  line("defaults.sampling.top_k", integer_or_unset(c.sampling.top_k));
  line("defaults.sampling.penalty_last_n", integer_or_unset(c.sampling.penalty_last_n));
  line("defaults.sampling.seed", integer_or_unset(c.sampling.seed));
  // SP5 M1 Task 5: the reasoning.* family and engine.fit_max_tokens.
  line("reasoning.effort",
       !c.reasoning.effort.has_value()                  ? std::string{"(unset)"}
       : *c.reasoning.effort == ReasoningEffort::none   ? "none"
       : *c.reasoning.effort == ReasoningEffort::low    ? "low"
       : *c.reasoning.effort == ReasoningEffort::medium ? "medium"
                                                        : "high");
  line("reasoning.budget_tokens", std::to_string(c.reasoning.budget_tokens));
  line("reasoning.close_retry", c.reasoning.close_retry ? "true" : "false");
  line("reasoning.loop_recovery",
       c.reasoning.loop_recovery == LoopRecovery::off      ? "off"
       : c.reasoning.loop_recovery == LoopRecovery::stop   ? "stop"
                                                           : "recover");
  line("reasoning.effort_position", c.reasoning.effort_position == EffortPosition::start ? "start" : "end");
  line("reasoning.anthropic_thinking",
       c.reasoning.anthropic_thinking == AnthropicThinking::model ? "model" : "on_request");
  line("engine.fit_max_tokens", c.engine.fit_max_tokens ? "true" : "false");
  // SP5 M1 Task 6: the lifecycle family (runconfig.py:35-38).
  line("engine.lazy_load", c.engine.lazy_load ? "true" : "false");
  line("engine.idle_unload_s", std::to_string(c.engine.idle_unload.count()));
  line("engine.mtp", c.engine.mtp ? "true" : "false");
  return out;
}

Config listener_config(const FrontendConfig& c) {
  return Config{c.listener.host.canonical_text(), c.listener.port, true,
                c.listener.host.scope() == AddressScope::loopback, c.listener.allow_remote,
                c.listener.allow_wildcard_bind};
}

ConfigErrors create_runtime_roots(const FrontendConfig& c) {
  ConfigErrors errors;
  const std::pair<const char*, const std::optional<std::filesystem::path>*> roots[] = {
      {"roots.logs", &c.roots.logs}, {"roots.cache", &c.roots.cache}};
  for (const auto& [key, root] : roots) {
    if (!root->has_value()) continue;
    auto opened = open_root(**root, RootPolicy::create_private);
    if (const auto* failure = std::get_if<PathError>(&opened)) add(errors, key, ConfigIssueCode::invalid_value, failure->message);
  }
  return errors;
}

}  // namespace secure_frontend

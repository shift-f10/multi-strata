#include "secure_frontend/frontend_config.hpp"

#include "secure_frontend/config_defaults.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/json.hpp"
#include "secure_frontend/model_inventory.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace secure_frontend {
namespace {
namespace d = config_defaults;
using T = ConfigValueType;

constexpr std::array<ConfigKey, 32> kSchema{{
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
    {"limits.http.request_deadline_ms", T::integer, false, 1, 3'600'000, d::kRequestDeadlineMs, false, "", "",
     "Total time to read one request, header and body."},
    {"limits.http.max_request_bytes", T::integer, false, 4096, 16'777'216, d::kMaxRequestBytes, false, "", "",
     "Largest request (header and body) the listener and parser accept."},
    {"limits.http.max_header_bytes", T::integer, false, 1024, 65'536, d::kMaxHeaderBytes, false, "", "",
     "Largest header block; at most limits.http.max_request_bytes."},
    {"limits.http.max_headers", T::integer, false, 8, 256, d::kMaxHeaders, false, "", "", "Most header fields."},
    {"limits.http.max_request_line_bytes", T::integer, false, 256, 16'384, d::kMaxRequestLineBytes, false, "", "",
     "Longest request line; at most limits.http.max_header_bytes."},
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
    {"limits.chat.default_max_tokens", T::integer, false, 1, 16'384, d::kChatDefaultMaxTokens, false, "", "",
     "max_tokens when a request omits it; at most limits.chat.max_completion_tokens."},
    {"limits.chat.max_generated_bytes", T::integer, false, 1, 16'777'216, d::kChatMaxGeneratedBytes, false, "", "",
     "Largest generated text returned."},
    {"limits.engine.ready_timeout_s", T::integer, false, 1, 86'400, d::kEngineReadyTimeoutS, false, "", "",
     "How long the first request waits for the engine's READY (upstream STRATA_ENGINE_READY_S)."},
    {"limits.engine.generation_timeout_s", T::integer, false, 1, 86'400, d::kEngineGenerationTimeoutS, false, "", "",
     "Total time for one generation before STOP."},
    {"limits.engine.stop_drain_timeout_s", T::integer, false, 1, 600, d::kEngineStopDrainTimeoutS, false, "", "",
     "Time to drain to DONE after STOP before the engine is marked failed."},
    {"limits.concurrency.max_concurrent_requests", T::integer, false, 1, 1, d::kMaxConcurrentRequests, false, "", "",
     "Requests served at once; only 1 until SP3."},
    {"roots.models", T::string, true, 0, 0, 0, false, "", "--models-root",
     "Absolute directory of .gguf files. The root itself may be a symlink; nothing below it may be."},
    {"roots.tokenizer_pack", T::string, true, 0, 0, 0, false, "", "--tokenizer-pack",
     "Absolute directory with vocab.json, merges.txt, token_type.json."},
    {"roots.secret", T::string, false, 0, 0, 0, false, "", "--secret-root",
     "Absolute directory holding the token file. Default: the config file's directory."},
    {"roots.logs", T::string, false, 0, 0, 0, false, "", "", "Absolute log directory (created 0700; unused in SP1)."},
    {"roots.cache", T::string, false, 0, 0, 0, false, "", "", "Absolute cache directory (created 0700; unused in SP1)."},
    {"token.source", T::string, false, 0, 0, 0, false, "file:token", "--token-file, --token-env",
     "file:<relative path below roots.secret> or env:<NAME>. Metadata only; the token is never in the config."},
    {"engine.profile", T::string, false, 0, 0, 0, false, "qwen", "--profile", "qwen or glm53."},
    {"engine.executable", T::string, true, 0, 0, 0, false, "", "--engine",
     "Absolute path of the engine; a regular file not writable by group or others."},
    {"engine.model_id", T::string, true, 0, 0, 0, false, "", "--model-id", "Model ID from the local inventory."},
    {"engine.args", T::string_array, false, 0, 0, 0, false, "", "--engine-arg (repeatable)",
     "Extra engine arguments; frontend-owned and unsupported flags are rejected."},
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

std::span<const ConfigKey> config_schema() noexcept { return kSchema; }

const ConfigKey* find_config_key(const std::string_view path) noexcept {
  for (const auto& key : kSchema) if (key.path == path) return &key;
  return nullptr;
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
        fallback = "`" + std::to_string(key.default_integer) + "`";
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
    }
    const std::string option = key.flag.empty() ? "-" : "`" + std::string{key.flag} + "`";
    out += "| `" + std::string{key.path} + "` | " + type + " | " + fallback + " | " + range + " | " + option + " | " +
           std::string{key.description} + " |\n";
  }
  return out;
}

std::string format_issue(const ConfigIssue& issue) { return issue.key_path + ": " + issue.reason; }

std::optional<ModelId> make_model_id(const std::string_view text) {
  if (!std::holds_alternative<std::string>(validate_model_id(text))) return std::nullopt;
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

  // limits
  const auto deadline_ms = read.integer("limits.http.request_deadline_ms");
  const auto max_request = read.integer("limits.http.max_request_bytes");
  const auto max_header = read.integer("limits.http.max_header_bytes");
  const auto max_headers = read.integer("limits.http.max_headers");
  const auto max_line = read.integer("limits.http.max_request_line_bytes");
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

  // roots: each is opened once, here, and held open by the FrontendConfig.
  const auto models = canonical_root(read, errors, "roots.models");
  const auto tokenizer = canonical_root(read, errors, "roots.tokenizer_pack");
  auto secret = canonical_root(read, errors, "roots.secret");
  const auto logs = creatable_root(read, errors, "roots.logs");
  const auto cache = creatable_root(read, errors, "roots.cache");

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
  const std::string profile_text = read.string("engine.profile").value_or("qwen");
  EngineProfile profile = EngineProfile::qwen;
  if (profile_text == "glm53") profile = EngineProfile::glm53;
  else if (profile_text != "qwen") add(errors, "engine.profile", ConfigIssueCode::invalid_value, "must be qwen or glm53");
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
        "must be 1-128 characters of [A-Za-z0-9._-], starting with a letter or digit");
  }
  const auto args = read.strings("engine.args");
  const auto arguments_profile = profile == EngineProfile::glm53 ? EngineArgumentsProfile::lighttransport_glm53
                                                                 : EngineArgumentsProfile::strata_0143;
  if (const auto rejected = validate_engine_user_arguments(arguments_profile, args)) {
    add(errors, "engine.args", ConfigIssueCode::invalid_value, rejected->message);
  }
  if (profile == EngineProfile::glm53 && args.empty()) {
    add(errors, "engine.args", ConfigIssueCode::missing_required, "--profile glm53 requires at least one --engine-arg");
  }

  if (!errors.empty() || !host || !models || !tokenizer || !token || !executable || !model_id) {
    if (errors.empty()) add(errors, "config file", ConfigIssueCode::invalid_value, "is incomplete");
    return errors;
  }
  const auto u32 = [](const std::int64_t v) { return static_cast<std::uint32_t>(v); };
  ListenerConfig listener{*host, static_cast<std::uint16_t>(port), allow_remote, allow_wildcard, u32(backlog)};
  const Limits limits{
      HttpLimits{std::chrono::milliseconds(deadline_ms), u32(max_request), u32(max_header), u32(max_headers), u32(max_line)},
      ChatLimits{u32(max_body), u32(max_messages), u32(max_message), u32(max_prompt), u32(max_completion), u32(default_max),
                 u32(max_generated)},
      EngineLimits{std::chrono::seconds(ready_s), std::chrono::seconds(generation_s), std::chrono::seconds(drain_s)},
      ConcurrencyLimits{u32(concurrent)}};
  Roots roots{*models, *tokenizer, secret, logs, cache};
  EngineLaunch engine{profile, *executable, std::move(*model_id), args};
  return ValidatedConfig{std::shared_ptr<const FrontendConfig>(
      new FrontendConfig(std::move(listener), limits, std::move(roots), std::move(*token), std::move(engine)))};
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
  line("limits.http.request_deadline_ms", std::to_string(c.limits.http.request_deadline.count()));
  line("limits.http.max_request_bytes", std::to_string(c.limits.http.max_request_bytes));
  line("limits.http.max_header_bytes", std::to_string(c.limits.http.max_header_bytes));
  line("limits.http.max_headers", std::to_string(c.limits.http.max_headers));
  line("limits.http.max_request_line_bytes", std::to_string(c.limits.http.max_request_line_bytes));
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
  line("limits.concurrency.max_concurrent_requests", std::to_string(c.limits.concurrency.max_concurrent_requests));
  line("roots.models", root_text(c.roots.models));
  line("roots.tokenizer_pack", root_text(c.roots.tokenizer_pack));
  line("roots.secret", root_or_unset(c.roots.secret));
  line("roots.logs", path_or_unset(c.roots.logs));
  line("roots.cache", path_or_unset(c.roots.cache));
  line("token.source", json_quoted((c.token.kind() == SecretSourceKind::environment_variable ? "env:" : "file:") +
                              c.token.location()));
  line("engine.profile", c.engine.profile == EngineProfile::glm53 ? "\"glm53\"" : "\"qwen\"");
  line("engine.executable", json_quoted(path_to_utf8(c.engine.executable.path())));
  line("engine.model_id", json_quoted(c.engine.model_id.value()));
  std::string args = "[";
  for (const auto& arg : c.engine.args) args += (args.size() > 1U ? "," : "") + json_quoted(arg);
  line("engine.args", args + "]");
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

#include "secure_frontend/config_file.hpp"

#include "secure_frontend/json.hpp"

#include <optional>
#include <string>

namespace secure_frontend {
namespace {

constexpr JsonLimits kConfigJsonLimits{.max_bytes = kMaxConfigFileBytes, .max_depth = 4U,
                                       .max_container_entries = 256U, .max_string_bytes = 4096U};

std::optional<ConfigDraftValue> draft_value(const JsonValue& value) {
  if (const auto* b = value.if_boolean()) return ConfigDraftValue{*b};
  if (const auto* i = value.if_integer()) return ConfigDraftValue{*i};
  if (const auto* s = value.if_string()) return ConfigDraftValue{*s};
  if (const auto* items = value.if_array()) {
    std::vector<std::string> strings;
    for (const auto& item : *items) {
      const auto* s = item.if_string();
      if (s == nullptr) return std::nullopt;
      strings.push_back(*s);
    }
    return ConfigDraftValue{std::move(strings)};
  }
  return std::nullopt;
}

void collect(const std::vector<JsonMember>& members, const std::string& prefix, FrontendConfigDraft& draft,
             ConfigErrors& errors) {
  for (const auto& member : members) {
    const std::string path = prefix.empty() ? member.key : prefix + "." + member.key;
    if (const ConfigKey* key = find_config_key(path)) {
      if (auto value = draft_value(member.value)) {
        draft.entries[path] = ConfigDraftEntry{std::move(*value), ConfigSource::file};
      } else {
        errors.push_back(ConfigIssue{path, ConfigIssueCode::wrong_type, std::string{type_reason(key->type)}});
      }
    } else if (is_config_section(path)) {
      if (const auto* inner = member.value.if_object()) collect(*inner, path, draft, errors);
      else errors.push_back(ConfigIssue{path, ConfigIssueCode::wrong_type, "must be an object"});
    } else {
      errors.push_back(ConfigIssue{path, ConfigIssueCode::unknown_key, "unknown key"});
    }
  }
}

}  // namespace

std::variant<FrontendConfigDraft, ConfigErrors> parse_config_text(const std::string_view text,
                                                                  const std::filesystem::path& config_directory) {
  const auto parsed = parse_json(text, kConfigJsonLimits);
  if (const auto* error = std::get_if<JsonError>(&parsed)) {
    const auto code = error->code == JsonErrorCode::duplicate_key ? ConfigIssueCode::duplicate_key
                                                                  : ConfigIssueCode::malformed_document;
    return ConfigErrors{ConfigIssue{"config file", code,
                                    std::string{describe_json_error(error->code)} + " (byte " +
                                        std::to_string(error->offset) + ")"}};
  }
  const auto* members = std::get<JsonValue>(parsed).if_object();
  if (members == nullptr) {
    return ConfigErrors{ConfigIssue{"config file", ConfigIssueCode::malformed_document, "must be a JSON object"}};
  }
  FrontendConfigDraft draft;
  draft.config_directory = config_directory;
  ConfigErrors errors;
  collect(*members, "", draft, errors);
  if (!errors.empty()) return errors;
  return draft;
}

}  // namespace secure_frontend

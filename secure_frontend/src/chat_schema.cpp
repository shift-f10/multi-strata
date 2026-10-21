#include "secure_frontend/chat_schema.hpp"

#include "secure_frontend/api_constants.hpp"
#include "secure_frontend/json.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <utility>
#include <variant>

namespace secure_frontend {
namespace {

constexpr std::size_t kMaximumModelBytes = 256U;  // model-id format bound, not a tuning limit

bool is_continuation(unsigned char byte) { return (byte & 0xc0U) == 0x80U; }

bool valid_utf8(std::string_view value) {
  for (std::size_t index = 0; index < value.size();) {
    const auto byte = static_cast<unsigned char>(value[index]);
    if (byte <= 0x7fU) {
      ++index;
    } else if (byte >= 0xc2U && byte <= 0xdfU && index + 1U < value.size() &&
               is_continuation(static_cast<unsigned char>(value[index + 1U]))) {
      index += 2U;
    } else if (byte == 0xe0U && index + 2U < value.size() &&
               static_cast<unsigned char>(value[index + 1U]) >= 0xa0U &&
               static_cast<unsigned char>(value[index + 1U]) <= 0xbfU &&
               is_continuation(static_cast<unsigned char>(value[index + 2U]))) {
      index += 3U;
    } else if (((byte >= 0xe1U && byte <= 0xecU) || (byte >= 0xeeU && byte <= 0xefU)) &&
               index + 2U < value.size() && is_continuation(static_cast<unsigned char>(value[index + 1U])) &&
               is_continuation(static_cast<unsigned char>(value[index + 2U]))) {
      index += 3U;
    } else if (byte == 0xedU && index + 2U < value.size() &&
               static_cast<unsigned char>(value[index + 1U]) >= 0x80U &&
               static_cast<unsigned char>(value[index + 1U]) <= 0x9fU &&
               is_continuation(static_cast<unsigned char>(value[index + 2U]))) {
      index += 3U;
    } else if (byte == 0xf0U && index + 3U < value.size() &&
               static_cast<unsigned char>(value[index + 1U]) >= 0x90U &&
               static_cast<unsigned char>(value[index + 1U]) <= 0xbfU &&
               is_continuation(static_cast<unsigned char>(value[index + 2U])) &&
               is_continuation(static_cast<unsigned char>(value[index + 3U]))) {
      index += 4U;
    } else if (byte >= 0xf1U && byte <= 0xf3U && index + 3U < value.size() &&
               is_continuation(static_cast<unsigned char>(value[index + 1U])) &&
               is_continuation(static_cast<unsigned char>(value[index + 2U])) &&
               is_continuation(static_cast<unsigned char>(value[index + 3U]))) {
      index += 4U;
    } else if (byte == 0xf4U && index + 3U < value.size() &&
               static_cast<unsigned char>(value[index + 1U]) >= 0x80U &&
               static_cast<unsigned char>(value[index + 1U]) <= 0x8fU &&
               is_continuation(static_cast<unsigned char>(value[index + 2U])) &&
               is_continuation(static_cast<unsigned char>(value[index + 3U]))) {
      index += 4U;
    } else {
      return false;
    }
  }
  return true;
}

bool contains_remote_scheme(std::string_view value) {
  constexpr std::array<std::string_view, 5> schemes{"http://", "https://", "file://", "data:", "mcp://"};
  std::string lowered;
  lowered.reserve(value.size());
  for (const unsigned char byte : value) lowered.push_back(static_cast<char>(std::tolower(byte)));
  for (const std::string_view scheme : schemes) {
    if (lowered.find(scheme) != std::string::npos) return true;
  }
  return false;
}

bool valid_model(std::string_view value) {
  if (value.empty() || value.size() > kMaximumModelBytes || contains_remote_scheme(value)) return false;
  for (const unsigned char byte : value) {
    if (!(std::isalnum(byte) || byte == '.' || byte == '_' || byte == '-')) return false;
  }
  return true;
}

bool valid_content(std::string_view value, const std::size_t max_message_bytes) {
  if (value.empty() || value.size() > max_message_bytes || !valid_utf8(value) || contains_remote_scheme(value)) return false;
  for (const unsigned char byte : value) {
    if (byte < 0x20U && byte != '\n' && byte != '\r' && byte != '\t') return false;
  }
  return true;
}

}  // namespace

namespace {

constexpr std::string_view kExtensionKeys[] = {"tools", "tool_choice", "functions", "function_call", "parallel_tool_calls", "mcp_servers"};
constexpr std::string_view kSp5Keys[] = {"top_k", "min_p", "top_logprobs", "response_format"};
template <std::size_t N>
std::string_view find_key(const std::string_view (&keys)[N], const std::string_view key) {
  for (const auto k : keys) {
    if (k == key) return k;
  }
  return {};
}

// Integer forms (`1`, `0`) are numbers exactly like `1.0`/`0.0` (Review Focus 5).
std::optional<double> number_of(const JsonValue& value) {
  if (const auto* i = value.if_integer()) return static_cast<double>(*i);
  if (const auto* d = value.if_decimal()) return *d;
  return std::nullopt;
}

// Pre-flight T7(c): named `refuse`, not `fail`. `param` must be a literal.
ChatRequestError refuse(const ApiError error, const std::string_view param = {}) { return {error, param}; }

}  // namespace

ChatRequestResult parse_chat_request(const std::string_view json, const ChatSchemaLimits& limits) {
  // Depth 4 (kChatMaxJsonDepth): request -> messages -> message -> one more
  // level, so `content` arrays and small extension objects reach the schema
  // and get their own error; deeper input is invalid_json at the reader.
  const JsonLimits json_limits{.max_bytes = limits.max_body_bytes, .max_depth = api_constants::kChatMaxJsonDepth,
                               .max_container_entries = std::max<std::size_t>(limits.max_messages, 16U),
                               .max_string_bytes = limits.max_body_bytes, .allow_fractions = true};
  const auto parsed = parse_json(json, json_limits);
  const auto* root = std::get_if<JsonValue>(&parsed);
  if (root == nullptr) return refuse(ApiError::invalid_json);
  const auto* members = root->if_object();
  if (members == nullptr) return refuse(ApiError::invalid_request);

  // Extensions first, in document order (EXT-01), including message roles.
  for (const auto& member : *members) {
    if (const auto key = find_key(kExtensionKeys, member.key); !key.empty()) return refuse(ApiError::extension_disabled, key);
    if (member.key == "messages") {
      if (const auto* items = member.value.if_array()) {
        for (const auto& item : *items) {
          const auto* fields = item.if_object();
          if (fields == nullptr) continue;
          for (const auto& field : *fields) {
            const auto* role = field.value.if_string();
            if (field.key == "role" && role != nullptr && (*role == "tool" || *role == "function")) {
              return refuse(ApiError::extension_disabled, "role");
            }
          }
        }
      }
    }
  }

  ChatCompletionRequest request;
  bool model_seen = false;
  bool messages_seen = false;
  bool max_seen = false;
  bool stream_options_seen = false;
  for (const auto& member : *members) {
    const std::string& key = member.key;
    const JsonValue& value = member.value;
    if (key == "model") {
      const auto* text = value.if_string();
      if (text == nullptr || text->size() > api_constants::kChatModelMaxBytes || !valid_model(*text)) {
        return refuse(ApiError::invalid_request);
      }
      request.model = *text;
      model_seen = true;
    } else if (key == "messages") {
      const auto* items = value.if_array();
      if (items == nullptr || items->empty() || items->size() > limits.max_messages) return refuse(ApiError::invalid_request);
      for (const auto& item : *items) {
        const auto* fields = item.if_object();
        if (fields == nullptr) return refuse(ApiError::invalid_request);
        ChatMessage message;
        bool role_seen = false;
        bool content_seen = false;
        for (const auto& field : *fields) {
          if (field.key == "content" && field.value.kind() == JsonKind::array) {
            return refuse(ApiError::unsupported_parameter, "content");
          }
          const auto* text = field.value.if_string();
          if (text == nullptr) return refuse(ApiError::invalid_request);
          if (field.key == "role" && (*text == "system" || *text == "user" || *text == "assistant")) {
            message.role = *text;
            role_seen = true;
          } else if (field.key == "content" && valid_content(*text, limits.max_message_bytes)) {
            message.content = *text;
            content_seen = true;
          } else {
            return refuse(ApiError::invalid_request);
          }
        }
        if (!role_seen || !content_seen) return refuse(ApiError::invalid_request);
        request.messages.push_back(std::move(message));
      }
      messages_seen = true;
    } else if (key == "max_tokens" || key == "max_completion_tokens") {
      // B2: any integer >= 1 is accepted; values above UINT32_MAX are clamped
      // here and the real budget is resolved against the config and context later.
      const auto* integer = value.if_integer();
      if (max_seen || integer == nullptr || *integer < 1) return refuse(ApiError::invalid_request);
      request.max_tokens = static_cast<std::size_t>(std::min<std::int64_t>(*integer, 4294967295LL));
      max_seen = true;
    } else if (key == "stream") {
      const auto* flag = value.if_boolean();
      if (flag == nullptr) return refuse(ApiError::invalid_request);
      request.stream = *flag;
    } else if (key == "stream_options") {
      const auto* options = value.if_object();
      if (options == nullptr) return refuse(ApiError::invalid_request);
      for (const auto& option : *options) {
        const bool* include_usage = option.value.if_boolean();
        if (option.key != "include_usage" || include_usage == nullptr) return refuse(ApiError::invalid_request);
        request.include_usage = *include_usage;
      }
      stream_options_seen = true;
    } else if (key == "n") {
      const auto* integer = value.if_integer();
      if (integer == nullptr) return refuse(ApiError::invalid_request);
      if (*integer != 1) return refuse(ApiError::unsupported_parameter, "n");
    } else if (key == "user") {
      const auto* text = value.if_string();
      if (text == nullptr || text->size() > api_constants::kChatUserMaxBytes) return refuse(ApiError::invalid_request);
    } else if (key == "temperature") {
      const auto number = number_of(value);
      if (!number || *number < 0.0 || *number > api_constants::kTemperatureMax) return refuse(ApiError::invalid_request);
      request.sampling.temperature = *number;
    } else if (key == "top_p") {
      const auto number = number_of(value);
      if (!number || *number <= 0.0 || *number > 1.0) return refuse(ApiError::invalid_request);
      request.sampling.top_p = *number;
    } else if (key == "seed") {
      // Above INT64_MAX (= kSeedMax) the reader already refused (invalid_json);
      // a decimal seed is not an integer (invalid_request).
      const auto* integer = value.if_integer();
      if (integer == nullptr || *integer < 0 || static_cast<std::uint64_t>(*integer) > api_constants::kSeedMax) {
        return refuse(ApiError::invalid_request);
      }
      request.sampling.seed = static_cast<std::uint64_t>(*integer);
    } else if (key == "presence_penalty" || key == "frequency_penalty") {
      const auto number = number_of(value);
      if (!number) return refuse(ApiError::invalid_request);
      if (*number != 0.0) {
        return refuse(ApiError::unsupported_parameter, key == "presence_penalty" ? "presence_penalty" : "frequency_penalty");
      }
    } else if (key == "logit_bias") {
      const auto* object = value.if_object();
      if (object == nullptr || !object->empty()) return refuse(ApiError::unsupported_parameter, "logit_bias");
    } else if (key == "stop") {
      const auto* array = value.if_array();
      if (!(value.kind() == JsonKind::null || (array != nullptr && array->empty()))) {
        return refuse(ApiError::unsupported_parameter, "stop");
      }
    } else if (key == "logprobs") {
      const auto* flag = value.if_boolean();
      if (flag == nullptr) return refuse(ApiError::invalid_request);
      if (*flag) return refuse(ApiError::unsupported_parameter, "logprobs");
    } else if (const auto sp5 = find_key(kSp5Keys, key); !sp5.empty()) {
      return refuse(ApiError::unsupported_parameter, sp5);
    } else {
      return refuse(ApiError::invalid_request);
    }
  }
  // stream_options is only valid with stream:true (accepted since M2).
  if (stream_options_seen && !request.stream) return refuse(ApiError::invalid_request);
  if (!model_seen || !messages_seen) return refuse(ApiError::invalid_request);
  return request;
}

std::optional<ChatCompletionRequest> parse_chat_completion_request(const std::string_view json,
                                                                   const ChatSchemaLimits& limits) {
  auto result = parse_chat_request(json, limits);
  if (auto* request = std::get_if<ChatCompletionRequest>(&result)) return std::move(*request);
  return std::nullopt;
}

std::optional<std::string> render_chat_completion_response(const ChatCompletionRequest& request,
                                                           std::string_view generated_text,
                                                           const ChatSchemaLimits& limits) {
  if (!valid_model(request.model) || generated_text.size() > limits.max_generated_bytes ||
      !valid_utf8(generated_text)) {
    return std::nullopt;
  }
  std::string response{"{\"id\":\"chatcmpl-local\",\"object\":\"chat.completion\",\"created\":0,\"model\":"};
  append_json_string(&response, request.model);
  response.append(",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":");
  append_json_string(&response, generated_text);
  response.append("},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":0,\"total_tokens\":0}}\n");
  return response;
}

std::optional<std::string> render_chat_completion(const CompletionView& view, const ChatSchemaLimits& limits) {
  if (view.text.size() > limits.max_generated_bytes || !valid_utf8(view.text) || !valid_utf8(view.model)) return std::nullopt;
  std::string out{"{\"id\":"};
  append_json_string(&out, view.id);
  out += ",\"object\":\"chat.completion\",\"created\":" + std::to_string(view.created) + ",\"model\":";
  append_json_string(&out, view.model);
  out += ",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":";
  append_json_string(&out, view.text);
  out += "},\"logprobs\":null,\"finish_reason\":";
  append_json_string(&out, view.finish_reason);
  out += "}],\"usage\":{\"prompt_tokens\":" + std::to_string(view.prompt_tokens) + ",\"completion_tokens\":" +
         std::to_string(view.completion_tokens) + ",\"total_tokens\":" + std::to_string(view.prompt_tokens + view.completion_tokens) + "}}\n";
  return out;
}

}  // namespace secure_frontend

#include "secure_frontend/chat_schema.hpp"

#include "secure_frontend/json.hpp"

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

std::optional<ChatCompletionRequest> parse_chat_completion_request(std::string_view json,
                                                                   const ChatSchemaLimits& limits) {
  if (json.empty() || json.size() > limits.max_body_bytes) return std::nullopt;
  // Depth 3: request object -> messages array -> message object. Deeper
  // input (content arrays, tool objects) fails closed at the reader.
  const JsonLimits json_limits{.max_bytes = limits.max_body_bytes, .max_depth = 3U,
                               .max_container_entries = limits.max_messages,
                               .max_string_bytes = limits.max_body_bytes};
  const auto parsed = parse_json(json, json_limits);
  const auto* root = std::get_if<JsonValue>(&parsed);
  const auto* members = root != nullptr ? root->if_object() : nullptr;
  if (members == nullptr) return std::nullopt;
  ChatCompletionRequest request;
  bool model_seen = false;
  bool messages_seen = false;
  for (const auto& member : *members) {
    if (member.key == "model") {
      const auto* value = member.value.if_string();
      if (value == nullptr || !valid_model(*value)) return std::nullopt;
      request.model = *value;
      model_seen = true;
    } else if (member.key == "messages") {
      const auto* items = member.value.if_array();
      if (items == nullptr || items->size() > limits.max_messages) return std::nullopt;
      for (const auto& item : *items) {
        const auto* fields = item.if_object();
        if (fields == nullptr) return std::nullopt;
        ChatMessage message;
        bool role_seen = false;
        bool content_seen = false;
        for (const auto& field : *fields) {
          const auto* text = field.value.if_string();
          if (text == nullptr) return std::nullopt;
          if (field.key == "role" && (*text == "system" || *text == "user" || *text == "assistant")) {
            message.role = *text;
            role_seen = true;
          } else if (field.key == "content" && valid_content(*text, limits.max_message_bytes)) {
            message.content = *text;
            content_seen = true;
          } else {
            return std::nullopt;
          }
        }
        if (!role_seen || !content_seen) return std::nullopt;
        request.messages.push_back(std::move(message));
      }
      messages_seen = true;
    } else if (member.key == "max_tokens") {
      const auto* value = member.value.if_integer();
      if (value == nullptr || *value < 0 || static_cast<std::uint64_t>(*value) > limits.max_completion_tokens) {
        return std::nullopt;
      }
      request.max_tokens = static_cast<std::size_t>(*value);
    } else if (member.key == "stream") {
      const auto* value = member.value.if_boolean();
      if (value == nullptr || *value) return std::nullopt;
    } else {
      return std::nullopt;
    }
  }
  if (!model_seen || !messages_seen || request.messages.empty()) return std::nullopt;
  return request;
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

}  // namespace secure_frontend

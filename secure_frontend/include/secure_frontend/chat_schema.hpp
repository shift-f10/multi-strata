#pragma once

#include "secure_frontend/config_defaults.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace secure_frontend {

// Deliberately small, offline-only subset of the OpenAI chat request schema.
// This is a schema boundary, not an engine API: it accepts only textual
// messages and has no representation for tools, images, URLs, or MCP.
struct ChatMessage final {
  std::string role;
  std::string content;
};

struct ChatCompletionRequest final {
  std::string model;
  std::vector<ChatMessage> messages;
  std::optional<std::size_t> max_tokens;
};

// Chat request/response bounds; derived from FrontendConfig by chat_schema_limits().
struct ChatSchemaLimits final {
  std::size_t max_body_bytes{static_cast<std::size_t>(config_defaults::kChatMaxBodyBytes)};
  std::size_t max_messages{static_cast<std::size_t>(config_defaults::kChatMaxMessages)};
  std::size_t max_message_bytes{static_cast<std::size_t>(config_defaults::kChatMaxMessageBytes)};
  std::size_t max_completion_tokens{static_cast<std::size_t>(config_defaults::kChatMaxCompletionTokens)};
  std::size_t max_generated_bytes{static_cast<std::size_t>(config_defaults::kChatMaxGeneratedBytes)};
};

// Returns nullopt for malformed JSON, unsupported fields/features, or values
// that exceed the fixed request limits.  Errors intentionally carry no client
// supplied input so callers cannot accidentally reflect sensitive prompts.
[[nodiscard]] std::optional<ChatCompletionRequest> parse_chat_completion_request(
    std::string_view json, const ChatSchemaLimits& limits = {});

// Produces the non-streaming response form only.  The generated text is JSON
// escaped and bounded; nullopt means either caller-owned request fields or the
// generated text are unsafe to serialize.
[[nodiscard]] std::optional<std::string> render_chat_completion_response(
    const ChatCompletionRequest& request, std::string_view generated_text, const ChatSchemaLimits& limits = {});

}  // namespace secure_frontend

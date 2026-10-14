#pragma once

#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/config_defaults.hpp"
#include "secure_frontend/sampling_params.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
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
  std::optional<std::size_t> max_tokens;   // >= 1, at most UINT32_MAX; clamped at resolve (B2)
  bool stream{false};
  bool include_usage{false};
  SamplingParams sampling{};
};

// Chat request/response bounds; derived from FrontendConfig by chat_schema_limits().
struct ChatSchemaLimits final {
  std::size_t max_body_bytes{static_cast<std::size_t>(config_defaults::kChatMaxBodyBytes)};
  std::size_t max_messages{static_cast<std::size_t>(config_defaults::kChatMaxMessages)};
  std::size_t max_message_bytes{static_cast<std::size_t>(config_defaults::kChatMaxMessageBytes)};
  std::size_t max_completion_tokens{static_cast<std::size_t>(config_defaults::kChatMaxCompletionTokens)};
  std::size_t max_generated_bytes{static_cast<std::size_t>(config_defaults::kChatMaxGeneratedBytes)};
};

struct ChatRequestError final {
  ApiError error;
  std::string_view param;   // a fixed key from api_errors (is_fixed_param_key) or empty
};
using ChatRequestResult = std::variant<ChatCompletionRequest, ChatRequestError>;

// Spec §3.1: the full request schema. Errors name only a fixed parameter key
// (string literal storage), never request bytes. Extension keys and tool or
// function roles are refused first, in document order (EXT-01).
[[nodiscard]] ChatRequestResult parse_chat_request(std::string_view json, const ChatSchemaLimits& limits = {});

// Wrapper over parse_chat_request: nullopt on any error.
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

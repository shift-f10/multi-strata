#pragma once

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

// Returns nullopt for malformed JSON, unsupported fields/features, or values
// that exceed the fixed request limits.  Errors intentionally carry no client
// supplied input so callers cannot accidentally reflect sensitive prompts.
[[nodiscard]] std::optional<ChatCompletionRequest> parse_chat_completion_request(
    std::string_view json);

// Produces the non-streaming response form only.  The generated text is JSON
// escaped and bounded; nullopt means either caller-owned request fields or the
// generated text are unsafe to serialize.
[[nodiscard]] std::optional<std::string> render_chat_completion_response(
    const ChatCompletionRequest& request, std::string_view generated_text);

}  // namespace secure_frontend

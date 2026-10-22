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
// This is a schema boundary, not an engine API: text messages are the rule;
// the ONE carve-out is SP5 M1 Task 12 (C-9): a content ARRAY of text/image_url
// parts, accepted only when the composition proved the active model can read
// images (vision_capable). It still has no representation for tools, URLs of
// any other kind, or MCP.
struct ChatMessagePart final {
  std::string text;            // set for a {"type":"text"} part
  std::string image_data_url;  // set for a {"type":"image_url"} part — the data URL, verbatim
};

struct ChatMessage final {
  std::string role;
  std::string content;           // the text of a string content, or of all text parts (parts form)
  std::vector<ChatMessagePart> parts{};  // empty: the string-content form; else the parts array
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
  // SP5 M1 Task 12 (C-9; Ruling T12-b): the content-array gate. vision_capable is set
  // ONLY from the composed launch — vision.enabled AND the manifest's launch.mmproj —
  // never from the request. max_images is vision.max_n (pin :103 family, re-scoped);
  // max_image_b64_chars bounds each URL's base64 LENGTH before anything decodes
  // (T12-c: the pin's IMAGE_URL_MAX = 32 MiB of decoded bytes, serve/server.py:2474).
  bool vision_capable{false};
  std::size_t max_images{4};
  std::size_t max_image_b64_chars{(std::size_t{32} << 20) / 3U * 4U + 4U};
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

// SP3 Task 15 (spec §3.5): the OpenAI chat.completion body for a finished
// generation — the form M2's streaming path finalizes with too.
struct CompletionView final {
  std::string_view id;
  std::int64_t created;
  std::string_view model;
  std::string_view text;
  std::string_view finish_reason;
  std::size_t prompt_tokens;
  std::size_t completion_tokens;
  // message.reasoning_content, written only when non-empty (upstream serve/server.py:5511-5513).
  std::string_view reasoning{};
};

[[nodiscard]] std::optional<std::string> render_chat_completion(const CompletionView& view, const ChatSchemaLimits& limits = {});

}  // namespace secure_frontend

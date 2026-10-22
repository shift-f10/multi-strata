#include "secure_frontend/qwen_prompt_renderer.hpp"

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

namespace secure_frontend {
namespace {

constexpr std::size_t kMaximumMessages = 128U;
constexpr std::size_t kMaximumMessageBytes = 64U * 1024U;
constexpr std::size_t kMaximumPromptBytes = 512U * 1024U;
constexpr std::size_t kMaximumImagePadRun = 65536U;  // sanity bound on an encoder's answer
constexpr std::string_view kStartMarker = "<|im_start|>";
constexpr std::string_view kEndMarker = "<|im_end|>";
constexpr std::string_view kVisionStartMarker = "<|vision_start|>";
constexpr std::string_view kImagePadMarker = "<|image_pad|>";
constexpr std::string_view kVisionEndMarker = "<|vision_end|>";
constexpr std::string_view kThinkOpenMarker = "<think>";
constexpr std::string_view kThinkCloseMarker = "</think>";

bool valid_utf8(std::string_view value) {
  for (std::size_t index = 0; index < value.size();) {
    const auto byte = static_cast<unsigned char>(value[index]);
    if (byte <= 0x7fU) {
      ++index;
    } else if (byte >= 0xc2U && byte <= 0xdfU && index + 1U < value.size() &&
               (static_cast<unsigned char>(value[index + 1U]) & 0xc0U) == 0x80U) {
      index += 2U;
    } else if (byte >= 0xe0U && byte <= 0xefU && index + 2U < value.size() &&
               (static_cast<unsigned char>(value[index + 1U]) & 0xc0U) == 0x80U &&
               (static_cast<unsigned char>(value[index + 2U]) & 0xc0U) == 0x80U &&
               !(byte == 0xe0U && static_cast<unsigned char>(value[index + 1U]) < 0xa0U) &&
               !(byte == 0xedU && static_cast<unsigned char>(value[index + 1U]) > 0x9fU)) {
      index += 3U;
    } else if (byte >= 0xf0U && byte <= 0xf4U && index + 3U < value.size() &&
               (static_cast<unsigned char>(value[index + 1U]) & 0xc0U) == 0x80U &&
               (static_cast<unsigned char>(value[index + 2U]) & 0xc0U) == 0x80U &&
               (static_cast<unsigned char>(value[index + 3U]) & 0xc0U) == 0x80U &&
               !(byte == 0xf0U && static_cast<unsigned char>(value[index + 1U]) < 0x90U) &&
               !(byte == 0xf4U && static_cast<unsigned char>(value[index + 1U]) > 0x8fU)) {
      index += 4U;
    } else {
      return false;
    }
  }
  return true;
}

bool safe_content(std::string_view content) {
  if (content.empty() || content.size() > kMaximumMessageBytes || !valid_utf8(content) ||
      content.find(kStartMarker) != std::string_view::npos ||
      content.find(kEndMarker) != std::string_view::npos ||
      content.find(kVisionStartMarker) != std::string_view::npos ||
      content.find(kImagePadMarker) != std::string_view::npos ||
      content.find(kVisionEndMarker) != std::string_view::npos) {
    return false;
  }
  for (const unsigned char byte : content) {
    if (byte < 0x20U && byte != '\n' && byte != '\r' && byte != '\t') return false;
  }
  return true;
}

bool append_bounded(std::string* prompt, std::string_view value) {
  if (value.size() > kMaximumPromptBytes - prompt->size()) return false;
  prompt->append(value);
  return true;
}

// Renders one message body: the string form appends its content; the parts form
// (Ruling T12-f) appends each text part and, for each image part, the Qwen
// template's run — vision_start + N x image_pad + vision_end — consuming the
// encoder's N in part order. Text parts obey the same safety rules as content.
bool append_message_body(std::string* prompt, const ChatMessage& message,
                         const std::span<const std::size_t> image_token_counts, std::size_t& image_index) {
  if (message.parts.empty()) return append_bounded(prompt, message.content);
  for (const auto& part : message.parts) {
    if (part.image_data_url.empty()) {
      if (!safe_content(part.text) || !append_bounded(prompt, part.text)) return false;
      continue;
    }
    if (image_index >= image_token_counts.size() || image_token_counts[image_index] == 0U ||
        image_token_counts[image_index] > kMaximumImagePadRun) {
      return false;  // the counts must cover every image part exactly (the route feeds both from one parse)
    }
    if (!append_bounded(prompt, kVisionStartMarker)) return false;
    for (std::size_t pad = 0; pad < image_token_counts[image_index]; ++pad) {
      if (!append_bounded(prompt, kImagePadMarker)) return false;
    }
    if (!append_bounded(prompt, kVisionEndMarker)) return false;
    ++image_index;
  }
  return true;
}

bool image_free_parts(const ChatMessage& message) {
  for (const auto& part : message.parts) {
    if (!part.image_data_url.empty()) return false;
  }
  return true;
}

// With a reasoning tail only the renderer may place the think markers: a client's
// literal could otherwise open or close the model's think block.
bool holds_think_marker(const ChatMessage& message) {
  const auto holds = [](const std::string_view text) {
    return text.find(kThinkOpenMarker) != std::string_view::npos || text.find(kThinkCloseMarker) != std::string_view::npos;
  };
  if (holds(message.content)) return true;
  for (const auto& part : message.parts) {
    if (holds(part.text)) return true;
  }
  return false;
}

}  // namespace

std::optional<std::string> render_qwen_text_prompt(const std::vector<ChatMessage>& messages,
                                                   const std::span<const std::size_t> image_token_counts,
                                                   const QwenThinking thinking) {
  if (messages.empty() || messages.size() > kMaximumMessages) return std::nullopt;
  if (thinking != QwenThinking::absent) {
    for (const auto& message : messages) {
      if (holds_think_marker(message)) return std::nullopt;
    }
  }

  std::size_t index = 0;
  if (messages.front().role == "system") {
    if (!safe_content(messages.front().content) || !image_free_parts(messages.front())) return std::nullopt;
    index = 1U;
  }
  if (index == messages.size()) return std::nullopt;

  bool expect_user = true;
  std::string prompt;
  prompt.reserve(256U);
  std::size_t image_index = 0;
  for (; index < messages.size(); ++index) {
    const ChatMessage& message = messages[index];
    const std::string_view expected_role = expect_user ? "user" : "assistant";
    if (message.role != expected_role) return std::nullopt;
    if (message.parts.empty()) {
      if (!safe_content(message.content)) return std::nullopt;
    } else if (message.role != "user" && !image_free_parts(message)) {
      return std::nullopt;  // images ride user turns (the pin reads the request's user images)
    }
    if (!append_bounded(&prompt, kStartMarker) || !append_bounded(&prompt, message.role) ||
        !append_bounded(&prompt, "\n") || !append_message_body(&prompt, message, image_token_counts, image_index) ||
        !append_bounded(&prompt, kEndMarker) || !append_bounded(&prompt, "\n")) {
      return std::nullopt;
    }
    expect_user = !expect_user;
  }
  // A generation prompt is valid only after a user turn. At that point the
  // next expected historical role would be assistant. And every count given
  // must have been consumed by an image part (exact match, both directions).
  if (expect_user || image_index != image_token_counts.size()) return std::nullopt;

  if (messages.front().role == "system") {
    std::string system_prefix;
    system_prefix.reserve(messages.front().content.size() + 32U);
    system_prefix.append(kStartMarker);
    system_prefix.append("system\n");
    system_prefix.append(messages.front().content);
    system_prefix.append(kEndMarker);
    system_prefix.push_back('\n');
    if (system_prefix.size() > kMaximumPromptBytes - prompt.size()) return std::nullopt;
    prompt.insert(0U, system_prefix);
  }
  if (!append_bounded(&prompt, kStartMarker) || !append_bounded(&prompt, "assistant\n")) {
    return std::nullopt;
  }
  // The Qwen3 template's add_generation_prompt tail (tokenizer/chat_template.jinja).
  if (thinking == QwenThinking::on && !append_bounded(&prompt, "<think>\n")) return std::nullopt;
  if (thinking == QwenThinking::off && !append_bounded(&prompt, "<think>\n\n</think>\n\n")) return std::nullopt;
  return prompt;
}

}  // namespace secure_frontend

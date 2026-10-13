#include "secure_frontend/qwen_prompt_renderer.hpp"

#include <cstddef>
#include <string_view>

namespace secure_frontend {
namespace {

constexpr std::size_t kMaximumMessages = 128U;
constexpr std::size_t kMaximumMessageBytes = 64U * 1024U;
constexpr std::size_t kMaximumPromptBytes = 512U * 1024U;
constexpr std::string_view kStartMarker = "<|im_start|>";
constexpr std::string_view kEndMarker = "<|im_end|>";

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
      content.find(kEndMarker) != std::string_view::npos) {
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

}  // namespace

std::optional<std::string> render_qwen_text_prompt(const std::vector<ChatMessage>& messages) {
  if (messages.empty() || messages.size() > kMaximumMessages) return std::nullopt;

  std::size_t index = 0;
  if (messages.front().role == "system") {
    if (!safe_content(messages.front().content)) return std::nullopt;
    index = 1U;
  }
  if (index == messages.size()) return std::nullopt;

  bool expect_user = true;
  std::string prompt;
  prompt.reserve(256U);
  for (; index < messages.size(); ++index) {
    const ChatMessage& message = messages[index];
    const std::string_view expected_role = expect_user ? "user" : "assistant";
    if (message.role != expected_role || !safe_content(message.content)) return std::nullopt;
    if (!append_bounded(&prompt, kStartMarker) || !append_bounded(&prompt, message.role) ||
        !append_bounded(&prompt, "\n") || !append_bounded(&prompt, message.content) ||
        !append_bounded(&prompt, kEndMarker) || !append_bounded(&prompt, "\n")) {
      return std::nullopt;
    }
    expect_user = !expect_user;
  }
  // A generation prompt is valid only after a user turn. At that point the
  // next expected historical role would be assistant.
  if (expect_user) return std::nullopt;

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
  return prompt;
}

}  // namespace secure_frontend

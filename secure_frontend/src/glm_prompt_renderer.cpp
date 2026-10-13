#include "secure_frontend/glm_prompt_renderer.hpp"

#include <array>
#include <cstddef>
#include <string_view>

namespace secure_frontend {
namespace {

constexpr std::size_t kMaximumMessages = 128U;
constexpr std::size_t kMaximumMessageBytes = 64U * 1024U;
constexpr std::size_t kMaximumPromptBytes = 512U * 1024U;
constexpr std::array<std::string_view, 6U> kControlLiterals = {
    "[gMASK]", "<sop>", "<|system|>", "<|user|>", "<|assistant|>", "<think>"};

bool valid_utf8(const std::string_view value) {
  for (std::size_t index = 0U; index < value.size();) {
    const auto byte = static_cast<unsigned char>(value[index]);
    if (byte <= 0x7fU) ++index;
    else if (byte >= 0xc2U && byte <= 0xdfU && index + 1U < value.size() &&
             (static_cast<unsigned char>(value[index + 1U]) & 0xc0U) == 0x80U) index += 2U;
    else if (byte >= 0xe0U && byte <= 0xefU && index + 2U < value.size() &&
             (static_cast<unsigned char>(value[index + 1U]) & 0xc0U) == 0x80U &&
             (static_cast<unsigned char>(value[index + 2U]) & 0xc0U) == 0x80U &&
             !(byte == 0xe0U && static_cast<unsigned char>(value[index + 1U]) < 0xa0U) &&
             !(byte == 0xedU && static_cast<unsigned char>(value[index + 1U]) > 0x9fU)) index += 3U;
    else if (byte >= 0xf0U && byte <= 0xf4U && index + 3U < value.size() &&
             (static_cast<unsigned char>(value[index + 1U]) & 0xc0U) == 0x80U &&
             (static_cast<unsigned char>(value[index + 2U]) & 0xc0U) == 0x80U &&
             (static_cast<unsigned char>(value[index + 3U]) & 0xc0U) == 0x80U &&
             !(byte == 0xf0U && static_cast<unsigned char>(value[index + 1U]) < 0x90U) &&
             !(byte == 0xf4U && static_cast<unsigned char>(value[index + 1U]) > 0x8fU)) index += 4U;
    else return false;
  }
  return true;
}

bool safe_content(const std::string_view content) {
  if (content.empty() || content.size() > kMaximumMessageBytes || !valid_utf8(content)) return false;
  for (const auto marker : kControlLiterals) {
    if (content.find(marker) != std::string_view::npos) return false;
  }
  for (const unsigned char byte : content) {
    if (byte < 0x20U && byte != '\n' && byte != '\r' && byte != '\t') return false;
  }
  return true;
}

bool append_bounded(std::string* const output, const std::string_view text) {
  if (text.size() > kMaximumPromptBytes - output->size()) return false;
  output->append(text);
  return true;
}

}  // namespace

std::optional<std::string> render_glm53_text_prompt(const std::vector<ChatMessage>& messages) {
  if (messages.empty() || messages.size() > kMaximumMessages) return std::nullopt;
  std::string output;
  output.reserve(256U);
  if (!append_bounded(&output, "[gMASK]<sop>")) return std::nullopt;

  std::size_t index = 0U;
  if (messages.front().role == "system") {
    if (!safe_content(messages.front().content) || !append_bounded(&output, "<|system|>") ||
        !append_bounded(&output, messages.front().content)) return std::nullopt;
    index = 1U;
  }
  if (index == messages.size()) return std::nullopt;

  bool expect_user = true;
  for (; index < messages.size(); ++index) {
    const ChatMessage& message = messages[index];
    if (message.role != (expect_user ? "user" : "assistant") || !safe_content(message.content) ||
        !append_bounded(&output, expect_user ? "<|user|>" : "<|assistant|>") ||
        !append_bounded(&output, message.content)) return std::nullopt;
    expect_user = !expect_user;
  }
  if (expect_user || !append_bounded(&output, "<|assistant|><think>")) return std::nullopt;
  return output;
}

}  // namespace secure_frontend

#pragma once

#include "secure_frontend/chat_schema.hpp"

#include <optional>
#include <string>
#include <vector>

namespace secure_frontend {

// Renders the intentionally constrained, text-only Qwen/ChatML generation
// prompt used by the native frontend:
//
//   <|im_start|>system\n{system}<|im_end|>\n
//   <|im_start|>user\n{user}<|im_end|>\n
//   <|im_start|>assistant\n{assistant}<|im_end|>\n
//   <|im_start|>assistant\n
// A conversation may omit system, otherwise it must begin with exactly one
// system message and then alternate user/assistant, ending in user. Only the
// system, user, and assistant roles are accepted. Content containing ChatML
// control markers or control bytes fails closed so user text cannot create a
// synthetic prompt boundary.
//
// This is deliberately not a Jinja implementation and does not claim parity
// with a model's tokenizer_config chat_template. Callers must choose this
// renderer only for models configured for this fixed prompt format.
[[nodiscard]] std::optional<std::string> render_qwen_text_prompt(
    const std::vector<ChatMessage>& messages);

}  // namespace secure_frontend

#pragma once

#include "secure_frontend/chat_schema.hpp"

#include <cstddef>
#include <optional>
#include <span>
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
//
// SP5 M1 Task 12 (Ruling T12-f): a message in the PARTS form (ChatMessage.parts)
// renders its text parts inline and its image parts as the Qwen template's
// per-image run — <|vision_start|> + N x <|image_pad|> + <|vision_end|> — where N
// is the image-token count the encoder answered (the pin expands the pad run one
// id per image token, serve/server.py:4488-4505; we compute it up front). The
// counts are consumed in part order across all messages; a request whose image
// parts do not match the counts fails closed.
[[nodiscard]] std::optional<std::string> render_qwen_text_prompt(
    const std::vector<ChatMessage>& messages, std::span<const std::size_t> image_token_counts = {});

}  // namespace secure_frontend

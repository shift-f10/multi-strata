#pragma once

#include "secure_frontend/chat_schema.hpp"

#include <optional>
#include <string>
#include <vector>

namespace secure_frontend {

// Renders the deliberately fixed, text-only GLM-5.3 prompt profile:
//
//   [gMASK]<sop><|system|>{system}<|user|>{user}<|assistant|>{assistant}<|user|>{user}<|assistant|><think>
//
// The system message is optional, but if supplied it must be first and occur
// once.  Remaining messages alternate user/assistant and must end in user.
// User text may not contain any GLM framing literal or control byte, so it
// cannot manufacture a new model turn.  This is a narrow local profile based
// on the documented LightTransport GLM fixture format, not a general GLM
// template interpreter and not compatibility with arbitrary tokenizer assets.
[[nodiscard]] std::optional<std::string> render_glm53_text_prompt(
    const std::vector<ChatMessage>& messages);

}  // namespace secure_frontend

#include "secure_frontend/chat_generation_plan.hpp"

#include "secure_frontend/qwen_prompt_renderer.hpp"
#include "secure_frontend/glm_prompt_renderer.hpp"

#include <utility>

namespace secure_frontend {
namespace {

constexpr std::size_t kDefaultMaxTokens = 256U;

ChatGenerationPlanError error(const ChatGenerationPlanErrorCode code,
                              const char* const message) {
  return ChatGenerationPlanError{code, message};
}

}  // namespace

ChatGenerationPlanResult make_qwen_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    const std::size_t maximum_prompt_tokens) {
  if (request.model.empty() || request.messages.empty() || maximum_prompt_tokens == 0U ||
      (request.max_tokens.has_value() && *request.max_tokens == 0U)) {
    return error(ChatGenerationPlanErrorCode::invalid_request,
                 "chat generation request is outside native serving limits");
  }

  const auto prompt = render_qwen_text_prompt(request.messages);
  if (!prompt) {
    return error(ChatGenerationPlanErrorCode::prompt_render_failed,
                 "chat messages cannot be represented by the fixed prompt format");
  }

  // The renderer alone owns these two fixed control markers.  User content
  // was rejected by the renderer before this narrow encoder is reached.
  const auto encoded = encode_qwen_chatml_prompt(tokenizer, *prompt);
  const auto* token_ids = std::get_if<std::vector<std::size_t>>(&encoded);
  if (token_ids == nullptr) {
    return error(ChatGenerationPlanErrorCode::tokenization_failed,
                 "rendered chat prompt cannot be encoded by the local tokenizer pack");
  }
  if (token_ids->empty() || token_ids->size() > maximum_prompt_tokens) {
    return error(ChatGenerationPlanErrorCode::prompt_too_large,
                 "encoded chat prompt exceeds native serving limits");
  }

  return ChatGenerationPlan{request.model, *token_ids,
                            request.max_tokens.value_or(kDefaultMaxTokens)};
}

ChatGenerationPlanResult make_glm53_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    const std::size_t maximum_prompt_tokens) {
  if (request.model.empty() || request.messages.empty() || maximum_prompt_tokens == 0U ||
      (request.max_tokens.has_value() && *request.max_tokens == 0U)) {
    return error(ChatGenerationPlanErrorCode::invalid_request,
                 "chat generation request is outside native serving limits");
  }
  const auto prompt = render_glm53_text_prompt(request.messages);
  if (!prompt) return error(ChatGenerationPlanErrorCode::prompt_render_failed,
                            "chat messages cannot be represented by the fixed GLM profile");
  const auto encoded = encode_glm53_prompt(tokenizer, *prompt);
  const auto* token_ids = std::get_if<std::vector<std::size_t>>(&encoded);
  if (token_ids == nullptr) return error(ChatGenerationPlanErrorCode::tokenization_failed,
                                          "rendered GLM prompt cannot be encoded by the local tokenizer pack");
  if (token_ids->empty() || token_ids->size() > maximum_prompt_tokens) {
    return error(ChatGenerationPlanErrorCode::prompt_too_large,
                 "encoded chat prompt exceeds native serving limits");
  }
  return ChatGenerationPlan{request.model, *token_ids,
                            request.max_tokens.value_or(kDefaultMaxTokens)};
}

}  // namespace secure_frontend

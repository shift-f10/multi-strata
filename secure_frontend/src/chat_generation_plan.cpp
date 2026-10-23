#include "secure_frontend/chat_generation_plan.hpp"

#include "secure_frontend/qwen_prompt_renderer.hpp"
#include "secure_frontend/glm_prompt_renderer.hpp"
#include "secure_frontend/gemma4_prompt_renderer.hpp"

#include <utility>

namespace secure_frontend {
namespace {

ChatGenerationPlanError error(const ChatGenerationPlanErrorCode code,
                              const char* const message) {
  return ChatGenerationPlanError{code, message};
}

// SP5 M1 Task 4 (parity row `sampling`): the plan's sampling is the request's
// own fields first, with unset entries filled from the defaults.sampling.*
// config rows.  A request field always wins; an unset config row stays unset
// so the engine keeps its own default.
SamplingParams merge_sampling(const SamplingParams& request, const SamplingDefaults& defaults) {
  SamplingParams out = request;
  const auto fill = [](std::optional<double>& field, const std::optional<double>& fallback) {
    if (!field.has_value()) field = fallback;
  };
  fill(out.temperature, defaults.temperature);
  fill(out.top_p, defaults.top_p);
  fill(out.min_p, defaults.min_p);
  fill(out.presence_penalty, defaults.presence_penalty);
  fill(out.repetition_penalty, defaults.repetition_penalty);
  fill(out.frequency_penalty, defaults.frequency_penalty);
  const auto fill_int = [](std::optional<std::int64_t>& field, const std::optional<std::int64_t>& fallback) {
    if (!field.has_value()) field = fallback;
  };
  fill_int(out.top_k, defaults.top_k);
  fill_int(out.penalty_last_n, defaults.penalty_last_n);
  // Config seed rows are validated positive and 32-bit capped (C-1), so the
  // widening cast to the wire's unsigned form is exact.
  if (!out.seed.has_value() && defaults.seed.has_value()) out.seed = static_cast<std::uint64_t>(*defaults.seed);
  return out;
}

// SP5 M1 Task 12: the request's image parts, counted in render order (messages
// outer, parts inner) — the same order the renderer consumes the counts in.
std::size_t count_image_parts(const ChatCompletionRequest& request) {
  std::size_t images = 0U;
  for (const auto& message : request.messages) {
    for (const auto& part : message.parts) {
      if (!part.image_data_url.empty()) ++images;
    }
  }
  return images;
}

}  // namespace

ChatGenerationPlanResult make_qwen_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    const std::size_t maximum_prompt_tokens, const std::size_t default_max_tokens,
    const SamplingDefaults& defaults, const std::span<const std::size_t> image_token_counts,
    const bool thinking, const std::optional<QwenEffortPlacement> effort) {
  if (request.model.empty() || request.messages.empty() || maximum_prompt_tokens == 0U ||
      (request.max_tokens.has_value() && *request.max_tokens == 0U)) {
    return error(ChatGenerationPlanErrorCode::invalid_request,
                 "chat generation request is outside native serving limits");
  }
  // Ruling T12-f: every image part needs exactly one encoder answer, and no answer may
  // lack an image part — a mismatch is a route wiring bug, closed here fail-closed.
  if (count_image_parts(request) != image_token_counts.size()) {
    return error(ChatGenerationPlanErrorCode::invalid_request,
                 "image answers do not match the request's image parts");
  }

  // Issue 19: a Qwen3 pack's think markers select the template's reasoning tail; a pack
  // without them keeps the plain prompt (the tags then fail closed in output as before).
  const auto think_tokens = find_qwen_think_tokens(tokenizer);
  const QwenThinking tail = !think_tokens.has_value() ? QwenThinking::absent : thinking ? QwenThinking::on : QwenThinking::off;
  const auto prompt = render_qwen_text_prompt(request.messages, image_token_counts, tail, effort);
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

  return ChatGenerationPlan{request.model, *token_ids, request.max_tokens.value_or(default_max_tokens),
                            merge_sampling(request.sampling, defaults), think_tokens, tail == QwenThinking::on,
                            find_qwen_end_of_turn_tokens(tokenizer), std::nullopt};
}

ChatGenerationPlanResult make_glm53_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    const std::size_t maximum_prompt_tokens, const std::size_t default_max_tokens,
    const SamplingDefaults& defaults, const std::span<const std::size_t> image_token_counts) {
  if (request.model.empty() || request.messages.empty() || maximum_prompt_tokens == 0U ||
      (request.max_tokens.has_value() && *request.max_tokens == 0U)) {
    return error(ChatGenerationPlanErrorCode::invalid_request,
                 "chat generation request is outside native serving limits");
  }
  // The glm53 profile never sees images (Task 11's manifest rules refuse launch.mmproj,
  // and the schema gate follows the composed capability): any image part or answer
  // closes the plan.
  if (count_image_parts(request) != 0U || !image_token_counts.empty()) {
    return error(ChatGenerationPlanErrorCode::invalid_request,
                 "the GLM profile cannot serve image parts");
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
  return ChatGenerationPlan{request.model, *token_ids, request.max_tokens.value_or(default_max_tokens),
                            merge_sampling(request.sampling, defaults), std::nullopt, false,
                            std::vector<std::size_t>{}, std::nullopt};
}

ChatGenerationPlanResult make_gemma4_chat_generation_plan(const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
                                                          const std::size_t maximum_prompt_tokens,
                                                          const std::size_t default_max_tokens, const SamplingDefaults& defaults,
                                                          const bool thinking) {
  if (request.model.empty() || request.messages.empty() || maximum_prompt_tokens == 0U ||
      (request.max_tokens.has_value() && *request.max_tokens == 0U)) {
    return error(ChatGenerationPlanErrorCode::invalid_request,
                 "chat generation request is outside native serving limits");
  }
  // Gemma 4 plan 1 is text only (vision_capable false, Task 10): an image part closes the plan.
  if (count_image_parts(request) != 0U) {
    return error(ChatGenerationPlanErrorCode::invalid_request, "the Gemma 4 profile cannot serve image parts");
  }
  // The pack must be Gemma's (spm_bpe, every marker exactly once with its GGUF type) before
  // anything is rendered for it.
  const auto markers = find_gemma4_markers(tokenizer);
  if (!markers.has_value()) {
    return error(ChatGenerationPlanErrorCode::tokenization_failed,
                 "the local tokenizer pack does not carry the Gemma 4 markers");
  }
  const auto prompt = render_gemma4_text_prompt(request.messages, thinking);
  if (!prompt) {
    return error(ChatGenerationPlanErrorCode::prompt_render_failed,
                 "chat messages cannot be represented by the fixed Gemma 4 template");
  }
  const auto encoded = encode_gemma4_prompt(tokenizer, *prompt);
  const auto* token_ids = std::get_if<std::vector<std::size_t>>(&encoded);
  if (token_ids == nullptr) {
    return error(ChatGenerationPlanErrorCode::tokenization_failed,
                 "rendered Gemma 4 prompt cannot be encoded by the local tokenizer pack");
  }
  if (token_ids->empty() || token_ids->size() > maximum_prompt_tokens) {
    return error(ChatGenerationPlanErrorCode::prompt_too_large,
                 "encoded chat prompt exceeds native serving limits");
  }
  // The reasoning split is the thought channel in both modes. The reply never starts inside it:
  // thinking off closed it in the prompt, and thinking on leaves the model to open it. Task 9: the
  // channel's name line must be "thought", and <turn|> and <eos> end the reply (both are CONTROL
  // tokens the markers check already found exactly once).
  auto stop_tokens = find_gemma4_end_of_turn_tokens(tokenizer);
  if (stop_tokens.size() != 2U) {
    return error(ChatGenerationPlanErrorCode::tokenization_failed,
                 "the local tokenizer pack does not carry the Gemma 4 markers");
  }
  return ChatGenerationPlan{request.model, *token_ids, request.max_tokens.value_or(default_max_tokens),
                            merge_sampling(request.sampling, defaults), ThinkTokens{markers->channel_open, markers->channel_close},
                            false, std::move(stop_tokens), std::string{"thought"}};
}

}  // namespace secure_frontend

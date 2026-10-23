#pragma once

#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/config_defaults.hpp"
#include "secure_frontend/qwen_prompt_renderer.hpp"
#include "secure_frontend/sampling_params.hpp"
#include "secure_frontend/tokenizer_pack.hpp"

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace secure_frontend {

struct SamplingDefaults;  // frontend_config.hpp: the defaults.sampling.* rows

// The only prompt format currently supported by the secure native serving
// path.  It is deliberately explicit: selecting a tokenizer pack alone must
// never cause an unreviewed model-provided template to execute.
struct ChatGenerationPlan final {
  std::string model;
  std::vector<std::size_t> prompt_token_ids;
  std::size_t max_tokens;
  SamplingParams sampling;  // SP5 M1 Task 4: config defaults, request fields win
  // The reasoning split for the reply: the pack's <think>/</think> ids (nullopt: the pack
  // has none, the plain prompt) and whether the prompt left a think block open, so the
  // reply begins as reasoning (upstream OutputParser(thinking=...), serve/frontend.py:884).
  std::optional<ThinkTokens> think_tokens{};
  bool starts_in_reasoning{false};
  // Issue 26: the end-of-turn ids that end the reply as stop (find_qwen_end_of_turn_tokens).
  std::vector<std::size_t> stop_tokens{};
};

enum class ChatGenerationPlanErrorCode {
  invalid_request,
  prompt_render_failed,
  tokenization_failed,
  prompt_too_large,
};

struct ChatGenerationPlanError final {
  ChatGenerationPlanErrorCode code;
  std::string message;
};

using ChatGenerationPlanResult = std::variant<ChatGenerationPlan, ChatGenerationPlanError>;

// Converts the already schema-validated request into a fixed Qwen ChatML prompt and
// then local token IDs.  This function never loads files, executes templates, starts
// the engine, or contacts the network.  It rejects zero output tokens and prompt sizes
// beyond the supplied fixed limit.
// SP5 M1 Task 12 (Ruling T12-f): image parts (schema-gated by the composed vision
// capability) render the template's per-image marker runs; image_token_counts carries
// the encoder's per-image token counts IN PART ORDER and must match the request's
// image parts exactly — a mismatch is an internal wiring bug, closed here.
// thinking (reasoning.effort; upstream's default is on, serve/frontend.py:134-148): when
// the pack carries <think>/</think>, true opens the template's think block and false
// writes it closed; a pack without them renders the plain prompt either way.
// effort (session log step 16): the template's reasoning sentence and where it sits
// (render_qwen_text_prompt); the route always passes one, nullopt keeps the fixed format.
[[nodiscard]] ChatGenerationPlanResult make_qwen_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    std::size_t maximum_prompt_tokens = static_cast<std::size_t>(config_defaults::kChatMaxPromptTokens),
    std::size_t default_max_tokens = static_cast<std::size_t>(config_defaults::kChatDefaultMaxTokens),
    const SamplingDefaults& defaults = {}, std::span<const std::size_t> image_token_counts = {},
    bool thinking = true, std::optional<QwenEffortPlacement> effort = std::nullopt);

// Converts a schema-validated text request using only the fixed GLM-5.3
// profile. It neither interprets a model template nor contacts the network.
// Images never reach this profile (the manifest rules refuse launch.mmproj for
// glm53, Task 11): an image part closes the plan as invalid_request.
[[nodiscard]] ChatGenerationPlanResult make_glm53_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    std::size_t maximum_prompt_tokens = static_cast<std::size_t>(config_defaults::kChatMaxPromptTokens),
    std::size_t default_max_tokens = static_cast<std::size_t>(config_defaults::kChatDefaultMaxTokens),
    const SamplingDefaults& defaults = {}, std::span<const std::size_t> image_token_counts = {});

// Gemma 4 plan 1 (spec §2.5, §6.3-§6.5): a schema-validated text request through the fixed
// Gemma 4 template. thinking writes <|think|> in the system turn; off closes the thought
// channel in the generation prompt. Gemma 4 plan 1 Task 3: a stub refusing every request
// (invalid_request) until Task 8 writes the renderer.
[[nodiscard]] ChatGenerationPlanResult make_gemma4_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    std::size_t maximum_prompt_tokens = static_cast<std::size_t>(config_defaults::kChatMaxPromptTokens),
    std::size_t default_max_tokens = static_cast<std::size_t>(config_defaults::kChatDefaultMaxTokens),
    const SamplingDefaults& defaults = {}, bool thinking = false);

}  // namespace secure_frontend

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
  // Gemma 4 plan 1 Task 9: the reasoning channel's name line (GenerationRunLimits::channel_name),
  // "thought" for gemma4; nullopt for qwen and glm53.
  std::optional<std::string> channel_name{};
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
// Gemma 4 template (render_gemma4_text_prompt, encode_gemma4_prompt). thinking writes <|think|>
// in the system turn; off closes the thought channel in the generation prompt. The pack must
// carry the Gemma 4 markers (find_gemma4_markers), else tokenization_failed; an image part is
// invalid_request (text only). The reasoning split is the thought channel, <|channel> and
// <channel|>, and the reply never starts inside it (starts_in_reasoning false in both modes).
[[nodiscard]] ChatGenerationPlanResult make_gemma4_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    std::size_t maximum_prompt_tokens = static_cast<std::size_t>(config_defaults::kChatMaxPromptTokens),
    std::size_t default_max_tokens = static_cast<std::size_t>(config_defaults::kChatDefaultMaxTokens),
    const SamplingDefaults& defaults = {}, bool thinking = false);

// Unified-engine design §3.2/§3.4: PLACEHOLDER chat templates for the merged-engine families
// deepseek (DeepSeek-V4.1-Flash) and raon1 (Raon-1-mini). Their real prompt templates and control
// markers are not yet pinned (they arrive with the box bring-up, §1.3); until then each renders a
// minimal, fail-closed, text-only role transcript encoded as ordinary byte_bpe text, with no
// reasoning split. An image part is invalid_request (text only). The profile is thereby wired end
// to end over the `unified` protocol flavor without claiming a format we have not reviewed.
// TODO(unified-engine, plan 4): replace with the reviewed DeepSeek / Raon templates and markers.
[[nodiscard]] ChatGenerationPlanResult make_deepseek_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    std::size_t maximum_prompt_tokens = static_cast<std::size_t>(config_defaults::kChatMaxPromptTokens),
    std::size_t default_max_tokens = static_cast<std::size_t>(config_defaults::kChatDefaultMaxTokens),
    const SamplingDefaults& defaults = {});
[[nodiscard]] ChatGenerationPlanResult make_raon1_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    std::size_t maximum_prompt_tokens = static_cast<std::size_t>(config_defaults::kChatMaxPromptTokens),
    std::size_t default_max_tokens = static_cast<std::size_t>(config_defaults::kChatDefaultMaxTokens),
    const SamplingDefaults& defaults = {});

}  // namespace secure_frontend

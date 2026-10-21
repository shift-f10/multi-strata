#pragma once

#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/config_defaults.hpp"
#include "secure_frontend/sampling_params.hpp"
#include "secure_frontend/tokenizer_pack.hpp"

#include <cstddef>
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

// Converts the already schema-validated, text-only request into a fixed Qwen
// ChatML prompt and then local token IDs.  This function never loads files,
// executes templates, starts the engine, or contacts the network.  It rejects
// zero output tokens and prompt sizes beyond the supplied fixed limit.
[[nodiscard]] ChatGenerationPlanResult make_qwen_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    std::size_t maximum_prompt_tokens = static_cast<std::size_t>(config_defaults::kChatMaxPromptTokens),
    std::size_t default_max_tokens = static_cast<std::size_t>(config_defaults::kChatDefaultMaxTokens),
    const SamplingDefaults& defaults = {});

// Converts a schema-validated text request using only the fixed GLM-5.3
// profile. It neither interprets a model template nor contacts the network.
[[nodiscard]] ChatGenerationPlanResult make_glm53_chat_generation_plan(
    const ChatCompletionRequest& request, const TokenizerPack& tokenizer,
    std::size_t maximum_prompt_tokens = static_cast<std::size_t>(config_defaults::kChatMaxPromptTokens),
    std::size_t default_max_tokens = static_cast<std::size_t>(config_defaults::kChatDefaultMaxTokens),
    const SamplingDefaults& defaults = {});

}  // namespace secure_frontend

#include "secure_frontend/chat_execution.hpp"

#include <limits>
#include <utility>
#include <vector>

namespace secure_frontend {
namespace {

ChatExecutionOutcome error(const ChatExecutionErrorCode code, const char* const message) {
  return ChatExecutionError{code, message};
}

}  // namespace

ChatExecutionService::ChatExecutionService(EngineProtocolClient& protocol,
                                           const ChatExecutionLimits limits,
                                           const NativeChatProfile profile)
    : protocol_(protocol), limits_(limits), profile_(profile) {}

ChatExecutionOutcome ChatExecutionService::execute(const ChatCompletionRequest& request,
                                                   const TokenizerPack& tokenizer) {
  if (limits_.maximum_prompt_tokens == 0U || limits_.maximum_output_tokens == 0U ||
      limits_.maximum_output_tokens > std::numeric_limits<std::uint32_t>::max() ||
      limits_.ready_timeout.count() < 0 || limits_.generation_timeout.count() < 0 ||
      limits_.stop_drain_timeout.count() < 0 ||
      protocol_.closed()) {
    return error(ChatExecutionErrorCode::invalid_request,
                 "native chat execution limits or engine state are invalid");
  }

  const auto plan_result = profile_ == NativeChatProfile::qwen
      ? make_qwen_chat_generation_plan(request, tokenizer, limits_.maximum_prompt_tokens)
      : make_glm53_chat_generation_plan(request, tokenizer, limits_.maximum_prompt_tokens);
  const auto* plan = std::get_if<ChatGenerationPlan>(&plan_result);
  if (plan == nullptr) {
    return error(ChatExecutionErrorCode::planning_failed,
                 "chat request cannot be represented by the native serving profile");
  }
  if (plan->max_tokens == 0U || plan->max_tokens > limits_.maximum_output_tokens ||
      plan->max_tokens > std::numeric_limits<std::uint32_t>::max()) {
    return error(ChatExecutionErrorCode::invalid_request,
                 "requested output exceeds native serving limits");
  }

  if (!received_ready_) {
    EngineReady ready{};
    if (protocol_.ready()) {
      return error(ChatExecutionErrorCode::engine_protocol_failed,
                   "engine protocol readiness state is inconsistent");
    }
    if (protocol_.await_ready(limits_.ready_timeout, ready).has_value()) {
      return error(ChatExecutionErrorCode::engine_protocol_failed,
                   "local engine did not become ready");
    }
    engine_context_tokens_ = ready.max_context_tokens;
    received_ready_ = true;
  }

  if (!protocol_.ready() || engine_context_tokens_ == 0U ||
      plan->prompt_token_ids.size() >= engine_context_tokens_ ||
      plan->max_tokens > engine_context_tokens_ - plan->prompt_token_ids.size()) {
    return error(ChatExecutionErrorCode::context_limit_exceeded,
                 "request exceeds the local engine context limit");
  }

  std::vector<std::uint32_t> prompt_ids;
  prompt_ids.reserve(plan->prompt_token_ids.size());
  for (const std::size_t token_id : plan->prompt_token_ids) {
    if (token_id > std::numeric_limits<std::uint32_t>::max()) {
      return error(ChatExecutionErrorCode::planning_failed,
                   "local tokenizer produced an unsupported token identifier");
    }
    prompt_ids.push_back(static_cast<std::uint32_t>(token_id));
  }

  if (protocol_.begin_generation(static_cast<std::uint32_t>(plan->max_tokens), prompt_ids)
          .has_value()) {
    return error(ChatExecutionErrorCode::engine_protocol_failed,
                 "local engine rejected the generation request");
  }

  EngineGeneration generation{};
  if (const auto generation_error = protocol_.read_generation(limits_.generation_timeout, generation);
      generation_error.has_value()) {
    if (generation_error->code != EngineProtocolErrorCode::timeout) {
      return error(ChatExecutionErrorCode::engine_protocol_failed,
                   "local engine generation failed");
    }
    // The generation is still active. Stop it and drain to DONE so the
    // engine is idle for the next request instead of wedged forever.
    if (protocol_.stop().has_value()) {
      protocol_.abandon();
      return error(ChatExecutionErrorCode::engine_protocol_failed, "engine could not be stopped");
    }
    EngineGeneration drained{};
    if (const auto drain_error = protocol_.read_generation(limits_.stop_drain_timeout, drained);
        drain_error.has_value()) {
      // Terminal failures already closed the protocol. A second timeout
      // means the engine ignores STOP; it must not receive further commands.
      if (drain_error->code == EngineProtocolErrorCode::timeout) protocol_.abandon();
      return error(ChatExecutionErrorCode::engine_protocol_failed, "engine did not drain after STOP");
    }
    return error(ChatExecutionErrorCode::generation_timed_out, "generation exceeded the time limit");
  }
  if (generation.token_ids.size() > plan->max_tokens) {
    return error(ChatExecutionErrorCode::engine_protocol_failed,
                 "local engine exceeded the requested output limit");
  }

  std::vector<std::size_t> generated_ids;
  generated_ids.reserve(generation.token_ids.size());
  for (const std::uint32_t token_id : generation.token_ids) {
    generated_ids.push_back(static_cast<std::size_t>(token_id));
  }
  const auto decoded = decode_token_ids(tokenizer, generated_ids);
  const auto* text = std::get_if<std::string>(&decoded);
  if (text == nullptr) {
    return error(ChatExecutionErrorCode::output_decode_failed,
                 "local engine output cannot be safely decoded");
  }
  return ChatExecutionResult{*text, generated_ids.size()};
}

EngineHealth ChatExecutionService::health() const noexcept {
  if (protocol_.closed()) return EngineHealth::failed;
  if (!received_ready_) return EngineHealth::starting;
  if (protocol_.generating()) return EngineHealth::generating;
  return EngineHealth::ready;
}

}  // namespace secure_frontend

#include "secure_frontend/chat_execution.hpp"

#include "secure_frontend/api_constants.hpp"
#include "secure_frontend/deadline.hpp"

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

namespace secure_frontend {
namespace {

ChatExecutionOutcome error(const ChatExecutionErrorCode code, const char* const message) {
  return ChatExecutionError{code, message};
}

}  // namespace

std::optional<std::size_t> resolve_max_tokens(const std::optional<std::size_t> requested, const std::size_t prompt_tokens,
                                              const std::size_t context_tokens, const std::size_t max_completion_tokens,
                                              const std::size_t default_max_tokens) noexcept {
  // The engine's rule (generate.cpp): n + max_new + kContextMarginTokens <= ctx.
  constexpr std::size_t kMargin = api_constants::kContextMarginTokens;
  std::size_t room = max_completion_tokens;
  if (context_tokens != 0U) {
    if (prompt_tokens >= context_tokens || context_tokens - prompt_tokens <= kMargin) return std::nullopt;
    room = context_tokens - prompt_tokens - kMargin;
  }
  const std::size_t base = requested.has_value() ? *requested
                           : (default_max_tokens == 0U ? max_completion_tokens : default_max_tokens);
  const std::size_t resolved = std::min({base, max_completion_tokens, room});
  if (resolved == 0U) return std::nullopt;
  return resolved;
}

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
      ? make_qwen_chat_generation_plan(request, tokenizer, limits_.maximum_prompt_tokens, limits_.default_max_tokens)
      : make_glm53_chat_generation_plan(request, tokenizer, limits_.maximum_prompt_tokens, limits_.default_max_tokens);
  const auto* plan = std::get_if<ChatGenerationPlan>(&plan_result);
  if (plan == nullptr) {
    return error(ChatExecutionErrorCode::planning_failed,
                 "chat request cannot be represented by the native serving profile");
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

  // B1/B2 (spec §5.4): an omitted max_tokens (plan value 0) is auto; a value
  // above the local output bound or the engine's context rule
  // (n + max_new + 8 <= --max-context) is clamped; only a prompt that leaves no
  // room is rejected. The result is at most maximum_output_tokens (<= uint32).
  const auto budget = resolve_max_tokens(plan->max_tokens == 0U ? std::nullopt : std::optional<std::size_t>{plan->max_tokens},
                                         plan->prompt_token_ids.size(), engine_context_tokens_,
                                         limits_.maximum_output_tokens, 0U);
  if (!protocol_.ready() || engine_context_tokens_ == 0U || !budget.has_value()) {
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

  // One request generation deadline (K1, R1): it bounds the GEN write overall
  // and then the read to DONE, which gets only what the write left.
  const auto generation_deadline = deadline_after(limits_.generation_timeout);
  if (protocol_.begin_generation(static_cast<std::uint32_t>(*budget), prompt_ids, generation_deadline)
          .has_value()) {
    return error(ChatExecutionErrorCode::engine_protocol_failed,
                 "local engine rejected the generation request");
  }

  EngineGeneration generation{};
  if (const auto generation_error = protocol_.read_generation(remaining_until(generation_deadline), generation);
      generation_error.has_value()) {
    if (generation_error->code != EngineProtocolErrorCode::timeout) {
      return error(ChatExecutionErrorCode::engine_protocol_failed,
                   "local engine generation failed");
    }
    // The generation is still active. Stop it and drain to DONE so the
    // engine is idle for the next request instead of wedged forever.
    if (protocol_.stop(EngineStopCause::generation_timeout).has_value()) {
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
  if (generation.token_ids.size() > *budget) {
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

void ChatExecutionService::adopt_ready(const EngineReady& ready) noexcept {
  engine_context_tokens_ = ready.max_context_tokens;
  received_ready_ = true;
}

}  // namespace secure_frontend

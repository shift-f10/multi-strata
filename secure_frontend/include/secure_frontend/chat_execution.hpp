#pragma once

#include "secure_frontend/chat_generation_plan.hpp"
#include "secure_frontend/config_defaults.hpp"
#include "secure_frontend/engine_protocol_client.hpp"

#include <chrono>
#include <cstddef>
#include <string>
#include <variant>

namespace secure_frontend {

// An explicit startup-selected prompt/tokenizer contract.  This is not
// inferred from a model name or tokenizer asset: that would allow a model
// artifact to select behavior in the HTTP-serving process.
enum class NativeChatProfile {
  qwen,
  glm53,
};

// Bounds for the native, non-streaming chat path, derived from FrontendConfig by
// chat_execution_limits(). Separate from engine-protocol bounds: both layers
// must agree before an engine command is issued.
struct ChatExecutionLimits final {
  std::size_t maximum_prompt_tokens{static_cast<std::size_t>(config_defaults::kChatMaxPromptTokens)};
  std::size_t maximum_output_tokens{static_cast<std::size_t>(config_defaults::kChatMaxCompletionTokens)};
  std::size_t default_max_tokens{static_cast<std::size_t>(config_defaults::kChatDefaultMaxTokens)};
  std::chrono::milliseconds ready_timeout{std::chrono::seconds(config_defaults::kEngineReadyTimeoutS)};
  std::chrono::milliseconds generation_timeout{std::chrono::seconds(config_defaults::kEngineGenerationTimeoutS)};
  // Total budget for draining to DONE after STOP once generation_timeout expires.
  std::chrono::milliseconds stop_drain_timeout{std::chrono::seconds(config_defaults::kEngineStopDrainTimeoutS)};
};

enum class ChatExecutionErrorCode {
  invalid_request,
  planning_failed,
  context_limit_exceeded,
  engine_protocol_failed,
  output_decode_failed,
  generation_timed_out,
};

struct ChatExecutionError final {
  ChatExecutionErrorCode code;
  std::string message;
};

struct ChatExecutionResult final {
  std::string text;
  std::size_t generated_tokens;
};

using ChatExecutionOutcome = std::variant<ChatExecutionResult, ChatExecutionError>;

// Engine protocol state for health reporting. Carries no engine or prompt data.
// starting: READY not yet received; ready: protocol idle; generating: a
// request is in flight; failed: the protocol is closed or failed.
enum class EngineHealth { starting, ready, generating, failed };

// Stateful adapter for one private Strata --serve connection. It accepts a
// schema-validated request, uses the startup-selected fixed prompt renderer
// and offline tokenizer, and decodes only ordinary generated token IDs. It does not load
// files, spawn processes, expose streaming data, or contact a network.
//
// The first execution waits for READY. Later executions reuse a clean idle
// protocol client. Any engine protocol failure is returned without reflecting
// engine or prompt data to a network caller.
class ChatExecutionService final {
 public:
  explicit ChatExecutionService(EngineProtocolClient& protocol,
                                ChatExecutionLimits limits = {},
                                NativeChatProfile profile = NativeChatProfile::qwen);

  [[nodiscard]] ChatExecutionOutcome execute(const ChatCompletionRequest& request,
                                              const TokenizerPack& tokenizer);

  [[nodiscard]] EngineHealth health() const noexcept;
  // Eager READY (SP2): the supervisor consumed READY on `protocol` before the
  // first request; execute() then never waits for it. Call once, before execute().
  void adopt_ready(const EngineReady& ready) noexcept;

 private:
  EngineProtocolClient& protocol_;
  ChatExecutionLimits limits_;
  NativeChatProfile profile_;
  bool received_ready_{false};
  std::size_t engine_context_tokens_{0U};
};

}  // namespace secure_frontend

#pragma once

#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/generation_gate.hpp"
#include "secure_frontend/request_router.hpp"
#include "secure_frontend/tokenizer_pack.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace secure_frontend {

struct ChatRouteConfig final {
  ChatSchemaLimits schema;
  std::string model_id;
  NativeChatProfile profile;
  std::size_t max_prompt_tokens;
  std::size_t max_completion_tokens;
  std::size_t default_max_tokens;   // 0 = auto (B1)
  SamplingDefaults sampling_default;  // SP5 M1 Task 4: defaults.sampling.* (request fields win)
  bool fit_max_tokens = true;         // SP5 M1 Task 5: engine.fit_max_tokens (false: over-room 400, pin :4536)
  // SP5 M1 Task 8: engine.min_tokens / engine.max_tokens — added frontend bounds on the
  // request output budget (0: unset; Ruling T8-e) — and model.aliases: extra exact model
  // names the chat route answers to (set_aliases :3764-3777; §4: never empty or partial).
  std::size_t minimum_output_tokens{0};
  std::size_t maximum_output_tokens{0};
  std::vector<std::string> model_aliases{};
  std::chrono::milliseconds queue_timeout;
  std::chrono::milliseconds write_stall;
  std::chrono::milliseconds response_write_deadline;
  std::chrono::milliseconds stream_keepalive;
};

[[nodiscard]] std::optional<std::string> make_completion_id();

// POST /v1/chat/completions, non-streaming (spec §2.2 P4-P6, §2.5, §3.1, §3.5).
class ChatRoute final {
 public:
  ChatRoute(ChatRouteConfig config, SupervisorPort& port, GenerationGate& gate, const TokenizerPack& tokenizer);
  [[nodiscard]] RouteResult handle(std::string_view body, const RequestContext& context);

 private:
  [[nodiscard]] HttpResponse refusal(GateRefusal refusal);
  [[nodiscard]] HttpResponse engine_unavailable();
  [[nodiscard]] RouteResult stream_response(std::optional<Lease>& lease, const std::vector<std::uint32_t>& prompt_ids,
                                            std::size_t max_tokens, const SamplingParams& sampling, bool include_usage,
                                            const RequestContext& context);
  ChatRouteConfig config_;
  SupervisorPort& port_;
  GenerationGate& gate_;
  const TokenizerPack& tokenizer_;
  std::atomic<std::size_t> last_context_{0};   // last READY context seen through a lease; 0 = unknown
};

}  // namespace secure_frontend

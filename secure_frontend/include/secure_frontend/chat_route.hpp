#pragma once

#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/generation_gate.hpp"
#include "secure_frontend/image_payload.hpp"
#include "secure_frontend/qwen_prompt_renderer.hpp"
#include "secure_frontend/request_router.hpp"
#include "secure_frontend/serve_monitor.hpp"
#include "secure_frontend/tokenizer_pack.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
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
  // reasoning.effort for the qwen profile: false only for "none" (the template's closed
  // think block); unset, low, medium and high think (upstream frontend.py:134-148).
  bool qwen_thinking = true;
  // Session log step 16: the level a thinking request without its own reasoning_effort gets
  // (reasoning.effort; unset is the template's default, high), and reasoning.effort_position
  // "end" (the template's sentence for a non-default level right before the answer).
  QwenEffort qwen_effort = QwenEffort::high;
  bool effort_at_end = false;
  // Gemma 4 plan 1 Task 10 (spec §6.6, D10): whether a gemma4 request that names no
  // reasoning_effort thinks (reasoning.effort low/medium/high); unset or none: off.
  bool gemma4_thinking_default = false;
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
  // SP5 M1 Task 12 (C-9, Ruling T12-b): the encoder path for the managed model that
  // reads images; nullptr whenever the schema's vision_capable gate is closed (the two
  // are one decision made by secure_server_main), so a content array never reaches a
  // route without a service.
  VisionService* vision{nullptr};
  // listener.monitor (session log step 16): told about each generation; null when off.
  ServeMonitor* monitor{nullptr};
};

[[nodiscard]] std::optional<std::string> make_completion_id();

// Gemma 4 plan 1 Task 10 (spec §6.6, D10): a gemma4 request thinks when its reasoning_effort
// is low, medium or high, not when it is none; a request that names none takes the server's
// default (gemma4_thinking_default: reasoning.effort, unset = off).
[[nodiscard]] bool gemma4_request_thinks(const std::optional<std::string>& reasoning_effort, bool thinking_default);

// The route's plan for a request, chosen by an exhaustive switch on the profile (Gemma 4 plan 1
// Tasks 3 and 10): qwen renders ChatML (images allowed, thinking and its effort sentence);
// glm53 the GLM profile; gemma4 the Gemma 4 template (text only: any image answer is
// invalid_request). `thinking` is the profile's own decision, made by the caller.
[[nodiscard]] ChatGenerationPlanResult select_chat_generation_plan(NativeChatProfile profile, const ChatCompletionRequest& request,
                                                                   const TokenizerPack& tokenizer, std::size_t maximum_prompt_tokens,
                                                                   const SamplingDefaults& defaults,
                                                                   std::span<const std::size_t> image_token_counts, bool thinking,
                                                                   QwenEffortPlacement qwen_effort);

// POST /v1/chat/completions, non-streaming (spec §2.2 P4-P6, §2.5, §3.1, §3.5).
class ChatRoute final {
 public:
  ChatRoute(ChatRouteConfig config, SupervisorPort& port, GenerationGate& gate, const TokenizerPack& tokenizer);
  [[nodiscard]] RouteResult handle(std::string_view body, const RequestContext& context);

 private:
  [[nodiscard]] HttpResponse refusal(GateRefusal refusal);
  [[nodiscard]] HttpResponse engine_unavailable();
  // SP5 M1 Task 12 (T12-i): `embeddings` non-empty begins a GENI generation; the
  // combined file it names must outlive the stream until the engine has run, so its
  // removal belongs to this closure, not the handle() cleaner. The plan supplies the
  // sampling and the reasoning split (issue 19).
  [[nodiscard]] RouteResult stream_response(std::optional<Lease>& lease, const std::vector<std::uint32_t>& prompt_ids,
                                            std::size_t max_tokens, const ChatGenerationPlan& plan, bool include_usage,
                                            const RequestContext& context, std::string embeddings = {},
                                            std::optional<std::filesystem::path> combined_file = std::nullopt);
  ChatRouteConfig config_;
  SupervisorPort& port_;
  GenerationGate& gate_;
  const TokenizerPack& tokenizer_;
  std::atomic<std::size_t> last_context_{0};   // last READY context seen through a lease; 0 = unknown
};

}  // namespace secure_frontend

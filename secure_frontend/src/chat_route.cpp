#include "secure_frontend/chat_route.hpp"

#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/chat_generation_plan.hpp"
#include "secure_frontend/chat_stream.hpp"
#include "secure_frontend/lease_hold.hpp"
#include "secure_frontend/shutdown_signal.hpp"
#include "secure_frontend/token_generator.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <variant>
#include <vector>

namespace secure_frontend {

std::optional<std::string> make_completion_id() {
  std::array<unsigned char, 16> bytes{};
  if (!fill_random(bytes.data(), bytes.size())) return std::nullopt;
  static constexpr char kHex[] = "0123456789abcdef";
  std::string id{"chatcmpl-"};
  for (const unsigned char b : bytes) { id.push_back(kHex[b >> 4U]); id.push_back(kHex[b & 0x0fU]); }
  return id;
}

ChatRoute::ChatRoute(ChatRouteConfig config, SupervisorPort& port, GenerationGate& gate, const TokenizerPack& tokenizer)
    : config_(std::move(config)), port_(port), gate_(gate), tokenizer_(tokenizer) {}

HttpResponse ChatRoute::engine_unavailable() {
  const HealthSnapshot snapshot = port_.snapshot();
  if (snapshot.state == SupervisorState::shutting_down || snapshot.state == SupervisorState::stopped) {
    return make_error_response(ApiError::server_shutting_down);
  }
  return make_error_response(ApiError::engine_unavailable, {.retry_after = engine_retry_after(snapshot.recovery)});
}

HttpResponse ChatRoute::refusal(const GateRefusal refusal) {
  switch (refusal) {
    case GateRefusal::busy:
    case GateRefusal::timeout: return make_error_response(ApiError::server_busy);
    case GateRefusal::cancelled: return HttpResponse{.status = kNoResponseStatus, .headers = {}, .body = {}, .log_code = "client_gone"};
    case GateRefusal::engine_unavailable: return engine_unavailable();
    case GateRefusal::shutting_down: return make_error_response(ApiError::server_shutting_down);
  }
  return make_error_response(ApiError::internal_error);
}

RouteResult ChatRoute::handle(const std::string_view body, const RequestContext& context) {
  // P4: schema, tokenization, budget (spec §5.4) - before any queue place is taken.
  const ChatRequestResult parsed = parse_chat_request(body, config_.schema);
  if (const auto* error = std::get_if<ChatRequestError>(&parsed)) return make_error_response(error->error, {.param = error->param});
  const ChatCompletionRequest& request = std::get<ChatCompletionRequest>(parsed);
  if (request.model != config_.model_id) return make_error_response(ApiError::model_not_found);
  const auto plan_result = config_.profile == NativeChatProfile::qwen
                               ? make_qwen_chat_generation_plan(request, tokenizer_, config_.max_prompt_tokens, 1U)
                               : make_glm53_chat_generation_plan(request, tokenizer_, config_.max_prompt_tokens, 1U);
  if (const auto* plan_error = std::get_if<ChatGenerationPlanError>(&plan_result)) {
    return make_error_response(plan_error->code == ChatGenerationPlanErrorCode::prompt_too_large ? ApiError::context_length_exceeded
                                                                                                  : ApiError::invalid_request);
  }
  const ChatGenerationPlan& plan = std::get<ChatGenerationPlan>(plan_result);
  std::vector<std::uint32_t> prompt_ids;
  prompt_ids.reserve(plan.prompt_token_ids.size());
  for (const std::size_t id : plan.prompt_token_ids) {
    if (id > std::numeric_limits<std::uint32_t>::max()) return make_error_response(ApiError::invalid_request);
    prompt_ids.push_back(static_cast<std::uint32_t>(id));
  }
  if (!resolve_max_tokens(request.max_tokens, prompt_ids.size(), last_context_.load(), config_.max_completion_tokens,
                          config_.default_max_tokens)) {
    return make_error_response(ApiError::context_length_exceeded);
  }

  // P5: the gate.
  auto admitted = gate_.admit(port_, std::chrono::steady_clock::now() + config_.queue_timeout, context.client_gone);
  if (const auto* refused = std::get_if<GateRefusal>(&admitted)) return refusal(*refused);
  std::optional<Lease> lease;
  lease.emplace(std::get<Lease>(std::move(admitted)));

  // P6 through the lease; the context rule is re-checked against this generation's READY.
  GenerationOutcome outcome = GenerationFailure::engine_unavailable;
  bool context_refused = false;
  const std::size_t context_tokens = lease->chat().context_tokens();
  last_context_ = context_tokens;
  const auto budget = resolve_max_tokens(request.max_tokens, prompt_ids.size(), context_tokens, config_.max_completion_tokens,
                                         config_.default_max_tokens);
  if (budget && request.stream) return stream_response(lease, prompt_ids, *budget, request, context);
  if (!budget) {
    context_refused = true;
  } else {
    outcome = lease->chat().run_generation(prompt_ids, {.max_tokens = *budget, .sampling = request.sampling},
                                           {.cancelled = context.client_gone, .shutting_down = context.shutting_down,
                                            .shutdown_requested = [] { return shutdown_signalled(); }},
                                           tokenizer_);
    // Ruling R-H: never report_fatal once shutdown has begun (pool flag or SP2 signal).
    const bool shutting = (context.shutting_down != nullptr && context.shutting_down->load()) || shutdown_signalled();
    if (lease->protocol().closed() && !shutting) port_.report_fatal(*lease, kill_reason_for(lease->protocol()));
  }
  lease.reset();     // SP2: generating -> ready
  gate_.release();   // only now may the next head proceed

  if (context_refused) return make_error_response(ApiError::context_length_exceeded);
  if (const auto* failure = std::get_if<GenerationFailure>(&outcome)) {
    switch (*failure) {
      case GenerationFailure::cancelled: return HttpResponse{.status = kNoResponseStatus, .headers = {}, .body = {}, .log_code = "client_gone"};
      case GenerationFailure::engine_error: return make_error_response(ApiError::engine_error);
      case GenerationFailure::engine_unavailable: return engine_unavailable();
      case GenerationFailure::decode_failed: return make_error_response(ApiError::internal_error);
      case GenerationFailure::shutting_down: return make_error_response(ApiError::server_shutting_down);
    }
  }
  const GenerationResult& result = std::get<GenerationResult>(outcome);
  const auto id = make_completion_id();
  if (!id) return make_error_response(ApiError::internal_error);
  const auto created = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  const auto rendered = render_chat_completion({.id = *id, .created = created, .model = config_.model_id, .text = result.text,
                                                .finish_reason = result.finish == FinishReason::length ? "length" : "stop",
                                                .prompt_tokens = result.prompt_tokens, .completion_tokens = result.completion_tokens},
                                               config_.schema);
  if (!rendered) return make_error_response(ApiError::internal_error);
  HttpResponse response{.status = 200, .headers = {{"Content-Type", "application/json; charset=utf-8"}}, .body = *rendered};
  if (result.timed_out) response.log_code = "generation_timeout";   // §8 log-only code; the client sees 200 length (B4)
  return response;
}

RouteResult ChatRoute::stream_response(std::optional<Lease>& lease, const std::vector<std::uint32_t>& prompt_ids, const std::size_t max_tokens,
                                       const ChatCompletionRequest& request, const RequestContext& context) {
  const std::atomic<bool>* flag = context.shutting_down;
  std::function<bool()> shutting_down = [flag] { return (flag != nullptr && flag->load()) || shutdown_signalled(); };  // R-H
  auto hold = std::make_shared<LeaseHold>(std::move(*lease), gate_, port_, shutting_down);
  lease.reset();
  auto id = make_completion_id();
  if (!id) {
    hold->end_generation();
    return make_error_response(ApiError::internal_error);
  }
  if (const auto failure = hold->lease().chat().begin(prompt_ids, {.max_tokens = max_tokens, .sampling = request.sampling})) {
    hold->end_generation();  // reports a closed protocol through the port
    return *failure == GenerationFailure::engine_error ? make_error_response(ApiError::engine_error) : engine_unavailable();
  }
  const auto created = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  SseIdentity identity{std::move(*id), static_cast<std::int64_t>(created), config_.model_id};
  ChatStreamSettings settings;
  settings.run = hold->lease().chat().drive_limits(max_tokens);
  settings.write_stall = config_.write_stall;
  settings.tail_deadline = config_.response_write_deadline;
  settings.keepalive = config_.stream_keepalive;
  settings.include_usage = request.include_usage;
  settings.prompt_tokens = prompt_ids.size();
  const TokenizerPack* tokenizer = &tokenizer_;
  return StreamHandler{[hold, identity = std::move(identity), settings, tokenizer, shutting_down](StreamSink& sink) {
    const TokenByteDecoder decoder(*tokenizer);
    const ChatStreamOutcome outcome = run_chat_stream(sink, hold->lease().protocol(), decoder, identity, settings, shutting_down,
                                                      [&hold](const GenerationRunResult&) { hold->end_generation(); });
    sink.set_log_code(outcome.log_code);
  }};
}

}  // namespace secure_frontend

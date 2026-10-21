#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/generation_run.hpp"
#include "support/test_support.hpp"
#include "support/test_tokenizer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

std::string byte_symbol(const unsigned char byte) {
  if (byte >= 33U && byte <= 126U) return std::string(1U, static_cast<char>(byte));
  unsigned int printable_before = 0U;
  for (unsigned int value = 33U; value <= 126U && value < byte; ++value) ++printable_before;
  const unsigned int code_point = 256U + static_cast<unsigned int>(byte) - printable_before;
  return {static_cast<char>(0xc0U | (code_point >> 6U)),
          static_cast<char>(0x80U | (code_point & 0x3fU))};
}

secure_frontend::TokenizerPack tokenizer_for(const std::string& text) {
  secure_frontend::TokenizerPack pack;
  std::unordered_set<std::string> seen;
  for (const unsigned char byte : text) {
    const std::string token = byte_symbol(byte);
    if (seen.insert(token).second) pack.tokens_by_id.push_back(token);
  }
  pack.token_types.assign(pack.tokens_by_id.size(), 1);
  // The fixed Qwen renderer owns these framing literals.  They must be
  // modeled as tokenizer CONTROL tokens, never as ordinary user text.
  pack.tokens_by_id.push_back("<|im_start|>");
  pack.token_types.push_back(3);
  pack.tokens_by_id.push_back("<|im_end|>");
  pack.token_types.push_back(3);
  return pack;
}

std::size_t token_id_for(const secure_frontend::TokenizerPack& pack, const std::string& token) {
  for (std::size_t index = 0; index < pack.tokens_by_id.size(); ++index) {
    if (pack.tokens_by_id[index] == token) return index;
  }
  return pack.tokens_by_id.size();
}

class FakeTransport final : public secure_frontend::EngineLineTransport {
 public:
  std::deque<secure_frontend::EngineReadResult> reads;
  std::vector<std::string> writes;
  std::vector<secure_frontend::MonotonicClock::time_point> deadlines;
  std::chrono::milliseconds delay_per_read{0};

  bool write_line(const std::string_view line, const secure_frontend::MonotonicClock::time_point deadline,
                  std::string&) override {
    writes.emplace_back(line);
    deadlines.push_back(deadline);
    return true;
  }

  secure_frontend::EngineReadResult read_line(std::chrono::milliseconds) override {
    if (delay_per_read.count() > 0) std::this_thread::sleep_for(delay_per_read);
    if (reads.empty()) return {secure_frontend::EngineReadKind::timeout, {}, {}};
    auto result = std::move(reads.front());
    reads.pop_front();
    return result;
  }
};

secure_frontend::EngineReadResult line(std::string value) {
  return {secure_frontend::EngineReadKind::line, std::move(value), {}};
}

secure_frontend::ChatCompletionRequest valid_request(const std::size_t max_tokens = 2U) {
  return {"qwen-local", {{"user", "Hi"}}, max_tokens};
}

secure_frontend::TokenizerPack glm_tokenizer_for(const std::string& text) {
  auto pack = tokenizer_for(text);
  // The Qwen control entries supplied by tokenizer_for are harmless here: the
  // GLM encoder allows only its own exact fixed control sequence.
  for (const std::string_view marker :
       {"[gMASK]", "<sop>", "<|system|>", "<|user|>", "<|assistant|>", "<think>"}) {
    pack.tokens_by_id.emplace_back(marker);
    pack.token_types.push_back(3);
  }
  return pack;
}

void executes_a_bounded_non_streaming_completion() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt + "OK");
  const auto output_o = token_id_for(tokenizer, "O");
  const auto output_k = token_id_for(tokenizer, "K");
  expect(output_o < tokenizer.tokens_by_id.size() && output_k < tokenizer.tokens_by_id.size(),
         "test tokenizer must include generated tokens");

  FakeTransport transport;
  transport.reads = {line("INFO private-engine"), line("READY 512"),
                     line("T " + std::to_string(output_o)),
                     line("T " + std::to_string(output_k)), line("DONE 2")};
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol);
  const auto result = service.execute(valid_request(), tokenizer);
  const auto* completion = std::get_if<secure_frontend::ChatExecutionResult>(&result);
  expect(completion != nullptr && completion->text == "OK" && completion->generated_tokens == 2U,
         "READY, GEN, token output, and local decode must compose into text");
  expect(transport.writes.size() == 1U && transport.writes.front().rfind("GEN 2 ", 0) == 0,
         "only canonical GEN may be sent to the local engine");

  transport.reads = {line("T " + std::to_string(output_o)), line("DONE 1")};
  const auto next_result = service.execute(valid_request(1U), tokenizer);
  const auto* next_completion = std::get_if<secure_frontend::ChatExecutionResult>(&next_result);
  expect(next_completion != nullptr && next_completion->text == "O" &&
             transport.writes.size() == 2U && transport.writes.back().rfind("GEN 1 ", 0) == 0,
         "an idle private engine may serve a second request without accepting a second READY");
}

void rejects_context_and_output_limits_before_generation() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt);
  FakeTransport context_transport;
  context_transport.reads = {line("READY 1")};
  secure_frontend::EngineProtocolClient context_protocol(context_transport);
  secure_frontend::ChatExecutionService context_service(context_protocol);
  const auto context_result = context_service.execute(valid_request(), tokenizer);
  const auto* context_error = std::get_if<secure_frontend::ChatExecutionError>(&context_result);
  expect(context_error != nullptr &&
             context_error->code == secure_frontend::ChatExecutionErrorCode::context_limit_exceeded &&
             context_transport.writes.empty(),
         "context overflow must not emit GEN");

  FakeTransport limit_transport;
  limit_transport.reads = {line("READY 512"), line("DONE 0")};
  secure_frontend::EngineProtocolClient limit_protocol(limit_transport);
  secure_frontend::ChatExecutionService limit_service(
      limit_protocol, {.maximum_prompt_tokens = 128U, .maximum_output_tokens = 1U});
  const auto limit_result = limit_service.execute(valid_request(2U), tokenizer);
  expect(std::holds_alternative<secure_frontend::ChatExecutionResult>(limit_result) &&
             limit_transport.writes.size() == 1U && limit_transport.writes.front().rfind("GEN 1 ", 0) == 0,
         "a request above the local output bound is clamped to it (B2), not rejected");
}

void fails_closed_on_invalid_engine_output() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  auto tokenizer = tokenizer_for(prompt + "Z");
  const auto forbidden = token_id_for(tokenizer, "Z");
  expect(forbidden < tokenizer.token_types.size(), "test tokenizer must include forbidden output token");
  if (forbidden >= tokenizer.token_types.size()) return;
  tokenizer.token_types[forbidden] = 3;

  FakeTransport transport;
  transport.reads = {line("READY 512"), line("T " + std::to_string(forbidden)), line("DONE 1")};
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol);
  const auto result = service.execute(valid_request(1U), tokenizer);
  const auto* failure = std::get_if<secure_frontend::ChatExecutionError>(&result);
  expect(failure != nullptr &&
             failure->code == secure_frontend::ChatExecutionErrorCode::output_decode_failed,
         "CONTROL token output must fail closed rather than be returned as text");
}

void executes_glm53_only_when_explicitly_selected() {
  const std::string prompt = "[gMASK]<sop><|user|>Hi<|assistant|><think>";
  const auto tokenizer = glm_tokenizer_for(prompt + "OK");
  const auto output_o = token_id_for(tokenizer, "O");
  const auto output_k = token_id_for(tokenizer, "K");
  FakeTransport transport;
  transport.reads = {line("READY 512"), line("PP 8 16 2.0 4.0"), line("T " + std::to_string(output_o)),
                     line("T " + std::to_string(output_k)), line("DONE 2")};
  secure_frontend::EngineProtocolClient protocol(
      transport, {}, secure_frontend::EngineProtocolFlavor::lighttransport_glm53);
  secure_frontend::ChatExecutionService service(
      protocol, {}, secure_frontend::NativeChatProfile::glm53);
  const auto result = service.execute({"glm-local", {{"user", "Hi"}}, 2U}, tokenizer);
  const auto* completion = std::get_if<secure_frontend::ChatExecutionResult>(&result);
  expect(completion != nullptr && completion->text == "OK" &&
             transport.writes.size() == 1U && transport.writes.front().rfind("GEN 2 ", 0) == 0,
         "the explicit GLM profile must use the same bounded private engine protocol");
}

// R1 (owner ruling 2026-10-14, RF10): the GEN write is bounded by the
// request's generation deadline, fixed when the generation starts; the read to
// DONE then has only what the write left of that same deadline.
void chat_gen_write_bounded_by_generation_deadline() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt + "OK");
  FakeTransport transport;
  transport.reads = {line("READY 512 stop"), line("T " + std::to_string(token_id_for(tokenizer, "O"))), line("DONE 1")};
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol, {.generation_timeout = std::chrono::milliseconds(7000)});
  const auto before = secure_frontend::MonotonicClock::now();
  const auto result = service.execute(valid_request(1U), tokenizer);
  const auto after = secure_frontend::MonotonicClock::now();
  expect(std::holds_alternative<secure_frontend::ChatExecutionResult>(result), "the request succeeds");
  expect(transport.deadlines.size() == 1U && transport.deadlines.front() >= before + std::chrono::milliseconds(7000) &&
             transport.deadlines.front() <= after + std::chrono::milliseconds(7000),
         "the GEN write deadline is the request's generation deadline");
}

// E2: after a timeout the service sends STOP, drains to DONE, and serves the next request.
void chat_recovers_after_generation_timeout() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt + "OK");
  const auto o = token_id_for(tokenizer, "O");
  FakeTransport transport;
  transport.reads = {line("READY 512 stop")};
  for (int i = 0; i < 10; ++i) transport.reads.push_back(line("T " + std::to_string(o)));
  transport.reads.push_back(line("DONE 10 1 1.0 1.0 cancel"));   // the drain after STOP
  transport.reads.push_back(line("T " + std::to_string(o)));      // the next request
  transport.reads.push_back(line("DONE 1 1 1.0 1.0 length"));
  transport.delay_per_read = std::chrono::milliseconds(60);
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol, {.generation_timeout = std::chrono::milliseconds(200), .stop_drain_timeout = std::chrono::seconds(2)});
  const auto first = service.execute(valid_request(10U), tokenizer);
  const auto* first_error = std::get_if<secure_frontend::ChatExecutionError>(&first);
  expect(first_error != nullptr && first_error->code == secure_frontend::ChatExecutionErrorCode::generation_timed_out, "a slow generation must time out");
  expect(std::count(transport.writes.begin(), transport.writes.end(), "STOP") == 1, "exactly one STOP must be sent after the timeout");
  expect(protocol.idle(), "the protocol must be idle again after the drain");
  transport.delay_per_read = std::chrono::milliseconds(0);
  const auto second = service.execute(valid_request(1U), tokenizer);
  expect(std::holds_alternative<secure_frontend::ChatExecutionResult>(second), "the next request must succeed after recovery");
}

void chat_marks_engine_failed_when_drain_fails() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt + "O");
  const auto o = token_id_for(tokenizer, "O");
  FakeTransport transport;
  transport.reads = {line("READY 512 stop")};
  for (int i = 0; i < 10; ++i) transport.reads.push_back(line("T " + std::to_string(o)));
  // No DONE ever arrives: the drain must give up.
  transport.delay_per_read = std::chrono::milliseconds(60);
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol, {.generation_timeout = std::chrono::milliseconds(150), .stop_drain_timeout = std::chrono::milliseconds(300)});
  const auto result = service.execute(valid_request(10U), tokenizer);
  const auto* error = std::get_if<secure_frontend::ChatExecutionError>(&result);
  expect(error != nullptr && error->code == secure_frontend::ChatExecutionErrorCode::engine_protocol_failed, "a failed drain is a protocol failure");
  expect(protocol.closed(), "a failed drain must close the protocol so health reports it");
}

// Review Focus 3: DONE ... nonfinite is a 503 for this request only.
void chat_rejects_nonfinite_done_and_stays_ready() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt + "O");
  const auto o = token_id_for(tokenizer, "O");
  FakeTransport transport;
  transport.reads = {line("READY 512 stop"), line("DONE 0 1 1.0 1.0 nonfinite"), line("T " + std::to_string(o)), line("DONE 1 1 1.0 1.0 length")};
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol);
  const auto first = service.execute(valid_request(1U), tokenizer);
  const auto* error = std::get_if<secure_frontend::ChatExecutionError>(&first);
  expect(error != nullptr && error->code == secure_frontend::ChatExecutionErrorCode::engine_protocol_failed, "nonfinite must not produce text");
  expect(protocol.idle(), "nonfinite does not kill the engine; the protocol stays idle");
  const auto second = service.execute(valid_request(1U), tokenizer);
  expect(std::holds_alternative<secure_frontend::ChatExecutionResult>(second), "the engine is usable after a nonfinite request");
}

void health_reflects_protocol_state() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt + "O");
  const auto o = token_id_for(tokenizer, "O");
  FakeTransport transport;
  transport.reads = {line("READY 512 stop"), line("T " + std::to_string(o)), line("DONE 1 1 1.0 1.0 length")};
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol);
  expect(service.health() == secure_frontend::EngineHealth::starting, "before READY the engine is starting");
  (void)service.execute(valid_request(1U), tokenizer);
  expect(service.health() == secure_frontend::EngineHealth::ready, "after a completed request the engine is ready");
}

// Review Focus 4: the engine closing stdout mid-generation is a failure, not text.
void health_is_failed_after_engine_closed_mid_generation() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt + "O");
  const auto o = token_id_for(tokenizer, "O");
  FakeTransport transport;
  transport.reads = {line("READY 512 stop"), line("T " + std::to_string(o)),
                     {secure_frontend::EngineReadKind::closed, {}, {}}};
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol);
  const auto result = service.execute(valid_request(2U), tokenizer);
  expect(std::holds_alternative<secure_frontend::ChatExecutionError>(result), "a closed engine must not yield partial text");
  const auto* failure = std::get_if<secure_frontend::ChatExecutionError>(&result);
  expect(failure != nullptr && failure->code == secure_frontend::ChatExecutionErrorCode::engine_protocol_failed,
         "a closed engine mid-generation must report engine_protocol_failed");
  expect(service.health() == secure_frontend::EngineHealth::failed, "health must report failed after the engine closed");
}

void health_is_failed_when_engine_closes_before_ready() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt);
  FakeTransport transport;
  transport.reads = {{secure_frontend::EngineReadKind::closed, {}, {}}};
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol);
  const auto result = service.execute(valid_request(1U), tokenizer);
  expect(std::holds_alternative<secure_frontend::ChatExecutionError>(result), "an engine that closes before READY must fail the request");
  expect(service.health() == secure_frontend::EngineHealth::failed, "health must report failed when the engine closes before READY");
}

void chat_applies_engine_context_rule_with_eight_token_margin() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt);
  // Count the prompt tokens by running one successful request first.
  FakeTransport probe; probe.reads = {line("READY 4096 stop"), line("DONE 0 1 1.0 1.0 length")};
  secure_frontend::EngineProtocolClient probe_protocol(probe);
  secure_frontend::ChatExecutionService probe_service(probe_protocol);
  (void)probe_service.execute(valid_request(1U), tokenizer);
  const std::string& gen = probe.writes.front();
  const std::size_t prompt_tokens = static_cast<std::size_t>(std::count(gen.begin(), gen.end(), ',')) + 1U;
  // ctx = prompt + max_new + 7 -> exceeds by one; ctx = prompt + max_new + 8 -> fits.
  for (const std::size_t margin : {7U, 8U}) {
    FakeTransport t; t.reads = {line("READY " + std::to_string(prompt_tokens + 1U + margin) + " stop"), line("DONE 0 1 1.0 1.0 length")};
    secure_frontend::EngineProtocolClient p(t);
    secure_frontend::ChatExecutionService s(p);
    const auto r = s.execute(valid_request(1U), tokenizer);
    const bool rejected = std::holds_alternative<secure_frontend::ChatExecutionError>(r);
    expect(rejected == (margin == 7U), "context rule must be prompt + max_new + 8 <= ctx (margin " + std::to_string(margin) + ")");
  }
}

void chat_uses_adopted_ready_without_waiting() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt + "OK");
  FakeTransport transport;
  transport.reads = {line("READY 512 stop"), line("T " + std::to_string(token_id_for(tokenizer, "O"))), line("DONE 1")};
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::EngineReady ready{};
  expect(!protocol.await_ready(std::chrono::seconds(1), ready).has_value(), "the supervisor consumed READY");
  secure_frontend::ChatExecutionService service(protocol);
  service.adopt_ready(ready);
  expect(service.health() == secure_frontend::EngineHealth::ready, "an adopted READY is ready before any request");
  const auto result = service.execute(valid_request(), tokenizer);
  expect(std::holds_alternative<secure_frontend::ChatExecutionResult>(result), "execute does not wait for a second READY");
}

void resolve_max_tokens_follows_decisions_1_and_2() {
  using secure_frontend::resolve_max_tokens;
  // requested, prompt, ctx, max_completion, default -> result
  expect(resolve_max_tokens(100U, 10U, 4096U, 4096U, 0U) == std::optional<std::size_t>{100U}, "fits as asked");
  expect(resolve_max_tokens(16384U, 10U, 100000U, 4096U, 0U) == std::optional<std::size_t>{4096U}, "clamped to max_completion (B2)");
  expect(resolve_max_tokens(1000U, 50U, 100U, 4096U, 0U) == std::optional<std::size_t>{42U}, "clamped to ctx - n - 8 (B2)");
  expect(resolve_max_tokens(std::nullopt, 50U, 100U, 4096U, 0U) == std::optional<std::size_t>{42U}, "auto = min(max, ctx - n - 8) (B1)");
  expect(resolve_max_tokens(std::nullopt, 10U, 100000U, 4096U, 0U) == std::optional<std::size_t>{4096U}, "auto capped by max_completion");
  expect(resolve_max_tokens(std::nullopt, 10U, 4096U, 4096U, 256U) == std::optional<std::size_t>{256U}, "a configured default applies");
  expect(!resolve_max_tokens(5U, 92U, 100U, 4096U, 0U).has_value(), "prompt alone fills the context: 400 (B2)");
  expect(resolve_max_tokens(5U, 91U, 100U, 4096U, 0U) == std::optional<std::size_t>{1U}, "one token of room is still allowed");
  expect(resolve_max_tokens(5U, 100000U, 0U, 4096U, 0U) == std::optional<std::size_t>{5U}, "unknown context: no context clamp");
}

// SP5 M1 Task 5 (parity row fit_max_tokens): the pin's two behaviours (serve/server.py:4526-4544).
// fit_max_tokens=false turns an EXPLICIT max_tokens over the room into a refusal instead of a
// shortening (:4536-4543); an auto request still takes the room (:4526-4540) and the engine-internal
// max_completion cap still clamps (B2 is not the pin's room rule; C-8 keeps it).
void resolve_max_tokens_fit_false_refuses_like_the_pin() {
  using secure_frontend::resolve_max_tokens;
  expect(resolve_max_tokens(1000U, 50U, 100U, 4096U, 0U, false) == std::nullopt,
         "fit false: an explicit request over the room is refused, never shortened (:4536)");
  expect(resolve_max_tokens(std::nullopt, 50U, 100U, 4096U, 0U, false) == std::optional<std::size_t>{42U},
         "fit false: an auto request still fits the room (:4526)");
  expect(resolve_max_tokens(16384U, 10U, 100000U, 4096U, 0U, false) == std::optional<std::size_t>{4096U},
         "fit false: the max_completion cap still clamps (B2)");
  expect(resolve_max_tokens(1000U, 50U, 100U, 4096U, 0U, true) == std::optional<std::size_t>{42U},
         "fit true keeps the shortening, today's behaviour (:4545)");
}

// SP3 Task 15 (run_generation, spec §2.6 P6): a transport that answers STOP
// with a cancel DONE the next time it is read. Adapted to the re-anchored
// write_line(line, deadline, error) signature; assertions as planned.
class StopAwareTransport final : public secure_frontend::EngineLineTransport {
 public:
  std::deque<std::string> reads;
  std::vector<std::string> writes;
  std::string cancel_line{"DONE 1 3 0 0 cancel"};
  bool answer_stop{true};
  bool write_line(const std::string_view line, const secure_frontend::MonotonicClock::time_point, std::string&) override {
    writes.emplace_back(line);
    if (line == "STOP" && answer_stop) reads.push_back(cancel_line);
    return true;
  }
  secure_frontend::EngineReadResult read_line(const std::chrono::milliseconds timeout) override {
    if (reads.empty()) {
      std::this_thread::sleep_for(std::min(timeout, std::chrono::milliseconds(2)));
      return {secure_frontend::EngineReadKind::timeout, {}, {}};
    }
    std::string next = std::move(reads.front());
    reads.pop_front();
    return {secure_frontend::EngineReadKind::line, std::move(next), {}};
  }
};

struct ReadyService final {
  StopAwareTransport transport;
  secure_frontend::EngineProtocolClient protocol{transport};
  secure_frontend::ChatExecutionService service;
  explicit ReadyService(secure_frontend::ChatExecutionLimits limits = {}) : service(protocol, limits) {
    transport.reads = {"READY 512 stop"};
    secure_frontend::EngineReady ready{};
    expect(!protocol.await_ready(std::chrono::seconds(1), ready).has_value(), "READY consumed");
    service.adopt_ready(ready);
  }
};

void run_generation_reports_finish_usage_and_context() {
  const auto tokenizer = tokenizer_for("OK");
  ReadyService f;
  expect(f.service.context_tokens() == 512U, "context_tokens is the READY context");
  const auto o = token_id_for(tokenizer, "O");
  const auto k = token_id_for(tokenizer, "K");
  f.transport.reads = {"T " + std::to_string(o), "T " + std::to_string(k), "DONE 2 3 1.0 1.0 length"};
  const auto outcome = f.service.run_generation({1U, 2U, 3U}, {.max_tokens = 2U}, {}, tokenizer);
  const auto* result = std::get_if<secure_frontend::GenerationResult>(&outcome);
  expect(result != nullptr && result->text == "OK" && result->prompt_tokens == 3U && result->completion_tokens == 2U &&
         result->finish == secure_frontend::FinishReason::length, "text, usage and finish from DONE");
  expect(f.transport.writes.front().rfind("GEN 2 ", 0) == 0, "GEN carries the resolved budget");
  f.transport.reads = {"T " + std::to_string(o), "DONE stop"};
  const auto short_form = f.service.run_generation({1U}, {.max_tokens = 5U}, {}, tokenizer);
  expect(std::holds_alternative<secure_frontend::GenerationResult>(short_form) &&
         std::get<secure_frontend::GenerationResult>(short_form).finish == secure_frontend::FinishReason::stop, "short DONE is stop");
}

void run_generation_cancel_sends_stop_and_drains() {
  const auto tokenizer = tokenizer_for("O");
  ReadyService f;
  f.transport.reads = {"T " + std::to_string(token_id_for(tokenizer, "O"))};
  int checks = 0;
  const auto outcome = f.service.run_generation({1U, 2U, 3U}, {.max_tokens = 100U}, {.cancelled = [&checks] { return ++checks > 2; }}, tokenizer);
  expect(std::holds_alternative<secure_frontend::GenerationFailure>(outcome) &&
         std::get<secure_frontend::GenerationFailure>(outcome) == secure_frontend::GenerationFailure::cancelled, "a gone client cancels");
  expect(std::count(f.transport.writes.begin(), f.transport.writes.end(), "STOP") == 1, "exactly one STOP");
  expect(f.protocol.idle(), "drained to DONE: the engine is idle for the next request");
}

void run_generation_timeout_stops_and_reports_timed_out() {
  const auto tokenizer = tokenizer_for("O");
  ReadyService f({.generation_timeout = std::chrono::milliseconds(100), .stop_drain_timeout = std::chrono::milliseconds(500)});
  const auto started = std::chrono::steady_clock::now();
  const auto outcome = f.service.run_generation({1U}, {.max_tokens = 100U}, {}, tokenizer);
  const auto* result = std::get_if<secure_frontend::GenerationResult>(&outcome);
  expect(result != nullptr && result->timed_out && result->finish == secure_frontend::FinishReason::length,
         "a timeout returns the text so far with length (B4), flagged timed_out for the log");
  expect(std::chrono::steady_clock::now() - started < std::chrono::seconds(1), "bounded by generation_timeout + drain");
  expect(f.protocol.idle(), "STOP drained");
}

void run_generation_drain_failure_abandons() {
  const auto tokenizer = tokenizer_for("O");
  ReadyService f({.generation_timeout = std::chrono::milliseconds(50), .stop_drain_timeout = std::chrono::milliseconds(100)});
  f.transport.answer_stop = false;
  const auto outcome = f.service.run_generation({1U}, {.max_tokens = 100U}, {}, tokenizer);
  expect(std::holds_alternative<secure_frontend::GenerationFailure>(outcome) &&
         std::get<secure_frontend::GenerationFailure>(outcome) == secure_frontend::GenerationFailure::engine_unavailable,
         "an engine that ignores STOP is unavailable");
  expect(f.protocol.closed(), "and abandoned (the route reports drain_failed through the port)");
}

void run_generation_shutdown_uses_short_drain() {
  const auto tokenizer = tokenizer_for("O");
  ReadyService f;
  std::atomic<bool> shutting{true};
  const auto outcome = f.service.run_generation({1U}, {.max_tokens = 100U}, {.cancelled = {}, .shutting_down = &shutting}, tokenizer);
  expect(std::holds_alternative<secure_frontend::GenerationFailure>(outcome) &&
         std::get<secure_frontend::GenerationFailure>(outcome) == secure_frontend::GenerationFailure::shutting_down, "shutdown");
  expect(std::count(f.transport.writes.begin(), f.transport.writes.end(), "STOP") == 1, "STOP sent during shutdown");
}

void run_generation_maps_engine_errors() {
  const auto tokenizer = tokenizer_for("O");
  {
    ReadyService f;
    f.transport.reads = {"DONE 0 1 1.0 1.0 nonfinite"};
    const auto outcome = f.service.run_generation({1U}, {.max_tokens = 5U}, {}, tokenizer);
    expect(std::get<secure_frontend::GenerationFailure>(outcome) == secure_frontend::GenerationFailure::engine_error && f.protocol.idle(),
           "nonfinite: engine_error, engine stays idle");
  }
  {
    ReadyService f;
    f.transport.reads = {"ERR bad request"};
    const auto outcome = f.service.run_generation({1U}, {.max_tokens = 5U}, {}, tokenizer);
    expect(std::get<secure_frontend::GenerationFailure>(outcome) == secure_frontend::GenerationFailure::engine_error && f.protocol.closed(),
           "ERR: engine_error, protocol closed (SP2 restarts and counts)");
  }
  {
    ReadyService f;
    f.transport.reads = {"T 0", "T 0", "DONE 2 1 0 0 stop"};
    const auto outcome = f.service.run_generation({1U}, {.max_tokens = 1U}, {}, tokenizer);
    expect(std::get<secure_frontend::GenerationFailure>(outcome) == secure_frontend::GenerationFailure::engine_error, "more tokens than asked");
  }
}

// SP3 M2 Task 5: drive_generation and the rebuilt run_generation.
// Ruling t5-test (as in Task 4): M1's write_line carries the absolute write
// deadline and begin_generation the GEN write deadline; the brief's shorter
// helper signatures are adapted to them, assertions unchanged.
std::string byte_id(const unsigned char byte) { return std::to_string(test_support::id_for_byte(byte)); }

// Thread-safe scripted transport (mandatory: a test thread appends while the loop reads).
class LockedTransport final : public secure_frontend::EngineLineTransport {
 public:
  void push(std::string line) { std::lock_guard lock(mutex_); reads_.push_back(std::move(line)); }
  [[nodiscard]] std::size_t stops() const { std::lock_guard lock(mutex_); return static_cast<std::size_t>(std::count(writes_.begin(), writes_.end(), "STOP")); }
  bool write_line(const std::string_view line, const secure_frontend::MonotonicClock::time_point, std::string&) override {
    std::lock_guard lock(mutex_);
    writes_.emplace_back(line);
    return true;
  }
  secure_frontend::EngineReadResult read_line(const std::chrono::milliseconds timeout) override {
    {
      std::lock_guard lock(mutex_);
      if (!reads_.empty()) {
        std::string next = std::move(reads_.front());
        reads_.pop_front();
        return {secure_frontend::EngineReadKind::line, std::move(next), {}};
      }
    }
    std::this_thread::sleep_for(std::min(timeout, std::chrono::milliseconds(2)));
    return {secure_frontend::EngineReadKind::timeout, {}, {}};
  }

 private:
  mutable std::mutex mutex_;
  std::deque<std::string> reads_;
  std::vector<std::string> writes_;
};

struct Collector final : secure_frontend::GenerationObserver {
  std::string text;
  int cancel_after_ticks{-1};
  int ticks{0};
  void on_text(const std::string_view piece) override { text += piece; }
  secure_frontend::RunCancel on_tick(bool) override {
    ++ticks;
    return cancel_after_ticks >= 0 && ticks > cancel_after_ticks ? secure_frontend::RunCancel::client_gone : secure_frontend::RunCancel::none;
  }
};

// A protocol already past READY and GEN, reading `records`.
struct Running final {
  LockedTransport transport;
  secure_frontend::EngineProtocolClient protocol{transport};
  explicit Running(const std::vector<std::string>& records) {
    transport.push("READY 512 stop");
    secure_frontend::EngineReady ready{};
    (void)protocol.await_ready(std::chrono::seconds(1), ready);
    (void)protocol.begin_generation(16, {1}, secure_frontend::deadline_after(std::chrono::seconds(5)));
    for (const auto& record : records) transport.push(record);
  }
};

void drive_generation_bytes_cap_cuts_on_code_point() {
  const auto pack = test_support::byte_tokenizer();
  const secure_frontend::TokenByteDecoder decoder(pack);
  Running run({"T " + byte_id('A'), "T " + byte_id(0xE2), "T " + byte_id(0x82), "T " + byte_id(0xAC), "T " + byte_id('B'),
               "DONE 5 1 0 0 cancel"});
  Collector collector;
  const auto result = secure_frontend::drive_generation(run.protocol, decoder, {.max_generated_bytes = 2U, .max_tokens = 16U}, collector);
  expect(collector.text == "A", "the euro sign does not fit in the 1 byte left and is not split: [" + collector.text + "]");
  expect(result.end == secure_frontend::RunEnd::length && result.bytes_capped, "the cap ends with length");
  expect(run.transport.stops() == 1U, "the cap sends STOP once");
  expect(run.protocol.idle(), "drained to idle");
}

void drive_generation_drops_tail_on_length_and_replaces_on_stop() {
  const auto pack = test_support::byte_tokenizer();
  const secure_frontend::TokenByteDecoder decoder(pack);
  Running cut({"T " + byte_id('A'), "T " + byte_id(0xE2), "DONE 2 1 0 0 length"});
  Collector at_length;
  expect(secure_frontend::drive_generation(cut.protocol, decoder, {}, at_length).end == secure_frontend::RunEnd::length && at_length.text == "A",
         "length: the held lead byte is dropped");
  Running eos({"T " + byte_id('A'), "T " + byte_id(0xE2), "DONE 2 1 0 0 stop"});
  Collector at_stop;
  expect(secure_frontend::drive_generation(eos.protocol, decoder, {}, at_stop).end == secure_frontend::RunEnd::stop &&
             at_stop.text == "A\xEF\xBF\xBD", "stop: the held tail becomes one U+FFFD");
}

void drive_generation_cancel_sends_stop_and_drains() {
  const auto pack = test_support::byte_tokenizer();
  const secure_frontend::TokenByteDecoder decoder(pack);
  Running run({"T " + byte_id('A')});
  Collector collector;
  collector.cancel_after_ticks = 1;
  std::thread late([&run] {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    run.transport.push("DONE 1 1 0 0 cancel");
  });
  const auto result = secure_frontend::drive_generation(run.protocol, decoder, {}, collector);
  late.join();
  expect(result.end == secure_frontend::RunEnd::cancelled && result.cancel == secure_frontend::RunCancel::client_gone, "cancel drains to cancelled");
  expect(run.transport.stops() == 1U, "one STOP");
}

void chat_max_tokens_cut_mid_character_returns_length() {
  const auto pack = test_support::byte_tokenizer();
  LockedTransport transport;
  transport.push("READY 512 stop");
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol);
  for (const auto& record : {"T " + byte_id('A'), "T " + byte_id(0xE2), "T " + byte_id(0x82), std::string("DONE 3 1 0 0 length")}) transport.push(record);
  const auto outcome = service.run_generation({1U, 2U}, {.max_tokens = 3U}, {}, pack);
  const auto* result = std::get_if<secure_frontend::GenerationResult>(&outcome);
  expect(result != nullptr, "a response cut mid-character is not decode_failed (spec §3.3 latent bug)");
  if (result != nullptr) {
    expect(result->text == "A" && result->finish == secure_frontend::FinishReason::length && result->completion_tokens == 3U, "text so far, length");
  }
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"executes_a_bounded_non_streaming_completion", executes_a_bounded_non_streaming_completion},
      {"rejects_context_and_output_limits_before_generation", rejects_context_and_output_limits_before_generation},
      {"fails_closed_on_invalid_engine_output", fails_closed_on_invalid_engine_output},
      {"executes_glm53_only_when_explicitly_selected", executes_glm53_only_when_explicitly_selected},
      {"chat_recovers_after_generation_timeout", chat_recovers_after_generation_timeout},
      {"chat_gen_write_bounded_by_generation_deadline", chat_gen_write_bounded_by_generation_deadline},
      {"chat_marks_engine_failed_when_drain_fails", chat_marks_engine_failed_when_drain_fails},
      {"chat_rejects_nonfinite_done_and_stays_ready", chat_rejects_nonfinite_done_and_stays_ready},
      {"health_reflects_protocol_state", health_reflects_protocol_state},
      {"health_is_failed_after_engine_closed_mid_generation", health_is_failed_after_engine_closed_mid_generation},
      {"health_is_failed_when_engine_closes_before_ready", health_is_failed_when_engine_closes_before_ready},
      {"chat_applies_engine_context_rule_with_eight_token_margin", chat_applies_engine_context_rule_with_eight_token_margin},
      {"chat_uses_adopted_ready_without_waiting", chat_uses_adopted_ready_without_waiting},
      {"resolve_max_tokens_follows_decisions_1_and_2", resolve_max_tokens_follows_decisions_1_and_2},
      {"resolve_max_tokens_fit_false_refuses_like_the_pin", resolve_max_tokens_fit_false_refuses_like_the_pin},
      {"run_generation_reports_finish_usage_and_context", run_generation_reports_finish_usage_and_context},
      {"run_generation_cancel_sends_stop_and_drains", run_generation_cancel_sends_stop_and_drains},
      {"run_generation_timeout_stops_and_reports_timed_out", run_generation_timeout_stops_and_reports_timed_out},
      {"run_generation_drain_failure_abandons", run_generation_drain_failure_abandons},
      {"run_generation_shutdown_uses_short_drain", run_generation_shutdown_uses_short_drain},
      {"drive_generation_bytes_cap_cuts_on_code_point", drive_generation_bytes_cap_cuts_on_code_point},
      {"drive_generation_drops_tail_on_length_and_replaces_on_stop", drive_generation_drops_tail_on_length_and_replaces_on_stop},
      {"drive_generation_cancel_sends_stop_and_drains", drive_generation_cancel_sends_stop_and_drains},
      {"chat_max_tokens_cut_mid_character_returns_length", chat_max_tokens_cut_mid_character_returns_length},
      {"run_generation_maps_engine_errors", run_generation_maps_engine_errors},
  }, failures);
}

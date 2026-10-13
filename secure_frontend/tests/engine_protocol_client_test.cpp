#include "secure_frontend/engine_protocol_client.hpp"

#include <chrono>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {
using secure_frontend::EngineLineTransport;
using secure_frontend::EngineProtocolClient;
using secure_frontend::EngineProtocolErrorCode;
using secure_frontend::EngineReadKind;
using secure_frontend::EngineReadResult;

int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}

class FakeTransport final : public EngineLineTransport {
 public:
  std::deque<EngineReadResult> reads;
  std::vector<std::string> writes;
  bool reject_writes{false};
  std::chrono::milliseconds delay_per_read{0};
  bool write_line(const std::string_view line, std::string& error) override {
    if (reject_writes) { error = "fake write failure"; return false; }
    writes.emplace_back(line); return true;
  }
  EngineReadResult read_line(std::chrono::milliseconds) override {
    if (delay_per_read.count() > 0) std::this_thread::sleep_for(delay_per_read);
    if (reads.empty()) return {EngineReadKind::timeout, {}, {}};
    auto result = std::move(reads.front()); reads.pop_front(); return result;
  }
};

EngineReadResult line(std::string value) { return {EngineReadKind::line, std::move(value), {}}; }

void runs_the_solo_protocol() {
  FakeTransport transport;
  transport.reads = {line("INFO engine=0.1.43"), line("READY 8192 stop"), line("T 12"), line("T 4294967295"), line("DONE 2 3 1.0 2.0 length")};
  EngineProtocolClient client(transport);
  secure_frontend::EngineReady ready{};
  expect(!client.await_ready(std::chrono::seconds(1), ready).has_value(), "READY should parse");
  expect(ready.max_context_tokens == 8192 && ready.supports_stop, "READY facts should parse exactly");
  expect(!client.begin_generation(4, {1, 2, 3}).has_value(), "GEN should be emitted");
  expect(transport.writes == std::vector<std::string>({"GEN 4 1,2,3"}), "GEN must have canonical literal syntax");
  secure_frontend::EngineGeneration generation;
  expect(!client.read_generation(std::chrono::seconds(1), generation).has_value(), "T/DONE sequence should parse");
  expect(generation.token_ids == std::vector<std::uint32_t>({12U, 4294967295U}), "all token ids should be collected");
  expect(generation.done_line == "DONE 2 3 1.0 2.0 length" && client.ready(), "DONE should restore idle state");
}

void stop_and_quit_are_explicit() {
  FakeTransport transport;
  transport.reads = {line("READY 1024 stop"), line("T 7"), line("DONE 1 1 1 1 stop")};
  EngineProtocolClient client(transport);
  secure_frontend::EngineReady ready{};
  (void)client.await_ready(std::chrono::seconds(1), ready);
  (void)client.begin_generation(2, {9});
  expect(!client.stop().has_value(), "STOP should be accepted during a generation");
  expect(!client.stop().has_value(), "a repeated STOP should be idempotent");
  secure_frontend::EngineGeneration generation;
  expect(!client.read_generation(std::chrono::seconds(1), generation).has_value(), "STOP must still drain through DONE");
  expect(!client.quit().has_value() && client.closed(), "QUIT should close a clean idle protocol");
  expect(transport.writes == std::vector<std::string>({"GEN 2 9", "STOP", "QUIT"}), "control writes must be exact");
}

void refuses_stop_when_not_advertised() {
  FakeTransport transport;
  transport.reads = {line("READY 1024")};
  EngineProtocolClient client(transport);
  secure_frontend::EngineReady ready{};
  (void)client.await_ready(std::chrono::seconds(1), ready);
  (void)client.begin_generation(2, {9});
  const auto error = client.stop();
  expect(error.has_value() && error->code == EngineProtocolErrorCode::invalid_state,
         "STOP must not be sent to engines that did not advertise support");
  expect(transport.writes == std::vector<std::string>({"GEN 2 9"}), "unsupported STOP must not be written");
}

void rejects_malformed_and_unexpected_engine_output() {
  FakeTransport bad_ready;
  bad_ready.reads = {line("READY 0")};
  EngineProtocolClient client(bad_ready);
  secure_frontend::EngineReady ready{};
  const auto ready_error = client.await_ready(std::chrono::seconds(1), ready);
  expect(ready_error.has_value() && ready_error->code == EngineProtocolErrorCode::malformed_line && client.closed(),
         "zero READY context must fail closed");

  FakeTransport bad_token;
  bad_token.reads = {line("READY 1"), line("T 4 extra")};
  EngineProtocolClient second(bad_token);
  (void)second.await_ready(std::chrono::seconds(1), ready);
  (void)second.begin_generation(1, {1});
  secure_frontend::EngineGeneration generation;
  const auto token_error = second.read_generation(std::chrono::seconds(1), generation);
  expect(token_error.has_value() && token_error->code == EngineProtocolErrorCode::malformed_line && second.closed(),
         "ambiguous token lines must fail closed");
}

void bounds_and_engine_errors_fail_closed() {
  FakeTransport transport;
  transport.reads = {line("READY 1"), line("ERR model rejected prompt")};
  EngineProtocolClient client(transport, {.max_line_bytes = 32, .max_prompt_tokens = 2, .max_generated_tokens = 1, .max_new_tokens = 4});
  secure_frontend::EngineReady ready{};
  (void)client.await_ready(std::chrono::seconds(1), ready);
  expect(client.begin_generation(5, {1}).has_value(), "over-limit max_new must be rejected before write");
  expect(client.begin_generation(1, {1, 2, 3}).has_value(), "over-limit prompt must be rejected before write");
  expect(!client.begin_generation(1, {1}).has_value(), "bounded request should start");
  secure_frontend::EngineGeneration generation;
  const auto error = client.read_generation(std::chrono::seconds(1), generation);
  expect(error.has_value() && error->code == EngineProtocolErrorCode::engine_error && client.closed(),
         "ERR must terminate the protocol instead of being ignored");
}

void prefill_progress_is_glm_only_and_strictly_bounded() {
  FakeTransport glm_transport;
  glm_transport.reads = {line("READY 64"), line("PP 16 32 10.5 1523.8"),
                         line("T 9"), line("DONE 1")};
  EngineProtocolClient glm_client(
      glm_transport, {}, secure_frontend::EngineProtocolFlavor::lighttransport_glm53);
  secure_frontend::EngineReady ready{};
  expect(!glm_client.await_ready(std::chrono::seconds(1), ready).has_value(),
         "GLM engine must still start with a normal READY record");
  expect(!glm_client.begin_generation(1, {1}).has_value(), "GLM generation should start normally");
  secure_frontend::EngineGeneration generation;
  expect(!glm_client.read_generation(std::chrono::seconds(1), generation).has_value() &&
             generation.token_ids == std::vector<std::uint32_t>({9U}),
         "only a valid GLM PP heartbeat may occur before token output");

  FakeTransport qwen_transport;
  qwen_transport.reads = {line("READY 64"), line("PP 16 32"), line("DONE 0")};
  EngineProtocolClient qwen_client(qwen_transport);
  (void)qwen_client.await_ready(std::chrono::seconds(1), ready);
  (void)qwen_client.begin_generation(1, {1});
  const auto qwen_error = qwen_client.read_generation(std::chrono::seconds(1), generation);
  expect(qwen_error.has_value() && qwen_error->code == EngineProtocolErrorCode::unexpected_line &&
             qwen_client.closed(),
         "Qwen mode must reject GLM PP records instead of silently discarding them");

  FakeTransport malformed_transport;
  malformed_transport.reads = {line("READY 64"), line("PP 33 32"), line("DONE 0")};
  EngineProtocolClient malformed_client(
      malformed_transport, {}, secure_frontend::EngineProtocolFlavor::lighttransport_glm53);
  (void)malformed_client.await_ready(std::chrono::seconds(1), ready);
  (void)malformed_client.begin_generation(1, {1});
  const auto malformed_error = malformed_client.read_generation(std::chrono::seconds(1), generation);
  expect(malformed_error.has_value() && malformed_error->code == EngineProtocolErrorCode::unexpected_line &&
             malformed_client.closed(),
         "malformed GLM progress must fail closed");
}

// E1: the timeout is a total budget, not a per-line allowance.
void generation_total_deadline_is_enforced() {
  FakeTransport transport;
  transport.reads = {line("READY 64 stop")};
  for (int i = 0; i < 20; ++i) transport.reads.push_back(line("T 1"));
  transport.reads.push_back(line("DONE 20 1 1.0 1.0 length"));
  transport.delay_per_read = std::chrono::milliseconds(100);
  EngineProtocolClient client(transport);
  secure_frontend::EngineReady ready{};
  (void)client.await_ready(std::chrono::seconds(1), ready);
  (void)client.begin_generation(20, {1});
  secure_frontend::EngineGeneration generation;
  const auto start = std::chrono::steady_clock::now();
  const auto error = client.read_generation(std::chrono::milliseconds(350), generation);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  expect(error.has_value() && error->code == EngineProtocolErrorCode::timeout, "20 lines at 100 ms each must exceed a 350 ms total budget");
  expect(elapsed < std::chrono::milliseconds(900), "the client must stop reading at the total deadline");
  expect(client.generating() && !client.idle(), "a timeout leaves the generation active for STOP/drain");
}

}  // namespace

// E4: a prompt at the engine's advertised context must fit the GEN line.
void gen_line_fits_max_prompt_tokens() {
  FakeTransport transport;
  transport.reads = {line("READY 4096 stop"), line("DONE 0 4000 1.0 1.0 length")};
  EngineProtocolClient client(transport);  // default limits: derive from READY
  secure_frontend::EngineReady ready{};
  (void)client.await_ready(std::chrono::seconds(1), ready);
  std::vector<std::uint32_t> prompt(4000U, 4294967295U);  // worst case: 10-digit ids
  expect(!client.begin_generation(1, prompt).has_value(), "4000 ten-digit ids must fit the derived GEN line limit");
  expect(transport.writes.size() == 1U && transport.writes.front().size() > 40000U, "the GEN line must actually carry every id");
}

int main() {
  runs_the_solo_protocol();
  stop_and_quit_are_explicit();
  refuses_stop_when_not_advertised();
  rejects_malformed_and_unexpected_engine_output();
  bounds_and_engine_errors_fail_closed();
  prefill_progress_is_glm_only_and_strictly_bounded();
  generation_total_deadline_is_enforced();
  gen_line_fits_max_prompt_tokens();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

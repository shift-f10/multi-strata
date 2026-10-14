#include "secure_frontend/engine_supervisor.hpp"
#include "secure_frontend/engine_stdio_process.hpp"

#include "support/fake_supervised_process.hpp"
#include "support/server_harness.hpp"
#include "support/test_paths.hpp"
#include "support/test_tokenizer.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <variant>
#include <vector>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#else
#include <unistd.h>
#endif

namespace {

using namespace std::chrono_literals;
using secure_frontend::SupervisorState;

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

void supervisor_health_literals_per_state() {
  struct Row {
    SupervisorState state;
    bool healthy;
    std::string_view engine;
    std::string_view recovery;
  };
  const std::vector<Row> rows{
      {SupervisorState::starting, false, "starting", ""},     {SupervisorState::ready, true, "ready", ""},
      {SupervisorState::generating, true, "generating", ""},  {SupervisorState::stopping, false, "failed", "restarting"},
      {SupervisorState::backoff, false, "failed", "restarting"}, {SupervisorState::circuit_open, false, "failed", "exhausted"},
      {SupervisorState::shutting_down, false, "failed", ""},  {SupervisorState::stopped, false, "failed", ""},
  };
  for (const auto& row : rows) {
    const auto health = secure_frontend::health_for(row.state);
    expect(health.state == row.state && health.healthy == row.healthy && health.engine == row.engine && health.recovery == row.recovery,
           "health literals for state " + std::to_string(static_cast<int>(row.state)));
  }
  secure_frontend::EngineSupervisor idle({}, [](std::uint64_t) -> secure_frontend::SpawnResult { return secure_frontend::SpawnFailure{"unused"}; });
  expect(idle.snapshot().state == SupervisorState::stopped && !idle.acquire().has_value(), "before start(): stopped, no lease");
}

secure_frontend::EngineLaunchPlan fake_plan(std::vector<std::string> arguments) {
  return {.command = {.executable = test_support::fake_engine_path(), .arguments = std::move(arguments), .environment = {}}};
}

void proc04_restart_backoff_then_circuit_open() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) { child.end({false, 1U}); });
  auto clock = std::make_shared<test_support::ManualClock>();
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor({}, fakes.factory(), clock, log.sink());
  std::mutex seen_mutex;
  std::vector<std::string_view> recovery_in_backoff;
  clock->on_sleep([&] {
    std::lock_guard lock(seen_mutex);
    recovery_in_backoff.push_back(supervisor.snapshot().recovery);
  });
  supervisor.start();
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 5s), "the 3rd consecutive failure opens the circuit");
  expect(clock->delays() == std::vector<std::chrono::milliseconds>{1000ms, 2000ms}, "backoff is exactly 1 s, then 2 s");
  expect(fakes.spawned() == 3U, "exactly three generations");
  {
    std::lock_guard lock(seen_mutex);
    expect(recovery_in_backoff == std::vector<std::string_view>{"restarting", "restarting"}, "backoff reports recovery=restarting");
  }
  const auto health = supervisor.snapshot();
  expect(!health.healthy && health.engine == "failed" && health.recovery == "exhausted", "circuit_open is failed/exhausted");
  expect(!supervisor.acquire().has_value(), "no lease in circuit_open");
  expect(log.contains("engine generation 1 ended: error_exit"), "each end is logged with its classification");
  supervisor.shutdown(5s);
}

void proc04_healthy_window_resets_failure_count() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) { child.push_line("READY 4096 stop"); });
  auto clock = std::make_shared<test_support::ManualClock>();
  secure_frontend::EngineSupervisor supervisor({}, fakes.factory(), clock);
  const auto fail_now = [&supervisor] {
    auto lease = supervisor.acquire();
    if (lease) supervisor.report_fatal(*lease, secure_frontend::KillReason::protocol_failed);
    return lease.has_value();
  };
  supervisor.start();
  expect(test_support::wait_generation_ready(supervisor, 1U, 5s), "generation 1 ready");
  clock->advance(301s);  // healthy for longer than the 300 s window
  expect(fail_now(), "lease on generation 1");
  expect(test_support::wait_generation_ready(supervisor, 2U, 5s), "generation 2 ready");
  expect(fail_now(), "generation 2 fails at once and counts on top");
  expect(test_support::wait_generation_ready(supervisor, 3U, 5s), "generation 3 ready");
  clock->advance(301s);
  expect(fail_now(), "generation 3 was healthy again");
  expect(test_support::wait_generation_ready(supervisor, 4U, 5s), "generation 4 ready: the circuit stayed closed");
  expect(clock->delays() == std::vector<std::chrono::milliseconds>{1000ms, 2000ms, 1000ms},
         "1 s, 2 s, then 1 s again after a healthy window reset the count");
  supervisor.shutdown(5s);
}

void proc04_recovers_after_transient_crash() {
  const auto dir = test_support::make_temp_dir("transient");
  secure_frontend::SupervisorConfig config;
  config.policy.backoff_initial = 50ms;
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor(
      config, secure_frontend::make_stdio_process_factory(fake_plan({"--fail-first=1", "--counter-file=" + test_support::utf8_path(dir / "count")})),
      std::make_shared<secure_frontend::SteadySupervisorClock>(), log.sink());
  supervisor.start();
  expect(test_support::wait_generation_ready(supervisor, 2U, 10s), "a one-off failure is recovered by generation 2");
  expect(log.contains("engine generation 1 ended: error_exit"), "generation 1's exit 1 is logged as error_exit");
  supervisor.shutdown(5s);
}

void proc04_missing_engine_opens_circuit_without_spinning() {
  const auto dir = test_support::make_temp_dir("missing-engine");
  auto clock = std::make_shared<test_support::ManualClock>();
  test_support::LogCapture log;
  const secure_frontend::EngineLaunchPlan plan{.command = {.executable = dir / "no-such-engine", .arguments = {}, .environment = {}}};
  secure_frontend::EngineSupervisor supervisor({}, secure_frontend::make_stdio_process_factory(plan), clock, log.sink());
  supervisor.start();
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 5s), "three spawn failures open the circuit");
  expect(supervisor.generations_started() == 3U, "exactly three attempts: no tight loop");
  expect(clock->delays() == std::vector<std::chrono::milliseconds>{1000ms, 2000ms}, "spawn failures back off like any failure");
  expect(log.contains("engine generation 1 ended: spawn_failed"), "logged as spawn_failed");
  const auto health = supervisor.snapshot();
  expect(health.engine == "failed" && health.recovery == "exhausted", "/health: failed / exhausted");
  supervisor.shutdown(5s);
}

// Review Focus 6: a client can make the engine answer ERR (SP0 keeps the
// per-request answer), and an ERR leaves the protocol failed, so the
// generation is replaced and counts as a failure. Three such requests in a
// row, inside the healthy window, open the circuit until the frontend restarts.
void proc04_client_err_lines_open_circuit_until_restart() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) {
    child.push_line("READY 4096 stop");
    child.push_line("ERR invalid request");  // the answer to the first GEN
  });
  auto clock = std::make_shared<test_support::ManualClock>();
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor({}, fakes.factory(), clock, log.sink());
  supervisor.start();
  const auto tokenizer = test_support::byte_tokenizer();
  const secure_frontend::ChatCompletionRequest request{"fake-model", {{"user", "Hi"}}, 2U};
  for (std::uint64_t generation = 1U; generation <= 3U; ++generation) {
    expect(test_support::wait_generation_ready(supervisor, generation, 5s), "generation " + std::to_string(generation) + " ready");
    const auto outcome = secure_frontend::execute_with_lease(supervisor, request, tokenizer);
    expect(outcome && std::holds_alternative<secure_frontend::ChatExecutionError>(*outcome), "the ERR request fails for its own client");
  }
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 5s), "the third client-triggered ERR opens the circuit");
  expect(fakes.spawned() == 3U, "no fourth generation: only a frontend restart closes the circuit");
  expect(clock->delays() == std::vector<std::chrono::milliseconds>{1000ms, 2000ms}, "the first two ERR generations back off like any failure");
  expect(log.contains("engine generation 3 ended: killed_by_supervisor(protocol_failed)"), "each ERR generation is killed as protocol_failed");
  const auto health = supervisor.snapshot();
  expect(health.engine == "failed" && health.recovery == "exhausted", "/health: failed / exhausted until restart");
  expect(!supervisor.acquire().has_value(), "no lease for any later client");
  supervisor.shutdown(5s);
}

// Spec §3.1: only the supervisor thread destroys a generation (on Windows the
// destructor terminates the Job and waits). A Lease that outlives its
// generation's end must not make the serving thread drop the last reference.
void supervisor_retires_ended_generation_on_its_own_thread() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) { child.push_line("READY 4096 stop"); });
  auto clock = std::make_shared<test_support::ManualClock>();
  secure_frontend::EngineSupervisor supervisor({}, fakes.factory(), clock, test_support::LogCapture{}.sink());
  supervisor.start();
  expect(test_support::wait_generation_ready(supervisor, 1U, 5s), "generation 1 ready");
  auto lease = supervisor.acquire();
  expect(lease.has_value(), "lease on generation 1");
  if (!lease) {
    supervisor.shutdown(5s);
    return;
  }
  supervisor.report_fatal(*lease, secure_frontend::KillReason::protocol_failed);
  expect(test_support::wait_generation_ready(supervisor, 2U, 5s), "generation 2 ready while generation 1 is still leased");
  const auto first = fakes.child(1U);
  lease.reset();  // the serving thread lets go of the ended generation
  {
    std::lock_guard lock(first->mutex);
    expect(first->destroyed_on != std::this_thread::get_id(), "the serving thread did not destroy generation 1");
  }
  supervisor.shutdown(5s);
  std::lock_guard lock(first->mutex);
  expect(first->destroyed_on == first->spawned_on, "generation 1 was destroyed on the supervisor thread");
}

void proc04_monitor_detects_idle_crash() {
#if defined(__linux__)
  {
    // Prove the pidfd path, not just the 100 ms fallback: on Linux (5.3+; the
    // dev host and CI run 5.15+) a started engine must offer a monitor handle.
    secure_frontend::EngineStdioProcess probe;
    expect(!probe.start({.executable = test_support::fake_engine_path(), .arguments = {}, .environment = {}}).has_value(), "probe start");
    expect(probe.monitor_handle() != secure_frontend::kNoMonitorHandle,
           "Linux: the monitor waits on a pidfd (pidfd_open), not the fallback poll");
    (void)probe.terminate(250ms);
  }
#endif
  secure_frontend::SupervisorConfig config;
  config.policy.max_consecutive_failures = 1U;  // one end opens the circuit: nothing respawns during the check
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor(
      config, secure_frontend::make_stdio_process_factory(fake_plan({"--crash-after-ready=KILL", "--crash-delay-ms=300"})),
      std::make_shared<secure_frontend::SteadySupervisorClock>(), log.sink());
  supervisor.start();
  expect(supervisor.wait_for_state(SupervisorState::ready, 10s), "ready");
  const auto ready_seen = std::chrono::steady_clock::now();
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 3s), "an idle death is noticed with no request");
  const auto noticed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - ready_seen);
  expect(noticed <= 1300ms, "within 1 s of the crash (which is 300 ms after READY); took " + std::to_string(noticed.count()) + " ms");
#if defined(_WIN32)
  expect(log.contains("engine generation 1 ended: error_exit"), "the fake's TerminateProcess(137) is an error exit");
#else
  expect(log.contains("engine generation 1 ended: killed_external"), "a SIGKILL we did not send is killed_external");
#endif
  supervisor.shutdown(5s);
}

void proc04_monitor_fallback_without_pidfd() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) { child.push_line("READY 4096 stop"); });
  secure_frontend::SupervisorConfig config;
  config.policy.max_consecutive_failures = 1U;
  config.monitor_poll = 20ms;
  secure_frontend::EngineSupervisor supervisor(config, fakes.factory());
  supervisor.start();
  expect(supervisor.wait_for_state(SupervisorState::ready, 5s), "ready");
  const auto started = std::chrono::steady_clock::now();
  fakes.child(1U)->end({false, 0U});  // no monitor handle: only the fallback poll can see this
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 2s), "the fallback poll notices the exit");
  expect(std::chrono::steady_clock::now() - started < 500ms, "within a few poll intervals");
  supervisor.shutdown(5s);
}

// Spec §3.3 / §3.1: a wake that is not shutdown (here: a Lease on the ended
// generation let go during the backoff) neither shortens the delay nor waits
// for it to sweep that generation.
void proc04_backoff_survives_stale_wake() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) { child.push_line("READY 4096 stop"); });
  secure_frontend::EngineSupervisor supervisor({}, fakes.factory(), std::make_shared<secure_frontend::SteadySupervisorClock>(),
                                               test_support::LogCapture{}.sink());
  supervisor.start();
  expect(test_support::wait_generation_ready(supervisor, 1U, 5s), "generation 1 ready");
  auto lease = supervisor.acquire();
  expect(lease.has_value(), "lease on generation 1");
  if (!lease) {
    supervisor.shutdown(5s);
    return;
  }
  supervisor.report_fatal(*lease, secure_frontend::KillReason::protocol_failed);
  expect(supervisor.wait_for_state(SupervisorState::backoff, 5s), "backoff after the first failure");
  const auto backoff_seen = std::chrono::steady_clock::now();
  std::this_thread::sleep_for(100ms);
  lease.reset();  // wakes the supervisor mid-backoff
  const auto first = fakes.child(1U);
  const auto swept_by = std::chrono::steady_clock::now() + 300ms;
  bool swept = false;
  while (!swept && std::chrono::steady_clock::now() < swept_by) {
    {
      std::lock_guard lock(first->mutex);
      swept = first->destroyed_on != std::thread::id{};
    }
    if (!swept) std::this_thread::sleep_for(5ms);
  }
  expect(swept, "the released generation is swept during the backoff, not after it");
  expect(supervisor.generations_started() == 1U, "the wake did not end the backoff early");
  expect(test_support::wait_generation_ready(supervisor, 2U, 5s), "generation 2 after the backoff");
  const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - backoff_seen);
  expect(waited >= 950ms, "the full 1 s backoff elapsed; took " + std::to_string(waited.count()) + " ms");
  supervisor.shutdown(5s);
}

void proc04_fatal_prefix_kills_engine() {
  // Protocol level: each prefix fails the generation; the trailing DONE is never consumed.
  for (std::size_t index = 0; index < secure_frontend::kEngineFatalPrefixes.size(); ++index) {
    auto child = std::make_shared<test_support::FakeChild>();
    test_support::FakeChildTransport transport(child);
    child->push_line("READY 4096 stop");
    secure_frontend::EngineProtocolClient protocol(transport);
    secure_frontend::EngineReady ready{};
    expect(!protocol.await_ready(1s, ready).has_value(), "READY");
    expect(!protocol.begin_generation(1, {1}).has_value(), "GEN");
    child->push_line("T 1");
    child->push_line(std::string(secure_frontend::kEngineFatalPrefixes[index]) + "12");
    child->push_line("DONE stop");
    secure_frontend::EngineGeneration generation{};
    const auto error = protocol.read_generation(1s, generation);
    expect(error && error->code == secure_frontend::EngineProtocolErrorCode::fatal_engine_line, "prefix " + std::to_string(index) + " is fatal");
    expect(protocol.closed() && secure_frontend::kill_reason_for(protocol) == secure_frontend::KillReason::fatal_line, "maps to fatal_line");
    std::lock_guard lock(child->mutex);
    expect(child->reads.size() == 1U && child->reads.front().line == "DONE stop", "the trailing DONE is not accepted");
  }
  // Supervisor level: the generation is killed and replaced.
  const auto tokenizer = test_support::byte_tokenizer();
  const secure_frontend::ChatCompletionRequest request{"fake-model", {{"user", "Hi"}}, 2U};
  for (int index = 0; index < 4; ++index) {
    secure_frontend::SupervisorConfig config;
    config.policy.backoff_initial = 20ms;
    test_support::LogCapture log;
    secure_frontend::EngineSupervisor supervisor(
        config, secure_frontend::make_stdio_process_factory(fake_plan({"--fatal-line=" + std::to_string(index)})),
        std::make_shared<secure_frontend::SteadySupervisorClock>(), log.sink());
    supervisor.start();
    expect(test_support::wait_generation_ready(supervisor, 1U, 10s), "generation 1 ready");
    const auto outcome = secure_frontend::execute_with_lease(supervisor, request, tokenizer);
    expect(outcome && std::holds_alternative<secure_frontend::ChatExecutionError>(*outcome), "the request fails; no result after a fatal line");
    expect(test_support::wait_generation_ready(supervisor, 2U, 10s), "the engine is replaced");
    expect(log.contains("engine generation 1 ended: killed_by_supervisor(fatal_line)"), "killed as fatal_line, prefix " + std::to_string(index));
    supervisor.shutdown(5s);
  }
}

// Spec §3.8: a fatal verify line before READY is a fatal_line kill, not a
// generic protocol failure.
void proc04_fatal_line_before_ready_kills_as_fatal_line() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) {
    child.push_line(std::string(secure_frontend::kEngineFatalPrefixes.front()) + "3");
  });
  secure_frontend::SupervisorConfig config;
  config.policy.max_consecutive_failures = 1U;  // one end opens the circuit: nothing respawns
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor(config, fakes.factory(), std::make_shared<test_support::ManualClock>(), log.sink());
  supervisor.start();
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 5s), "the generation ends before READY");
  expect(log.contains("engine generation 1 ended: killed_by_supervisor(fatal_line)"), "killed as fatal_line, not protocol_failed");
  supervisor.shutdown(5s);
}

void proc04_ready_timeout_kills_and_counts() {
  secure_frontend::SupervisorConfig config;
  config.policy.ready_timeout = 200ms;
  config.policy.max_consecutive_failures = 2U;
  config.policy.backoff_initial = 20ms;
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor(config, secure_frontend::make_stdio_process_factory(fake_plan({"--hang-before-ready"})),
                                               std::make_shared<secure_frontend::SteadySupervisorClock>(), log.sink());
  supervisor.start();
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 5s), "two READY timeouts open the circuit: each one counts");
  expect(supervisor.generations_started() == 2U, "two generations");
  expect(log.contains("engine generation 1 ended: killed_by_supervisor(ready_timeout)"), "killed as ready_timeout");
  supervisor.shutdown(5s);
}

void proc04_drain_failure_kills_and_restarts() {
  secure_frontend::SupervisorConfig config;
  config.chat_limits.generation_timeout = 200ms;
  config.chat_limits.stop_drain_timeout = 200ms;
  config.policy.backoff_initial = 20ms;
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor(config, secure_frontend::make_stdio_process_factory(fake_plan({"--hang-in-gen"})),
                                               std::make_shared<secure_frontend::SteadySupervisorClock>(), log.sink());
  supervisor.start();
  expect(test_support::wait_generation_ready(supervisor, 1U, 10s), "generation 1 ready");
  const auto tokenizer = test_support::byte_tokenizer();
  const secure_frontend::ChatCompletionRequest request{"fake-model", {{"user", "Hi"}}, 2U};
  const auto outcome = secure_frontend::execute_with_lease(supervisor, request, tokenizer);
  expect(outcome && std::holds_alternative<secure_frontend::ChatExecutionError>(*outcome), "the request fails after STOP is ignored");
  expect(test_support::wait_generation_ready(supervisor, 2U, 10s), "a new generation replaces the wedged one");
  expect(log.contains("engine generation 1 ended: killed_by_supervisor(drain_failed)"), "killed as drain_failed");
  supervisor.shutdown(5s);
}

std::size_t open_handle_count() {
#if defined(_WIN32)
  DWORD count = 0;
  (void)GetProcessHandleCount(GetCurrentProcess(), &count);
  return count;
#else
  std::size_t count = 0;
  std::error_code error;
  for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd", error)) {
    (void)entry;
    ++count;  // includes the iterator's own descriptor: the same on every call
  }
  return count;
#endif
}

void proc04_no_leak_across_restarts() {
  secure_frontend::SupervisorConfig config;
  config.policy.max_consecutive_failures = 100U;
  config.policy.backoff_initial = 1ms;
  config.policy.backoff_max = 1ms;
  secure_frontend::EngineSupervisor supervisor(config, secure_frontend::make_stdio_process_factory(fake_plan({})));
  supervisor.start();
  std::optional<std::size_t> baseline;
  for (std::uint64_t generation = 1U; generation <= 11U; ++generation) {  // 10 forced restarts
    expect(test_support::wait_generation_ready(supervisor, generation, 10s), "generation " + std::to_string(generation) + " ready");
    const std::size_t handles = open_handle_count();
    if (!baseline) baseline = handles;
    expect(handles == *baseline, "descriptor/handle count stable at generation " + std::to_string(generation) + ": " + std::to_string(handles) +
                                     " vs " + std::to_string(*baseline));
#if !defined(_WIN32)
    const auto children = test_support::children_of(static_cast<long>(getpid()));
    expect(children.size() == 1U, "exactly one live engine, saw " + std::to_string(children.size()));
    for (const long child : children) expect(test_support::process_alive(child), "no zombie among the children");
#endif
    auto lease = supervisor.acquire();
    expect(lease.has_value(), "lease");
    if (!lease) break;
    auto* stdio = dynamic_cast<secure_frontend::EngineStdioProcess*>(&lease->process());
    expect(stdio != nullptr && stdio->pending_bytes_for_tests() == 0U, "a new generation starts with an empty stdout buffer");
    supervisor.report_fatal(*lease, secure_frontend::KillReason::protocol_failed);
  }
  supervisor.shutdown(5s);
}

void proc04_unreaped_child_opens_circuit() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) {
    child.reapable = false;  // the kill lands, but the child can never be reaped
    child.push_line("READY 4096 stop");
  });
  secure_frontend::SupervisorConfig config;
  config.policy.reap_timeout = 100ms;
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor(config, fakes.factory(), std::make_shared<test_support::ManualClock>(), log.sink());
  supervisor.start();
  expect(supervisor.wait_for_state(SupervisorState::ready, 5s), "ready");
  {
    auto lease = supervisor.acquire();
    expect(lease.has_value(), "lease");
    if (lease) supervisor.report_fatal(*lease, secure_frontend::KillReason::protocol_failed);
  }
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 2s), "an unreaped child opens the circuit");
  expect(fakes.spawned() == 1U, "no respawn while the child is unreaped, although failures are below the limit");
  expect(supervisor.snapshot().recovery == "exhausted", "recovery=exhausted");
  expect(log.contains("engine generation 1 ended: unreaped"), "logged as unreaped");
  supervisor.shutdown(5s);
}

}  // namespace

int main(int argc, char* argv[]) {
  return secure_frontend_test::run_cases(argc, argv, {{"supervisor_health_literals_per_state", supervisor_health_literals_per_state},
                                                {"proc04_restart_backoff_then_circuit_open", proc04_restart_backoff_then_circuit_open},
                                                {"proc04_healthy_window_resets_failure_count", proc04_healthy_window_resets_failure_count},
                                                {"proc04_recovers_after_transient_crash", proc04_recovers_after_transient_crash},
                                                {"proc04_missing_engine_opens_circuit_without_spinning", proc04_missing_engine_opens_circuit_without_spinning},
                                                {"proc04_client_err_lines_open_circuit_until_restart", proc04_client_err_lines_open_circuit_until_restart},
                                                {"supervisor_retires_ended_generation_on_its_own_thread", supervisor_retires_ended_generation_on_its_own_thread},
                                                {"proc04_monitor_detects_idle_crash", proc04_monitor_detects_idle_crash},
                                                {"proc04_monitor_fallback_without_pidfd", proc04_monitor_fallback_without_pidfd},
                                                {"proc04_backoff_survives_stale_wake", proc04_backoff_survives_stale_wake},
                                                {"proc04_fatal_prefix_kills_engine", proc04_fatal_prefix_kills_engine},
                                                {"proc04_fatal_line_before_ready_kills_as_fatal_line", proc04_fatal_line_before_ready_kills_as_fatal_line},
                                                {"proc04_ready_timeout_kills_and_counts", proc04_ready_timeout_kills_and_counts},
                                                {"proc04_drain_failure_kills_and_restarts", proc04_drain_failure_kills_and_restarts},
                                                {"proc04_no_leak_across_restarts", proc04_no_leak_across_restarts},
                                                {"proc04_unreaped_child_opens_circuit", proc04_unreaped_child_opens_circuit}}, failures);
}

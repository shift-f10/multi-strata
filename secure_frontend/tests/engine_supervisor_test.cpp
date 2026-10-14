#include "secure_frontend/engine_supervisor.hpp"
#include "secure_frontend/cgroup_scope.hpp"
#include "secure_frontend/engine_environment.hpp"
#include "secure_frontend/engine_stdio_process.hpp"
#include "secure_frontend/privilege_check.hpp"
#include "secure_frontend/shutdown_signal.hpp"

#include "support/fake_engine_dump.hpp"
#include "support/fake_supervised_process.hpp"
#include "support/server_harness.hpp"
#include "support/test_paths.hpp"
#include "support/test_tokenizer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <new>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <variant>
#include <vector>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#else
#include <cerrno>
#include <csignal>
#include <sys/resource.h>
#include <sys/wait.h>
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
    expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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
  expect(supervisor.start(), "the supervisor starts");
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

#if !defined(_WIN32)
// The sweep reaped `pid` (not merely killed it): it is no longer our child,
// not even as a zombie. Hygiene: this process is the subreaper, so a
// grandchild the sweep missed is ours; kill it only while it is alive (a
// recycled pid is never signalled) and collect it.
void expect_swept_and_reaped(const long pid) {
  int status = 0;
  const pid_t waited = waitpid(static_cast<pid_t>(pid), &status, WNOHANG);
  expect(waited == -1 && errno == ECHILD, "the swept grandchild was reaped, not left a zombie");
  if (waited == 0 && test_support::process_alive(pid)) test_support::kill_process(pid);
  if (waited == 0) (void)waitpid(static_cast<pid_t>(pid), &status, 0);
}

void proc05_setsid_grandchild_is_reaped() {
  const auto dir = test_support::make_temp_dir("c2");
  const auto pidfile = dir / "grandchild.pid";
  secure_frontend::SupervisorConfig config;
  config.policy.max_consecutive_failures = 1U;
  secure_frontend::EngineSupervisor supervisor(
      config, secure_frontend::make_stdio_process_factory(
                  fake_plan({"--spawn-grandchild", "--grandchild-setsid", "--grandchild-pidfile=" + test_support::utf8_path(pidfile)})));
  expect(supervisor.start(), "the supervisor starts");
  expect(test_support::wait_generation_ready(supervisor, 1U, 10s), "ready");
  const auto grandchild = test_support::read_pidfile(pidfile, 5s);
  expect(grandchild.has_value(), "the escaping grandchild started");
  if (!grandchild) return;
  {
    auto lease = supervisor.acquire();
    if (lease) supervisor.report_fatal(*lease, secure_frontend::KillReason::protocol_failed);
  }
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 5s), "the generation ended");
  expect(test_support::wait_until_gone(*grandchild, 2s), "a setsid grandchild outside the engine's group is swept");
  expect_swept_and_reaped(*grandchild);
  supervisor.shutdown(5s);
}

void proc05_setsid_grandchild_is_reaped_at_shutdown() {
  const auto dir = test_support::make_temp_dir("c2-shutdown");
  const auto pidfile = dir / "grandchild.pid";
  secure_frontend::EngineSupervisor supervisor(
      {}, secure_frontend::make_stdio_process_factory(
              fake_plan({"--spawn-grandchild", "--grandchild-setsid", "--grandchild-pidfile=" + test_support::utf8_path(pidfile)})));
  expect(supervisor.start(), "the supervisor starts");
  expect(test_support::wait_generation_ready(supervisor, 1U, 10s), "ready");
  const auto grandchild = test_support::read_pidfile(pidfile, 5s);
  expect(grandchild.has_value(), "the escaping grandchild started");
  if (!grandchild) return;
  expect(test_support::process_alive(*grandchild), "precondition: the grandchild is alive before shutdown");
  supervisor.shutdown(5s);
  expect(test_support::wait_until_gone(*grandchild, 2s), "a setsid grandchild alive at shutdown is swept");
  expect_swept_and_reaped(*grandchild);
}

// C5 (spec §3.7d): with a delegated cgroup v2 each generation runs in its own
// child cgroup, and cgroup.kill ends a setsid escape with the orphan sweep off.
void proc05_cgroup_kill_when_delegated() {
  const auto cgroups = secure_frontend::EngineCgroups::detect();
  if (!cgroups) {
    test_support::skip("no delegated cgroup v2 is writable here; run under `systemd-run --user --scope -p Delegate=yes` to exercise it");
  }
  const auto dir = test_support::make_temp_dir("c5");
  const auto pidfile = dir / "grandchild.pid";
  secure_frontend::SupervisorConfig config;
  config.policy.max_consecutive_failures = 1U;
  config.sweep_orphans = false;  // prove that cgroup.kill does the work, not the subreaper sweep
  auto plan = fake_plan({"--spawn-grandchild", "--grandchild-setsid", "--grandchild-pidfile=" + test_support::utf8_path(pidfile)});
  plan.use_delegated_cgroup = true;
  secure_frontend::EngineSupervisor supervisor(config, secure_frontend::make_stdio_process_factory(plan));
  expect(supervisor.start(), "the supervisor starts");
  expect(test_support::wait_generation_ready(supervisor, 1U, 10s), "ready");
  const auto grandchild = test_support::read_pidfile(pidfile, 5s);
  expect(grandchild.has_value(), "grandchild started");
  const auto generation = cgroups->generation_directory(1U);
  if (grandchild) {
    expect(test_support::cgroup_directory_of(*grandchild) == generation, "the setsid grandchild runs in the generation's cgroup");
  }
  {
    auto lease = supervisor.acquire();
    if (lease) supervisor.report_fatal(*lease, secure_frontend::KillReason::protocol_failed);
  }
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 5s), "the generation ended");
  if (grandchild) {
    expect(test_support::wait_until_gone(*grandchild, 2s), "cgroup.kill ends a setsid grandchild with no sweep");
    test_support::kill_process(*grandchild);
  }
  expect(!std::filesystem::exists(generation), "the generation's cgroup is removed");
  supervisor.shutdown(5s);
}
#endif

#if defined(_WIN32)
// Supervisor-level smoke for the Windows launch settings (spec §3.7): the fake
// runs with --default-error-mode, so it has only the error mode it inherits
// from the frontend. Abort / fastfail path; error mode only (std::abort raises
// no SEH exception, so the Job's DIE_ON_UNHANDLED_EXCEPTION is not exercised).
void proc04_windows_abort_does_not_stall() {
  secure_frontend::SupervisorConfig config;
  config.policy.backoff_initial = 20ms;
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor(config,
                                               secure_frontend::make_stdio_process_factory(fake_plan({"--abort-in-gen", "--default-error-mode"})),
                                               std::make_shared<secure_frontend::SteadySupervisorClock>(), log.sink());
  expect(supervisor.start(), "the supervisor starts");
  expect(test_support::wait_generation_ready(supervisor, 1U, 10s), "ready");
  const auto tokenizer = test_support::byte_tokenizer();
  const auto started = std::chrono::steady_clock::now();
  (void)secure_frontend::execute_with_lease(supervisor, {"fake-model", {{"user", "Hi"}}, 2U}, tokenizer);
  expect(log.wait_for("engine generation 1 ended: abort", 5s), "the abort is observed, not stalled on a WER dialog");
  expect(std::chrono::steady_clock::now() - started < 5s, "within 5 s");
  supervisor.shutdown(5s);
}

// Sibling smoke: a real unhandled exception (access violation) with the
// inherited error mode, so the Job's DIE_ON_UNHANDLED_EXCEPTION is on the path.
void proc04_windows_crash_does_not_stall() {
  secure_frontend::SupervisorConfig config;
  config.policy.backoff_initial = 20ms;
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor(
      config,
      secure_frontend::make_stdio_process_factory(fake_plan({"--crash-after-ready=SEGV", "--crash-delay-ms=300", "--default-error-mode"})),
      std::make_shared<secure_frontend::SteadySupervisorClock>(), log.sink());
  expect(supervisor.start(), "the supervisor starts");
  expect(test_support::wait_generation_ready(supervisor, 1U, 10s), "ready");
  const auto started = std::chrono::steady_clock::now();
  expect(log.wait_for("engine generation 1 ended: crashed", 5s), "the crash is observed and classified crashed, not stalled on WER");
  expect(std::chrono::steady_clock::now() - started < 5s, "within 5 s");
  supervisor.shutdown(5s);
}

// K2 (spec §3.10): an engine that never reads stdin cannot hang the serving
// thread; the stalled chunk is cancelled at its deadline and the supervisor
// kills the engine as write_timeout.
void proc04_windows_write_timeout_kills_engine() {
  secure_frontend::SupervisorConfig config;
  config.policy.backoff_initial = 20ms;
  // The request must end through the write deadline, deterministically: a
  // short generation_timeout (2 s) bounds the case even if a write completed,
  // and the prompt cap is raised for the large prompt below.
  config.chat_limits.generation_timeout = 2s;
  config.chat_limits.maximum_prompt_tokens = 100000U;
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor(
      config, secure_frontend::make_stdio_process_factory(fake_plan({"--stall-stdin", "--ready-context=131072"})),
      std::make_shared<secure_frontend::SteadySupervisorClock>(), log.sink());
  expect(supervisor.start(), "the supervisor starts");
  expect(test_support::wait_generation_ready(supervisor, 1U, 10s), "ready");
  const auto tokenizer = test_support::byte_tokenizer();
  // 60,000 '0' bytes are 60,000 prompt tokens of id 239 (three digits plus a
  // comma each): the GEN line is about 240 KB, more than 3x the 64 KiB pipe
  // buffer, and this engine never reads stdin, so a chunk must stall past the
  // 1 s no-progress deadline. (60,000 stays under the renderer's 65,536-byte
  // per-message cap, so the request reaches the write.)
  const secure_frontend::ChatCompletionRequest request{"fake-model", {{"user", std::string(60000U, '0')}}, 2U};
  const auto started = std::chrono::steady_clock::now();
  const auto outcome = secure_frontend::execute_with_lease(supervisor, request, tokenizer);
  expect(outcome && std::holds_alternative<secure_frontend::ChatExecutionError>(*outcome), "the request fails");
  expect(std::chrono::steady_clock::now() - started < 5s, "the blocked write is cancelled at its deadline");
  expect(log.wait_for("engine generation 1 ended: killed_by_supervisor(write_timeout)", 5s), "killed as write_timeout");
  supervisor.shutdown(5s);
}
#endif

// RF4: an exception that escapes the supervisor thread (the factory, the log
// sink, the clock) opens the circuit instead of reaching std::terminate, and
// a generation still alive at that point is killed and reaped first.
class ThrowingClock final : public secure_frontend::SupervisorClock {
 public:
  [[nodiscard]] time_point now() const override {
    if (armed_.load()) throw std::runtime_error("clock");
    return std::chrono::steady_clock::now();
  }
  [[nodiscard]] bool sleep_backoff(const std::chrono::milliseconds delay, secure_frontend::SupervisorWake& wake) override {
    return wake.wait(secure_frontend::kNoMonitorHandle, delay) == secure_frontend::SupervisorWake::Event::timeout;
  }
  void arm() { armed_.store(true); }

 private:
  std::atomic<bool> armed_{false};
};

void expect_exhausted_then_stopped(secure_frontend::EngineSupervisor& supervisor, const std::string& what) {
  expect(supervisor.wait_for_state(SupervisorState::circuit_open, 5s), what + " opens the circuit");
  const auto health = supervisor.snapshot();
  expect(!health.healthy && health.engine == "failed" && health.recovery == "exhausted", what + ": /health is failed/exhausted");
  expect(!supervisor.acquire().has_value(), what + ": no lease");
  supervisor.shutdown(5s);
  expect(supervisor.snapshot().state == SupervisorState::stopped, what + ": the shutdown still completes");
}

void supervisor_exception_opens_circuit() {
  {
    secure_frontend::EngineSupervisor supervisor(
        {}, [](std::uint64_t) -> secure_frontend::SpawnResult { throw std::runtime_error("factory"); },
        std::make_shared<test_support::ManualClock>(), [](std::string_view) {});
    expect(supervisor.start(), "the supervisor starts");
    expect_exhausted_then_stopped(supervisor, "a throwing factory");
  }
  {
    test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) { child.end({false, 1U}); });
    secure_frontend::EngineSupervisor supervisor({}, fakes.factory(), std::make_shared<test_support::ManualClock>(),
                                                 [](std::string_view) { throw std::runtime_error("log"); });
    expect(supervisor.start(), "the supervisor starts");
    expect_exhausted_then_stopped(supervisor, "a throwing log sink");
    expect(fakes.spawned() == 1U, "no restart after the exception");
  }
  {
    test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) { child.push_line("READY 4096 stop"); });
    auto clock = std::make_shared<ThrowingClock>();
    secure_frontend::EngineSupervisor supervisor({}, fakes.factory(), clock, [](std::string_view) {});
    expect(supervisor.start(), "the supervisor starts");
    expect(test_support::wait_generation_ready(supervisor, 1U, 5s), "generation 1 ready");
    clock->arm();
    {
      auto lease = supervisor.acquire();
      expect(lease.has_value(), "lease on generation 1");
      // The supervisor thread reads the clock as the generation ends: it throws with generation 1 still current.
      if (lease) supervisor.report_fatal(*lease, secure_frontend::KillReason::protocol_failed);
      expect(supervisor.wait_for_state(SupervisorState::circuit_open, 5s), "a throwing clock opens the circuit");
    }
    const auto child = fakes.child(1U);
    expect(child != nullptr && child->kills >= 1, "the live generation is killed before the circuit opens");
    expect_exhausted_then_stopped(supervisor, "a throwing clock");
    expect(fakes.spawned() == 1U, "no restart after the exception");
  }
}

// Spec §3.7: with no Lease out, shutdown closes engine stdin first (the engine
// exits 0 on EOF), then always kills the group; the end is logged as the
// supervisor's own shutdown, not as a clean exit.
void supervisor_shutdown_sends_eof_first_then_kills() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) { child.push_line("READY 4096 stop"); });
  test_support::LogCapture log;
  secure_frontend::EngineSupervisor supervisor({}, fakes.factory(), std::make_shared<test_support::ManualClock>(), log.sink());
  expect(supervisor.start(), "the supervisor starts");
  expect(test_support::wait_generation_ready(supervisor, 1U, 5s), "generation 1 ready");
  const auto started = std::chrono::steady_clock::now();
  supervisor.shutdown(5s);
  expect(std::chrono::steady_clock::now() - started < 1s, "an engine that exits on EOF is not waited on for the 2 s budget");
  expect(supervisor.snapshot().state == SupervisorState::stopped, "stopped");
  const auto child = fakes.child(1U);
  expect(child != nullptr, "generation 1 exists");
  if (!child) return;
  std::lock_guard lock(child->mutex);
  expect(child->exit.has_value() && !child->exit->signaled && child->exit->value == 0U, "the engine ended on stdin EOF (exit 0)");
  expect(child->kills == 1, "the group is SIGKILLed anyway (spec §3.7: always), saw " + std::to_string(child->kills));
  expect(log.contains("engine generation 1 ended: killed_by_supervisor(shutdown)"), "logged as the supervisor's shutdown");
}

// RF4 / spec §3.7: a Lease still out at shutdown keeps engine stdin (no EOF
// under a request), and it must not outlive shutdown() pointing at the
// supervisor: destroying it after the supervisor is gone touches nothing.
void supervisor_lease_outliving_shutdown_is_safe() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) { child.push_line("READY 4096 stop"); });
  test_support::LogCapture log;
  alignas(secure_frontend::EngineSupervisor) unsigned char storage[sizeof(secure_frontend::EngineSupervisor)];
  auto* supervisor = new (storage) secure_frontend::EngineSupervisor({}, fakes.factory(), std::make_shared<test_support::ManualClock>(), log.sink());
  expect(supervisor->start(), "the supervisor starts");
  expect(test_support::wait_generation_ready(*supervisor, 1U, 5s), "generation 1 ready");
  std::optional<secure_frontend::Lease> lease = supervisor->acquire();
  expect(lease.has_value(), "lease on generation 1");
  supervisor->shutdown(5s);
  expect(supervisor->snapshot().state == SupervisorState::stopped, "shutdown completes with the Lease still out");
  if (const auto child = fakes.child(1U)) {
    std::lock_guard lock(child->mutex);
    expect(child->exit.has_value() && child->exit->signaled == test_support::fake_kill_status().signaled &&
               child->exit->value == test_support::fake_kill_status().value,
           "no EOF under a leased request: the engine is killed, not closed");
  }
  expect(log.contains("engine generation 1 ended: killed_by_supervisor(shutdown)"), "logged as the supervisor's shutdown");
  supervisor->~EngineSupervisor();
  // Poison the supervisor's memory: a Lease that still pointed at it would lock
  // a garbage mutex and write to a garbage descriptor.
  std::memset(storage, 0xA5, sizeof(storage));
  lease.reset();
  expect(true, "the Lease outlived the supervisor without touching it");
}

// Sets a variable of this test process for one case and restores the previous
// value (or removes it) when the case ends.
class ScopedParentVariable final {
 public:
  ScopedParentVariable(const char* name, const char* value) : name_(name) {
    if (const char* previous = std::getenv(name)) previous_ = std::string(previous);
    set(value);
  }
  ~ScopedParentVariable() {
    if (previous_) {
      set(previous_->c_str());
    } else {
#if defined(_WIN32)
      (void)_putenv_s(name_, "");  // an empty value removes it
#else
      (void)unsetenv(name_);
#endif
    }
  }
  ScopedParentVariable(const ScopedParentVariable&) = delete;
  ScopedParentVariable& operator=(const ScopedParentVariable&) = delete;

 private:
  void set(const char* value) const {
#if defined(_WIN32)
    (void)_putenv_s(name_, value);
#else
    (void)setenv(name_, value, 1);
#endif
  }
  const char* name_;
  std::optional<std::string> previous_;
};

// N1 (spec §3.9): the engine's environment is exactly the rendered allowlist.
void proc02_child_env_is_exact_allowlist() {
  // A hostile parent environment: none of it may reach the engine.
  const ScopedParentVariable token("STRATA_TEST_TOKEN_ENV", "secret-token-value");
  const ScopedParentVariable api_key("STRATA_API_KEY", "k");
  const ScopedParentVariable home("HOME", "/home/someone");
  const ScopedParentVariable preload("LD_PRELOAD", "/nonexistent/libstrata-test.so");
  const ScopedParentVariable proxy("HTTPS_PROXY", "http://proxy.invalid:3128");
  const ScopedParentVariable devices("CUDA_VISIBLE_DEVICES", "0");
  const auto state = test_support::make_temp_dir("n1");
  const secure_frontend::EngineEnvironment environment{
      .lib_dirs = {state / "lib"}, .temp_dir = state / "engine-tmp", .cuda_cache_dir = state / "cache" / "cuda"};
  auto plan = fake_plan({});
  plan.environment = environment;
  auto spawned = secure_frontend::make_stdio_process_factory(plan)(1U);
  auto* process = std::get_if<std::unique_ptr<secure_frontend::SupervisedProcess>>(&spawned);
  expect(process != nullptr, "spawn");
  if (process == nullptr) return;
  auto& transport = (*process)->transport();
  expect(transport.read_line(5s).line == "READY 4096 stop", "READY");
  const auto dump = test_support::request_dump(transport, 5s);
  expect(dump.has_value(), "DUMP");
  if (!dump) return;
  auto rendered = environment;
  rendered.temp_dir = state / "engine-tmp" / "1";
  std::vector<std::string> expected;
  for (const auto& [name, value] : secure_frontend::render_engine_environment(rendered)) expected.push_back(name + "=" + value);
  std::sort(expected.begin(), expected.end());
  // On a mismatch, name the entries that differ (names only, never values).
  std::string differing;
  const auto missing_from = [&differing](const std::vector<std::string>& side, const std::vector<std::string>& other,
                                         const char* mark) {
    for (const auto& entry : side) {
      if (std::find(other.begin(), other.end(), entry) == other.end()) differing += mark + entry.substr(0, entry.find('='));
    }
  };
  missing_from(dump->env, expected, " +");
  missing_from(expected, dump->env, " -");
  expect(dump->env == expected, "the child environment is exactly the rendered allowlist; differing:" + differing);
  for (const auto& entry : dump->env) {
    for (const std::string_view banned : secure_frontend::kNeverForwardedEnvironment) {
      expect(entry.rfind(std::string(banned) + "=", 0) != 0, "never forwarded: " + std::string(banned));
    }
    expect(entry.rfind("STRATA_TEST_TOKEN_ENV=", 0) != 0, "the token variable never reaches the engine");
    if (entry.rfind("STRATA_", 0) == 0) {
      expect(entry.rfind("STRATA_HIPBLASLT_TUNING=", 0) == 0 || entry.rfind("STRATA_WATCHDOG_S=", 0) == 0 ||
                 entry.rfind("STRATA_WATCHDOG_IO_S=", 0) == 0,
             "no other STRATA_* variable: " + entry.substr(0, entry.find('=')));
    }
  }
  expect(secure_frontend::is_owner_only_directory(state / "engine-tmp" / "1"), "the generation's temp directory exists, owner-only");
  // The directory goes away once the generation is reaped, exactly as
  // end_generation / shutdown_generation do it (kill, reap, release_resources).
  (*process)->kill_group();
  for (int step = 0; step < 500 && !(*process)->try_reap(); ++step) std::this_thread::sleep_for(10ms);
  (*process)->release_resources(1000ms);
  expect(!std::filesystem::exists(state / "engine-tmp" / "1"), "the generation's temp directory is removed after the reap");
}

#if !defined(_WIN32)
// RF4: the shutdown signal handler preserves errno, also when its wake write
// fails (a full self-pipe gives EAGAIN).
void shutdown_signal_preserves_errno() {
  secure_frontend::SupervisorWake wake;
  expect(wake.valid(), "wake pipe");
  for (int i = 0; i < 200000; ++i) wake.notify();  // fill the non-blocking pipe: the next write fails
  secure_frontend::install_shutdown_signals(wake);
  expect(!secure_frontend::shutdown_signalled(), "not signalled before SIGTERM");
  errno = EDOM;
  (void)std::raise(SIGTERM);
  const int after = errno;
  expect(after == EDOM, "errno survives the handler, saw " + std::to_string(after));
  expect(secure_frontend::shutdown_signalled(), "SIGTERM sets the shutdown flag");
  expect(wake.wait(secure_frontend::kNoMonitorHandle, 0ms) == secure_frontend::SupervisorWake::Event::woken, "the wake is readable");
  secure_frontend::release_shutdown_signals(wake);
}

// RF4: without its wake pipe the supervisor thread could never be woken for
// shutdown, so start() refuses and spawns nothing.
void supervisor_start_refuses_without_wake() {
  test_support::FakeFactory fakes([](test_support::FakeChild& child, std::uint64_t) { child.push_line("READY 4096 stop"); });
  rlimit saved{};
  expect(getrlimit(RLIMIT_NOFILE, &saved) == 0, "read RLIMIT_NOFILE");
  rlimit none = saved;
  none.rlim_cur = 0;  // no new descriptor at all: pipe2 fails with EMFILE
  expect(setrlimit(RLIMIT_NOFILE, &none) == 0, "lower RLIMIT_NOFILE");
  auto supervisor = std::make_unique<secure_frontend::EngineSupervisor>(
      secure_frontend::SupervisorConfig{}, fakes.factory(), std::make_shared<test_support::ManualClock>(), [](std::string_view) {});
  expect(setrlimit(RLIMIT_NOFILE, &saved) == 0, "restore RLIMIT_NOFILE");
  expect(!supervisor->start(), "start() refuses when the wake could not be created");
  expect(supervisor->snapshot().state == SupervisorState::stopped && fakes.spawned() == 0U, "nothing is spawned");
  supervisor.reset();
}
#endif

// G4 (spec §3.12): the frontend runs as the invoking unprivileged user.
void proc06_refuses_privileged_start() {
  expect(secure_frontend::privileged_start_error({.posix_root = true, .windows_elevated = false}).has_value(), "root is refused");
  expect(secure_frontend::privileged_start_error({.posix_root = false, .windows_elevated = true}).has_value(), "an elevated token is refused");
  expect(!secure_frontend::privileged_start_error({.posix_root = false, .windows_elevated = false}).has_value(), "an unprivileged user starts");
#if !defined(_WIN32)
  expect(secure_frontend::current_process_privileges().posix_root == (geteuid() == 0), "the probe reads the effective uid");
#endif
}

// Task 29 Step 5a: the CUDA cache follows roots.cache when it is set.
void engine_environment_uses_cache_root_when_set() {
  const std::filesystem::path state{"/srv/state"};
  const auto plain = secure_frontend::engine_environment_for(state, std::nullopt, {"/opt/engine"});
  expect(plain.cuda_cache_dir == state / "cache" / "cuda", "without roots.cache the CUDA cache stays below the state dir");
  expect(plain.temp_dir == state / "engine-tmp", "the per-generation temp root is <state>/engine-tmp");
  expect(plain.lib_dirs == std::vector<std::filesystem::path>{"/opt/engine"}, "lib dirs pass through");
  const auto cached = secure_frontend::engine_environment_for(state, std::filesystem::path{"/var/cache/strata"}, {});
  expect(cached.cuda_cache_dir == std::filesystem::path{"/var/cache/strata"} / "cuda", "roots.cache holds the CUDA cache when set");
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
                                                {"proc04_unreaped_child_opens_circuit", proc04_unreaped_child_opens_circuit},
                                                {"supervisor_exception_opens_circuit", supervisor_exception_opens_circuit},
                                                {"supervisor_shutdown_sends_eof_first_then_kills", supervisor_shutdown_sends_eof_first_then_kills},
                                                {"supervisor_lease_outliving_shutdown_is_safe", supervisor_lease_outliving_shutdown_is_safe},
                                                {"proc06_refuses_privileged_start", proc06_refuses_privileged_start},
                                                {"engine_environment_uses_cache_root_when_set", engine_environment_uses_cache_root_when_set},
                                                {"proc02_child_env_is_exact_allowlist", proc02_child_env_is_exact_allowlist},
#if !defined(_WIN32)
                                                {"shutdown_signal_preserves_errno", shutdown_signal_preserves_errno},
                                                {"supervisor_start_refuses_without_wake", supervisor_start_refuses_without_wake},
                                                {"proc05_setsid_grandchild_is_reaped", proc05_setsid_grandchild_is_reaped},
                                                {"proc05_setsid_grandchild_is_reaped_at_shutdown", proc05_setsid_grandchild_is_reaped_at_shutdown},
                                                {"proc05_cgroup_kill_when_delegated", proc05_cgroup_kill_when_delegated},
#endif
#if defined(_WIN32)
                                                {"proc04_windows_abort_does_not_stall", proc04_windows_abort_does_not_stall},
                                                {"proc04_windows_crash_does_not_stall", proc04_windows_crash_does_not_stall},
                                                {"proc04_windows_write_timeout_kills_engine", proc04_windows_write_timeout_kills_engine},
#endif
                                               }, failures);
}

#include "secure_frontend/engine_stdio_process.hpp"
#include "secure_frontend/exit_status.hpp"

#include "support/fake_engine_dump.hpp"
#include "support/test_paths.hpp"

#include <chrono>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#include <csignal>
#include <pthread.h>
#include <sys/types.h>
#endif

namespace {

using namespace std::chrono_literals;
using secure_frontend::ExitKind;
using secure_frontend::ExitPlatform;
using secure_frontend::ExitStatus;
using secure_frontend::KillReason;

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

std::optional<ExitStatus> wait_reaped(secure_frontend::EngineStdioProcess& child, const std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    if (auto status = child.try_reap()) return status;
    if (std::chrono::steady_clock::now() >= deadline) return std::nullopt;
    std::this_thread::sleep_for(10ms);
  }
}

void proc04_exit_status_is_classified() {
  struct Row {
    ExitStatus status;
    KillReason sent;
    ExitPlatform platform;
    ExitKind kind;
    KillReason reason;
    const char* name;
  };
  const std::vector<Row> table{
      {{false, 0U}, KillReason::none, ExitPlatform::posix, ExitKind::clean_exit, KillReason::none, "posix exit 0"},
      {{false, 1U}, KillReason::none, ExitPlatform::posix, ExitKind::error_exit, KillReason::none, "posix exit 1 (ERR path or CUDA fault)"},
      {{false, 127U}, KillReason::none, ExitPlatform::posix, ExitKind::error_exit, KillReason::none, "posix exit 127 after a successful exec"},
      {{true, 6U}, KillReason::none, ExitPlatform::posix, ExitKind::abort, KillReason::none, "posix SIGABRT (watchdog)"},
      {{true, 9U}, KillReason::none, ExitPlatform::posix, ExitKind::killed_external, KillReason::none, "posix SIGKILL not ours (OOM)"},
      {{true, 11U}, KillReason::none, ExitPlatform::posix, ExitKind::crashed, KillReason::none, "posix SIGSEGV"},
      {{true, 9U}, KillReason::fatal_line, ExitPlatform::posix, ExitKind::killed_by_supervisor, KillReason::fatal_line, "posix our SIGKILL"},
      {{true, 15U}, KillReason::shutdown, ExitPlatform::posix, ExitKind::killed_by_supervisor, KillReason::shutdown, "posix our SIGTERM"},
      {{true, 6U}, KillReason::protocol_failed, ExitPlatform::posix, ExitKind::abort, KillReason::none, "aborted before our kill landed"},
      {{false, 0U}, KillReason::none, ExitPlatform::windows, ExitKind::clean_exit, KillReason::none, "windows exit 0"},
      {{false, 1U}, KillReason::none, ExitPlatform::windows, ExitKind::error_exit, KillReason::none, "windows exit 1"},
      {{false, 3U}, KillReason::none, ExitPlatform::windows, ExitKind::abort, KillReason::none, "windows abort() exit 3"},
      {{false, 0xC0000409U}, KillReason::none, ExitPlatform::windows, ExitKind::abort, KillReason::none, "windows fast-fail abort"},
      {{false, 0xC0000005U}, KillReason::none, ExitPlatform::windows, ExitKind::crashed, KillReason::none, "windows access violation"},
      {{false, 0x20000001U}, KillReason::ready_timeout, ExitPlatform::windows, ExitKind::killed_by_supervisor, KillReason::ready_timeout,
       "windows our TerminateJobObject code"},
  };
  for (const auto& row : table) {
    const auto got = secure_frontend::classify_exit(row.status, row.sent, row.platform);
    expect(got.kind == row.kind && got.reason == row.reason, std::string("classification: ") + row.name);
  }
  expect(secure_frontend::describe_exit({ExitKind::killed_by_supervisor, KillReason::fatal_line}) == "killed_by_supervisor(fatal_line)",
         "describe a supervisor kill");
  expect(secure_frontend::describe_exit({ExitKind::abort, KillReason::none}) == "abort", "describe an abort");

  // Real children: the raw status is captured by try_reap() and classified natively.
  struct Live {
    std::string argument;
    ExitKind kind;
  };
  std::vector<Live> live{{"--exit-before-ready=1", ExitKind::error_exit}, {"--crash-after-ready=ABRT", ExitKind::abort},
                         {"--crash-after-ready=SEGV", ExitKind::crashed}};
#if !defined(_WIN32)
  live.push_back({"--crash-after-ready=KILL", ExitKind::killed_external});
#endif
  for (const auto& run : live) {
    secure_frontend::EngineStdioProcess child;
    expect(!child.start({.executable = test_support::fake_engine_path(), .arguments = {run.argument}, .environment = {}}).has_value(),
           "start " + run.argument);
    const auto status = wait_reaped(child, 10s);
    expect(status.has_value(), "the child must end: " + run.argument);
    if (status) {
      expect(secure_frontend::classify_exit(*status, KillReason::none).kind == run.kind, "live classification: " + run.argument);
      expect(child.exit_status() == status, "exit_status() keeps the reaped status");
    }
  }
  // Our own kill is ours, never confused with the engine's `return 1`.
  secure_frontend::EngineStdioProcess killed;
  expect(!killed.start({.executable = test_support::fake_engine_path(), .arguments = {"--hang-before-ready"}, .environment = {}}).has_value(),
         "start hang");
  expect(killed.terminate(100ms), "terminate");
  const auto status = killed.exit_status();
  expect(status && secure_frontend::classify_exit(*status, KillReason::shutdown).kind == ExitKind::killed_by_supervisor,
         "a supervisor kill classifies as ours");
}

#if !defined(_WIN32)
void proc05_group_killed_after_leader_reaped() {
  const auto dir = test_support::make_temp_dir("c1");
  const auto pidfile = dir / "grandchild.pid";
  secure_frontend::EngineStdioProcess engine;
  expect(!engine.start({.executable = test_support::fake_engine_path(),
                        .arguments = {"--spawn-grandchild", "--grandchild-ignore-term", "--grandchild-pidfile=" + test_support::utf8_path(pidfile)},
                        .environment = {}})
              .has_value(),
         "start");
  expect(engine.read_line(5s).line == "READY 4096 stop", "READY");
  const auto grandchild = test_support::read_pidfile(pidfile, 5s);
  expect(grandchild.has_value(), "the grandchild started");
  if (!grandchild) return;
  (void)kill(static_cast<pid_t>(engine.pid()), SIGKILL);  // only the leader
  expect(wait_reaped(engine, 5s).has_value(), "the leader is reaped first");
  expect(test_support::process_alive(*grandchild), "precondition: the grandchild outlived its leader");
  expect(engine.terminate(200ms), "terminate succeeds");
  expect(test_support::wait_until_gone(*grandchild, 2s), "a group member dies although the leader was already reaped");
  test_support::kill_process(*grandchild);
}
#endif

#if !defined(_WIN32)
void proc02_child_signal_state_is_default() {
  struct sigaction ignore {};
  ignore.sa_handler = SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  struct sigaction previous {};
  (void)sigaction(SIGPIPE, &ignore, &previous);  // what install_process_defaults() does in the frontend
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, SIGUSR1);
  sigset_t old_mask;
  (void)pthread_sigmask(SIG_BLOCK, &block, &old_mask);
  secure_frontend::EngineStdioProcess child;
  const bool started = !child.start({.executable = test_support::fake_engine_path(), .arguments = {}, .environment = {}}).has_value();
  (void)pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
  (void)sigaction(SIGPIPE, &previous, nullptr);
  expect(started, "start");
  expect(child.read_line(5s).line == "READY 4096 stop", "READY");
  const auto dump = test_support::request_dump(child, 5s);
  expect(dump && dump->sig_blocked == "0000000000000000", "the engine starts with an empty signal mask, saw " + (dump ? dump->sig_blocked : ""));
  expect(dump && dump->sig_ignored == "0000000000000000", "and nothing ignored (default SIGPIPE), saw " + (dump ? dump->sig_ignored : ""));
  (void)child.terminate(250ms);
}
#endif

}  // namespace

int main(int argc, char* argv[]) {
  return secure_frontend_test::run_cases(argc, argv,
                                         {
                                             {"proc04_exit_status_is_classified", proc04_exit_status_is_classified},
#if !defined(_WIN32)
                                             {"proc05_group_killed_after_leader_reaped", proc05_group_killed_after_leader_reaped},
                                             {"proc02_child_signal_state_is_default", proc02_child_signal_state_is_default},
#endif
                                         },
                                         failures);
}

#pragma once

// Internal, POSIX-only helpers shared by EngineProcess and EngineStdioProcess.
//
// Everything that allocates (argv, envp, the executable path, the descriptor
// sweep limit) is prepared BEFORE fork().  The child body, exec_child(), uses
// only async-signal-safe calls (prctl, getppid, setpgid, open, fcntl, dup2, close, syscall,
// sigaction, sigprocmask, execve, write, _exit), so it is safe even when other
// parent threads held the allocator lock at the moment of fork().

#if !defined(_WIN32)

#include "secure_frontend/engine_process.hpp"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <string>
#include <vector>

#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif

namespace secure_frontend::posix_launch {

// The child reports a pre-exec failure's errno through this descriptor.  It is
// close-on-exec, so a successful execve closes it and the parent reads EOF.
inline constexpr int kReportFd = 3;
// Descriptors the child needs are first lifted to >= this floor, so the dup2
// calls onto 0..kReportFd can never overwrite one of their own sources (which
// happens when the parent runs with some of 0..2 closed).
inline constexpr int kLiftFloor = 10;
inline constexpr long kSweepCap = 65536;
inline constexpr int kSweepDefault = 1024;

// argv/envp point into the storage vectors, so this object is filled in place
// and never copied or moved.
struct PreparedExec {
  PreparedExec() = default;
  PreparedExec(const PreparedExec&) = delete;
  PreparedExec& operator=(const PreparedExec&) = delete;

  std::string executable;
  std::vector<std::string> argument_storage;
  std::vector<char*> argv;
  std::vector<std::string> environment_storage;
  std::vector<char*> envp;
  int sweep_limit{kSweepDefault};
  // The forking process, recorded before fork(); the child compares getppid() to it.
  pid_t expected_parent{-1};
};

inline void prepare(PreparedExec& out, const EngineCommand& command, const bool insert_serve) {
  out.expected_parent = getpid();
  out.executable = command.executable.string();
  out.argument_storage.reserve(command.arguments.size() + 2);
  out.argument_storage.push_back(out.executable);
  if (insert_serve) out.argument_storage.emplace_back("--serve");
  out.argument_storage.insert(out.argument_storage.end(), command.arguments.begin(), command.arguments.end());
  out.argv.reserve(out.argument_storage.size() + 1);
  for (auto& argument : out.argument_storage) out.argv.push_back(argument.data());
  out.argv.push_back(nullptr);
  out.environment_storage.reserve(command.environment.size());
  for (const auto& [name, value] : command.environment) out.environment_storage.push_back(name + "=" + value);
  out.envp.reserve(out.environment_storage.size() + 1);
  for (auto& entry : out.environment_storage) out.envp.push_back(entry.data());
  out.envp.push_back(nullptr);
  const long open_max = sysconf(_SC_OPEN_MAX);
  out.sweep_limit = open_max > 0 ? static_cast<int>(std::min(open_max, kSweepCap)) : kSweepDefault;
}

// Spec §3.12, parent side: every signal is blocked in the forking thread from
// just before fork() until fork() returns, so no handler (the shutdown
// self-pipe) can run in the child between fork and exec.
class BlockAllSignals final {
 public:
  BlockAllSignals() noexcept {
    sigset_t all;
    sigfillset(&all);
    (void)pthread_sigmask(SIG_SETMASK, &all, &previous_);
  }
  ~BlockAllSignals() { (void)pthread_sigmask(SIG_SETMASK, &previous_, nullptr); }
  BlockAllSignals(const BlockAllSignals&) = delete;
  BlockAllSignals& operator=(const BlockAllSignals&) = delete;

 private:
  sigset_t previous_{};
};

// Spec §3.12, child side (async-signal-safe): SIG_IGN survives execve, so put
// every disposition back to SIG_DFL (the engine gets the default SIGPIPE, not
// the frontend's ignore), then clear the mask inherited from the parent.
inline void reset_signal_state() noexcept {
  struct sigaction defaults {};
  defaults.sa_handler = SIG_DFL;
  sigemptyset(&defaults.sa_mask);
  for (int signal_number = 1; signal_number < NSIG; ++signal_number) {
    if (signal_number == SIGKILL || signal_number == SIGSTOP) continue;
    (void)sigaction(signal_number, &defaults, nullptr);
  }
  sigset_t none;
  sigemptyset(&none);
  (void)sigprocmask(SIG_SETMASK, &none, nullptr);
}

[[noreturn]] inline void fail(const int report_fd) noexcept {
  const int saved_errno = errno;
  (void)!write(report_fd, &saved_errno, sizeof(saved_errno));
  _exit(127);
}

inline int lift(const int fd) noexcept { return fd < 0 ? -1 : fcntl(fd, F_DUPFD_CLOEXEC, kLiftFloor); }

// Runs in the forked child only.  stdin_fd/stdout_fd of -1 keep the inherited
// descriptor; null_stderr points fd 2 at /dev/null.  Every descriptor above
// kReportFd is closed before execve, and kReportFd itself is close-on-exec.
[[noreturn]] inline void exec_child(const PreparedExec& prepared, const int stdin_fd, const int stdout_fd,
                                    const bool null_stderr, const int report_fd) noexcept {
#if defined(__linux__)
  // Spec §3.7(c): the leader dies with the frontend. PDEATHSIG fires when the
  // forking *thread* exits, which is why only the long-lived supervisor thread
  // forks engines. If the parent already died between fork() and here,
  // getppid() differs and the child exits instead of running orphaned.
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) fail(report_fd);
  if (getppid() != prepared.expected_parent) _exit(127);
#endif
  if (setpgid(0, 0) != 0) fail(report_fd);
  const int report = lift(report_fd);
  if (report < 0) fail(report_fd);
  const int in = lift(stdin_fd);
  const int out = lift(stdout_fd);
  if ((stdin_fd >= 0 && in < 0) || (stdout_fd >= 0 && out < 0)) fail(report);
  int err = -1;
  if (null_stderr) {
    const int sink = open("/dev/null", O_WRONLY | O_CLOEXEC);
    err = lift(sink);
    if (err < 0) fail(report);
  }
  // dup2 onto a different descriptor clears FD_CLOEXEC on the target, so 0..2
  // survive execve; the report descriptor gets FD_CLOEXEC back explicitly.
  if ((in >= 0 && dup2(in, STDIN_FILENO) < 0) || (out >= 0 && dup2(out, STDOUT_FILENO) < 0) ||
      (err >= 0 && dup2(err, STDERR_FILENO) < 0) || dup2(report, kReportFd) < 0 ||
      fcntl(kReportFd, F_SETFD, FD_CLOEXEC) != 0) {
    fail(report);
  }
#if defined(__linux__) && defined(SYS_close_range)
  if (syscall(SYS_close_range, static_cast<unsigned>(kReportFd + 1), ~0U, 0U) != 0)
#endif
  {
    for (int fd = kReportFd + 1; fd < prepared.sweep_limit; ++fd) (void)close(fd);
  }
  reset_signal_state();
  execve(prepared.executable.c_str(), prepared.argv.data(), prepared.envp.data());
  fail(kReportFd);
}

}  // namespace secure_frontend::posix_launch

#endif  // !defined(_WIN32)

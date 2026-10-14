#pragma once

#include <chrono>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace secure_frontend {

// Environment is an allowlist: no parent environment variables are inherited.
struct EngineCommand final {
  std::filesystem::path executable;
  std::vector<std::string> arguments;
  std::map<std::string, std::string, std::less<>> environment;
  // Linux, delegated cgroup v2 only: the child writes itself into this
  // cgroup.procs before execve, so even its escaping descendants stay inside.
  // `{}`: existing designated initializers that omit it keep compiling (-Werror).
  std::optional<std::filesystem::path> cgroup_procs{};
  // The child's working directory (spec §3.12): the engine writes its
  // cwd-relative `pack/full` default and `strata-stall-<pid>.dmp` there. Empty: inherit.
  // `{}`: existing designated initializers that omit it keep compiling (-Werror).
  std::filesystem::path working_directory{};
  // Linux: PR_SET_NO_NEW_PRIVS before execve (spec §3.12). The server turns it
  // on by default (owner decision 2026-10-13); --allow-new-privileges turns it off.
  // `{false}`: existing designated initializers that omit it keep compiling (-Werror).
  bool no_new_privileges{false};
};

enum class ProcessErrorCode {
  invalid_command,
  already_running,
  spawn_failed,
  platform_failure,
};

struct ProcessError final {
  ProcessErrorCode code;
  std::string message;
};

// Owns one engine child and its process group (or Windows Job Object).
// start() always invokes the supplied executable directly; it never uses a shell.
// Test-only (SP0): no production code uses it; the server's engine runs under
// EngineStdioProcess and EngineSupervisor. It is deliberately not C1-hardened.
class EngineProcess final {
 public:
  EngineProcess() = default;
  ~EngineProcess();
  EngineProcess(const EngineProcess&) = delete;
  EngineProcess& operator=(const EngineProcess&) = delete;
  EngineProcess(EngineProcess&& other) noexcept;
  EngineProcess& operator=(EngineProcess&& other) noexcept;

  [[nodiscard]] std::optional<ProcessError> start(const EngineCommand& command);
  [[nodiscard]] bool running();
  // Returns an exit code when the child exits; nullopt means the timeout elapsed.
  [[nodiscard]] std::optional<int> wait_for(std::chrono::milliseconds timeout);
  // Terminates the whole child group, waits at most grace, then force-kills it.
  // POSIX: the group SIGKILL is sent only while the leader is unreaped. Unlike
  // spec C1 (EngineStdioProcess) it does not always SIGKILL the group: wait_for
  // reaps the leader, so a later group kill could hit a recycled pgid. Kept as
  // is by design (controller ruling RF12); used by tests only.
  [[nodiscard]] bool terminate(std::chrono::milliseconds grace);

 private:
#if defined(_WIN32)
  void* process_handle_{nullptr};
  void* job_handle_{nullptr};
#else
  int process_id_{-1};
#endif
  std::optional<int> exit_code_;

  void cleanup() noexcept;
};

}  // namespace secure_frontend

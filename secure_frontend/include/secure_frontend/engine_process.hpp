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

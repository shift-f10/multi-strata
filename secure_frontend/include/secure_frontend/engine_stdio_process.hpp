#pragma once

#include "secure_frontend/engine_process.hpp"
#include "secure_frontend/engine_protocol_client.hpp"

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>

namespace secure_frontend {

// Owns a Strata --serve child and provides its line-delimited stdin/stdout
// protocol.  It deliberately starts a supplied executable directly, with an
// environment allowlist, and never invokes a shell.
class EngineStdioProcess final : public EngineLineTransport {
 public:
  static constexpr std::size_t kMaxReadLineBytes = 8192;              // engine → frontend records are short
  static constexpr std::size_t kMaxWriteLineBytes = 16U * 1024U * 1024U;  // GEN line; bounded above by the protocol client

  EngineStdioProcess() = default;
  ~EngineStdioProcess() override;
  EngineStdioProcess(const EngineStdioProcess&) = delete;
  EngineStdioProcess& operator=(const EngineStdioProcess&) = delete;

  // Inserts the literal --serve argument immediately after the executable. The
  // caller must not supply it; this placement is required by the GLM runner
  // and is accepted by the original Strata command-line parser.
  [[nodiscard]] std::optional<ProcessError> start(const EngineCommand& command);
  [[nodiscard]] bool running();
  [[nodiscard]] bool terminate(std::chrono::milliseconds grace);

  [[nodiscard]] bool write_line(std::string_view line, std::string& error) override;
  [[nodiscard]] EngineReadResult read_line(std::chrono::milliseconds timeout) override;

#if !defined(_WIN32)
  // Test seam: the POSIX child pid, so tests can inspect /proc/<pid> after terminate.
  [[nodiscard]] int pid_for_tests() const noexcept { return process_id_; }
#endif

 private:
#if defined(_WIN32)
  void* process_handle_{nullptr};
  void* job_handle_{nullptr};
  void* stdin_write_{nullptr};
  void* stdout_read_{nullptr};
#else
  int process_id_{-1};
  int stdin_write_{-1};
  int stdout_read_{-1};
#endif
  std::string pending_stdout_;

  void cleanup() noexcept;
};

}  // namespace secure_frontend

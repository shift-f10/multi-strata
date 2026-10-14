#pragma once

#include <chrono>
#include <cstdint>

namespace secure_frontend {

// "Nothing to monitor": no pidfd (POSIX) or no process handle (Windows).
inline constexpr std::intptr_t kNoMonitorHandle = -1;

// The supervisor thread's single wait point: a non-blocking self-pipe (POSIX)
// or a manual-reset event (Windows) fired by report_fatal(), shutdown() and
// the shutdown signal handlers, optionally waited on together with the
// engine's pidfd / process handle.
class SupervisorWake final {
 public:
  enum class Event { woken, monitored, timeout };

  SupervisorWake();
  ~SupervisorWake();
  SupervisorWake(const SupervisorWake&) = delete;
  SupervisorWake& operator=(const SupervisorWake&) = delete;

  // Async-signal-safe on POSIX (a single write(2)); SetEvent on Windows.
  void notify() noexcept;
  // Waits for notify(), for `monitored` to become signalled (pidfd readable /
  // process handle signalled; kNoMonitorHandle = none), or for `timeout`
  // (negative = forever). A signal that interrupts the wait reports `woken`.
  [[nodiscard]] Event wait(std::intptr_t monitored, std::chrono::milliseconds timeout) noexcept;

 private:
  void drain() noexcept;
#if defined(_WIN32)
  void* event_{nullptr};
#else
  int read_fd_{-1};
  int write_fd_{-1};
#endif
};

}  // namespace secure_frontend

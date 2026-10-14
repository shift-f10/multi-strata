#include "secure_frontend/shutdown_signal.hpp"

#include <atomic>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"

#include <mutex>
#else
#include <cerrno>
#include <csignal>
#endif

namespace secure_frontend {
namespace {

std::atomic<SupervisorWake*> g_wake{nullptr};
static_assert(std::atomic<SupervisorWake*>::is_always_lock_free, "the signal handler needs a lock-free pointer");

#if defined(_WIN32)
std::atomic<bool> g_signalled{false};
HANDLE g_done = nullptr;
// The console handler runs on its own thread (not in signal context), so it
// may lock: release_shutdown_signals() never returns while it uses the wake.
std::mutex g_wake_mutex;

// Runs on a thread the system creates for the event.
BOOL WINAPI on_console_event(const DWORD type) {
  if (type != CTRL_C_EVENT && type != CTRL_BREAK_EVENT && type != CTRL_CLOSE_EVENT) return FALSE;
  g_signalled.store(true);
  {
    std::lock_guard lock(g_wake_mutex);
    if (auto* wake = g_wake.load()) wake->notify();
  }
  // Keep the process alive while the orderly shutdown runs (CTRL_CLOSE ends it
  // when we return); the supervisor sets g_done once every engine is gone.
  if (g_done != nullptr) (void)WaitForSingleObject(g_done, 5000);
  return TRUE;
}
#else
volatile std::sig_atomic_t g_signalled = 0;

void on_signal(int) {
  const int saved_errno = errno;
  g_signalled = 1;
  if (auto* wake = g_wake.load()) wake->notify();  // one write(2): async-signal-safe
  errno = saved_errno;
}
#endif

}  // namespace

void install_shutdown_signals(SupervisorWake& wake) noexcept {
  g_wake.store(&wake);
#if defined(_WIN32)
  if (g_done == nullptr) g_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  (void)SetConsoleCtrlHandler(on_console_event, TRUE);
#else
  struct sigaction action {};
  action.sa_handler = on_signal;
  sigemptyset(&action.sa_mask);
  action.sa_flags = 0;  // no SA_RESTART: a blocked accept() on the main thread returns EINTR
  (void)sigaction(SIGTERM, &action, nullptr);
  (void)sigaction(SIGINT, &action, nullptr);
#endif
}

// POSIX: called after the supervisor thread is joined, so a handler can only
// run on the calling thread, entirely before or after the exchange.
void release_shutdown_signals(const SupervisorWake& wake) noexcept {
#if defined(_WIN32)
  std::lock_guard lock(g_wake_mutex);
#endif
  SupervisorWake* expected = const_cast<SupervisorWake*>(&wake);
  (void)g_wake.compare_exchange_strong(expected, nullptr);
}

bool shutdown_signalled() noexcept {
#if defined(_WIN32)
  return g_signalled.load();
#else
  return g_signalled != 0;
#endif
}

void notify_shutdown_complete() noexcept {
#if defined(_WIN32)
  if (g_done != nullptr) (void)SetEvent(g_done);
#endif
}

}  // namespace secure_frontend

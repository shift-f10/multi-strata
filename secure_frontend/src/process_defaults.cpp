#include "secure_frontend/process_defaults.hpp"

#if !defined(_WIN32)
#include <csignal>
#endif

namespace secure_frontend {

void install_process_defaults() noexcept {
#if !defined(_WIN32)
  struct sigaction action {};
  action.sa_handler = SIG_IGN;
  sigemptyset(&action.sa_mask);
  (void)sigaction(SIGPIPE, &action, nullptr);
#endif
}

}  // namespace secure_frontend

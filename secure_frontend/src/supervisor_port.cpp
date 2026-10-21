#include "secure_frontend/generation_gate.hpp"

namespace secure_frontend {

HealthSnapshot SupervisorPort::snapshot() {
  std::lock_guard lock(mutex_);
  return supervisor_.snapshot();
}

std::optional<Lease> SupervisorPort::acquire() {
  std::lock_guard lock(mutex_);
  return supervisor_.acquire();
}

void SupervisorPort::report_fatal(const Lease& lease, const KillReason reason) {
  std::lock_guard lock(mutex_);
  supervisor_.report_fatal(lease, reason);
}

}  // namespace secure_frontend

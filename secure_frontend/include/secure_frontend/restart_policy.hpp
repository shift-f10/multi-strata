#pragma once

#include "secure_frontend/supervision_defaults.hpp"

#include <chrono>
#include <cstdint>

namespace secure_frontend {

// Spec §3.3 restart policy. Defaults come from supervision_defaults.hpp; SP1
// turns them into typed configuration.
struct RestartPolicy final {
  std::uint32_t max_consecutive_failures{supervision_defaults::kMaxConsecutiveFailures};
  std::chrono::milliseconds backoff_initial{supervision_defaults::kBackoffInitial};
  std::uint32_t backoff_factor{supervision_defaults::kBackoffFactor};
  std::chrono::milliseconds backoff_max{supervision_defaults::kBackoffMax};
  std::chrono::milliseconds healthy_window{supervision_defaults::kHealthyWindow};
  std::chrono::milliseconds ready_timeout{supervision_defaults::kReadyTimeout};
  std::chrono::milliseconds reap_timeout{supervision_defaults::kReapTimeout};
};

struct RestartDecision final {
  bool circuit_open{false};
  std::chrono::milliseconds delay{0};
  std::uint32_t consecutive_failures{0};
};

// Spec §3.3: a failure is any unrequested end, every §3.5 kill and any spawn
// failure. Delays grow initial * factor^(n-1), capped at backoff_max; the
// max_consecutive_failures-th failure opens the circuit for good.
class RestartTracker final {
 public:
  explicit RestartTracker(RestartPolicy policy) noexcept : policy_(policy) {}
  // `healthy_for` is the ended generation's continuous ready/generating time
  // (zero for spawn failures and generations that never became ready);
  // reaching healthy_window first resets the count to 0.
  [[nodiscard]] RestartDecision record_failure(std::chrono::milliseconds healthy_for) noexcept;
  [[nodiscard]] std::uint32_t consecutive_failures() const noexcept { return failures_; }

 private:
  RestartPolicy policy_;
  std::uint32_t failures_{0};
};

}  // namespace secure_frontend

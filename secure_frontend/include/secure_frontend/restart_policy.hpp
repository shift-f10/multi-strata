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

}  // namespace secure_frontend

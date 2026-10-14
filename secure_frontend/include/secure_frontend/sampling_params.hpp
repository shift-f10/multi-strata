#pragma once

#include <cstdint>
#include <optional>

namespace secure_frontend {

// Decision B6 option (e): the only sampling keys passed to the engine's GEN
// line, each already bounded by the chat schema. Absent = the engine default
// (greedy).
struct SamplingParams final {
  std::optional<double> temperature;   // 0..2
  std::optional<double> top_p;         // (0, 1]
  std::optional<std::uint64_t> seed;   // 0..2^63-1
  [[nodiscard]] bool empty() const noexcept { return !temperature && !top_p && !seed; }
};

}  // namespace secure_frontend

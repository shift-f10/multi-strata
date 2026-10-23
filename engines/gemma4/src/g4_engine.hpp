// strata-gemma4-engine: the inference engine (plan Task 6). One session: the held tokens'
// KV state, read by `process` (prompt chunks or one decode step) and continued or truncated
// by the serve loop's reuse rule.
#pragma once

#include "g4_model.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace g4 {

struct EngineConfig final {
  std::string model;
  int max_context{32768};
  int chunk{512};
  double expert_vram_gib{-1.0};  // -1: the free VRAM after everything else, less a reserve
  int expert_slots{0};           // 0: from the budget
};

struct LoadReport final {
  int slots_per_layer{0};
  double resident_pct{0.0};
  double vram_used_mib{0.0};
  double vram_total_mib{0.0};
  double pinned_gib{0.0};
  double load_seconds{0.0};
  int ring_rows{0};
};

class Engine {
 public:
  virtual ~Engine() = default;
  // Loads the model (checked by check_model) onto the current CUDA device. nullptr and a
  // fixed `error` on failure.
  [[nodiscard]] static std::unique_ptr<Engine> create(const EngineConfig& config, const ModelDesc& model, std::string& error);

  [[nodiscard]] virtual int context() const = 0;
  [[nodiscard]] virtual int ring_spare() const = 0;  // sliding-ring rows beyond the window (reuse rule)
  [[nodiscard]] virtual int position() const = 0;    // tokens held
  // Keeps the first `p` held positions (p <= position()); the serve loop's reuse rule
  // decides when that is exact.
  virtual void truncate(int p) = 0;
  // Reads `n` tokens at position(): one decode step for n == 1, else prompt chunks of at most
  // `chunk` tokens; `progress(done)` after each chunk may return false to stop between chunks.
  // Returns the tokens read; -1 on a CUDA failure (the engine is then unusable).
  virtual int process(const std::int32_t* ids, int n, const std::function<bool(int)>& progress) = 0;
  // The last read position's logits (soft-capped).
  virtual bool logits(std::vector<float>& out) = 0;
  virtual int greedy() = 0;  // argmax of those logits; -1 on failure, -2 when they are not finite
  // Moves VRAM expert slots toward the most-routed experts (at most `max_swaps` copies).
  virtual void rebalance(int max_swaps) = 0;
  // Test hook: every read position's layer outputs land in sink[(pos*30 + layer)*2816 ...].
  virtual void set_layer_sink(std::vector<float>* sink) = 0;
  [[nodiscard]] virtual LoadReport report() const = 0;
};

}  // namespace g4

// strata-unified-engine: u::ExpertTier -- the ONE shared expert-placement facility
// for every family (design 2026-10-23 s3.5). It replaces each engine's ad-hoc MoE
// placement with a single hybrid VRAM/RAM tier plus an expert-hit profile:
//
//   * pin all experts in host RAM (an arena the family fills from the GGUF), and
//     keep S VRAM slots that hold the hottest experts;
//   * WARM-START: at load, fill each layer's slots from a committed-or-saved
//     profile, hottest first, so decode AND prefill are fast from the first token
//     (not after a live rebalance converges -- gemma4's weakness, s3.5);
//   * learn one: --expert-profile-save dumps the decayed routing scores as a
//     per-model profile; a later start reads it (`read_expert_profile`);
//   * LIVE REBALANCE: between rounds, swap the most-routed non-resident experts
//     into the coldest resident slots, as the correction on top of the warm start;
//   * compute(layer, ids, weights, x) -> out: run the routed experts' FFN, the
//     resident ones from VRAM and the rest streamed from the host arena, SwiGLU
//     them and combine by the router weights (+ an optional shared expert).
//
// Ported from Maya's expert_cache.{hpp,cpp} (the slot storage, residency table,
// per-layer admission, profile format STRP, warm-start fill) and
// expert_source.hpp (pin-all-in-RAM arena, the resident/non-resident split by
// router index). Trimmed to the lean single facility; the DMA-overlap/PCIe-share
// perf machinery and the prefill multi-token dispatch are left for the GPU box.
//
// This header is pure C++ (device memory is held as void*/uint8_t*), so it is only
// compiled into the CUDA build (u_experts.cu, behind STRATA_U_CUDA); family graphs
// include it to place and run their experts.
#pragma once

#include "kernels/common.cuh"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace u {

inline constexpr std::int32_t kNotResident = -1;

// ---- the expert-hit profile (format byte-for-byte Maya's tools/make_profile.py:
// "STRP", then uint32 {version, n_layers, n_expert, slots, n_ranked}, then n_ranked
// (uint16 layer, uint16 expert) pairs ranked by descending routing frequency, then
// an n_layers*n_expert int32 table of each pair's rank (-1 = not ranked)). ----

// Reads `path` for `n_layers`x`n_expert`; fills `ranked` (hottest first) and the
// profile's own `slots`. False with `err` on any mismatch (fail closed).
[[nodiscard]] bool read_expert_profile(const std::string& path, std::int64_t n_layers, std::int64_t n_expert,
                                       std::vector<std::pair<std::int32_t, std::int32_t>>& ranked,
                                       std::int64_t& slots, std::string& err);

// Writes `ranked` in that format, atomically (a .tmp renamed over `path`).
[[nodiscard]] bool write_expert_profile(const std::string& path, std::int64_t n_layers, std::int64_t n_expert,
                                        const std::vector<std::pair<std::int32_t, std::int32_t>>& ranked,
                                        std::string& err);

// Ranks EVERY (layer, expert): the experts resident now first (where the swaps
// left the tier), then the rest; within each, by `heat` (decayed routing counts,
// descending), then by `prior` (the profile this run started from), then by index.
// `resident` and `heat` are n_layers*n_expert (`heat` may be empty: the prior
// decides). Maya expert_cache.cpp rank_learned_profile.
[[nodiscard]] std::vector<std::pair<std::int32_t, std::int32_t>> rank_learned_profile(
    std::int64_t n_layers, std::int64_t n_expert, const std::vector<std::uint8_t>& resident,
    const std::vector<double>& heat, const std::vector<std::pair<std::int32_t, std::int32_t>>& prior);

class ExpertTier {
 public:
  // The gated FFN activation the family uses between up/gate and the down
  // projection. A shared facility must offer all three: GLM/raon1 clamp, qwen is
  // plain SwiGLU, gemma4 is GeGLU.
  enum class Act { swiglu, swiglu_clamped, geglu };

  // The MoE geometry and the expert blob layout. Every expert's bytes are one
  // contiguous blob of `blob_bytes`, holding gate[n_ff,n_embd], up[n_ff,n_embd]
  // and down[n_embd,n_ff] at the given offsets, each in its quant format. (A
  // shared expert, when present, is blob index `n_expert` of its layer.)
  struct Config {
    std::int64_t n_layers = 0;
    std::int64_t n_expert = 0;   // routed experts per layer
    std::int64_t n_embd = 0;     // hidden width
    std::int64_t n_ff = 0;       // expert (MoE) intermediate width
    k::Quant gate = k::Quant::q4_k;
    k::Quant up = k::Quant::q4_k;
    k::Quant down = k::Quant::q6_k;
    Act act = Act::swiglu;       // gated activation (GLM/raon1 => swiglu_clamped)
    float act_limit = 10.0f;     // the swiglu_clamped limit (config's swiglu_limit)
    std::int64_t gate_off = 0;   // byte offset of each matrix inside a blob
    std::int64_t up_off = 0;
    std::int64_t down_off = 0;
    std::int64_t blob_bytes = 0; // bytes of one expert blob (gate+up+down, padded)
    std::int64_t vram_slots = 0; // S total VRAM slots (0 = all experts stream from RAM)
    bool per_layer_admission = true;
    bool has_shared_expert = false;
  };

  ExpertTier() = default;
  ~ExpertTier();
  ExpertTier(const ExpertTier&) = delete;
  ExpertTier& operator=(const ExpertTier&) = delete;

  // Allocates the VRAM slot arena, the residency table and the decode scratch,
  // and checks the allocation against the card. False with `err` on a bad config
  // or an allocation short of what was asked for.
  [[nodiscard]] bool open(const Config& cfg, std::string& err);
  void close();
  [[nodiscard]] bool valid() const { return opened_; }

  // The host arena: `base` holds every expert blob, pinned (the family mmaps/reads
  // the GGUF into it; ExpertTier best-effort cudaHostRegisters it for DMA). Blob
  // (layer, expert) is at `base + blob_index(layer, expert) * blob_bytes`, with a
  // shared expert at expert index n_expert. `bytes` is the arena size for the
  // registration and bounds check.
  [[nodiscard]] bool set_host_arena(const std::uint8_t* base, std::int64_t bytes, std::string& err);

  // WARM START: fill the VRAM slots from `ranked` (hottest first), per-layer. Runs
  // blocking host->device copies and verifies each slot. Call once after
  // set_host_arena. An empty `ranked` leaves the tier cold (streams everything).
  [[nodiscard]] bool warm_start(const std::vector<std::pair<std::int32_t, std::int32_t>>& ranked,
                                std::string& err);

  // Residency query: (layer, expert) -> slot or kNotResident. Bounds-checked.
  [[nodiscard]] std::int32_t slot_of(std::int64_t layer, std::int64_t expert) const;
  [[nodiscard]] std::int64_t resident_count() const { return admitted_; }
  [[nodiscard]] std::int64_t slots() const { return vram_slots_; }

  // LIVE REBALANCE. `note_routing` decays the per-(layer,expert) usage and bumps
  // the layer's routed ids (call each decode step). `rebalance` then, per layer,
  // swaps a non-resident expert whose usage exceeds the coldest resident's (by the
  // margin) into that slot, re-filling it from the host arena on `stream`. Returns
  // the number of swaps, or -1 with `err`.
  void note_routing(std::int64_t layer, const std::int32_t* ids, std::int64_t k);
  [[nodiscard]] std::int64_t rebalance(float margin, void* stream, std::string& err);

  // COMPUTE one token's MoE FFN:
  //   out[n_embd] = sum_{i<k} weights[i] * down(silu(gate(x)) * up(x))[expert ids[i]]
  //                 (+ the shared expert when configured).
  // `ids` and `weights` are HOST arrays of length k (k <= 64); `x` and `out` are
  // DEVICE [n_embd]. Resident experts are read from their VRAM slot, non-resident
  // ones streamed from the host arena into a reused staging slot (ordered on
  // `stream`). All work enqueues on `stream`. False with `err` on a bad call.
  [[nodiscard]] bool compute(std::int64_t layer, const std::int32_t* ids, const float* weights,
                             const float* x, float* out, std::int64_t k, void* stream, std::string& err);

  // Save what the tier learned (warm-start prior + live routing) as a profile.
  [[nodiscard]] bool save_profile(const std::string& path, std::string& err) const;

  // For the INFO line / startup report.
  [[nodiscard]] std::int64_t fills() const { return fills_; }
  [[nodiscard]] std::int64_t stream_misses() const { return stream_misses_; }

 private:
  std::int64_t blob_index(std::int64_t layer, std::int64_t expert) const;  // into the host arena
  void layer_slot_range(std::int64_t layer, std::int64_t& lo, std::int64_t& hi) const;
  std::int32_t admit(std::int64_t layer, std::int64_t expert);  // next free slot or kNotResident
  bool fill_slot_blocking(std::int32_t slot, std::int64_t layer, std::int64_t expert, std::string& err);

  Config cfg_{};
  bool opened_ = false;
  bool host_registered_ = false;

  const std::uint8_t* host_base_ = nullptr;  // the pinned RAM arena (family-owned)
  std::int64_t host_bytes_ = 0;

  std::uint8_t* vram_base_ = nullptr;        // S slots of blob_bytes, device
  std::int64_t vram_slots_ = 0;
  std::vector<std::int32_t> residency_;      // [n_layers*n_expert] -> slot or -1
  std::vector<std::int64_t> layer_next_;     // per-layer next free slot (per-layer admission)
  std::int64_t next_free_ = 0;               // global next free (when not per-layer)
  std::int64_t admitted_ = 0;
  std::int64_t fills_ = 0;
  std::int64_t stream_misses_ = 0;

  std::vector<double> usage_;                // [n_layers*n_expert] decayed routing counts
  std::vector<std::pair<std::int32_t, std::int32_t>> prior_;  // the profile this run started from

  // decode scratch (device), sized in open()
  std::uint8_t* d_stage_ = nullptr;          // one blob, reused for non-resident experts
  void* d_xq8_embd_ = nullptr;               // Q8_1 of x (n_embd)
  void* d_hq8_ = nullptr;                     // Q8_1 of h (n_ff)
  float* d_g_ = nullptr;                      // gate output [n_ff]
  float* d_u_ = nullptr;                      // up output   [n_ff]
  float* d_h_ = nullptr;                      // silu(g)*u   [n_ff]
  float* d_parts_ = nullptr;                  // [(k_max) * n_embd]
  float* d_shared_ = nullptr;                 // shared expert output [n_embd]
  float* d_weights_ = nullptr;                // [k_max]
  std::int64_t k_max_ = 64;
};

}  // namespace u

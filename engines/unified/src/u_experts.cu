// strata-unified-engine: u::ExpertTier implementation (see u_experts.hpp).
//
// Ported from Maya's expert_cache.{hpp,cpp} (slot storage, residency table,
// per-layer admission, the STRP profile format, warm-start fill) and
// expert_source.hpp (pin-all-in-RAM arena; the resident/non-resident split).
// Trimmed to the one lean facility: single-token decode compute, a reused
// staging slot for non-resident experts, and a simple usage-driven rebalance.
// The DMA/PCIe-overlap machinery and the multi-token (prefill) dispatch in Maya
// are deliberately left for the GPU box.
#include "u_experts.hpp"

#include "kernels/common.cuh"

#include <cuda_runtime.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace u {
namespace {

constexpr char kMagic[4] = {'S', 'T', 'R', 'P'};
constexpr std::uint32_t kProfileVersion = 1;
constexpr float kDecay = 0.999f;  // per-step decay of the routing usage counts

bool read_u32(std::ifstream& in, std::uint32_t& v) {
  return static_cast<bool>(in.read(reinterpret_cast<char*>(&v), 4));
}

}  // namespace

// ================================ profile I/O ================================

bool read_expert_profile(const std::string& path, std::int64_t n_layers, std::int64_t n_expert,
                         std::vector<std::pair<std::int32_t, std::int32_t>>& ranked, std::int64_t& slots,
                         std::string& err) {
  ranked.clear();
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    err = "expert profile: cannot open " + path;
    return false;
  }
  char magic[4];
  if (!in.read(magic, 4) || std::memcmp(magic, kMagic, 4) != 0) {
    err = "expert profile: bad magic (not STRP)";
    return false;
  }
  std::uint32_t version = 0, nl = 0, ne = 0, slots_field = 0, n_ranked = 0;
  if (!read_u32(in, version) || !read_u32(in, nl) || !read_u32(in, ne) || !read_u32(in, slots_field) ||
      !read_u32(in, n_ranked)) {
    err = "expert profile: truncated header";
    return false;
  }
  if (version != kProfileVersion) {
    err = "expert profile: unsupported version";
    return false;
  }
  if ((std::int64_t)nl != n_layers || (std::int64_t)ne != n_expert) {
    err = "expert profile: shape mismatch (layers/experts)";
    return false;
  }
  if ((std::int64_t)n_ranked > n_layers * n_expert) {
    err = "expert profile: n_ranked exceeds layers*experts";
    return false;
  }
  ranked.reserve(n_ranked);
  for (std::uint32_t i = 0; i < n_ranked; ++i) {
    std::uint16_t layer = 0, expert = 0;
    if (!in.read(reinterpret_cast<char*>(&layer), 2) || !in.read(reinterpret_cast<char*>(&expert), 2)) {
      err = "expert profile: truncated ranked pairs";
      return false;
    }
    if (layer >= nl || expert >= ne) {
      err = "expert profile: a ranked pair is out of range";
      return false;
    }
    ranked.emplace_back((std::int32_t)layer, (std::int32_t)expert);
  }
  // The trailing frequency/rank table is the profile's own working; the tier
  // measures heat by running, so it is not read back (Maya expert_cache.hpp).
  slots = (std::int64_t)slots_field;
  return true;
}

bool write_expert_profile(const std::string& path, std::int64_t n_layers, std::int64_t n_expert,
                          const std::vector<std::pair<std::int32_t, std::int32_t>>& ranked, std::string& err) {
  const std::string tmp = path + ".tmp";
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) {
      err = "expert profile: cannot write " + tmp;
      return false;
    }
    out.write(kMagic, 4);
    const std::uint32_t n_ranked = (std::uint32_t)ranked.size();
    const std::uint32_t hdr[5] = {kProfileVersion, (std::uint32_t)n_layers, (std::uint32_t)n_expert, n_ranked,
                                  n_ranked};
    out.write(reinterpret_cast<const char*>(hdr), sizeof(hdr));
    for (const auto& [layer, expert] : ranked) {
      const std::uint16_t l = (std::uint16_t)layer, e = (std::uint16_t)expert;
      out.write(reinterpret_cast<const char*>(&l), 2);
      out.write(reinterpret_cast<const char*>(&e), 2);
    }
    // the n_layers*n_expert int32 rank table (-1 = not ranked)
    std::vector<std::int32_t> table((std::size_t)(n_layers * n_expert), -1);
    for (std::size_t r = 0; r < ranked.size(); ++r) {
      const std::int64_t idx = (std::int64_t)ranked[r].first * n_expert + ranked[r].second;
      if (idx >= 0 && idx < (std::int64_t)table.size()) table[(std::size_t)idx] = (std::int32_t)r;
    }
    out.write(reinterpret_cast<const char*>(table.data()), (std::streamsize)(table.size() * sizeof(std::int32_t)));
    if (!out) {
      err = "expert profile: write failed";
      return false;
    }
  }
  std::remove(path.c_str());
  if (std::rename(tmp.c_str(), path.c_str()) != 0) {
    err = "expert profile: rename over target failed";
    return false;
  }
  return true;
}

std::vector<std::pair<std::int32_t, std::int32_t>> rank_learned_profile(
    std::int64_t n_layers, std::int64_t n_expert, const std::vector<std::uint8_t>& resident,
    const std::vector<double>& heat, const std::vector<std::pair<std::int32_t, std::int32_t>>& prior) {
  const std::int64_t n = n_layers * n_expert;
  std::vector<std::int32_t> prior_rank((std::size_t)n, (std::int32_t)n);  // absent => last
  for (std::size_t r = 0; r < prior.size(); ++r) {
    const std::int64_t idx = (std::int64_t)prior[r].first * n_expert + prior[r].second;
    if (idx >= 0 && idx < n) prior_rank[(std::size_t)idx] = (std::int32_t)r;
  }
  std::vector<std::int64_t> order((std::size_t)n);
  for (std::int64_t i = 0; i < n; ++i) order[(std::size_t)i] = i;
  auto res = [&](std::int64_t i) { return (std::size_t)i < resident.size() ? resident[(std::size_t)i] : 0; };
  auto hot = [&](std::int64_t i) { return (std::size_t)i < heat.size() ? heat[(std::size_t)i] : 0.0; };
  std::stable_sort(order.begin(), order.end(), [&](std::int64_t a, std::int64_t b) {
    if (res(a) != res(b)) return res(a) > res(b);          // resident first
    if (hot(a) != hot(b)) return hot(a) > hot(b);          // then hotter
    if (prior_rank[(std::size_t)a] != prior_rank[(std::size_t)b])
      return prior_rank[(std::size_t)a] < prior_rank[(std::size_t)b];  // then the old place
    return a < b;                                          // then index
  });
  std::vector<std::pair<std::int32_t, std::int32_t>> ranked;
  ranked.reserve((std::size_t)n);
  for (std::int64_t idx : order)
    ranked.emplace_back((std::int32_t)(idx / n_expert), (std::int32_t)(idx % n_expert));
  return ranked;
}

// ================================ ExpertTier ================================

ExpertTier::~ExpertTier() { close(); }

std::int64_t ExpertTier::blob_index(std::int64_t layer, std::int64_t expert) const {
  const std::int64_t stride = cfg_.n_expert + (cfg_.has_shared_expert ? 1 : 0);
  return layer * stride + expert;
}

void ExpertTier::layer_slot_range(std::int64_t layer, std::int64_t& lo, std::int64_t& hi) const {
  if (!cfg_.per_layer_admission) {
    lo = 0;
    hi = vram_slots_;
    return;
  }
  const std::int64_t q = cfg_.n_layers > 0 ? vram_slots_ / cfg_.n_layers : 0;
  lo = layer * q;
  hi = (layer == cfg_.n_layers - 1) ? vram_slots_ : (layer + 1) * q;
}

std::int32_t ExpertTier::slot_of(std::int64_t layer, std::int64_t expert) const {
  if (layer < 0 || layer >= cfg_.n_layers || expert < 0 || expert >= cfg_.n_expert) return kNotResident;
  return residency_[(std::size_t)(layer * cfg_.n_expert + expert)];
}

std::int32_t ExpertTier::admit(std::int64_t layer, std::int64_t expert) {
  if (layer < 0 || layer >= cfg_.n_layers || expert < 0 || expert >= cfg_.n_expert) return kNotResident;
  const std::size_t ri = (std::size_t)(layer * cfg_.n_expert + expert);
  if (residency_[ri] != kNotResident) return residency_[ri];
  std::int64_t lo = 0, hi = 0;
  layer_slot_range(layer, lo, hi);
  std::int64_t& next = cfg_.per_layer_admission ? layer_next_[(std::size_t)layer] : next_free_;
  if (next < lo) next = lo;
  if (next >= hi) return kNotResident;  // this layer's slots are full; never evicts here (warm start)
  const std::int32_t slot = (std::int32_t)next++;
  residency_[ri] = slot;
  ++admitted_;
  return slot;
}

bool ExpertTier::fill_slot_blocking(std::int32_t slot, std::int64_t layer, std::int64_t expert,
                                    std::string& err) {
  const std::uint8_t* src = host_base_ + blob_index(layer, expert) * cfg_.blob_bytes;
  std::uint8_t* dst = vram_base_ + (std::int64_t)slot * cfg_.blob_bytes;
  const cudaError_t e = cudaMemcpy(dst, src, (std::size_t)cfg_.blob_bytes, cudaMemcpyHostToDevice);
  if (e != cudaSuccess) {
    err = std::string("expert tier: slot fill failed: ") + cudaGetErrorString(e);
    return false;
  }
  ++fills_;
  return true;
}

bool ExpertTier::open(const Config& cfg, std::string& err) {
  if (opened_) {
    err = "expert tier: already open";
    return false;
  }
  if (cfg.n_layers <= 0 || cfg.n_expert <= 0 || cfg.n_embd <= 0 || cfg.n_ff <= 0 || cfg.blob_bytes <= 0) {
    err = "expert tier: bad geometry (layers/experts/embd/ff/blob_bytes must be > 0)";
    return false;
  }
  if (cfg.vram_slots < 0 || cfg.vram_slots > cfg.n_layers * cfg.n_expert) {
    err = "expert tier: vram_slots out of range";
    return false;
  }
  if (cfg.n_embd % 32 != 0 || cfg.n_ff % 32 != 0) {
    err = "expert tier: n_embd and n_ff must be multiples of 32 (Q8_1 activation)";
    return false;
  }
  cfg_ = cfg;
  vram_slots_ = cfg.vram_slots;
  residency_.assign((std::size_t)(cfg.n_layers * cfg.n_expert), kNotResident);
  layer_next_.assign((std::size_t)cfg.n_layers, 0);
  usage_.assign((std::size_t)(cfg.n_layers * cfg.n_expert), 0.0);
  next_free_ = 0;
  admitted_ = 0;
  fills_ = 0;
  stream_misses_ = 0;

  // VRAM slot arena (checked against the card: a short allocation would report
  // hits for slots it does not hold -- Maya ExpertCache::open).
  if (vram_slots_ > 0) {
    const std::size_t bytes = (std::size_t)vram_slots_ * (std::size_t)cfg.blob_bytes;
    if (cudaMalloc(reinterpret_cast<void**>(&vram_base_), bytes) != cudaSuccess) {
      err = "expert tier: cudaMalloc for the VRAM slots failed (" + std::to_string(bytes) + " bytes)";
      return false;
    }
  }

  // decode scratch
  const std::size_t q8_embd = k::q8_1_scratch_bytes((int)cfg.n_embd, 1);
  const std::size_t q8_ff = k::q8_1_scratch_bytes((int)cfg.n_ff, 1);
  bool ok = cudaMalloc(reinterpret_cast<void**>(&d_stage_), (std::size_t)cfg.blob_bytes) == cudaSuccess;
  ok = ok && cudaMalloc(&d_xq8_embd_, q8_embd) == cudaSuccess;
  ok = ok && cudaMalloc(&d_hq8_, q8_ff) == cudaSuccess;
  ok = ok && cudaMalloc(reinterpret_cast<void**>(&d_g_), (std::size_t)cfg.n_ff * sizeof(float)) == cudaSuccess;
  ok = ok && cudaMalloc(reinterpret_cast<void**>(&d_u_), (std::size_t)cfg.n_ff * sizeof(float)) == cudaSuccess;
  ok = ok && cudaMalloc(reinterpret_cast<void**>(&d_h_), (std::size_t)cfg.n_ff * sizeof(float)) == cudaSuccess;
  ok = ok && cudaMalloc(reinterpret_cast<void**>(&d_parts_),
                        (std::size_t)k_max_ * cfg.n_embd * sizeof(float)) == cudaSuccess;
  ok = ok && cudaMalloc(reinterpret_cast<void**>(&d_weights_), (std::size_t)k_max_ * sizeof(float)) == cudaSuccess;
  if (cfg.has_shared_expert)
    ok = ok && cudaMalloc(reinterpret_cast<void**>(&d_shared_), (std::size_t)cfg.n_embd * sizeof(float)) == cudaSuccess;
  if (!ok) {
    err = "expert tier: cudaMalloc for the decode scratch failed";
    close();
    return false;
  }
  opened_ = true;
  return true;
}

bool ExpertTier::set_host_arena(const std::uint8_t* base, std::int64_t bytes, std::string& err) {
  if (!opened_) {
    err = "expert tier: set_host_arena before open";
    return false;
  }
  if (!base || bytes <= 0) {
    err = "expert tier: null/empty host arena";
    return false;
  }
  const std::int64_t stride = cfg_.n_expert + (cfg_.has_shared_expert ? 1 : 0);
  const std::int64_t need = cfg_.n_layers * stride * cfg_.blob_bytes;
  if (bytes < need) {
    err = "expert tier: host arena smaller than the expert layout needs";
    return false;
  }
  host_base_ = base;
  host_bytes_ = bytes;
  // Best-effort page-lock + register for DMA; a failure just means the async
  // staging copy falls back to a pageable copy (slower, still correct).
  if (cudaHostRegister(const_cast<std::uint8_t*>(base), (std::size_t)bytes, cudaHostRegisterDefault) ==
      cudaSuccess)
    host_registered_ = true;
  else
    cudaGetLastError();  // clear the sticky error
  return true;
}

bool ExpertTier::warm_start(const std::vector<std::pair<std::int32_t, std::int32_t>>& ranked,
                            std::string& err) {
  if (!opened_ || !host_base_) {
    err = "expert tier: warm_start before open/set_host_arena";
    return false;
  }
  prior_ = ranked;
  std::fill(residency_.begin(), residency_.end(), kNotResident);
  std::fill(layer_next_.begin(), layer_next_.end(), 0);
  next_free_ = 0;
  admitted_ = 0;
  if (vram_slots_ == 0) return true;  // cold tier: everything streams from RAM
  for (const auto& [layer, expert] : ranked) {
    const std::int32_t slot = admit(layer, expert);
    if (slot == kNotResident) continue;  // that layer's slots are full; others may still have room
    if (!fill_slot_blocking(slot, layer, expert, err)) return false;
  }
  return true;
}

void ExpertTier::note_routing(std::int64_t layer, const std::int32_t* ids, std::int64_t k) {
  if (!opened_ || layer < 0 || layer >= cfg_.n_layers || usage_.empty()) return;
  double* row = usage_.data() + layer * cfg_.n_expert;
  for (std::int64_t e = 0; e < cfg_.n_expert; ++e) row[e] *= kDecay;
  for (std::int64_t i = 0; i < k; ++i) {
    const std::int32_t e = ids[i];
    if (e >= 0 && e < cfg_.n_expert) row[e] += 1.0;
  }
}

std::int64_t ExpertTier::rebalance(float margin, void* stream, std::string& err) {
  if (!opened_ || !host_base_ || vram_slots_ == 0) return 0;
  std::int64_t swaps = 0;
  const auto s = static_cast<cudaStream_t>(stream);
  for (std::int64_t layer = 0; layer < cfg_.n_layers; ++layer) {
    const double* row = usage_.data() + layer * cfg_.n_expert;
    // Repeatedly swap the hottest non-resident expert into the coldest resident
    // slot while the gain clears `margin` (bounded by n_expert iterations).
    for (std::int64_t iter = 0; iter < cfg_.n_expert; ++iter) {
      std::int64_t cold_e = -1, hot_e = -1;
      double cold_v = 0.0, hot_v = -1.0;
      for (std::int64_t e = 0; e < cfg_.n_expert; ++e) {
        const bool resident = residency_[(std::size_t)(layer * cfg_.n_expert + e)] != kNotResident;
        if (resident) {
          if (cold_e < 0 || row[e] < cold_v) { cold_v = row[e]; cold_e = e; }
        } else {
          if (row[e] > hot_v) { hot_v = row[e]; hot_e = e; }
        }
      }
      if (cold_e < 0 || hot_e < 0 || hot_v <= cold_v + (double)margin) break;
      const std::int32_t slot = residency_[(std::size_t)(layer * cfg_.n_expert + cold_e)];
      residency_[(std::size_t)(layer * cfg_.n_expert + cold_e)] = kNotResident;
      residency_[(std::size_t)(layer * cfg_.n_expert + hot_e)] = slot;
      const std::uint8_t* src = host_base_ + blob_index(layer, hot_e) * cfg_.blob_bytes;
      std::uint8_t* dst = vram_base_ + (std::int64_t)slot * cfg_.blob_bytes;
      if (cudaMemcpyAsync(dst, src, (std::size_t)cfg_.blob_bytes, cudaMemcpyHostToDevice, s) != cudaSuccess) {
        err = "expert tier: rebalance refill failed";
        return -1;
      }
      ++fills_;
      ++swaps;
    }
  }
  return swaps;
}

bool ExpertTier::compute(std::int64_t layer, const std::int32_t* ids, const float* weights, const float* x,
                         float* out, std::int64_t k, void* stream, std::string& err) {
  if (!opened_ || !host_base_) {
    err = "expert tier: compute before open/set_host_arena";
    return false;
  }
  if (layer < 0 || layer >= cfg_.n_layers || k < 1 || k > k_max_) {
    err = "expert tier: compute bad layer/k";
    return false;
  }
  const auto s = static_cast<cudaStream_t>(stream);
  if (cudaMemcpyAsync(d_weights_, weights, (std::size_t)k * sizeof(float), cudaMemcpyHostToDevice, s) !=
      cudaSuccess) {
    err = "expert tier: weight upload failed";
    return false;
  }

  // x is shared by every routed expert's gate and up: prepare it once.
  const bool x_needs_q8 = k::is_quantized(cfg_.gate) || k::is_quantized(cfg_.up);
  if (x_needs_q8) k::quantize_q8_1(x, d_xq8_embd_, (int)cfg_.n_embd, 1, stream);

  auto run_ffn = [&](const std::uint8_t* blob_dev, float* parts) {
    const void* gate_w = blob_dev + cfg_.gate_off;
    const void* up_w = blob_dev + cfg_.up_off;
    const void* down_w = blob_dev + cfg_.down_off;
    // gate, up: n_in = n_embd, n_out = n_ff (quantized path only in this lean
    // cut; f32/bf16 experts are a documented box extension).
    k::mmvq(cfg_.gate, gate_w, d_xq8_embd_, d_g_, (int)cfg_.n_embd, (int)cfg_.n_ff, 1, stream);
    k::mmvq(cfg_.up, up_w, d_xq8_embd_, d_u_, (int)cfg_.n_embd, (int)cfg_.n_ff, 1, stream);
    switch (cfg_.act) {
      case Act::swiglu_clamped:
        k::swiglu_clamped(d_g_, d_u_, d_h_, cfg_.n_ff, cfg_.act_limit, stream);
        break;
      case Act::geglu:
        k::geglu(d_g_, d_u_, d_h_, cfg_.n_ff, stream);
        break;
      case Act::swiglu:
      default:
        k::swiglu(d_g_, d_u_, d_h_, cfg_.n_ff, stream);
        break;
    }
    k::quantize_q8_1(d_h_, d_hq8_, (int)cfg_.n_ff, 1, stream);
    // down: n_in = n_ff, n_out = n_embd.
    k::mmvq(cfg_.down, down_w, d_hq8_, parts, (int)cfg_.n_ff, (int)cfg_.n_embd, 1, stream);
  };

  for (std::int64_t i = 0; i < k; ++i) {
    const std::int32_t e = ids[i];
    if (e < 0 || e >= cfg_.n_expert) {
      err = "expert tier: routed id out of range";
      return false;
    }
    const std::int32_t slot = slot_of(layer, e);
    const std::uint8_t* blob_dev;
    if (slot != kNotResident) {
      blob_dev = vram_base_ + (std::int64_t)slot * cfg_.blob_bytes;  // resident: read VRAM
    } else {
      // Non-resident: stream from the host arena into the reused staging slot.
      // Ordered on `stream`, so the FFN below reads it before the next expert
      // overwrites it.
      const std::uint8_t* src = host_base_ + blob_index(layer, e) * cfg_.blob_bytes;
      if (cudaMemcpyAsync(d_stage_, src, (std::size_t)cfg_.blob_bytes, cudaMemcpyHostToDevice, s) !=
          cudaSuccess) {
        err = "expert tier: non-resident stream failed";
        return false;
      }
      blob_dev = d_stage_;
      ++stream_misses_;
    }
    run_ffn(blob_dev, d_parts_ + i * cfg_.n_embd);
  }

  float* shared = nullptr;
  if (cfg_.has_shared_expert) {
    const std::uint8_t* src = host_base_ + blob_index(layer, cfg_.n_expert) * cfg_.blob_bytes;
    if (cudaMemcpyAsync(d_stage_, src, (std::size_t)cfg_.blob_bytes, cudaMemcpyHostToDevice, s) != cudaSuccess) {
      err = "expert tier: shared expert stream failed";
      return false;
    }
    run_ffn(d_stage_, d_shared_);
    shared = d_shared_;
  }

  k::moe_combine(d_parts_, d_weights_, shared, out, cfg_.n_embd, k, stream);
  return true;
}

bool ExpertTier::save_profile(const std::string& path, std::string& err) const {
  std::vector<std::uint8_t> resident((std::size_t)(cfg_.n_layers * cfg_.n_expert), 0);
  for (std::size_t i = 0; i < residency_.size(); ++i) resident[i] = residency_[i] != kNotResident ? 1 : 0;
  const auto ranked = rank_learned_profile(cfg_.n_layers, cfg_.n_expert, resident, usage_, prior_);
  return write_expert_profile(path, cfg_.n_layers, cfg_.n_expert, ranked, err);
}

void ExpertTier::close() {
  if (vram_base_) cudaFree(vram_base_);
  if (d_stage_) cudaFree(d_stage_);
  if (d_xq8_embd_) cudaFree(d_xq8_embd_);
  if (d_hq8_) cudaFree(d_hq8_);
  if (d_g_) cudaFree(d_g_);
  if (d_u_) cudaFree(d_u_);
  if (d_h_) cudaFree(d_h_);
  if (d_parts_) cudaFree(d_parts_);
  if (d_shared_) cudaFree(d_shared_);
  if (d_weights_) cudaFree(d_weights_);
  if (host_registered_ && host_base_) cudaHostUnregister(const_cast<std::uint8_t*>(host_base_));
  vram_base_ = nullptr;
  d_stage_ = nullptr;
  d_xq8_embd_ = d_hq8_ = nullptr;
  d_g_ = d_u_ = d_h_ = d_parts_ = d_shared_ = d_weights_ = nullptr;
  host_base_ = nullptr;
  host_registered_ = false;
  opened_ = false;
}

}  // namespace u

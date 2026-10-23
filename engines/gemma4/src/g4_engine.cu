// strata-gemma4-engine: load, placement and the forward passes (plan Task 6; spec §2.3, §4).
#include "g4_engine.hpp"

#include "g4_file.hpp"
#include "g4_kernels.cuh"

#include <cublas_v2.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <numeric>
#include <vector>

namespace g4 {
namespace {

using Clock = std::chrono::steady_clock;

constexpr std::size_t kAlign = 256;
constexpr std::size_t align_up(std::size_t n) { return (n + kAlign - 1) / kAlign * kAlign; }
constexpr int kGuRows = 2 * kFfExp;  // 1408: gate rows then up rows

std::size_t row_bytes(TensorType t, std::uint64_t cols) {
  return t == TensorType::q8_0 ? static_cast<std::size_t>(cols / 32 * 34)
         : t == TensorType::bf16 ? static_cast<std::size_t>(cols * 2)
                                 : static_cast<std::size_t>(cols * 4);
}

// GGUF Q8_0 rows ([fp16 d][32 x int8] blocks) into the engine's int8 plane and fp16 scale plane.
void repack_q8(const std::uint8_t* src, std::size_t rows, std::size_t cols, std::int8_t* q, std::uint16_t* s) {
  const std::size_t nb = cols / 32;
  for (std::size_t r = 0; r < rows; ++r) {
    for (std::size_t b = 0; b < nb; ++b) {
      const std::uint8_t* blk = src + (r * nb + b) * 34;
      std::memcpy(&s[r * nb + b], blk, 2);
      std::memcpy(&q[r * cols + b * 32], blk + 2, 32);
    }
  }
}

// One expert blob: [gate_up weights][gate_up scales][down weights][down scales], each part
// 256-byte aligned; a BF16 matrix has no scales. The two matrices may differ in type (the
// Q8_K_XL file's layer 29: Q8_0 gate_up, BF16 down).
struct ExpertLayout {
  g4k::WKind gu_kind{g4k::WKind::q8};
  g4k::WKind dn_kind{g4k::WKind::q8};
  std::size_t gu_w{0}, gu_s{0}, dn_w{0}, dn_s{0}, bytes{0};
};

ExpertLayout expert_layout(TensorType gu, TensorType dn) {
  ExpertLayout L;
  const std::size_t gu_n = std::size_t(kGuRows) * kEmbd, dn_n = std::size_t(kEmbd) * kFfExp;
  L.gu_kind = gu == TensorType::q8_0 ? g4k::WKind::q8 : g4k::WKind::bf16;
  L.dn_kind = dn == TensorType::q8_0 ? g4k::WKind::q8 : g4k::WKind::bf16;
  std::size_t at = 0;
  L.gu_w = at;
  at = align_up(at + gu_n * (L.gu_kind == g4k::WKind::q8 ? 1 : 2));
  L.gu_s = at;
  if (L.gu_kind == g4k::WKind::q8) at = align_up(at + gu_n / 32 * 2);
  L.dn_w = at;
  at = align_up(at + dn_n * (L.dn_kind == g4k::WKind::q8 ? 1 : 2));
  L.dn_s = at;
  if (L.dn_kind == g4k::WKind::q8) at = align_up(at + dn_n / 32 * 2);
  L.bytes = at;
  return L;
}

struct DevLayer {
  bool sliding{true};
  int hd{kHeadSwa};
  int n_kv{kKvHeadsSwa};
  g4k::Mat q{}, k{}, v{}, o{}, gate{}, up{}, down{}, router{};
  float *attn_norm{}, *q_norm{}, *k_norm{}, *post_attn_norm{}, *ffn_norm{}, *post_ffw_norm_1{}, *gate_inp_scale{};
  float *pre_ffw_norm_2{}, *down_scale{}, *post_ffw_norm_2{}, *post_ffw_norm{}, *layer_scale{};
  ExpertLayout ex{};
  std::uint8_t* host_experts{};   // pinned, mapped: 128 blobs
  std::uint8_t* host_alias{};     // the device's address for it
  std::uint8_t* slots{};          // device: n_slots blobs
  int n_slots{0};
  std::vector<int> slot_of;       // expert -> slot, -1 when in RAM
  std::vector<int> expert_in;     // slot -> expert
  std::vector<g4k::ExpertPtr> table_host;
  g4k::ExpertPtr* table{};        // device [128]
  int* counts{};                  // device [128] routing counts since the last rebalance
  std::vector<double> score;      // decayed routing counts
  __half* kc{};
  __half* vc{};
  int cap{0};
};

class Gemma4Engine final : public Engine {
 public:
  ~Gemma4Engine() override { release(); }

  bool load(const EngineConfig& cfg, const ModelDesc& m, std::string& error);

  int context() const override { return ctx_; }
  int ring_spare() const override { return ring_ - kWindow; }
  int position() const override { return pos_; }
  void truncate(int p) override { pos_ = std::clamp(p, 0, pos_); }
  int process(const std::int32_t* ids, int n, const std::function<bool(int)>& progress) override;
  bool logits(std::vector<float>& out) override;
  int greedy() override;
  void rebalance(int max_swaps) override;
  void set_layer_sink(std::vector<float>* sink) override { sink_ = sink; }
  LoadReport report() const override { return report_; }

 private:
  bool cuda_ok(cudaError_t e, const char* what);
  bool launch_ok(const char* what) { return cuda_ok(cudaGetLastError(), what); }
  template <typename T>
  bool alloc(T*& p, std::size_t count) {
    void* raw = nullptr;
    if (!cuda_ok(cudaMalloc(&raw, std::max<std::size_t>(count, 1) * sizeof(T)), "cudaMalloc")) return false;
    allocations_.push_back(raw);
    p = static_cast<T*>(raw);
    return true;
  }
  bool upload_vector(const TensorSpan& t, float*& out);
  bool upload_matrix(const TensorSpan& t, g4k::Mat& out);
  bool load_experts(DevLayer& L, const LayerDesc& d);
  bool place_experts(double vram_gib, int forced_slots, std::string& error);
  bool gemm(const g4k::Mat& w, const float* x, float* y, int T);
  bool sgemm(int rows, int T, int cols, const float* w, const float* x, float* y);
  bool forward_one(std::int32_t id);
  bool forward_batch(const std::int32_t* ids, int T);
  bool prompt_attention(DevLayer& L, int pos0, int T);
  bool moe_batch(DevLayer& L, int T);
  bool head(const float* x_row);
  void dump_layer(int layer, int pos0, int T);
  void release();

  ReadOnlyFile file_;
  std::vector<std::uint8_t> staging_;
  std::vector<void*> allocations_;
  std::vector<void*> pinned_;
  cudaStream_t st_{};
  cublasHandle_t blas_{};
  bool broken_{false};

  int ctx_{0}, chunk_{0}, ring_{0}, pos_{0}, max_splits_{0};
  float eps_{1e-6f}, base_full_{1e6f}, base_swa_{1e4f}, softcap_{30.0f};
  std::vector<DevLayer> layers_;
  g4k::Mat embd_{};
  float* output_norm_{};
  float* rope_freqs_{};

  // scratch
  int* ids_d_{};
  int* ids_h_{};  // pinned
  float *x_{}, *x1_{}, *h_{}, *o_{}, *dense_{}, *rn_{}, *e_in_{}, *moe_{};
  float *qraw_{}, *qout_{}, *attn_{}, *kraw_{}, *vraw_{};
  __half* q16_{};
  float *g_{}, *u_{}, *m_{}, *rl_{}, *wts_{};
  int *picks_{}, *order_{}, *inv_{};
  int* picks_h_{};  // pinned
  int* order_h_{};  // pinned
  float *xg_{}, *gu_{}, *mx_{}, *yg_{};
  float *wdq_{}, *w1_{}, *w2_{};
  float* s_buf_{};
  __half* p_buf_{};
  std::size_t s_floats_{0};
  float* dscratch_{};
  float* logits_{};
  float* xn_{};
  float* argmax_scratch_{};
  int* argmax_out_{};
  int* argmax_h_{};  // pinned

  std::vector<float>* sink_{nullptr};
  LoadReport report_{};
};

bool Gemma4Engine::cuda_ok(cudaError_t e, const char* what) {
  if (e == cudaSuccess) return true;
  std::fprintf(stderr, "strata-gemma4: CUDA error in %s: %s\n", what, cudaGetErrorString(e));
  broken_ = true;
  return false;
}

void Gemma4Engine::release() {
  if (blas_ != nullptr) cublasDestroy(blas_);
  blas_ = nullptr;
  for (void* p : allocations_) cudaFree(p);
  allocations_.clear();
  for (void* p : pinned_) cudaFreeHost(p);
  pinned_.clear();
  if (st_ != nullptr) cudaStreamDestroy(st_);
  st_ = nullptr;
}

bool Gemma4Engine::upload_vector(const TensorSpan& t, float*& out) {
  if (!t.present) {
    out = nullptr;
    return true;
  }
  staging_.resize(static_cast<std::size_t>(t.bytes));
  if (!file_.read_at(t.file_offset, staging_.data(), staging_.size())) {
    std::fprintf(stderr, "strata-gemma4: cannot read the model file\n");
    return false;
  }
  if (!alloc(out, static_cast<std::size_t>(t.bytes / 4))) return false;
  return cuda_ok(cudaMemcpy(out, staging_.data(), staging_.size(), cudaMemcpyHostToDevice), "upload");
}

bool Gemma4Engine::upload_matrix(const TensorSpan& t, g4k::Mat& out) {
  out.rows = static_cast<int>(t.rows);
  out.cols = static_cast<int>(t.cols);
  const std::size_t rows = static_cast<std::size_t>(t.rows), cols = static_cast<std::size_t>(t.cols);
  const std::size_t rb = row_bytes(t.type, t.cols);
  if (t.type == TensorType::f32 || t.type == TensorType::bf16) {
    out.kind = t.type == TensorType::f32 ? g4k::WKind::f32 : g4k::WKind::bf16;
    std::uint8_t* d = nullptr;
    if (!alloc(d, rows * rb)) return false;
    const std::size_t step = std::max<std::size_t>(1, (64u << 20) / rb);
    for (std::size_t r0 = 0; r0 < rows; r0 += step) {
      const std::size_t n = std::min(step, rows - r0);
      staging_.resize(n * rb);
      if (!file_.read_at(t.file_offset + r0 * rb, staging_.data(), n * rb)) return false;
      if (!cuda_ok(cudaMemcpy(d + r0 * rb, staging_.data(), n * rb, cudaMemcpyHostToDevice), "upload")) return false;
    }
    out.w = d;
    out.s = nullptr;
    return true;
  }
  out.kind = g4k::WKind::q8;
  std::int8_t* q = nullptr;
  __half* s = nullptr;
  if (!alloc(q, rows * cols) || !alloc(s, rows * (cols / 32))) return false;
  const std::size_t step = std::max<std::size_t>(1, (32u << 20) / rb);
  std::vector<std::int8_t> hq;
  std::vector<std::uint16_t> hs;
  for (std::size_t r0 = 0; r0 < rows; r0 += step) {
    const std::size_t n = std::min(step, rows - r0);
    staging_.resize(n * rb);
    if (!file_.read_at(t.file_offset + r0 * rb, staging_.data(), n * rb)) return false;
    hq.resize(n * cols);
    hs.resize(n * (cols / 32));
    repack_q8(staging_.data(), n, cols, hq.data(), hs.data());
    if (!cuda_ok(cudaMemcpy(q + r0 * cols, hq.data(), hq.size(), cudaMemcpyHostToDevice), "upload") ||
        !cuda_ok(cudaMemcpy(s + r0 * (cols / 32), hs.data(), hs.size() * 2, cudaMemcpyHostToDevice), "upload")) {
      return false;
    }
  }
  out.w = q;
  out.s = s;
  return true;
}

bool Gemma4Engine::load_experts(DevLayer& L, const LayerDesc& d) {
  L.ex = expert_layout(d.gate_up_exps.type, d.down_exps.type);
  void* host = nullptr;
  if (!cuda_ok(cudaHostAlloc(&host, L.ex.bytes * kExperts, cudaHostAllocMapped | cudaHostAllocPortable), "cudaHostAlloc")) {
    std::fprintf(stderr, "strata-gemma4: cannot pin %.2f GiB of host memory for a layer's experts\n",
                 double(L.ex.bytes * kExperts) / double(1ull << 30));
    return false;
  }
  pinned_.push_back(host);
  L.host_experts = static_cast<std::uint8_t*>(host);
  void* alias = nullptr;
  if (!cuda_ok(cudaHostGetDevicePointer(&alias, host, 0), "cudaHostGetDevicePointer")) return false;
  L.host_alias = static_cast<std::uint8_t*>(alias);
  const std::size_t gu_rb = row_bytes(d.gate_up_exps.type, kEmbd), dn_rb = row_bytes(d.down_exps.type, kFfExp);
  const std::size_t gu_file = gu_rb * kGuRows, dn_file = dn_rb * kEmbd;
  for (int e = 0; e < kExperts; ++e) {
    std::uint8_t* blob = L.host_experts + L.ex.bytes * static_cast<std::size_t>(e);
    const std::uint64_t gu_at = d.gate_up_exps.file_offset + gu_file * static_cast<std::size_t>(e);
    const std::uint64_t dn_at = d.down_exps.file_offset + dn_file * static_cast<std::size_t>(e);
    if (L.ex.gu_kind == g4k::WKind::q8) {
      staging_.resize(gu_file);
      if (!file_.read_at(gu_at, staging_.data(), gu_file)) return false;
      repack_q8(staging_.data(), kGuRows, kEmbd, reinterpret_cast<std::int8_t*>(blob + L.ex.gu_w),
                reinterpret_cast<std::uint16_t*>(blob + L.ex.gu_s));
    } else if (!file_.read_at(gu_at, blob + L.ex.gu_w, gu_file)) {
      return false;
    }
    if (L.ex.dn_kind == g4k::WKind::q8) {
      staging_.resize(dn_file);
      if (!file_.read_at(dn_at, staging_.data(), dn_file)) return false;
      repack_q8(staging_.data(), kEmbd, kFfExp, reinterpret_cast<std::int8_t*>(blob + L.ex.dn_w),
                reinterpret_cast<std::uint16_t*>(blob + L.ex.dn_s));
    } else if (!file_.read_at(dn_at, blob + L.ex.dn_w, dn_file)) {
      return false;
    }
  }
  return true;
}

g4k::ExpertPtr expert_ptr(const ExpertLayout& ex, const std::uint8_t* blob) {
  g4k::ExpertPtr p{};
  p.gu_w = blob + ex.gu_w;
  p.dn_w = blob + ex.dn_w;
  p.gu_s = ex.gu_kind == g4k::WKind::q8 ? reinterpret_cast<const __half*>(blob + ex.gu_s) : nullptr;
  p.dn_s = ex.dn_kind == g4k::WKind::q8 ? reinterpret_cast<const __half*>(blob + ex.dn_s) : nullptr;
  return p;
}

bool Gemma4Engine::place_experts(double vram_gib, int forced_slots, std::string& error) {
  std::size_t free_b = 0, total_b = 0;
  if (!cuda_ok(cudaMemGetInfo(&free_b, &total_b), "cudaMemGetInfo")) {
    error = "cannot read the free VRAM";
    return false;
  }
  std::size_t per_slot = 0;
  for (const auto& L : layers_) per_slot += L.ex.bytes;
  const std::size_t reserve = std::size_t(640) << 20;
  const std::size_t budget = vram_gib >= 0 ? static_cast<std::size_t>(vram_gib * double(1ull << 30))
                                           : (free_b > reserve ? free_b - reserve : 0);
  int S = forced_slots > 0 ? forced_slots : static_cast<int>(std::min<std::size_t>(kExperts, budget / per_slot));
  if (S > kExperts) S = kExperts;
  if (static_cast<std::size_t>(S) * per_slot + (std::size_t(128) << 20) > free_b) {
    if (forced_slots > 0) {
      error = "--expert-slots does not fit in the free VRAM";
      return false;
    }
    S = static_cast<int>((free_b > (std::size_t(128) << 20) ? free_b - (std::size_t(128) << 20) : 0) / per_slot);
  }
  for (auto& L : layers_) {
    L.n_slots = S;
    L.slot_of.assign(kExperts, -1);
    L.expert_in.assign(static_cast<std::size_t>(S), -1);
    L.score.assign(kExperts, 0.0);
    L.table_host.resize(kExperts);
    if (S > 0 && !alloc(L.slots, L.ex.bytes * static_cast<std::size_t>(S))) {
      error = "cannot allocate the expert slots";
      return false;
    }
    for (int e = 0; e < kExperts; ++e) {
      if (e < S) {
        if (!cuda_ok(cudaMemcpy(L.slots + L.ex.bytes * static_cast<std::size_t>(e), L.host_experts + L.ex.bytes * static_cast<std::size_t>(e),
                                L.ex.bytes, cudaMemcpyHostToDevice),
                     "slot fill")) {
          error = "cannot fill the expert slots";
          return false;
        }
        L.slot_of[static_cast<std::size_t>(e)] = e;
        L.expert_in[static_cast<std::size_t>(e)] = e;
        L.table_host[static_cast<std::size_t>(e)] = expert_ptr(L.ex, L.slots + L.ex.bytes * static_cast<std::size_t>(e));
      } else {
        L.table_host[static_cast<std::size_t>(e)] = expert_ptr(L.ex, L.host_alias + L.ex.bytes * static_cast<std::size_t>(e));
      }
    }
    if (!alloc(L.table, kExperts) || !alloc(L.counts, kExperts)) return false;
    if (!cuda_ok(cudaMemcpy(L.table, L.table_host.data(), sizeof(g4k::ExpertPtr) * kExperts, cudaMemcpyHostToDevice), "table") ||
        !cuda_ok(cudaMemset(L.counts, 0, sizeof(int) * kExperts), "counts")) {
      return false;
    }
  }
  report_.slots_per_layer = S;
  report_.resident_pct = 100.0 * S / kExperts;
  return true;
}

bool Gemma4Engine::load(const EngineConfig& cfg, const ModelDesc& m, std::string& error) {
  const auto t0 = Clock::now();
  if (!file_.open(cfg.model)) {
    error = "cannot open the model file";
    return false;
  }
  ctx_ = cfg.max_context;
  chunk_ = cfg.chunk;
  ring_ = kWindow + std::max(cfg.chunk, kWindow);
  eps_ = m.rms_eps;
  base_full_ = m.rope_base_full;
  base_swa_ = m.rope_base_swa;
  softcap_ = m.softcap;
  if (!cuda_ok(cudaStreamCreateWithFlags(&st_, cudaStreamNonBlocking), "stream") || cublasCreate(&blas_) != CUBLAS_STATUS_SUCCESS ||
      cublasSetStream(blas_, st_) != CUBLAS_STATUS_SUCCESS) {
    error = "cannot initialise CUDA or cuBLAS";
    return false;
  }
  if (!upload_matrix(m.token_embd, embd_) || !upload_vector(m.output_norm, output_norm_) || !upload_vector(m.rope_freqs, rope_freqs_)) {
    error = "cannot load the embedding";
    return false;
  }
  layers_.resize(kLayers);
  std::size_t pinned = 0;
  for (int i = 0; i < kLayers; ++i) {
    const LayerDesc& d = m.layers[static_cast<std::size_t>(i)];
    DevLayer& L = layers_[static_cast<std::size_t>(i)];
    L.sliding = d.sliding;
    L.hd = d.head_dim;
    L.n_kv = d.kv_heads;
    const bool ok = upload_vector(d.attn_norm, L.attn_norm) && upload_matrix(d.attn_q, L.q) && upload_matrix(d.attn_k, L.k) &&
                    (!d.attn_v.present || upload_matrix(d.attn_v, L.v)) && upload_matrix(d.attn_output, L.o) &&
                    upload_vector(d.attn_q_norm, L.q_norm) && upload_vector(d.attn_k_norm, L.k_norm) &&
                    upload_vector(d.post_attention_norm, L.post_attn_norm) && upload_vector(d.ffn_norm, L.ffn_norm) &&
                    upload_matrix(d.ffn_gate, L.gate) && upload_matrix(d.ffn_up, L.up) && upload_matrix(d.ffn_down, L.down) &&
                    upload_vector(d.post_ffw_norm_1, L.post_ffw_norm_1) && upload_matrix(d.gate_inp, L.router) &&
                    upload_vector(d.gate_inp_scale, L.gate_inp_scale) && upload_vector(d.pre_ffw_norm_2, L.pre_ffw_norm_2) &&
                    upload_vector(d.down_exps_scale, L.down_scale) && upload_vector(d.post_ffw_norm_2, L.post_ffw_norm_2) &&
                    upload_vector(d.post_ffw_norm, L.post_ffw_norm) && upload_vector(d.layer_output_scale, L.layer_scale) &&
                    load_experts(L, d);
    if (!ok) {
      error = "cannot load layer weights";
      return false;
    }
    pinned += L.ex.bytes * kExperts;
    L.cap = L.sliding ? ring_ : ctx_;
    const std::size_t cache = static_cast<std::size_t>(L.n_kv) * L.cap * L.hd;
    if (!alloc(L.kc, cache) || !alloc(L.vc, cache)) {
      error = "cannot allocate the KV cache (lower --max-context)";
      return false;
    }
    std::fprintf(stderr, "strata-gemma4: layer %d loaded (%s; experts %s/%s) at %.1f s\n", i, L.sliding ? "sliding" : "full",
                 L.ex.gu_kind == g4k::WKind::q8 ? "Q8_0" : "BF16", L.ex.dn_kind == g4k::WKind::q8 ? "Q8_0" : "BF16",
                 std::chrono::duration<double>(Clock::now() - t0).count());
  }
  staging_.clear();
  staging_.shrink_to_fit();
  // scratch, sized for one prompt chunk
  const std::size_t C = static_cast<std::size_t>(chunk_);
  max_splits_ = g4k::attn_decode_splits(ctx_);
  s_floats_ = std::size_t(32) << 20;  // 128 MB of prompt-attention scores
  const bool scratch_ok =
      alloc(ids_d_, C) && alloc(x_, C * kEmbd) && alloc(x1_, C * kEmbd) && alloc(h_, C * kEmbd) && alloc(o_, C * kEmbd) &&
      alloc(dense_, C * kEmbd) && alloc(rn_, C * kEmbd) && alloc(e_in_, C * kEmbd) && alloc(moe_, C * kEmbd) &&
      alloc(qraw_, C * kHeads * kHeadFull) && alloc(qout_, C * kHeads * kHeadFull) && alloc(attn_, C * kHeads * kHeadFull) &&
      alloc(q16_, C * kHeads * kHeadFull) && alloc(kraw_, C * kKvHeadsSwa * kHeadSwa) && alloc(vraw_, C * kKvHeadsSwa * kHeadSwa) &&
      alloc(g_, C * kFf) && alloc(u_, C * kFf) && alloc(m_, C * kFf) && alloc(rl_, C * kExperts) && alloc(wts_, C * 8) &&
      alloc(picks_, C * 8) && alloc(order_, C * 8) && alloc(inv_, C * 8) && alloc(xg_, C * 8 * kEmbd) && alloc(gu_, C * 8 * kGuRows) &&
      alloc(mx_, C * 8 * kFfExp) && alloc(yg_, C * 8 * kEmbd) && alloc(wdq_, std::size_t(kHeads) * kHeadFull * kEmbd) &&
      alloc(w1_, std::size_t(kGuRows) * kEmbd) && alloc(w2_, std::size_t(kEmbd) * kFfExp) && alloc(s_buf_, s_floats_) &&
      alloc(p_buf_, s_floats_) && alloc(dscratch_, std::size_t(kHeads) * max_splits_ * (kHeadFull + 2)) &&
      alloc(logits_, kVocab) && alloc(xn_, kEmbd) && alloc(argmax_out_, 1) && alloc(argmax_scratch_, 4096);
  if (!scratch_ok) {
    error = "cannot allocate the scratch buffers (lower --chunk or --max-context)";
    return false;
  }
  void* pin = nullptr;
  if (!cuda_ok(cudaHostAlloc(&pin, (C * 26 + 16) * sizeof(int), cudaHostAllocDefault), "cudaHostAlloc")) {
    error = "cannot pin the transfer buffers";
    return false;
  }
  pinned_.push_back(pin);
  ids_h_ = static_cast<int*>(pin);
  picks_h_ = ids_h_ + 2 * C;
  order_h_ = picks_h_ + 8 * C;
  argmax_h_ = order_h_ + 16 * C;  // order (8C) then inv (8C)
  if (!place_experts(cfg.expert_vram_gib, cfg.expert_slots, error)) return false;
  std::size_t free_b = 0, total_b = 0;
  cudaMemGetInfo(&free_b, &total_b);
  report_.vram_used_mib = double(total_b - free_b) / double(1 << 20);
  report_.vram_total_mib = double(total_b) / double(1 << 20);
  report_.pinned_gib = double(pinned) / double(1ull << 30);
  report_.ring_rows = ring_;
  report_.load_seconds = std::chrono::duration<double>(Clock::now() - t0).count();
  file_.close();
  return !broken_;
}

bool Gemma4Engine::sgemm(int rows, int T, int cols, const float* w, const float* x, float* y) {
  const float one = 1.0f, zero = 0.0f;
  // row-major y[T][rows] = x[T][cols] * w[rows][cols]^T  ==  column-major y^T = w^T(op T) * x^T
  return cublasSgemm(blas_, CUBLAS_OP_T, CUBLAS_OP_N, rows, T, cols, &one, w, cols, x, cols, &zero, y, rows) ==
         CUBLAS_STATUS_SUCCESS;
}

bool Gemma4Engine::gemm(const g4k::Mat& w, const float* x, float* y, int T) {
  const float* wf = static_cast<const float*>(w.w);
  if (w.kind != g4k::WKind::f32) {
    g4k::dequant(w, wdq_, st_);
    wf = wdq_;
  }
  if (!sgemm(w.rows, T, w.cols, wf, x, y)) {
    std::fprintf(stderr, "strata-gemma4: cuBLAS SGEMM failed\n");
    broken_ = true;
    return false;
  }
  return true;
}

void Gemma4Engine::dump_layer(int layer, int pos0, int T) {
  if (sink_ == nullptr) return;
  const std::size_t need = static_cast<std::size_t>(pos0 + T) * kLayers * kEmbd;
  if (sink_->size() < need) sink_->resize(need, 0.0f);
  std::vector<float> rows(static_cast<std::size_t>(T) * kEmbd);
  cudaMemcpyAsync(rows.data(), x_, rows.size() * 4, cudaMemcpyDeviceToHost, st_);
  cudaStreamSynchronize(st_);
  for (int t = 0; t < T; ++t) {
    std::memcpy(sink_->data() + (static_cast<std::size_t>(pos0 + t) * kLayers + layer) * kEmbd,
                rows.data() + static_cast<std::size_t>(t) * kEmbd, kEmbd * 4);
  }
}

bool Gemma4Engine::head(const float* x_row) {
  g4k::rmsnorm(x_row, output_norm_, nullptr, 1.0f, xn_, 1, kEmbd, eps_, st_);
  g4k::matvec(embd_, xn_, logits_, 1, st_);
  g4k::softcap(logits_, kVocab, softcap_, st_);
  return launch_ok("head");
}

bool Gemma4Engine::forward_one(std::int32_t id) {
  const int pos = pos_;
  ids_h_[0] = id;
  cudaMemcpyAsync(ids_d_, ids_h_, sizeof(int), cudaMemcpyHostToDevice, st_);
  g4k::embed_q8(ids_d_, 1, static_cast<const std::int8_t*>(embd_.w), embd_.s, kEmbd, std::sqrt(float(kEmbd)), x_, st_);
  for (int l = 0; l < kLayers; ++l) {
    DevLayer& L = layers_[static_cast<std::size_t>(l)];
    g4k::rmsnorm(x_, L.attn_norm, nullptr, 1.0f, h_, 1, kEmbd, eps_, st_);
    g4k::matvec(L.q, h_, qraw_, 1, st_);
    g4k::matvec(L.k, h_, kraw_, 1, st_);
    if (L.sliding) g4k::matvec(L.v, h_, vraw_, 1, st_);
    g4k::QkvPost p{qraw_, kraw_, L.sliding ? vraw_ : kraw_, L.q_norm, L.k_norm, L.sliding ? nullptr : rope_freqs_,
                   L.sliding ? base_swa_ : base_full_, L.hd, kHeads, L.n_kv, pos, 1, L.sliding ? ring_ : 0, L.cap, eps_,
                   qout_, nullptr, L.kc, L.vc};
    g4k::qkv_post(p, st_);
    g4k::attn_decode(qout_, L.kc, L.vc, L.hd, kHeads, L.n_kv, L.cap, L.sliding ? ring_ : 0, L.sliding ? kWindow : 0, pos, attn_,
                     dscratch_, max_splits_, st_);
    g4k::matvec(L.o, attn_, o_, 1, st_);
    g4k::add_rmsnorm(x_, o_, L.post_attn_norm, x1_, 1, kEmbd, eps_, st_);
    g4k::rmsnorm(x1_, L.ffn_norm, nullptr, 1.0f, h_, 1, kEmbd, eps_, st_);
    g4k::matvec(L.gate, h_, g_, 1, st_);
    g4k::matvec(L.up, h_, u_, 1, st_);
    g4k::geglu(g_, kFf, u_, kFf, m_, 1, kFf, st_);
    g4k::matvec(L.down, m_, dense_, 1, st_);
    g4k::rmsnorm(x1_, nullptr, L.gate_inp_scale, 1.0f / std::sqrt(float(kEmbd)), rn_, 1, kEmbd, eps_, st_);
    g4k::matvec(L.router, rn_, rl_, 1, st_);
    g4k::router_topk(rl_, 1, picks_, wts_, L.counts, st_);
    g4k::rmsnorm(x1_, L.pre_ffw_norm_2, nullptr, 1.0f, e_in_, 1, kEmbd, eps_, st_);
    g4k::matvec_experts(L.ex.gu_kind, 0, kGuRows, kEmbd, L.table, picks_, 8, e_in_, 0, gu_, st_);
    g4k::geglu(gu_, kGuRows, gu_ + kFfExp, kGuRows, mx_, 8, kFfExp, st_);
    g4k::matvec_experts(L.ex.dn_kind, 1, kEmbd, kFfExp, L.table, picks_, 8, mx_, kFfExp, yg_, st_);
    g4k::moe_combine(yg_, wts_, picks_, L.down_scale, 8, kEmbd, moe_, st_);
    g4k::ffn_end(x1_, dense_, moe_, L.post_ffw_norm_1, L.post_ffw_norm_2, L.post_ffw_norm, L.layer_scale, x_, 1, kEmbd, eps_, st_);
    if (sink_ != nullptr) dump_layer(l, pos, 1);
  }
  if (!head(x_)) return false;
  pos_ = pos + 1;
  return true;
}

bool Gemma4Engine::prompt_attention(DevLayer& L, int pos0, int T) {
  const int ring = L.sliding ? ring_ : 0;
  const int Lk = L.sliding ? std::min(ring_, pos0 + T) : pos0 + T;
  const int G = kHeads / L.n_kv;
  const int hd = L.hd;
  const int Ts = static_cast<int>(std::max<std::size_t>(1, std::min<std::size_t>(T, s_floats_ / (std::size_t(G) * Lk))));
  const float one = 1.0f, zero = 0.0f;
  for (int g = 0; g < L.n_kv; ++g) {
    const __half* K = L.kc + static_cast<std::size_t>(g) * L.cap * hd;
    const __half* V = L.vc + static_cast<std::size_t>(g) * L.cap * hd;
    for (int t0 = 0; t0 < T; t0 += Ts) {
      const int ts = std::min(Ts, T - t0);
      const __half* Q = q16_ + (static_cast<std::size_t>(t0) * kHeads + static_cast<std::size_t>(g) * G) * hd;
      float* O = attn_ + (static_cast<std::size_t>(t0) * kHeads + static_cast<std::size_t>(g) * G) * hd;
      if (cublasGemmStridedBatchedEx(blas_, CUBLAS_OP_T, CUBLAS_OP_N, Lk, ts, hd, &one, K, CUDA_R_16F, hd, 0, Q, CUDA_R_16F,
                                     kHeads * hd, hd, &zero, s_buf_, CUDA_R_32F, Lk, static_cast<long long>(ts) * Lk, G,
                                     CUBLAS_COMPUTE_32F, CUBLAS_GEMM_DEFAULT) != CUBLAS_STATUS_SUCCESS) {
        std::fprintf(stderr, "strata-gemma4: cuBLAS attention scores failed\n");
        broken_ = true;
        return false;
      }
      g4k::attn_softmax(s_buf_, p_buf_, G, ts, Lk, pos0 + t0, ring, L.sliding ? kWindow : 0, pos0 + T - 1, st_);
      if (cublasGemmStridedBatchedEx(blas_, CUBLAS_OP_N, CUBLAS_OP_N, hd, ts, Lk, &one, V, CUDA_R_16F, hd, 0, p_buf_, CUDA_R_16F,
                                     Lk, static_cast<long long>(ts) * Lk, &zero, O, CUDA_R_32F, kHeads * hd, hd, G,
                                     CUBLAS_COMPUTE_32F, CUBLAS_GEMM_DEFAULT) != CUBLAS_STATUS_SUCCESS) {
        std::fprintf(stderr, "strata-gemma4: cuBLAS attention output failed\n");
        broken_ = true;
        return false;
      }
    }
  }
  return launch_ok("prompt attention");
}

bool Gemma4Engine::moe_batch(DevLayer& L, int T) {
  const int A = T * 8;
  if (!cuda_ok(cudaMemcpyAsync(picks_h_, picks_, sizeof(int) * A, cudaMemcpyDeviceToHost, st_), "picks") ||
      !cuda_ok(cudaStreamSynchronize(st_), "sync")) {
    return false;
  }
  std::vector<int> count(kExperts, 0), offset(kExperts + 1, 0);
  for (int a = 0; a < A; ++a) ++count[static_cast<std::size_t>(picks_h_[a])];
  for (int e = 0; e < kExperts; ++e) offset[static_cast<std::size_t>(e) + 1] = offset[static_cast<std::size_t>(e)] + count[static_cast<std::size_t>(e)];
  std::vector<int> fill(offset.begin(), offset.end() - 1);
  int* inv_h = order_h_ + A;
  for (int a = 0; a < A; ++a) {
    const int at = fill[static_cast<std::size_t>(picks_h_[a])]++;
    order_h_[at] = a;
    inv_h[a] = at;
  }
  cudaMemcpyAsync(order_, order_h_, sizeof(int) * A, cudaMemcpyHostToDevice, st_);
  cudaMemcpyAsync(inv_, inv_h, sizeof(int) * A, cudaMemcpyHostToDevice, st_);
  g4k::gather_rows(e_in_, order_, A, kEmbd, xg_, st_);
  for (int e = 0; e < kExperts; ++e) {
    const int n = count[static_cast<std::size_t>(e)];
    if (n == 0) continue;
    const int off = offset[static_cast<std::size_t>(e)];
    g4k::dequant_expert(L.ex.gu_kind, 0, kGuRows, kEmbd, L.table, e, w1_, st_);
    if (!sgemm(kGuRows, n, kEmbd, w1_, xg_ + static_cast<std::size_t>(off) * kEmbd, gu_ + static_cast<std::size_t>(off) * kGuRows)) {
      broken_ = true;
      return false;
    }
  }
  g4k::geglu(gu_, kGuRows, gu_ + kFfExp, kGuRows, mx_, A, kFfExp, st_);
  for (int e = 0; e < kExperts; ++e) {
    const int n = count[static_cast<std::size_t>(e)];
    if (n == 0) continue;
    const int off = offset[static_cast<std::size_t>(e)];
    g4k::dequant_expert(L.ex.dn_kind, 1, kEmbd, kFfExp, L.table, e, w2_, st_);
    if (!sgemm(kEmbd, n, kFfExp, w2_, mx_ + static_cast<std::size_t>(off) * kFfExp, yg_ + static_cast<std::size_t>(off) * kEmbd)) {
      broken_ = true;
      return false;
    }
  }
  g4k::scatter_combine(yg_, inv_, wts_, picks_, L.down_scale, T, kEmbd, moe_, st_);
  return launch_ok("prompt experts");
}

bool Gemma4Engine::forward_batch(const std::int32_t* ids, int T) {
  const int pos0 = pos_;
  std::memcpy(ids_h_, ids, sizeof(int) * static_cast<std::size_t>(T));
  cudaMemcpyAsync(ids_d_, ids_h_, sizeof(int) * static_cast<std::size_t>(T), cudaMemcpyHostToDevice, st_);
  g4k::embed_q8(ids_d_, T, static_cast<const std::int8_t*>(embd_.w), embd_.s, kEmbd, std::sqrt(float(kEmbd)), x_, st_);
  for (int l = 0; l < kLayers; ++l) {
    DevLayer& L = layers_[static_cast<std::size_t>(l)];
    g4k::rmsnorm(x_, L.attn_norm, nullptr, 1.0f, h_, T, kEmbd, eps_, st_);
    if (!gemm(L.q, h_, qraw_, T) || !gemm(L.k, h_, kraw_, T) || (L.sliding && !gemm(L.v, h_, vraw_, T))) return false;
    g4k::QkvPost p{qraw_, kraw_, L.sliding ? vraw_ : kraw_, L.q_norm, L.k_norm, L.sliding ? nullptr : rope_freqs_,
                   L.sliding ? base_swa_ : base_full_, L.hd, kHeads, L.n_kv, pos0, T, L.sliding ? ring_ : 0, L.cap, eps_,
                   qout_, q16_, L.kc, L.vc};
    g4k::qkv_post(p, st_);
    if (!prompt_attention(L, pos0, T)) return false;
    if (!gemm(L.o, attn_, o_, T)) return false;
    g4k::add_rmsnorm(x_, o_, L.post_attn_norm, x1_, T, kEmbd, eps_, st_);
    g4k::rmsnorm(x1_, L.ffn_norm, nullptr, 1.0f, h_, T, kEmbd, eps_, st_);
    if (!gemm(L.gate, h_, g_, T) || !gemm(L.up, h_, u_, T)) return false;
    g4k::geglu(g_, kFf, u_, kFf, m_, T, kFf, st_);
    if (!gemm(L.down, m_, dense_, T)) return false;
    g4k::rmsnorm(x1_, nullptr, L.gate_inp_scale, 1.0f / std::sqrt(float(kEmbd)), rn_, T, kEmbd, eps_, st_);
    if (!gemm(L.router, rn_, rl_, T)) return false;
    g4k::router_topk(rl_, T, picks_, wts_, L.counts, st_);
    g4k::rmsnorm(x1_, L.pre_ffw_norm_2, nullptr, 1.0f, e_in_, T, kEmbd, eps_, st_);
    if (!moe_batch(L, T)) return false;
    g4k::ffn_end(x1_, dense_, moe_, L.post_ffw_norm_1, L.post_ffw_norm_2, L.post_ffw_norm, L.layer_scale, x_, T, kEmbd, eps_, st_);
    if (sink_ != nullptr) dump_layer(l, pos0, T);
  }
  if (!head(x_ + static_cast<std::size_t>(T - 1) * kEmbd)) return false;
  pos_ = pos0 + T;
  return true;
}

int Gemma4Engine::process(const std::int32_t* ids, int n, const std::function<bool(int)>& progress) {
  if (broken_) return -1;
  if (n <= 0 || pos_ + n > ctx_) return 0;
  int done = 0;
  while (done < n) {
    const int left = n - done;
    if (left <= 4) {
      for (int i = 0; i < left; ++i) {
        if (!forward_one(ids[done + i])) return -1;
      }
      done = n;
    } else {
      const int T = std::min(left, chunk_);
      if (!forward_batch(ids + done, T)) return -1;
      done += T;
      if (n > 1) rebalance(256);
    }
    if (!cuda_ok(cudaStreamSynchronize(st_), "process")) return -1;
    if (n > 1 && progress && !progress(done) && done < n) break;
  }
  return done;
}

bool Gemma4Engine::logits(std::vector<float>& out) {
  out.resize(kVocab);
  return cuda_ok(cudaMemcpyAsync(out.data(), logits_, sizeof(float) * kVocab, cudaMemcpyDeviceToHost, st_), "logits") &&
         cuda_ok(cudaStreamSynchronize(st_), "logits");
}

int Gemma4Engine::greedy() {
  g4k::argmax(logits_, kVocab, argmax_out_, argmax_scratch_, st_);
  if (!cuda_ok(cudaMemcpyAsync(argmax_h_, argmax_out_, sizeof(int), cudaMemcpyDeviceToHost, st_), "argmax") ||
      !cuda_ok(cudaStreamSynchronize(st_), "argmax")) {
    return -1;
  }
  return argmax_h_[0];
}

void Gemma4Engine::rebalance(int max_swaps) {
  if (broken_ || layers_.empty() || layers_[0].n_slots == 0 || layers_[0].n_slots >= kExperts) return;
  std::vector<int> counts(kExperts);
  int swaps = 0;
  for (auto& L : layers_) {
    if (cudaMemcpyAsync(counts.data(), L.counts, sizeof(int) * kExperts, cudaMemcpyDeviceToHost, st_) != cudaSuccess ||
        cudaMemsetAsync(L.counts, 0, sizeof(int) * kExperts, st_) != cudaSuccess || cudaStreamSynchronize(st_) != cudaSuccess) {
      broken_ = true;
      return;
    }
    for (int e = 0; e < kExperts; ++e) L.score[static_cast<std::size_t>(e)] = L.score[static_cast<std::size_t>(e)] * 0.85 + counts[static_cast<std::size_t>(e)];
  }
  for (std::size_t round = 0; swaps < max_swaps; ++round) {
    bool any = false;
    for (auto& L : layers_) {
      if (swaps >= max_swaps) break;
      int hot = -1, cold_slot = -1;
      for (int e = 0; e < kExperts; ++e) {
        if (L.slot_of[static_cast<std::size_t>(e)] < 0 && (hot < 0 || L.score[static_cast<std::size_t>(e)] > L.score[static_cast<std::size_t>(hot)])) hot = e;
      }
      for (int s = 0; s < L.n_slots; ++s) {
        const int e = L.expert_in[static_cast<std::size_t>(s)];
        if (cold_slot < 0 || L.score[static_cast<std::size_t>(e)] < L.score[static_cast<std::size_t>(L.expert_in[static_cast<std::size_t>(cold_slot)])]) cold_slot = s;
      }
      if (hot < 0 || cold_slot < 0) continue;
      const int cold = L.expert_in[static_cast<std::size_t>(cold_slot)];
      if (L.score[static_cast<std::size_t>(hot)] <= L.score[static_cast<std::size_t>(cold)] * 1.25 + 0.5) continue;
      std::uint8_t* slot = L.slots + L.ex.bytes * static_cast<std::size_t>(cold_slot);
      if (cudaMemcpyAsync(slot, L.host_experts + L.ex.bytes * static_cast<std::size_t>(hot), L.ex.bytes, cudaMemcpyHostToDevice, st_) != cudaSuccess) {
        broken_ = true;
        return;
      }
      L.table_host[static_cast<std::size_t>(hot)] = expert_ptr(L.ex, slot);
      L.table_host[static_cast<std::size_t>(cold)] = expert_ptr(L.ex, L.host_alias + L.ex.bytes * static_cast<std::size_t>(cold));
      L.slot_of[static_cast<std::size_t>(hot)] = cold_slot;
      L.slot_of[static_cast<std::size_t>(cold)] = -1;
      L.expert_in[static_cast<std::size_t>(cold_slot)] = hot;
      if (cudaMemcpyAsync(L.table + hot, &L.table_host[static_cast<std::size_t>(hot)], sizeof(g4k::ExpertPtr), cudaMemcpyHostToDevice, st_) != cudaSuccess ||
          cudaMemcpyAsync(L.table + cold, &L.table_host[static_cast<std::size_t>(cold)], sizeof(g4k::ExpertPtr), cudaMemcpyHostToDevice, st_) != cudaSuccess) {
        broken_ = true;
        return;
      }
      ++swaps;
      any = true;
    }
    if (!any) break;
  }
  if (swaps > 0) cudaStreamSynchronize(st_);
}

}  // namespace

std::unique_ptr<Engine> Engine::create(const EngineConfig& config, const ModelDesc& model, std::string& error) {
  auto e = std::make_unique<Gemma4Engine>();
  if (!e->load(config, model, error)) {
    if (error.empty()) error = "the engine could not load the model";
    return nullptr;
  }
  return e;
}

}  // namespace g4

// engines/unified/src/family/ds4_graph.cu
// -----------------------------------------------------------------------------
// The DeepSeek-V4.1-Flash (ds4) family graph, ported from engines/maya-ref/src/ds4
// (ds4_model.cu / ds4_main.cpp, MIT) onto the unified engine's shared facilities.
// This is the CORE SERVE GRAPH: geometry load, the per-layer forward pass (MLA
// attention over the compressed/latent KV window + the learned sparse index, then
// the sigmoid-routed MoE through u::ExpertTier), the head, sampling, the DSpark
// speculative round, and the generate() serve loop emitting T / PP / DONE via the
// sink.
//
// WHAT IS SHARED (NOT duplicated here) — design §1.2, §3.1, plan T1.1/T1.2:
//   kernels/common.cuh : u::k::  matmul / mmvq (quantized weight GEMV), rmsnorm,
//                        rope, softmax, router_sigmoid (sigmoid router + bias + top-k),
//                        sampler.
//   u_experts.hpp      : u::ExpertTier  — the VRAM/RAM/CPU expert tiering + the
//                        expert-hit-profile warm start + online rebalance; it runs
//                        the routed-expert GEMMs given the router picks.
// WHAT IS DS4-SPECIFIC (in kernels/ds4_*.cu): MLA / latent-KV window, the learned
//   index/sparse attention, the hyper-connection residual streams, and DSpark.
//
// SCOPE (lean serve path): single GPU. The reference's multi-GPU tensor
// parallelism, the threaded/async mailbox decode, EXL3 exotic layouts, vision and
// the slot/checkpoint conversation machinery are dropped (design §1.2). The deep
// paths that remain relevant (full DSpark sampled speculative acceptance, the exotic
// KV FP8/FP4 packing, chunked prefill) are STRUCTURED STUBS with precise TODOs
// citing ds4_model.cu file:line; the GPU box fills + parity-checks them (plan T1.4).
//
// Compiled only on the GPU box (STRATA_U_CUDA ON, CUDA language). On host / CI this
// is an empty translation unit; the engine serves via u::make_family_graph's stub.
// -----------------------------------------------------------------------------
#include "family/ds4_graph.hpp"

#if defined(STRATA_U_CUDA)

#include "kernels/common.cuh"     // u::k::  (shared generic kernels; T1.1)
#include "u_experts.hpp"          // u::ExpertTier (shared expert tier; T1.2)
#include "kernels/ds4_mla.cuh"
#include "kernels/ds4_index.cuh"
#include "kernels/ds4_dspark.cuh"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <cuda_runtime.h>

// -----------------------------------------------------------------------------
// SHARED CONTRACTS. u::k (kernels/common.cuh) is landed and used directly: this
// graph calls k::mmvq_f32 / k::f32_gemv / k::bf16_gemv (the matvec per quant),
// k::rms_norm, k::swiglu, k::add_inplace, k::f32_gemv (router logits),
// k::router_sigmoid (ds4 is a sigmoid-routed family), k::sample_tokens /
// k::SamplerParams. See the Weight helper (wmul) for the quant dispatch.
//
// u::ExpertTier (u_experts.hpp, lane T1.2) is NOT landed yet; the expected
// interface this graph relies on is:
//
//   namespace u {
//     class ExpertTier {
//      public:
//       // Writes the WEIGHTED routed-expert sum for a window of T tokens:
//       //   out[t][:n_embd] = sum_{i<k} weights[t][i] * expert(ids[t][i])(x[t])
//       // across the VRAM / RAM / CPU tiers (hidden). ids/weights are [T][kPicks];
//       // the shared expert is added by the caller. layer indexes the per-layer
//       // expert weights the facility loaded (warm-started from the hit profile).
//       bool run_window(int layer, const float* x, const int* ids, const float* weights, int T, int k,
//                       int n_embd, int n_ff, float swiglu_limit, float* out, void* stream, std::string& err);
//     };
//   }
// TODO(box): reconcile run_window against u_experts.hpp once T1.2 lands.
// -----------------------------------------------------------------------------

namespace u {
namespace {

inline double now_ms() {
  using namespace std::chrono;
  return (double) duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count() / 1000.0;
}

#define DS4_CK(expr)                                                                    \
  do {                                                                                  \
    const cudaError_t e_ = (expr);                                                      \
    if (e_ != cudaSuccess) { err = std::string("ds4 cuda: ") + cudaGetErrorString(e_); return false; } \
  } while (0)

using ds4::kWin;
using ds4::kPicks;

// Extended ds4 geometry: the common dims from u::Geometry plus the MLA / index /
// DSpark dims DeepSeek carries. The reference reads these from the pack's kv with
// DeepSeek HF-config names (ds4_model.cu Geo::from, :468-496). The unified
// u::Geometry guard only carries the common dims (u_geometry.hpp:31-48).
//
// TODO(box): wire the ds4.* GGUF metadata keys into these fields. Either extend
//   u_geometry's reader with a ds4 block, or pass the GgufFile to make_ds4_graph.
//   Key map (GGUF ds4.* <- DeepSeek config, ds4_model.cu:469-491):
//     ds4.attention.key_length            <- head_dim                (hd)
//     ds4.attention.q_lora_rank           <- q_lora_rank             (q_lora)
//     ds4.attention.kv_lora_rank          <- kv latent / o_lora_rank (o_lora)
//     ds4.rope.dimension_count            <- qk_rope_head_dim        (rd)
//     ds4.attention.o_groups              <- o_groups
//     ds4.expert_count / used / shared    <- n_routed_experts / per_tok / shared
//     ds4.hc_mult                         <- hc_mult                 (hc streams)
//     ds4.index.n_heads / head_dim / topk <- index_n_heads/head_dim/topk
//     ds4.candidate.topk_blocks / block   <- candidate_topk_blocks / block_size
//     ds4.compress_ratios[]               <- compress_ratios (per layer)
//     ds4.kv_source_layer_ids[] / index_source_layer_ids[] / engram_layer_ids[]
//     ds4.dspark.* (block_size, noise_token_id, markov_rank, target_layer_ids, ...)
struct Ds4Geometry {
  // common (from u::Geometry)
  int vocab = 0, dim = 0, nl = 0, heads = 0, ff = 0, n_exp = 0, k_exp = 0, shared = 0;
  int64_t context = 0;
  double rope_theta = 1e4;
  // MLA
  int hd = 0;            // head_dim (the per-head K=V latent width)
  int q_lora = 0;        // query down-projection rank
  int o_lora = 0;        // output / kv latent rank
  int o_groups = 0;      // grouped output projection
  int rd = 0;            // rope dim (a suffix of hd)
  int hc = 1;            // hyper-connection streams
  int win = 0;           // sliding window of raw KV rows
  float eps = 1e-20f, hc_eps = 1e-6f, route_scale = 1.0f, swiglu_limit = 0.0f;
  int sinkhorn = 0;
  // learned index
  int ix_heads = 0, ix_hd = 0, ix_topk = 0, cand_topk = 0, cand_blk = 0;
  // per-layer: compress ratio (0 = not a KV source), and which layers source KV /
  // index / engram. From the ds4.* list keys.
  std::vector<int> ratios, kv_src, ix_src, eg_layers;
  // DSpark drafter
  int n_mtp = 0, d_block = 0, d_noise = 0, d_rank = 0;
  std::vector<int> d_targets;
};

// Derives the extended geometry from the guarded common geometry. Fills what
// u::Geometry carries; leaves the MLA/index/DSpark dims for the box to wire (above).
Ds4Geometry derive_geometry(const Geometry& gg, std::uint32_t context) {
  Ds4Geometry g;
  g.vocab = (int) gg.vocab_size;
  g.dim = (int) gg.embedding_length;
  g.nl = (int) gg.block_count;
  g.heads = (int) gg.head_count;
  g.hd = (int) gg.head_dim;
  g.ff = (int) gg.expert_feed_forward_length;
  g.n_exp = (int) gg.expert_count;
  g.k_exp = (int) gg.expert_used_count;
  g.shared = (int) gg.expert_shared_count;
  g.context = (int64_t) context;
  g.rope_theta = gg.rope_freq_base;
  // TODO(box): the remaining fields (q_lora, o_lora, o_groups, rd, hc, win,
  //   ix_*, cand_*, ratios[], kv_src[], ix_src[], eg_layers[], DSpark) come from
  //   the ds4.* keys — see the key map above. Defaults left at 0 fail closed in
  //   load() until wired.
  return g;
}

// A resident weight matrix: a quantized/bf16/f32 blob plus its format. Replaces the
// reference's x3::Mat (EXL3) with the unified engine's quant set (u::k::Quant). The
// GGUF loader fills {q, w}; the matvec goes through Impl::wmul -> u::k mmvq/gemv.
struct Weight {
  k::Quant q = k::Quant::bf16;
  const void* w = nullptr;
};

// One transformer layer's resident weights (lean; TP mates / EXL3 classes dropped).
// Origin: ds4_model.cu struct Layer (:704-812) trimmed to the serve path.
struct Layer {
  int il = 0, ratio = 0;
  bool kv_src = false, ix_src = false, owns_k = false, cand_src = false, uses_cand = false;
  int src = -1, ik_src = -1, eg = -1;
  // attention
  Weight wq_a, wq_b, wkv, wo_b, c_wkv, c_wgate, i_wq_b, i_wk;
  Weight wo_a[16];
  const float* q_norm = nullptr;
  const float* kv_norm = nullptr;
  const float* attn_norm = nullptr;
  const float* ffn_norm = nullptr;
  const float* c_norm = nullptr;
  const float* ik_norm = nullptr;
  const float* sink = nullptr;
  const float* hca_fn = nullptr; const float* hca_scale = nullptr; const float* hca_base = nullptr;
  const float* hcf_fn = nullptr; const float* hcf_scale = nullptr; const float* hcf_base = nullptr;
  const uint16_t* i_wproj = nullptr;
  // MoE
  Weight s1, s3, s2;           // shared expert (gate, up, down)
  const float* gate_w = nullptr;   // router, F32 [n_exp][dim]
  const float* gate_bias = nullptr;
  // engram
  Weight eg_wkv;
  const float* eg_w = nullptr;
  // KV window ring + compressor state (device)
  uint8_t* win_ring = nullptr;     // [win] rows of kKvFp8(hd)
  float* c_kv = nullptr;           // compressor partial group (ratio>1)
  float* c_score = nullptr;
  int n_exp = 0, k_exp = 0;
};

// A KV source layer's compressed KV + index keys (append-only). Origin: struct Src
// (ds4_model.cu:814-834), trimmed to one device.
struct Src {
  int layer = 0, ratio = 1;
  int64_t cap = 0;
  uint8_t* ckv = nullptr;   // rows of kKvFp4(hd)
  uint8_t* ik = nullptr;    // rows of kKvFp4p(ix_hd)
};

}  // namespace

// =============================================================================
// Ds4Graph::Impl — the resident model and the window scratch.
// =============================================================================
struct Ds4Graph::Impl {
  Ds4Geometry g;
  std::uint32_t ctx = 0;
  bool ready = false;

  std::vector<Layer> L;
  std::vector<Src> srcs;
  std::unique_ptr<ExpertTier> experts;   // the shared tier facility (T1.2)

  // head
  const float* head_norm = nullptr;
  Weight head;

  // rope frequency tables (F32, precomputed on load): the window / compressor bases.
  float* freqs_win = nullptr;
  float* freqs_comp = nullptr;

  // generation state
  int64_t pos = 0;
  std::vector<int32_t> toks;

  // device stream + window scratch (allocated in alloc_scratch). Sizes are rows of
  // up to kWin tokens; the routed-expert rows are kWin*kPicks. Origin: struct Dev
  // (ds4_model.cu:524-584) trimmed to the serve path.
  cudaStream_t st = nullptr;
  float *h = nullptr, *h2 = nullptr, *x = nullptr, *pre = nullptr;
  float *mix = nullptr, *a_pre = nullptr, *a_post = nullptr, *a_comb = nullptr;
  float *f_pre = nullptr, *f_post = nullptr, *f_comb = nullptr;
  float *qr = nullptr, *q = nullptr, *kvr = nullptr, *ckr = nullptr, *cgr = nullptr, *latent = nullptr;
  float *ikr = nullptr, *iq = nullptr, *iw = nullptr, *scores = nullptr;
  float *o = nullptr, *oa = nullptr, *ao = nullptr;
  float *glog = nullptr, *sg = nullptr, *su = nullptr, *sh = nullptr, *sh_out = nullptr;
  float *rw = nullptr, *moe_routed = nullptr, *logits_dev = nullptr;
  uint16_t *emb_rows = nullptr, *ext = nullptr;
  int *ridx = nullptr, *topk = nullptr, *cand = nullptr, *tok_dev = nullptr;
  void* q8_scratch = nullptr;         // Q8_1 activation scratch for mmvq_f32 (<=8 cols)
  uint16_t* x16 = nullptr;            // one activation column as BF16, for bf16_gemv
  ds4::TopkScratch tks{};
  ds4::AttnScratch attn_scr{};
  uint16_t* embed_pinned = nullptr;   // the embedding table (BF16), host-pinned
  uint16_t* h_emb = nullptr;          // a window's embedding rows (pinned)
  int n_logits = 0;

  // The quant-dispatched matvec: y[T][n_out] = W . x[T][n_in], W in Weight::q.
  // Quantized -> k::mmvq_f32 in column groups of <=8; bf16 -> per-column k::bf16_gemv
  // (x converted to BF16 in x16); f32 -> per-column k::f32_gemv. Replaces the
  // reference's x3::mv/job (ds4_model.cu mv/mv_n :8909-8945).
  void wmul(const Weight& m, const float* xin, float* y, int n_in, int n_out, int T);

  // strides (ds4_model.cu:6145-6147, 3242-3247)
  int topk_stride() const { return std::max(g.ix_topk, 32); }
  int cand_stride() const { return std::max(g.cand_topk, 32); }
  long long bm_stride() const { return (long long) (g.context + 64) / std::max(1, g.cand_blk) + 64; }
  std::size_t ckv_rb() const { return ds4::kv_row_bytes(ds4::kKvFp4, g.hd); }
  std::size_t ik_rb() const { return ds4::kv_row_bytes(ds4::kKvFp4p, g.ix_hd); }

  bool load(const Geometry& gg, std::uint32_t context, std::string& err);
  bool alloc_scratch(std::string& err);
  bool forward(const int* tk, int T, int logits_rows, std::string& err);
  bool layer_forward(Layer& l, int64_t p0, int T, std::string& err);
  bool head_forward(int T, std::string& err);
  bool step(int token, bool want_logits, std::string& err) { return forward(&token, 1, want_logits ? 1 : 0, err); }
  int sample(const k::SamplerParams& sp);
  bool draft(int y, std::vector<int>& out, std::vector<float>& conf, const k::SamplerParams& sp, std::string& err);
  bool verify(int y, const std::vector<int>& drafts, const k::SamplerParams& sp, int& accepted, int& next,
              std::string& err);
  ~Impl();
};

// --------------------------------------------------------------- load / alloc

bool Ds4Graph::Impl::load(const Geometry& gg, std::uint32_t context, std::string& err) {
  g = derive_geometry(gg, context);
  ctx = context;
  if (g.dim <= 0 || g.nl <= 0 || g.heads <= 0 || g.hd <= 0 || g.vocab <= 0) {
    err = "ds4: incomplete geometry (the ds4.* MLA/index keys are not wired yet — see derive_geometry TODO)";
    return false;
  }
  DS4_CK(cudaStreamCreate(&st));
  // TODO(box): read the GGUF tensors and fill every Layer's Weight {q,w} and norm
  //   pointers, the head, the router gate_w/gate_bias, and the per-layer expert
  //   weights into u::ExpertTier (warm-started from the expert-hit profile, §3.5).
  //   Allocate win_ring / c_kv / c_score per layer and the Src ckv/ik caches
  //   (cap = context / ratio rows of ckv_rb()/ik_rb()). Precompute freqs_win /
  //   freqs_comp (DeepSeek YaRN rope, ds4_model.cu rope_freqs :500-521). Load the
  //   embedding table into embed_pinned. Reference: ds4_model.cu load() (:2306),
  //   alloc (:2750), place_experts (:4541), load_experts (:5293). Set ready on success.
  L.assign((std::size_t) g.nl, Layer{});
  experts = std::make_unique<ExpertTier>();
  if (!alloc_scratch(err)) return false;
  // ready stays false until the GPU box implements the weight/KV/profile/embedding
  // loads above and the ds4.* geometry wiring. available() reports false and the
  // serve loop refuses to generate until then — honest about the resident state.
  ready = false;   // TODO(box): set true once load() fills the weights + embed_pinned.
  return true;
}

bool Ds4Graph::Impl::alloc_scratch(std::string& err) {
  const int D = g.dim, H = std::max(1, g.hc), HD = g.hd, NH = g.heads, FF = g.ff;
  const int W = kWin;
  auto da = [&](auto** pp, std::size_t count) -> bool {
    using T = std::remove_reference_t<decltype(**pp)>;
    void* q = nullptr;
    const cudaError_t e = cudaMalloc(&q, count * sizeof(T));
    if (e != cudaSuccess) { err = std::string("ds4 alloc: ") + cudaGetErrorString(e); return false; }
    *pp = static_cast<T*>(q);
    return true;
  };
  // rows of up to kWin tokens; routed-expert rows kWin*kPicks (ds4_model.cu:2750+).
  const std::size_t WH = (std::size_t) W * H * D;
  if (!(da(&h, WH) && da(&h2, WH) && da(&x, (std::size_t) W * D) && da(&pre, (std::size_t) W * 8) &&
        da(&mix, (std::size_t) W * 32) && da(&a_pre, (std::size_t) W * 8) && da(&a_post, (std::size_t) W * 8) &&
        da(&a_comb, (std::size_t) W * 64) && da(&f_pre, (std::size_t) W * 8) && da(&f_post, (std::size_t) W * 8) &&
        da(&f_comb, (std::size_t) W * 64) && da(&qr, (std::size_t) W * std::max(1, g.q_lora)) &&
        da(&q, (std::size_t) W * NH * HD) && da(&kvr, (std::size_t) W * HD) && da(&ckr, (std::size_t) W * HD) &&
        da(&cgr, (std::size_t) W * HD) && da(&latent, (std::size_t) W * HD) &&
        da(&ikr, (std::size_t) W * std::max(1, g.ix_hd)) &&
        da(&iq, (std::size_t) W * std::max(1, g.ix_heads) * std::max(1, g.ix_hd)) && da(&iw, (std::size_t) W * 64) &&
        da(&scores, (std::size_t) W * (g.context + 64)) && da(&o, (std::size_t) W * NH * HD) &&
        da(&oa, (std::size_t) W * std::max(1, g.o_groups) * std::max(1, g.o_lora)) && da(&ao, (std::size_t) W * D) &&
        da(&glog, (std::size_t) W * 1024) && da(&sg, (std::size_t) W * FF) && da(&su, (std::size_t) W * FF) &&
        da(&sh, (std::size_t) W * FF) && da(&sh_out, (std::size_t) W * D) &&
        da(&rw, (std::size_t) W * kPicks) && da(&moe_routed, (std::size_t) W * D) &&
        da(&logits_dev, (std::size_t) W * g.vocab) && da(&emb_rows, (std::size_t) W * D) &&
        da(&ext, (std::size_t) (g.win + W) * HD) && da(&ridx, (std::size_t) W * kPicks) &&
        da(&topk, (std::size_t) W * topk_stride()) && da(&cand, (std::size_t) W * cand_stride()) && da(&tok_dev, W)))
    return false;
  DS4_CK(cudaMallocHost((void**) &h_emb, (std::size_t) W * D * sizeof(uint16_t)));
  // Q8_1 scratch for the widest matvec (dim or ff, up to 8 columns a call) and a
  // one-column BF16 activation buffer for bf16_gemv.
  const int max_in = std::max(std::max(D, FF), std::max(std::max(1, g.q_lora), NH * HD));
  DS4_CK(cudaMalloc(&q8_scratch, k::q8_1_scratch_bytes(max_in, 8)));
  if (!da(&x16, (std::size_t) max_in)) return false;
  // tks / attn_scr sizing: ds4_model.cu:2768-2769. Left for the box when the index
  // dims are wired (topk_stride()/ix_hd depend on ds4.* keys).
  return true;
}

// The quant-dispatched matvec. See the declaration for the contract.
void Ds4Graph::Impl::wmul(const Weight& m, const float* xin, float* y, int n_in, int n_out, int T) {
  if (m.q == k::Quant::f32) {
    for (int t = 0; t < T; ++t)
      k::f32_gemv(xin + (std::size_t) t * n_in, (const float*) m.w, y + (std::size_t) t * n_out, n_in, n_out, st);
  } else if (m.q == k::Quant::bf16) {
    for (int t = 0; t < T; ++t) {
      k::f32_to_bf16(xin + (std::size_t) t * n_in, x16, n_in, st);
      k::bf16_gemv(x16, (const uint16_t*) m.w, y + (std::size_t) t * n_out, n_in, n_out, st);
    }
  } else {
    for (int c0 = 0; c0 < T; c0 += 8) {
      const int nc = std::min(8, T - c0);
      k::mmvq_f32(m.q, m.w, xin + (std::size_t) c0 * n_in, q8_scratch, y + (std::size_t) c0 * n_out, n_in, n_out, nc,
                  st);
    }
  }
}

// --------------------------------------------------------------- the forward pass

// One transformer layer over a window of T tokens at p0, single GPU. Faithful to
// the host-routed serve path of ds4_model.cu layer() (:11432-11941), re-expressed
// on the shared kernels; TP / async-mailbox / EXL3-class branches dropped (§1.2).
bool Ds4Graph::Impl::layer_forward(Layer& l, int64_t p0, int T, std::string& err) {
  const int D = g.dim, H = std::max(1, g.hc), HD = g.hd, NH = g.heads, FF = g.ff;
  const float* freqs = l.ratio ? freqs_comp : freqs_win;

  // -- Engram (only engram layers; ds4_model.cu:11445-11460). STRUCTURED: the
  //    kernels are stubs (ds4_mla engram_*); the host n-gram read is the box's.
  if (l.eg >= 0 && l.eg_w != nullptr) {
    // TODO(box): issue the n-gram rows (ds4_model.cu eg_issue :6254 / eg_finish
    //   :6334), dequant, project eg_wkv, then engram_gate into h. Skipped here.
  }

  // -- Attention block: hyper-connection mix/split, then MLA.
  ds4::hc_mix(h, l.hca_fn, H * D, (2 + H) * H, T, g.eps, mix, st);
  ds4::hc_split(mix, l.hca_scale, l.hca_base, H, g.sinkhorn, g.hc_eps, T, a_pre, a_post, a_comb, st);
  ds4::hc_pre_norm(h, pre, l.attn_norm, D, H, T, g.eps, x, st);

  // query: down (wq_a) -> RMSNorm(q_norm) -> up (wq_b) -> RoPE
  wmul(l.wq_a, x, qr, D, g.q_lora, T);
  ds4::Finish fq; fq.w = l.q_norm; fq.eps = g.eps;
  ds4::finish(qr, T, g.q_lora, g.q_lora, fq, st);
  wmul(l.wq_b, qr, q, g.q_lora, NH * HD, T);
  ds4::Finish fr; fr.rd = g.rd; fr.pos = (int) p0; fr.vpp = NH; fr.freqs = freqs;
  ds4::finish(q, T * NH, HD, HD, fr, st);

  // KV latent for this window's rows -> the FP8 window ring.
  ds4::ring_to_ext(l.win_ring, ext, p0, g.win, HD, st);
  wmul(l.wkv, x, kvr, D, HD, T);
  ds4::Finish fk; fk.w = l.kv_norm; fk.eps = g.eps; fk.rd = g.rd; fk.pos = (int) p0; fk.freqs = freqs;
  fk.quant = 1; fk.dst = ext + (std::size_t) g.win * HD; fk.dst_stride = HD;
  ds4::finish(kvr, T, HD, HD, fk, st);
  ds4::ext_to_ring(ext, l.win_ring, p0, g.win, T, HD, st, nullptr);

  // per-query window extents; nsel filled after the index selects.
  ds4::AttnRows ar{};
  for (int t = 0; t < T; ++t) {
    const int first = (int) std::max<int64_t>(g.win - p0, t + 1);
    ar.win0[t] = first;
    ar.nwin[t] = g.win + t - first + 1;
    ar.nsel[t] = 0;
  }

  const void* ckv = nullptr;
  if (l.ratio > 0 && l.src >= 0) {
    Src& sr = srcs[(std::size_t) l.src];
    const int R = l.ratio;
    const int64_t g_first = p0 / R, g_end = (p0 + T) / R;
    const int ng = (int) std::max<int64_t>(0, g_end - g_first);
    // compress this window's KV into the latent groups.
    if (l.kv_src) {
      wmul(l.c_wkv, x, ckr, D, HD, T);
      if (R > 1) {
        wmul(l.c_wgate, x, cgr, D, HD, T);
        ds4::compress_win(ckr, cgr, l.c_kv, l.c_score, R, (int) p0, T, HD, l.c_norm, g.eps, latent, st);
      } else {
        ds4::Finish fc; fc.w = l.c_norm; fc.eps = g.eps;
        ds4::finish(ckr, T, HD, HD, fc, st);
        DS4_CK(cudaMemcpyAsync(latent, ckr, (std::size_t) T * HD * 4, cudaMemcpyDeviceToDevice, st));
      }
    }
    // per-query compressed-position limits.
    ds4::Rows lim{};
    int clen_max = 0;
    for (int t = 0; t < T; ++t) {
      lim.n[t] = (int) ((p0 + t + 1) / R);
      lim.k[t] = std::min(g.ix_topk, lim.n[t]);
      clen_max = std::max(clen_max, lim.n[t]);
    }
    // the learned sparse index: score the compressed positions and pick top-k.
    if (l.ix_src && l.ik_src >= 0) {
      Src& ks = srcs[(std::size_t) l.ik_src];
      if (l.owns_k && ng > 0) {
        wmul(l.i_wk, latent, ikr, HD, g.ix_hd, ng);
        ds4::Finish fi; fi.rd = g.rd; fi.pos = (int) (g_first * R); fi.pos_step = R; fi.freqs = freqs;
        fi.quant = 3; fi.pdst = ks.ik + (std::size_t) g_first * ik_rb(); fi.pdst_stride = (long long) ik_rb();
        ds4::finish(ikr, ng, g.ix_hd, g.ix_hd, fi, st);
      }
      if (clen_max > 0) {
        wmul(l.i_wq_b, qr, iq, g.q_lora, g.ix_heads * g.ix_hd, T);
        ds4::Finish fi; fi.rd = g.rd; fi.pos = (int) p0; fi.vpp = g.ix_heads; fi.freqs = freqs; fi.quant = 3;
        ds4::finish(iq, T * g.ix_heads, g.ix_hd, g.ix_hd, fi, st);
        ds4::gemv_f16_rows(l.i_wproj, x, (std::size_t) D, g.ix_heads, D, T,
                           1.0f / std::sqrt((float) g.ix_hd) / std::sqrt((float) g.ix_heads), iw, 64, st);
        const long long ss = (long long) g.context + 64;
        ds4::index_score(iq, iw, ks.ik, g.ix_heads, g.ix_hd, T, clen_max, nullptr, 0, 1, lim, scores, ss, st);
        if (l.cand_src) {
          ds4::Rows cr = lim;
          for (int t = 0; t < T; ++t) cr.k[t] = g.cand_topk;
          ds4::cand_blocks(scores, ss, T, cr, g.cand_blk, /*bm*/ scores, bm_stride(), cand, cand_stride(), st);
        }
        ds4::topk(scores, ss, T, lim, nullptr, 0, 1, topk, topk_stride(), st, &tks);
      }
    }
    // write the compressed KV rows (FP4) for the layers that read this source.
    if (l.kv_src && ng > 0) {
      ds4::Finish fc; fc.rd = g.rd; fc.pos = (int) (g_first * R); fc.pos_step = R; fc.freqs = freqs;
      fc.quant = 2; fc.pdst = sr.ckv + (std::size_t) g_first * ckv_rb(); fc.pdst_stride = (long long) ckv_rb();
      ds4::finish(latent, ng, HD, HD, fc, st);
    }
    for (int t = 0; t < T; ++t) ar.nsel[t] = lim.n[t] > 0 ? std::min(g.ix_topk, lim.n[t]) : 0;
    ckv = sr.ckv;
  }

  // sparse attention over the window rows + the selected compressed rows.
  ds4::sparse_attn(q, ext, ckv, topk, topk_stride(), ar, l.sink, NH, HD, T,
                   1.0f / std::sqrt((float) HD), o, st, ds4::kKvFp4, 0, &attn_scr);
  ds4::Finish fo; fo.rd = g.rd; fo.pos = (int) p0; fo.vpp = NH; fo.freqs = freqs; fo.inverse = 1;
  ds4::finish(o, T * NH, HD, HD, fo, st);
  // output projection: grouped wo_a then wo_b.
  const int OG = std::max(1, g.o_groups), per = (NH * HD) / OG;
  for (int gi = 0; gi < OG; ++gi)
    wmul(l.wo_a[gi], o + (std::size_t) gi * per, oa + (std::size_t) gi * g.o_lora, per, OG * g.o_lora, T);
  wmul(l.wo_b, oa, ao, OG * g.o_lora, D, T);
  ds4::hc_post(ao, h, a_post, a_comb, D, H, T, h2, st);
  std::swap(h, h2);

  // -- MoE block: hyper-connection mix/split, then shared + routed experts.
  ds4::hc_mix(h, l.hcf_fn, H * D, (2 + H) * H, T, g.eps, mix, st);
  ds4::hc_split(mix, l.hcf_scale, l.hcf_base, H, g.sinkhorn, g.hc_eps, T, f_pre, f_post, f_comb, st);
  ds4::hc_pre_norm(h, a_pre, l.ffn_norm, D, H, T, g.eps, x, st);

  // the shared expert (always-on FFN). ds4::swiglu is DeepSeek's CLAMPED SwiGLU
  // (swiglu_limit); the generic k::swiglu is the unclamped join, so the clamp stays
  // a ds4 variant for parity.
  wmul(l.s1, x, sg, D, FF, T);
  wmul(l.s3, x, su, D, FF, T);
  ds4::swiglu(sg, su, T * FF, g.swiglu_limit, sh, st);
  wmul(l.s2, sh, sh_out, FF, D, T);

  // route (F32 logits per token) + the sigmoid router, then the routed experts via
  // the shared tier (VRAM/RAM/CPU hidden). ds4 is a sigmoid-routed family.
  // TODO(box): the reference scores experts as sqrt(softplus(logits)) (noaux_tc,
  //   ds4_kernels.cuh:96-98), not plain sigmoid. Confirm k::router_sigmoid matches
  //   DeepSeek's selection+weights for parity, else add a ds4 router variant.
  for (int t = 0; t < T; ++t)
    k::f32_gemv(x + (std::size_t) t * D, l.gate_w, glog + (std::size_t) t * l.n_exp, D, l.n_exp, st);
  k::router_sigmoid(glog, l.gate_bias, T, l.n_exp, l.k_exp, g.route_scale, /*norm_w*/ true, ridx, rw, st);
  if (!experts->run_window(l.il, x, ridx, rw, T, l.k_exp, D, FF, g.swiglu_limit, moe_routed, st, err)) return false;

  // moe result = routed + shared; then the hyper-connection recombine.
  k::add_inplace(moe_routed, sh_out, (std::int64_t) T * D, st);
  ds4::hc_post(moe_routed, h, f_post, f_comb, D, H, T, h2, st);
  std::swap(h, h2);
  DS4_CK(cudaMemcpyAsync(pre, f_pre, (std::size_t) T * 8 * 4, cudaMemcpyDeviceToDevice, st));
  return true;
}

bool Ds4Graph::Impl::head_forward(int T, std::string& err) {
  // collapse the hyper-connection streams, final RMSNorm, then the LM head. The
  // reference does this on the head device (head_rows_dev, ds4_model.cu:11173).
  const int D = g.dim, H = std::max(1, g.hc);
  ds4::hc_pre_norm(h, pre, head_norm, D, H, T, g.eps, x, st);
  // only the last n_logits rows need logits.
  const int r0 = std::max(0, T - n_logits);
  wmul(head, x + (std::size_t) r0 * D, logits_dev, D, g.vocab, n_logits);
  (void) err;
  return true;
}

// Feeds a window of T tokens at the current position, leaving logits for the last
// `logits_rows` rows on the device. Mirrors ds4_model.cu forward()/forward_serial
// (:11198-11310) for a single GPU.
bool Ds4Graph::Impl::forward(const int* tk, int T, int logits_rows, std::string& err) {
  if (T < 1 || T > kWin) { err = "ds4: a window of 1.." + std::to_string(kWin) + " tokens"; return false; }
  if (pos + T > g.context) { err = "ds4: the context is full"; return false; }
  for (int t = 0; t < T; ++t)
    if (tk[t] < 0 || tk[t] >= g.vocab) { err = "ds4: token out of range"; return false; }
  const int64_t p0 = pos;
  const int D = g.dim, H = std::max(1, g.hc);
  for (int t = 0; t < T; ++t) toks.push_back(tk[t]);
  n_logits = std::min(logits_rows, T);
  // embedding rows -> hyper-connection streams.
  for (int t = 0; t < T; ++t)
    std::memcpy(h_emb + (std::size_t) t * D, embed_pinned + (std::size_t) tk[t] * D, (std::size_t) D * 2);
  DS4_CK(cudaMemcpyAsync(emb_rows, h_emb, (std::size_t) T * D * 2, cudaMemcpyHostToDevice, st));
  ds4::embed(emb_rows, T, h, D, H, st);
  ds4::init_pre(pre, T, st);
  for (int il = 0; il < g.nl; ++il)
    if (!layer_forward(L[(std::size_t) il], p0, T, err)) return false;
  if (!head_forward(T, err)) return false;
  DS4_CK(cudaStreamSynchronize(st));
  pos += T;
  // TODO(box): seed the DSpark drafter blocks with this window's tap rows
  //   (ds4_model.cu seed_drafter :8946) so draft() can run next.
  return true;
}

// --------------------------------------------------------------- sampling

int Ds4Graph::Impl::sample(const k::SamplerParams& sp) {
  const int r0 = std::max(0, n_logits - 1);
  // TODO(box): pass the penalty history tail (toks) when sp has penalties; nullptr
  //   / 0 here (no penalties) — ds4_model.cu pen_rows (:9174) builds that window.
  k::sample_tokens(logits_dev + (std::size_t) r0 * g.vocab, 1, g.vocab, nullptr, 0, sp, tok_dev, st);
  int t = -1;
  cudaMemcpyAsync(&t, tok_dev, 4, cudaMemcpyDeviceToHost, st);
  cudaStreamSynchronize(st);
  return t;
}

// --------------------------------------------------------------- DSpark drafter

// Proposes g.d_block draft tokens after y, each with a confidence. GREEDY core is
// faithful (the drafter's argmax); the SAMPLED speculative draws are a structured
// stub. Origin: ds4_model.cu draft_ (:9023-9169).
bool Ds4Graph::Impl::draft(int y, std::vector<int>& out, std::vector<float>& conf, const k::SamplerParams& sp,
                           std::string& err) {
  out.clear();
  conf.clear();
  if (g.n_mtp == 0 || g.d_block < 1) return true;   // no drafter loaded
  (void) y; (void) sp;
  // TODO(box): run the mtp.* blocks as window layers over [y, noise...], then the
  //   drafter's final norm + the trunk head, the Markov bias (ds4::markov_add), the
  //   per-position argmax (k::sample_tokens, greedy) and the confidence head
  //   (ds4::confidence). The SAMPLED path (speculative draws from the request's own
  //   chain, DS4_DSPARK_SAMPLE) and the TP Markov-share head are the deep stubs here.
  //   Reference: ds4_model.cu:9023-9169. Until wired, offer no drafts (the serve
  //   loop falls back to a plain step, which is correct, just not accelerated).
  (void) err;
  return true;
}

// Verifies [y, drafts] in one window and reports how many drafts the trunk accepts
// and the next token. GREEDY acceptance is faithful; the sampled speculative-
// sampling rule (min(1, p/q) with a residual draw) is a structured stub falling back
// to greedy. Origin: ds4_model.cu verify (:9231-9307).
bool Ds4Graph::Impl::verify(int y, const std::vector<int>& drafts, const k::SamplerParams& sp, int& accepted,
                            int& next, std::string& err) {
  const int n = (int) std::min<std::size_t>(drafts.size(), (std::size_t) kWin - 1);
  const int T = n + 1;
  int tk[kWin];
  tk[0] = y;
  for (int i = 0; i < n; ++i) tk[i + 1] = drafts[(std::size_t) i];
  // run the window once, logits for all T rows.
  const int64_t p0 = pos;
  if (!forward(tk, T, T, err)) return false;
  // greedy acceptance: the trunk's argmax agreeing with each draft in turn.
  std::vector<int> argmax((std::size_t) T);
  k::SamplerParams g0 = sp;
  g0.greedy = true;
  g0.temperature = 0.0f;
  // sample the T rows greedily (one call a row keeps it simple + matches the stub).
  for (int i = 0; i < T; ++i) {
    k::sample_tokens(logits_dev + (std::size_t) i * g.vocab, 1, g.vocab, nullptr, 0, g0, tok_dev, st);
    cudaMemcpyAsync(&argmax[(std::size_t) i], tok_dev, 4, cudaMemcpyDeviceToHost, st);
    cudaStreamSynchronize(st);
  }
  int m = 0;
  while (m < n && argmax[(std::size_t) m] == drafts[(std::size_t) m]) ++m;
  next = argmax[(std::size_t) m];
  accepted = m;
  // roll the state back to keep y + the m accepted drafts (positions p0 .. p0+m).
  // TODO(box): the ring / compressor rollback for the rejected tail
  //   (ds4_model.cu rollback :9311, ring_restore / comp_restore_batch) and re-seed
  //   the drafter (seed_drafter). Here we rewind the host position/tokens only; the
  //   device KV past p0+m+1 is overwritten when those positions are fed again.
  if (m + 1 < T) {
    pos = p0 + m + 1;
    toks.resize((std::size_t) pos);
  }
  if (!sp.greedy) {
    // Sampled speculative-sampling acceptance is the deep stub: we accepted on the
    // greedy rule above, which is exact only for temperature<=0. TODO(box): port the
    // min(1,p/q) + residual-draw rule (ds4_model.cu:9260-9295, k::sample_verify).
  }
  return true;
}

Ds4Graph::Impl::~Impl() {
  auto fr = [](auto*& p) { if (p) cudaFree(p); p = nullptr; };
  fr(h); fr(h2); fr(x); fr(pre); fr(mix); fr(a_pre); fr(a_post); fr(a_comb); fr(f_pre); fr(f_post); fr(f_comb);
  fr(qr); fr(q); fr(kvr); fr(ckr); fr(cgr); fr(latent); fr(ikr); fr(iq); fr(iw); fr(scores); fr(o); fr(oa); fr(ao);
  fr(glog); fr(sg); fr(su); fr(sh); fr(sh_out); fr(rw); fr(moe_routed); fr(logits_dev);
  fr(emb_rows); fr(ext); fr(ridx); fr(topk); fr(cand); fr(tok_dev); fr(x16);
  if (q8_scratch) cudaFree(q8_scratch);
  if (h_emb) cudaFreeHost(h_emb);
  if (st) cudaStreamDestroy(st);
}

// =============================================================================
// Ds4Graph — the public FamilyGraph.
// =============================================================================
Ds4Graph::Ds4Graph(std::unique_ptr<Impl> impl) : p_(std::move(impl)) {}
Ds4Graph::~Ds4Graph() = default;

std::uint32_t Ds4Graph::context() const { return p_->ctx; }
bool Ds4Graph::available() const { return p_ && p_->ready; }
std::string Ds4Graph::describe() const { return "ds4(MLA+latent-KV+index+DSpark)"; }

// One generation request on the converged `u` protocol. Mirrors the serve/round
// loop of engines/maya-ref/src/ds4/ds4_main.cpp (serve :361, round :204, the
// decode loop :1002-1044), emitting PP / T / DONE through the sink.
bool Ds4Graph::generate(const Gen& request, const LineSink& sink, std::string& error) {
  Impl& m = *p_;
  if (!m.ready) { error = "ds4: model not loaded"; return false; }
  m.pos = 0;
  m.toks.clear();

  const std::size_t total = request.ids.size();
  const double t0 = now_ms();

  // ---- prefill: feed the prompt in windows of kWin, emitting PP progress.
  std::size_t done = 0;
  std::vector<int> ids(request.ids.begin(), request.ids.end());
  while (done < total) {
    const int n = (int) std::min<std::size_t>((std::size_t) kWin, total - done);
    const bool last = done + (std::size_t) n == total;
    // the prompt's last token gets a logit row (we sample from it); the rest none.
    if (!m.forward(ids.data() + done, n, last ? 1 : 0, error)) return false;
    done += (std::size_t) n;
    const double ms = now_ms() - t0;
    sink(emit(PromptProgress{(std::uint32_t) done, (std::uint32_t) total, ms,
                             ms > 0 ? 1000.0 * (double) done / ms : 0.0}));
  }

  // ---- decode: speculative rounds when a drafter is loaded, else a plain step.
  const double t1 = now_ms();
  // request params (temperature/top_p/top_k/min_p/seed) parsed by the caller into
  // the Gen; here we read the shared defaults. TODO(box): map request.params keys
  // (temperature, top_p, ...) into SamplerParams, as ds4_main parse_request does.
  k::SamplerParams sp{};
  sp.greedy = true;
  sp.temperature = 0.0f;
  // TODO(box): for seeded sampling, advance sp.counter by the draws per token
  //   (ds4_main counter++), and set penalties (set_penalties / pen_rows).

  const std::int64_t limit =
      request.max_new > 0 ? (std::int64_t) request.max_new : m.g.context - (std::int64_t) total;
  std::int64_t produced = 0;
  std::uint32_t spec_hits = 0, spec_steps = 0;
  Finish finish = Finish::length;

  int tok = m.sample(sp);
  std::vector<int> got;
  for (;;) {
    sink(emit(Token{(std::uint32_t) tok}));
    ++produced;
    bool is_eos = false;   // TODO(box): the request/engine EOS set (ds4_main eos list).
    if (is_eos) { finish = Finish::stop; break; }
    if (produced >= limit || m.pos >= m.g.context) { finish = Finish::length; break; }
    if (got.empty()) {
      const int room = (int) std::min<std::int64_t>(limit - produced, m.g.context - m.pos);
      std::vector<int> drafts;
      std::vector<float> conf;
      int acc = 0, nxt = tok;
      bool did_spec = false;
      if (room > 1 && m.g.n_mtp > 0 && m.draft(tok, drafts, conf, sp, error) && !drafts.empty()) {
        // keep drafts while confident and within room.
        int keep = 0;
        while (keep < (int) drafts.size() && keep < room - 1 && conf[(std::size_t) keep] >= 0.5f) ++keep;
        drafts.resize((std::size_t) keep);
        if (keep > 0) {
          if (!m.verify(tok, drafts, sp, acc, nxt, error)) return false;
          for (int i = 0; i < acc; ++i) got.push_back(drafts[(std::size_t) i]);
          got.push_back(nxt);
          spec_steps += (std::uint32_t) keep;
          spec_hits += (std::uint32_t) acc;
          did_spec = true;
        }
      }
      if (!did_spec) {
        if (!m.step(tok, true, error)) return false;
        got.push_back(m.sample(sp));
      }
      std::reverse(got.begin(), got.end());
    }
    tok = got.back();
    got.pop_back();
  }

  const double t2 = now_ms();
  sink(emit(Done{(std::uint32_t) produced, (std::uint32_t) total, t1 - t0, t2 - t1, finish, spec_hits, spec_steps,
                 /*reused*/ 0}));
  return true;
}

// The factory. Builds, loads, and returns the graph; nullptr + error on failure.
std::unique_ptr<FamilyGraph> make_ds4_graph(const Geometry& geom, std::uint32_t context, std::string& error) {
  error.clear();
  if (geom.family != FamilyId::ds4) { error = "make_ds4_graph: not a ds4 geometry"; return nullptr; }
  auto impl = std::make_unique<Ds4Graph::Impl>();
  if (!impl->load(geom, context, error)) return nullptr;
  return std::unique_ptr<FamilyGraph>(new Ds4Graph(std::move(impl)));
}

}  // namespace u

#endif  // STRATA_U_CUDA

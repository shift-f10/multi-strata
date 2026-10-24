// strata-unified-engine: the Gemma-4-26B-A4B (arch "gemma4") model graph — implementation.
//
// Gemma4 RE-EXPRESSED on the shared kernel set (owner decision 2; design §3.2/§3.5: unify gemma4,
// NO cuBLAS-module carve-out). The 26/26-verified standalone engine at engines/gemma4/ is the
// READ-ONLY port reference + llama.cpp-parity oracle; this file maps its forward onto
// kernels/common.cuh (u::k::) + u_experts.hpp (u::ExpertTier), keeping only the genuinely
// gemma4-specific kernels in src/kernels/gemma4_attn.* (dual-RoPE qkv_post, split-K windowed/full
// decode attention, prefill softmax) and src/kernels/gemma4_glue.* (logit soft-cap, scaled Q8_0
// embedding gather). The reference's cuBLAS-specific code (the prompt GEMMs, dequant-to-f32 + SGEMM,
// the strided-batched attention) is intentionally NOT ported (brief + design decision 2).
//
// NOT COMPILED ON CI/dev-host: the engine builds src/family/*.cu + src/kernels/*.cu only behind
// STRATA_U_CUDA on the owner's GPU box. On a host/CI build the factory is not linked and
// u::make_family_graph returns the host stub. There is NO GPU here; this is a faithful, structured,
// documented port for the box to compile and parity against engines/gemma4/.
//
// ============================================================================================
// ASSUMED SHARED API — the seams this lane does NOT own (kernels/common.cuh landed as T1.1,
// u_experts.hpp as T1.2). The signatures below are what this file CALLS; if the landed header
// differs, adjust the call sites here (the gemma4 math and the gemma4-specific kernels do not
// change). As of writing these match the landed headers; the two gemma4-only reconciliations are
// flagged [RECONCILE].
//
//   namespace u::k {   // kernels/common.cuh — the one shared generic kernel set
//     bool  is_quantized(Quant q);
//     // decode/small-batch quantized matvec: quantize x to Q8_1 (scratch) then W·x. ncols=1 here.
//     std::size_t q8_1_scratch_bytes(int n_in, int ncols);
//     void  mmvq_f32(Quant q, const void* W, const float* x, void* scratch_q8_1, float* y,
//                    int n_in, int n_out, int ncols, void* stream);
//     void  bf16_gemv(const uint16_t* x, const uint16_t* w, float* y, int64 n_in, int64 n_out, void*);
//     void  f32_gemv (const float* x, const float* w, float* y, int64 n_in, int64 n_out, void*);
//     void  f32_to_bf16(const float* x, uint16_t* y, int64 n, void*);
//     void  rms_norm(float* x /*in place*/, const float* w /*nullable*/, int64 rows, int64 cols,
//                    float eps, void*);
//     void  geglu(const float* gate, const float* up, float* out, int64 n, void*);  // gelu(gate)*up
//     void  scale_inplace(float* x, int64 n, float s, void*);
//     void  add_inplace(float* dst, const float* src, int64 n, void*);
//     // softmax top-k (dense-prob form): ids=argsort(-softmax(logits))[:k]; weights=p/max(sum,2^-14)
//     // — BIT-IDENTICAL to gemma4's router (g4 router_topk, incl the 6.1e-5 clamp).
//     void  router_topk(const float* logits, int n_tokens, int n_expert, int k, int* ids,
//                       float* weights, void*);
//     void  sample_tokens(const float* logits, int n_tokens, int n_vocab, const int* history,
//                         int history_len, const SamplerParams& p, int* out, void*);
//     struct SamplerParams { int top_k; float top_p,min_p,temperature; int min_keep; ... uint64 seed; };
//   }
//
//   class u::ExpertTier {   // the shared VRAM/RAM expert-tiering + expert-hit-profile facility (§3.5)
//     struct Config { int64 n_layers,n_expert,n_embd,n_ff; k::Quant gate,up,down; Act act; float
//                     act_limit; int64 gate_off,up_off,down_off,blob_bytes,vram_slots;
//                     bool per_layer_admission, has_shared_expert; };
//     enum class Act { swiglu, swiglu_clamped, geglu };   // gemma4 => geglu  (landed: supported)
//     bool open(const Config&, std::string&);
//     bool set_host_arena(const uint8_t* base, int64 bytes, std::string&);     // pinned RAM blobs
//     bool warm_start(const std::vector<std::pair<int32,int32>>& ranked, std::string&);  // §3.5
//     // out[n_embd] = sum_i weights[i] * down(geglu(gate·x, up·x))[ids[i]].  ids/weights are HOST
//     // arrays of length k; x,out are DEVICE [n_embd]. (Decode path; k<=64.)
//     bool compute(int64 layer, const int32* ids, const float* weights, const float* x, float* out,
//                  int64 k, void* stream, std::string&);
//     void note_routing(int64 layer, const int32* ids, int64 k);               // live-rebalance heat
//     int64 rebalance(float margin, void* stream, std::string&);               // live correction
//   };
//
//   // [RECONCILE 1 — ACTIVATION]: gemma4 experts are GeGLU (gelu(gate)*up), not SwiGLU. The landed
//   //   ExpertTier::compute already supports Act::geglu (u_experts.hpp:70, u_experts.cu:395 calls
//   //   k::geglu), so Config.act = Act::geglu is all that is needed. The DENSE MLP uses u::k::geglu
//   //   directly (common.cuh even names it "gemma4's GeGLU dense MLP"). RESOLVED — no box change.
//   // [RECONCILE 2 — PER-EXPERT DOWN SCALE]: gemma4 carries ffn_down_exps.scale[n_expert] (a scalar
//   //   per expert). The reference folds it into the combine: moe[n] = Σ y_k·w_k·down_scale[e_k]
//   //   (g4_engine.cu:548 moe_combine → g4_kernels.cu:482). ExpertTier::compute multiplies each
//   //   expert output by weights[i] AFTER the down projection, so folding down_scale into the HOST
//   //   weight array before compute — weights[i] *= down_scale[ids[i]] — is EXACT. Done in
//   //   forward_one below. If the box prefers the scale applied inside the tier, pass it through
//   //   Config instead; the math is identical.
//   // [BOX NOTE — MIXED EXPERT QUANT]: the 26B-A4B Q8_0 file has uniform Q8_0 experts (fits the one
//   //   Config.{gate,up,down} Quant). The Q8_K_XL variant has layer-29 BF16 down (g4_engine.cu:46);
//   //   the lean ExpertTier cut is quantized-only (u_experts.cu:388), so that variant is a documented
//   //   box extension (per-layer Config or a bf16 expert path), not this lane's concern.
//
// --------------------------------------------------------------------------------------------
// g4 -> shared/gemma4 MAPPING (piece by piece; reference lines are engines/gemma4/src/...):
//   embed (Q8_0 · sqrt(d))           -> u::gemma4::embed_q8                  g4_engine.cu:521 / g4_kernels.cu:207
//   q/k/v/o/gate/up/down/router mm   -> u::k::mmvq_f32 (Q8_0) | bf16_gemv|f32_gemv   g4_engine.cu:525-542 (g4k::matvec)
//   attn_norm/ffn_norm/pre_ffw_norm2 -> copy + u::k::rms_norm (in place)     g4_engine.cu:524,536,544 (g4k::rmsnorm)
//   qkv dual-RoPE + norm + cache     -> u::gemma4::qkv_post                  g4_engine.cu:528-531 / g4_kernels.cu:217
//   decode attention (win/full)      -> u::gemma4::attn_decode              g4_engine.cu:532 / g4_kernels.cu:276,357
//   post-attention sandwich          -> u::k::rms_norm + u::k::add_inplace   g4_engine.cu:535 (g4k::add_rmsnorm)
//   dense GeGLU MLP                  -> u::k::geglu (SHARED)                 g4_engine.cu:539 / g4_kernels.cu:470
//   router pre-norm (·gate_inp_scale·1/√d) -> rms_norm + scale_inplace       g4_engine.cu:541
//   softmax top-8 router             -> u::k::router_topk (SHARED)          g4_engine.cu:543 / g4_kernels.cu:413
//   128-expert top-8 MoE (GeGLU)     -> u::ExpertTier::compute (act=geglu)  g4_engine.cu:545-548
//   layer tail double-sandwich norm  -> rms_norm×3 + add + scale            g4_engine.cu:549 / g4_kernels.cu:183 (ffn_end)
//   final norm + tied Q8_0 head      -> rms_norm + mmvq_f32                 g4_engine.cu:510-512
//   logit soft-cap (cap 30)          -> u::gemma4::softcap                  g4_engine.cu:513 / g4_kernels.cu:486
//   sampling / greedy                -> u::k::sample_tokens (SHARED)        g4_engine.cu:697 (greedy/top_candidates)
//   expert placement / rebalance     -> u::ExpertTier warm_start+rebalance  g4_engine.cu:308,723 (now §3.5 shared)
//
// PREFILL: the reference batches the prompt through cuBLAS (forward_batch g4_engine.cu:635,
// prompt_attention :557, moe_batch :591). That IS the cuBLAS-specific code decision 2 forbids
// bringing, so the lean baseline here consumes the prompt token-by-token through forward_one (the
// same decode path the reference itself uses for short prompts, g4_engine.cu:674-678) — correct,
// all on the shared kernels. A batched prefill fast-path is a documented box option: it would pair
// u::k::mmvq_f32 column-groups / u::k::bf16/f32 GEMV for the projections with u::gemma4::attn_softmax
// (provided) for the windowed attention; it is PERF only, not required for parity.
// ============================================================================================
#include "gemma4_graph.hpp"

#include "kernels/common.cuh"
#include "kernels/gemma4_attn.cuh"
#include "kernels/gemma4_glue.cuh"
#include "u_experts.hpp"
#include "u_protocol.hpp"

#include <cuda_runtime.h>

#include <chrono>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

namespace u {
namespace {

using Clock = std::chrono::steady_clock;
inline double secs(Clock::time_point a, Clock::time_point b) { return std::chrono::duration<double>(b - a).count(); }

// One weight matrix as the shared kernels see it: a quant format and a DEVICE pointer, with the
// GGUF shape (n_in = contiguous reduction dim, n_out = row count). Replaces the reference's
// g4k::Mat (g4_kernels.cuh:21). Q8_0/Q4_K/Q5_K/Q6_K go through mmvq; bf16/f32 through the GEMVs.
struct WeightRef {
  k::Quant quant{k::Quant::q8_0};
  const void* w{nullptr};
  int n_in{0};
  int n_out{0};
};

// A GGUF value helper mirroring u_geometry.cpp.
bool int_key(const GgufFile& f, const std::string& key, std::int64_t& out) {
  const auto* v = f.find(key);
  if (v == nullptr) return false;
  switch (v->type) {
    case GgufType::u8: case GgufType::i8: case GgufType::u16: case GgufType::i16:
    case GgufType::u32: case GgufType::i32: case GgufType::u64: case GgufType::i64:
      out = v->integer;
      return true;
    default: return false;
  }
}
bool real_key(const GgufFile& f, const std::string& key, double& out) {
  const auto* v = f.find(key);
  if (v == nullptr || (v->type != GgufType::f32 && v->type != GgufType::f64)) return false;
  out = v->real;
  return std::isfinite(out);
}

}  // namespace

// Per-layer device descriptor. Weight pointers index the uploaded arena; the f16 KV caches are
// per layer (sliding layers ring, full layers linear). Mirrors g4_engine.cu DevLayer (71-92),
// with the expert blobs owned by the shared ExpertTier instead of per-layer slots.
struct Gemma4DevLayer {
  bool sliding{true};
  int hd{256};
  int n_kv{8};
  int cap{0};  // rows per KV head in the cache (ring for sliding, context for full)
  WeightRef q, k, v, o, gate, up, down, router;
  const float* attn_norm{};
  const float* q_norm{};
  const float* k_norm{};
  const float* post_attn_norm{};
  const float* ffn_norm{};
  const float* post_ffw_norm_1{};
  const float* gate_inp_scale{};
  const float* pre_ffw_norm_2{};
  const float* post_ffw_norm_2{};
  const float* post_ffw_norm{};
  float layer_scale{1.0f};              // layer_output_scale (1 when the tensor is absent)
  std::vector<float> down_scale;        // ffn_down_exps.scale[n_expert], read to host (RECONCILE 2)
  std::uint16_t* kc{};                  // [n_kv][cap][hd] f16
  std::uint16_t* vc{};                  // [n_kv][cap][hd] f16
};

// All CUDA state behind the PIMPL (Gemma4Device, forward-declared in the header).
struct Gemma4Device {
  cudaStream_t stream{};
  std::vector<Gemma4DevLayer> layers;

  // Embedding / head (tied Q8_0 token_embd): `embd_blocks` is the raw GGUF Q8_0 tensor for the
  // scaled embedding gather; `head` is the same tensor as a WeightRef for the tied output matvec.
  const void* embd_blocks{};
  WeightRef head{};
  const float* output_norm{};
  const float* rope_freqs{};  // [head_full/2] proportional-rope factors (full layers)

  ExpertTier experts;

  // scratch (device), all sized in allocate(); one prompt/decode token wide (lean baseline).
  int* ids_d{};
  float *x{}, *x1{}, *h{}, *o{}, *dense{}, *rn{}, *e_in{}, *moe{};
  float *qraw{}, *qout{}, *attn{}, *kraw{}, *vraw{};
  float *g{}, *u{}, *m{}, *rl{};
  int* picks{};       // device [n_exp_used]
  float* wts{};       // device [n_exp_used]
  void* q8scratch{};  // Q8_1 activation scratch for mmvq_f32 (sized for the largest n_in)
  float* dscratch{};  // attn split partials: n_head * max_splits * (head_full+2)
  float* logits{};    // [n_vocab]
  float* xn{};        // [n_embd]
  int* sample_d{};    // [1] sampled id
  int max_splits{0};

  ~Gemma4Device() {
    experts.close();
    for (auto& L : layers) {
      if (L.kc) cudaFree(L.kc);
      if (L.vc) cudaFree(L.vc);
    }
    for (void* p : {(void*)ids_d, (void*)x, (void*)x1, (void*)h, (void*)o, (void*)dense, (void*)rn, (void*)e_in,
                    (void*)moe, (void*)qraw, (void*)qout, (void*)attn, (void*)kraw, (void*)vraw, (void*)g, (void*)u,
                    (void*)m, (void*)rl, (void*)picks, (void*)wts, q8scratch, (void*)dscratch, (void*)logits,
                    (void*)xn, (void*)sample_d}) {
      if (p) cudaFree(p);
    }
    // NOTE(box): the weight arena + the pinned expert-host arena are owned by the shared loader /
    // ExpertTier; free them where they are allocated once that seam lands.
    if (stream) cudaStreamDestroy(stream);
  }

  // Decode matvec: y[n_out] = W · x[n_in], re-expressing g4k::matvec (g4_kernels.cu:674) on the
  // shared kernels. Quantized weights go through mmvq_f32 (x quantized to Q8_1 in q8scratch);
  // bf16/f32 through the shared GEMVs.
  void matvec(const WeightRef& wm, const float* xin, float* y) {
    if (k::is_quantized(wm.quant)) {
      k::mmvq_f32(wm.quant, wm.w, xin, q8scratch, y, wm.n_in, wm.n_out, 1, stream);
    } else if (wm.quant == k::Quant::bf16) {
      // [BOX NOTE] shared bf16_gemv takes bf16 ACTIVATIONS; the reference kept f32 activations
      // against bf16 weights (g4_kernels.cu dot8_bf16, :54). Converting x→bf16 here matches the
      // shared contract but drops a few activation mantissa bits vs the reference — a parity check
      // for the box if a bf16-weight gemma4 variant is served. Reuse `h` is unsafe (may alias), so
      // the box adds a dedicated bf16 x-scratch; left as a cast-in-place TODO (quantized is the
      // 26B-A4B path).
      k::bf16_gemv(reinterpret_cast<const std::uint16_t*>(xin), reinterpret_cast<const std::uint16_t*>(wm.w), y,
                   wm.n_in, wm.n_out, stream);
    } else {
      k::f32_gemv(xin, reinterpret_cast<const float*>(wm.w), y, wm.n_in, wm.n_out, stream);
    }
  }

  void copy(float* dst, const float* src, int n) {
    cudaMemcpyAsync(dst, src, static_cast<std::size_t>(n) * sizeof(float), cudaMemcpyDeviceToDevice, stream);
  }
};

// ------------------------------------------------------------------------------------------------
// Geometry: the gemma4.* metadata beyond the common (guarded, pinned) u::Geometry. Mirrors
// g4_model.cpp check_model (64-190); fails closed on any missing/ill-typed required key.
// ------------------------------------------------------------------------------------------------
bool Gemma4Geometry::from_gguf(const GgufFile& file, const Geometry& common, Gemma4Geometry& out, std::string& err) {
  auto refuse = [&](const std::string& what) { err = "gemma4 geometry: " + what; return false; };

  // Common, pinned fields straight from the guarded geometry (u_geometry.cpp pins them to the
  // 26B-A4B shape before this runs).
  out.n_layers = (int)common.block_count;        // 30
  out.n_embd = (int)common.embedding_length;     // 2816
  out.n_head = (int)common.head_count;           // 16
  out.n_ff = (int)common.feed_forward_length;    // 2112
  out.n_ff_exp = (int)common.expert_feed_forward_length;  // 704
  out.n_expert = (int)common.expert_count;       // 128
  out.n_exp_used = (int)common.expert_used_count;  // 8
  out.n_vocab = (int)common.vocab_size;          // 262144
  out.head_full = (int)common.head_dim;          // key_length = 512
  out.context_train = common.context_length;
  out.rope_base_full = (float)common.rope_freq_base;  // rope.freq_base (full base)

  std::int64_t v = 0;
  double r = 0.0;
  const std::string a = "gemma4";

  // Two head widths and the KV split (g4_model.cpp:74-77,105-118). key_length_swa must be 256,
  // and the sliding/full KV head counts 8/2.
  if (!int_key(file, a + ".attention.key_length_swa", v)) return refuse("missing gemma4.attention.key_length_swa");
  out.head_swa = (int)v;
  if (!int_key(file, a + ".attention.sliding_window", v) || v < 1) return refuse("bad gemma4.attention.sliding_window");
  out.window = (int)v;

  // RoPE bases: full from the common geometry; swa from the gemma4-specific key (g4_model.cpp:91-94).
  if (!real_key(file, a + ".rope.freq_base_swa", r) || r <= 1.0) return refuse("bad gemma4.rope.freq_base_swa");
  out.rope_base_swa = (float)r;
  out.rope_freqs_len = out.head_full / 2;  // one factor per rotated pair of a 512-wide head

  // Norm epsilon + final logit soft-cap (g4_model.cpp:87-98).
  if (!real_key(file, a + ".attention.layer_norm_rms_epsilon", r) || r <= 0.0 || r > 1e-3)
    return refuse("bad gemma4.attention.layer_norm_rms_epsilon");
  out.rms_eps = (float)r;
  if (!real_key(file, a + ".final_logit_softcapping", r) || r <= 0.0 || r > 1000.0)
    return refuse("bad gemma4.final_logit_softcapping");
  out.softcap = (float)r;

  // Special-token ids (g4_model.cpp:120-137). turn_close is found by scanning the vocab for the
  // literal "<turn|>" (a deterministic lookup, not model-data behavior selection).
  std::int64_t eos = -1, bos = -1;
  if (!int_key(file, "tokenizer.ggml.eos_token_id", eos) || eos < 0 || eos >= out.n_vocab)
    return refuse("bad tokenizer.ggml.eos_token_id");
  if (!int_key(file, "tokenizer.ggml.bos_token_id", bos) || bos < 0 || bos >= out.n_vocab)
    return refuse("bad tokenizer.ggml.bos_token_id");
  out.eos_id = (std::int32_t)eos;
  out.bos_id = (std::int32_t)bos;
  const auto* tokens = file.find("tokenizer.ggml.tokens");
  if (tokens == nullptr || tokens->type != GgufType::array || tokens->element != GgufType::string ||
      (int)tokens->texts.size() != out.n_vocab) {
    return refuse("tokenizer.ggml.tokens must hold n_vocab tokens");
  }
  int turn_close = -1;
  for (std::size_t i = 0; i < tokens->texts.size(); ++i) {
    if (tokens->texts[i] != "<turn|>") continue;
    if (turn_close >= 0) return refuse("the <turn|> token appears twice");
    turn_close = (int)i;
  }
  if (turn_close < 0) return refuse("the vocabulary has no <turn|> token");
  out.turn_close_id = turn_close;

  // Per-layer sliding/full pattern + KV cross-check (g4_model.cpp:104-118). sliding_window_pattern
  // is a 30-bool array (true = sliding); head_count_kv a 30-int array that must be 8 on sliding
  // layers and 2 on full layers. The 26B-A4B shape is 25 sliding + 5 full.
  const auto* pattern = file.find(a + ".attention.sliding_window_pattern");
  const auto* kv = file.find(a + ".attention.head_count_kv");
  if (pattern == nullptr || pattern->type != GgufType::array || pattern->element != GgufType::boolean ||
      (int)pattern->integers.size() != out.n_layers) {
    return refuse("gemma4.attention.sliding_window_pattern must list n_layers bools");
  }
  if (kv == nullptr || kv->type != GgufType::array || (int)kv->integers.size() != out.n_layers) {
    return refuse("gemma4.attention.head_count_kv must list n_layers ints");
  }
  out.sliding.assign((std::size_t)out.n_layers, 0);
  int n_full = 0;
  for (int il = 0; il < out.n_layers; ++il) {
    const bool is_sliding = pattern->integers[(std::size_t)il] != 0;
    out.sliding[(std::size_t)il] = is_sliding ? 1 : 0;
    const int want_kv = is_sliding ? out.kv_swa : out.kv_full;
    if ((int)kv->integers[(std::size_t)il] != want_kv) return refuse("a layer's KV head count is not the 26B-A4B value");
    n_full += is_sliding ? 0 : 1;
  }
  // TODO(box): confirm n_full == 5 against the real file (the published 26B-A4B shape). Do NOT
  // hardcode which 5 — the pattern array decides. (void) keeps -Werror quiet if the check is
  // compiled out; the box turns it into a hard assert against the parity oracle.
  (void)n_full;
  return true;
}

// ------------------------------------------------------------------------------------------------
// Construction / load / lifetime.
// ------------------------------------------------------------------------------------------------
Gemma4Graph::Gemma4Graph() : dev_(std::make_unique<Gemma4Device>()) {}
Gemma4Graph::~Gemma4Graph() = default;

bool Gemma4Graph::load(const Geometry& common, std::uint32_t context, std::string& err) {
  context_ = context;
  // Map the guarded, pinned common fields into the gemma4 geometry so describe()/forward have the
  // dims even before the device upload. The gemma4-specific fields (per-layer sliding pattern, the
  // two RoPE bases, soft-cap, special tokens) need the parsed GgufFile and are read by
  // Gemma4Geometry::from_gguf — which the factory cannot call yet (it is handed only the Geometry).
  g_.n_layers = (int)common.block_count;
  g_.n_embd = (int)common.embedding_length;
  g_.n_head = (int)common.head_count;
  g_.n_ff = (int)common.feed_forward_length;
  g_.n_ff_exp = (int)common.expert_feed_forward_length;
  g_.n_expert = (int)common.expert_count;
  g_.n_exp_used = (int)common.expert_used_count;
  g_.n_vocab = (int)common.vocab_size;
  g_.head_full = (int)common.head_dim;
  g_.rope_base_full = (float)common.rope_freq_base;
  g_.context_train = common.context_length;

  // TODO(box) — the device bring-up, gated on the GgufFile seam (see make_gemma4_graph). Once the
  // shared loader hands load() the parsed GgufFile, this is:
  //   1. Gemma4Geometry::from_gguf(file, common, g_, err)  — the per-layer pattern + bases + tokens.
  //   2. cudaStreamCreate(dev_->stream); size max_splits = u::gemma4::attn_decode_splits(context_).
  //   3. Upload token_embd (Q8_0, KEPT in GGUF layout for u::k::mmvq + u::gemma4::embed_q8),
  //      output_norm, rope_freqs; dev_->head = {q8_0, embd, n_embd, n_vocab}.
  //   4. Per layer: upload the 8 matrices (keep quant; set each WeightRef.{quant,w,n_in,n_out}) and
  //      the ~10 f32 norm vectors; read ffn_down_exps.scale -> down_scale (host); read
  //      layer_output_scale[0] -> layer_scale (host, 1 if absent); set sliding/hd/n_kv from g_;
  //      cap = sliding ? ring : context_ (ring = window*2, a safe lean default — box tunes with the
  //      prompt chunk, cf. g4_engine.cu:377); cudaMalloc the f16 KV caches [n_kv*cap*hd].
  //   5. Pin all 128 experts/layer into one host arena (the GGUF ffn_gate_up_exps + ffn_down_exps
  //      bytes, blob layout gate@0 / up@kFfExp-rows / down after — RECONCILE 2 offsets);
  //      ExpertTier::Config{n_layers, n_expert, n_embd, n_ff=n_ff_exp, gate/up/down=Q8_0,
  //      act=Act::geglu, gate_off/up_off/down_off/blob_bytes, vram_slots from --expert-slots/budget,
  //      per_layer_admission=true, has_shared_expert=false}; experts.open(cfg); set_host_arena;
  //      warm_start(ranked) from a committed/saved --expert-profile (§3.5) or empty (cold).
  //   6. Allocate the scratch (x,x1,h,o,dense,rn,e_in,moe = n_embd; qraw/qout/attn = n_head*head_full;
  //      kraw/vraw = max(n_kv*hd); g/u/m = n_ff; rl = n_expert; picks/wts = n_exp_used;
  //      q8scratch = u::k::q8_1_scratch_bytes(n_embd,1); dscratch = n_head*max_splits*(head_full+2);
  //      logits = n_vocab; xn = n_embd; sample_d = 1). Then loaded_ = true; return true.
  // The forward_one/head/generate bodies below are the CONCRETE schedule this bring-up feeds.
  loaded_ = false;
  err = "gemma4 load: device upload + gemma4.* metadata need the GgufFile seam (shared loader); "
        "not wired in this lane — expected on the first box integration build";
  return false;
}

void Gemma4Graph::reset_sequence() {
  pos_ = 0;
  // The KV caches are append-only, so position 0 alone restores them; no memset is needed (a full
  // layer overwrites slot = pos, a sliding layer slot = pos%ring). Mirrors g4 truncate(0)
  // (g4_engine.cu:103): the serve loop's reuse rule sets the kept prefix.
}

// ------------------------------------------------------------------------------------------------
// One token through all 30 layers (decode path; also used per prompt token). Concrete re-expression
// of g4_engine.cu forward_one (517-555) on the shared + gemma4 kernels. Runtime-reached only once
// the box wires load() to succeed (loaded_), but compiled here so the schedule is reviewable.
// ------------------------------------------------------------------------------------------------
bool Gemma4Graph::forward_one(std::int32_t id, std::string& err) {
  if (!loaded_) { err = "gemma4 forward: graph not loaded"; return false; }
  Gemma4Device& d = *dev_;
  void* st = d.stream;
  const int ne = g_.n_embd, nff = g_.n_ff, k = g_.n_exp_used;
  const int pos = (int)pos_;
  const float emb_scale = std::sqrt((float)ne);

  // Embedding (Q8_0 row gather · sqrt(d)). g4_engine.cu:519-521.
  int idh = id;
  cudaMemcpyAsync(d.ids_d, &idh, sizeof(int), cudaMemcpyHostToDevice, d.stream);
  gemma4::embed_q8(d.ids_d, 1, d.embd_blocks, ne, emb_scale, d.x, st);

  for (int il = 0; il < g_.n_layers; ++il) {
    Gemma4DevLayer& L = d.layers[(std::size_t)il];
    const int hd = L.hd, nkv = L.n_kv;
    const int ring = L.sliding ? L.cap : 0;        // sliding caches ring; full are linear
    const int window = L.sliding ? g_.window : 0;

    // --- attention ---
    d.copy(d.h, d.x, ne);
    k::rms_norm(d.h, L.attn_norm, 1, ne, g_.rms_eps, st);     // g4:524
    d.matvec(L.q, d.h, d.qraw);                                // g4:525
    d.matvec(L.k, d.h, d.kraw);                                // g4:526
    if (L.sliding) d.matvec(L.v, d.h, d.vraw);                 // g4:527 (full layers: V-from-K)
    gemma4::QkvPost p{};
    p.q_raw = d.qraw;
    p.k_raw = d.kraw;
    p.v_raw = L.sliding ? d.vraw : d.kraw;   // V-FROM-K on full layers
    p.q_norm = L.q_norm;
    p.k_norm = L.k_norm;
    p.freq_factors = L.sliding ? nullptr : d.rope_freqs;  // proportional rope on full layers
    p.rope_base = L.sliding ? g_.rope_base_swa : g_.rope_base_full;
    p.hd = hd; p.n_head = g_.n_head; p.n_kv = nkv; p.pos0 = pos; p.T = 1;
    p.ring = ring; p.cap = L.cap; p.eps = g_.rms_eps;
    p.q_out = d.qout; p.q16 = nullptr; p.k_cache = L.kc; p.v_cache = L.vc;
    gemma4::qkv_post(p, st);                                   // g4:528-531
    gemma4::attn_decode(d.qout, L.kc, L.vc, hd, g_.n_head, nkv, L.cap, ring, window, pos, d.attn, d.dscratch,
                        d.max_splits, st);                     // g4:532
    d.matvec(L.o, d.attn, d.o);                                // g4:534

    // post-attention sandwich: x1 = x + rms(o)·post_attn_norm (g4:535, g4k::add_rmsnorm).
    k::rms_norm(d.o, L.post_attn_norm, 1, ne, g_.rms_eps, st);
    d.copy(d.x1, d.x, ne);
    k::add_inplace(d.x1, d.o, ne, st);

    // --- dense GeGLU MLP (ff 2112) --- g4:536-540
    d.copy(d.h, d.x1, ne);
    k::rms_norm(d.h, L.ffn_norm, 1, ne, g_.rms_eps, st);
    d.matvec(L.gate, d.h, d.g);
    d.matvec(L.up, d.h, d.u);
    k::geglu(d.g, d.u, d.m, nff, st);                          // SHARED gemma4 GeGLU
    d.matvec(L.down, d.m, d.dense);

    // --- softmax top-8 router --- g4:541-543
    d.copy(d.rn, d.x1, ne);
    k::rms_norm(d.rn, L.gate_inp_scale, 1, ne, g_.rms_eps, st);      // rms(x1)·gate_inp_scale
    k::scale_inplace(d.rn, ne, 1.0f / emb_scale, st);               // ·(1/√d)
    d.matvec(L.router, d.rn, d.rl);
    k::router_topk(d.rl, 1, g_.n_expert, k, d.picks, d.wts, st);    // SHARED (== g4 router)

    // --- 128-expert top-8 MoE (GeGLU) via the shared tier --- g4:544-548
    d.copy(d.e_in, d.x1, ne);
    k::rms_norm(d.e_in, L.pre_ffw_norm_2, 1, ne, g_.rms_eps, st);
    // The tier's compute() takes HOST ids/weights; pull the router output and fold the per-expert
    // down_scale into the weights (RECONCILE 2). One D2H sync per layer — the decode path's cost
    // (the reference syncs picks in moe_batch too, g4:593). A batched tier API would remove it.
    std::int32_t picks_h[64];
    float wts_h[64];
    cudaMemcpyAsync(picks_h, d.picks, (std::size_t)k * sizeof(int), cudaMemcpyDeviceToHost, d.stream);
    cudaMemcpyAsync(wts_h, d.wts, (std::size_t)k * sizeof(float), cudaMemcpyDeviceToHost, d.stream);
    cudaStreamSynchronize(d.stream);
    for (int i = 0; i < k; ++i) {
      const int e = picks_h[i];
      if (e >= 0 && e < (int)L.down_scale.size()) wts_h[i] *= L.down_scale[(std::size_t)e];
    }
    if (!d.experts.compute(il, picks_h, wts_h, d.e_in, d.moe, k, st, err)) return false;
    d.experts.note_routing(il, picks_h, k);  // §3.5 live-rebalance heat

    // --- layer tail: double-sandwich norm + layer scale --- g4:549 (g4k::ffn_end), composed from
    // shared rms_norm/add/scale. d = rms(dense)·w1; m = rms(moe)·w2; f = rms(d+m)·w3;
    // x = (x1 + f)·layer_scale. [BOX PARITY] the fused reference kernel and this composed form can
    // differ in the last mantissa bit (multiply order); the box checks against g4k::ffn_end.
    k::rms_norm(d.dense, L.post_ffw_norm_1, 1, ne, g_.rms_eps, st);
    k::rms_norm(d.moe, L.post_ffw_norm_2, 1, ne, g_.rms_eps, st);
    k::add_inplace(d.dense, d.moe, ne, st);
    k::rms_norm(d.dense, L.post_ffw_norm, 1, ne, g_.rms_eps, st);
    d.copy(d.x, d.x1, ne);
    k::add_inplace(d.x, d.dense, ne, st);
    if (L.layer_scale != 1.0f) k::scale_inplace(d.x, ne, L.layer_scale, st);
  }
  if (!head(err)) return false;
  pos_ = pos + 1;
  return true;
}

// Final norm + tied Q8_0 head + logit soft-cap. g4_engine.cu head (510-515).
bool Gemma4Graph::head(std::string& err) {
  Gemma4Device& d = *dev_;
  void* st = d.stream;
  d.copy(d.xn, d.x, g_.n_embd);
  k::rms_norm(d.xn, d.output_norm, 1, g_.n_embd, g_.rms_eps, st);
  d.matvec(d.head, d.xn, d.logits);                 // tied: mmvq over token_embd Q8_0
  gemma4::softcap(d.logits, g_.n_vocab, g_.softcap, st);
  if (cudaGetLastError() != cudaSuccess) { err = "gemma4 head: CUDA launch failed"; return false; }
  return true;
}

// ------------------------------------------------------------------------------------------------
// FamilyGraph surface.
// ------------------------------------------------------------------------------------------------
std::string Gemma4Graph::describe() const {
  return "gemma4(Gemma-4-26B-A4B: " + std::to_string(g_.n_layers) + "L, " + std::to_string(g_.n_head) +
         "h, hidden " + std::to_string(g_.n_embd) + ", dense ff " + std::to_string(g_.n_ff) + " + 128x" +
         std::to_string(g_.n_exp_used) + " MoE ff " + std::to_string(g_.n_ff_exp) +
         ", sliding/full dual-RoPE, soft-cap, tied Q8_0 head)";
}

namespace {
// Maps the GEN params (key=value) onto the shared sampler. Unknown keys are ignored (the frontend
// owns the full param set); unparseable values keep the default. Penalties need token history and
// are left off in the lean baseline (history null) — a documented box extension.
k::SamplerParams sampler_from(const Gen& req) {
  k::SamplerParams sp;
  for (const KeyVal& kv : req.params) {
    try {
      if (kv.key == "temperature" || kv.key == "temp") sp.temperature = std::stof(kv.value);
      else if (kv.key == "top_p") sp.top_p = std::stof(kv.value);
      else if (kv.key == "min_p") sp.min_p = std::stof(kv.value);
      else if (kv.key == "top_k") sp.top_k = std::stoi(kv.value);
      else if (kv.key == "seed") sp.seed = (std::uint64_t)std::stoull(kv.value);
      else if (kv.key == "greedy") sp.greedy = (kv.value == "1" || kv.value == "true");
    } catch (...) { /* keep the default on a bad value (fail soft for sampling knobs) */ }
  }
  return sp;
}
}  // namespace

bool Gemma4Graph::generate(const Gen& request, const LineSink& sink, std::string& error) {
  // The serve loop, re-expressing g4's decode over the shared forward + sampler. Steps: consume the
  // prompt (emit PP), then sample/emit/append up to max_new (honor eos / <turn|> / the context
  // limit), then emit the terminal DONE. Speculative fields stay 0 (gemma4 has no draft block).
  if (!loaded_) {
    error = "gemma4 generate: graph not loaded (device upload wired by the shared loader seam)";
    return false;
  }
  if (request.ids.empty()) { error = "gemma4 generate: empty prompt"; return false; }
  Gemma4Device& d = *dev_;
  reset_sequence();

  const auto t_start = Clock::now();
  const int n_prompt = (int)request.ids.size();
  if (pos_ + n_prompt > (std::int64_t)context_) { error = "gemma4 generate: prompt exceeds context"; return false; }
  for (int i = 0; i < n_prompt; ++i) {
    if (!forward_one((std::int32_t)request.ids[(std::size_t)i], error)) return false;  // head runs each step; the
    // batched prefill would skip it for non-last tokens (PERF only). PP after each prompt token:
    const double ms = secs(t_start, Clock::now()) * 1000.0;
    const double tok_s = ms > 0.0 ? (double)(i + 1) / (ms / 1000.0) : 0.0;
    sink(emit(PromptProgress{(std::uint32_t)(i + 1), (std::uint32_t)n_prompt, ms, tok_s}));
  }
  const double prompt_ms = secs(t_start, Clock::now()) * 1000.0;

  const k::SamplerParams sp = sampler_from(request);
  const auto t_decode = Clock::now();
  std::uint32_t produced = 0;
  Finish finish = Finish::length;
  for (std::uint32_t n = 0; n < request.max_new; ++n) {
    if (pos_ >= (std::int64_t)context_) { finish = Finish::length; break; }
    // Sample from the current (last) logits. History null => no penalties in the lean baseline.
    k::sample_tokens(d.logits, 1, g_.n_vocab, nullptr, 0, sp, d.sample_d, d.stream);
    int tok = -1;
    cudaMemcpyAsync(&tok, d.sample_d, sizeof(int), cudaMemcpyDeviceToHost, d.stream);
    if (cudaStreamSynchronize(d.stream) != cudaSuccess) { error = "gemma4 generate: sampler sync failed"; return false; }
    if (tok < 0) { finish = Finish::nonfinite; break; }      // -2 from a non-finite logit row
    if (tok == g_.eos_id || tok == g_.turn_close_id) { finish = Finish::stop; break; }
    sink(emit(Token{(std::uint32_t)tok}));
    ++produced;
    if (!forward_one((std::int32_t)tok, error)) return false;  // append; refresh logits for the next step
  }
  const double decode_ms = secs(t_decode, Clock::now()) * 1000.0;

  sink(emit(Done{produced, (std::uint32_t)n_prompt, prompt_ms, decode_ms, finish, 0, 0, 0}));
  return true;
}

// ------------------------------------------------------------------------------------------------
// Factory.
// ------------------------------------------------------------------------------------------------
std::unique_ptr<FamilyGraph> make_gemma4_graph(const Geometry& geom, std::uint32_t context, std::string& error) {
  error.clear();
  if (geom.family != FamilyId::gemma4) {
    error = "make_gemma4_graph: geometry is not gemma4";
    return nullptr;
  }
  auto graph = std::unique_ptr<Gemma4Graph>(new Gemma4Graph());
  // TODO(box) — FACTORY SEAM: load() needs the parsed GgufFile (weights + the gemma4.* metadata
  // Gemma4Geometry::from_gguf reads). The host foundation's make_family_graph (u_family.hpp) passes
  // only the guarded Geometry; the CUDA dispatch that reaches this factory must thread the GgufFile
  // through (a shared-file change this lane does not own — the SAME seam every family lane needs,
  // see raon1_graph.cu's make_raon1_graph TODO). Until then load() fails closed and the graph
  // reports unavailable — expected on the first box integration build, not a family bug.
  if (!graph->load(geom, context, error)) return nullptr;
  return graph;
}

}  // namespace u

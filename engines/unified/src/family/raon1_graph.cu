// strata-unified-engine: the Raon-1-mini (arch "raon1") model graph — implementation.
//
// Modeled on engines/maya-ref/src/core/glm_model.cu (Raon is a near-twin of GLM-5.3-Flash). The
// per-layer schedule, the RDA/Gated-MLA mixers and the sigmoid MoE follow GLM's forward; the
// family-unique kernels are in src/kernels/raon1_rda.* and src/kernels/raon1_mla.* (ported from
// glm_kda / glm_dsa). Everything generic rides the shared substrate: the generic kernels in
// kernels/common.cuh (u::k::) and the expert-tiering facility in u_experts.hpp (u::ExpertTier).
//
// NOT COMPILED ON CI/dev-host. The unified engine builds the family .cu only behind STRATA_U_CUDA
// on the owner's GPU box (design §1.3 / plan "What is verifiable where"); a host/CI build links the
// stub and u::make_family_graph returns it. This file is written for the box, which compiles and
// parities it against the real Raon-1-mini weights.
//
// ============================================================================================
// ASSUMED SHARED API — reconcile with the landed T1.1 (kernels/common.cuh) and T1.2 (u_experts.hpp)
// headers before the first box build. These are the shared seams this lane does not own; the
// signatures below are the intent, named from the brief and GLM's usage. Where one differs from the
// landed header, adjust the call sites in forward()/layer_*()/generate() — the math and the Raon
// kernels do not change.
//
//   namespace u::k {                 // kernels/common.cuh — the one generic kernel set
//     // row-major matmul/GEMV: out[T,n_out] = x[T,n_in] * W[n_out,n_in]^T (+bias). mmvq is the
//     // quantized-weight GEMV (W is a ggml-quantized row tensor); matmul the F32 path.
//     void matmul(const float* x, const float* W, const float* bias, int T, int n_in, int n_out,
//                 float* out, void* stream);
//     void mmvq (const void*  Wq, int wtype, const float* x, int T, int n_in, int n_out,
//                float* out, void* stream);
//     void rmsnorm(const float* x, const float* w, int T, int n, float eps, float* out, void* stream);
//     void softmax(const float* x, int rows, int cols, float* out, void* stream);
//     // sigmoid router: top-k of sigmoid(logits+bias), optionally renormalized to sum 1 and scaled.
//     void router_sigmoid(const float* logits, const float* bias, int T, int n_expert, int n_used,
//                         bool renorm, float w_scale, int* out_ids, float* out_w, void* stream);
//     void silu(const float* x, int n, float* out, void* stream);
//     void gelu(const float* x, int n, float* out, void* stream);
//     void swiglu(const float* gate, const float* up, float clamp /*0=none*/, int64_t n,
//                 float* out, void* stream);  // silu(gate)*up, GLM's clamped variant when clamp>0
//     // sampling: picks one token id from the last row's logits (greedy/top-p/temp per params).
//     int  sample(const float* logits, int n_vocab, const SamplerParams& sp, void* stream);
//   }
//
//   // u_experts.hpp — the shared VRAM/RAM expert-tiering + expert-hit-profile facility (§3.5),
//   // used by every family's MoE. Built once per model; applies the routed experts for a layer.
//   class u::ExpertTier {
//    public:
//     // For T tokens' activations x[T,n_embd], with the per-token routed ids[T,n_used] and
//     // renormalized weights w[T,n_used], accumulate the routed-expert FFN sum into out[T,n_embd].
//     void apply(int layer, const float* x, const int* ids, const float* w, int n_used, int T,
//                float* out, void* stream);
//   };
// ============================================================================================
#include "raon1_graph.hpp"

#include "kernels/common.cuh"
#include "kernels/raon1_mla.cuh"
#include "kernels/raon1_rda.cuh"
#include "u_experts.hpp"

#include <cuda_runtime.h>

#include <string>
#include <vector>

namespace u {
namespace {

// Per-layer weight-name prefix, llama.cpp/GLM convention ("blk.<il>."). The exact Raon tensor
// base names (q/k/v projections, conv, decay, LoRA A/B, router, experts) are confirmed on the box
// against the real GGUF — they follow GLM's where the pieces match (see the per-call TODOs).
// [[maybe_unused]]: the call sites live in the layer_*() bodies the box wires onto the shared
// scratch/weight layout (the mixers below are structural until then); -Werror would flag it.
[[maybe_unused]] std::string blk(int il, const char* suffix) {
  return "blk." + std::to_string(il) + "." + suffix;
}

}  // namespace

// ------------------------------------------------------------------------------------------------
// Geometry: the raon1.* metadata beyond the common (pinned) u::Geometry.
// ------------------------------------------------------------------------------------------------
bool Raon1Geometry::from_gguf(const GgufFile& file, const Geometry& common, Raon1Geometry& out,
                              std::string& err) {
  // The common, pinned fields come straight from the guarded geometry (u_geometry.cpp exact()s
  // them, so these are already validated against Raon's published shape).
  out.n_embd = (int)common.embedding_length;
  out.n_layers = (int)common.block_count;
  out.n_head = (int)common.head_count;
  out.head_dim = (int)common.head_dim;  // 128: RDA head dim and MLA value head dim
  out.n_vocab = (int)common.vocab_size;
  out.n_ff_dense = (int)common.feed_forward_length;
  out.n_ff_exp = (int)common.expert_feed_forward_length;
  out.n_expert = (int)common.expert_count;
  out.n_exp_used = (int)common.expert_used_count;
  out.n_shared = (int)common.expert_shared_count;
  out.router = common.router;  // sigmoid (pinned)
  out.v_head = out.head_dim;

  const std::string arch = common.arch;  // "raon1"
  auto geti = [&](const char* suffix, int def) -> int {
    const GgufValue* v = file.find(arch + suffix);
    return (v != nullptr) ? (int)v->integer : def;
  };
  auto getf = [&](const char* suffix, float def) -> float {
    const GgufValue* v = file.find(arch + suffix);
    return (v != nullptr) ? (float)v->real : def;
  };

  // first_k_dense_replace == leading_dense_block_count (GLM's dense_lead). Published = 1.
  out.dense_lead = geti(".leading_dense_block_count", 1);

  // MLA LoRA ranks and head dims. TODO(box): confirm the exact raon1.* key names — these follow
  // the deepseek2/GLM convention (q_lora_rank / kv_lora_rank / key_length / value_length). The
  // published values are the defaults so a GGUF that omits them still loads the documented shape.
  out.q_lora = geti(".attention.q_lora_rank", 576);
  out.kv_lora = geti(".attention.kv_lora_rank", 512);
  out.qk_nope = geti(".attention.key_length_mla", 192);  // TODO(box): MLA QK head dim key name
  out.v_head = geti(".attention.value_length", out.head_dim);  // V 128

  // RDA short conv + decay-gate lower bound (GLM KDA analogues). TODO(box): confirm presence/keys.
  out.d_conv = geti(".rda.conv_kernel", 4);                 // 0/absent => the graph skips rda_conv
  out.rda_lower_bound = getf(".rda.gate_lower_bound", -5.0f);

  // MoE routing / norm knobs.
  out.w_scale = getf(".expert_weights_scale", 1.0f);
  out.swiglu_clamp = getf(".swiglu_clamp", 0.0f);  // 0 => no clamp (plain SwiGLU)
  out.norm_eps = getf(".attention.layer_norm_rms_epsilon", 1e-5f);
  out.router_renormalize = geti(".expert_weights_norm", 1) != 0;

  // DFlash draft layers counted inside block_count (GLM's nextn). 0 => no draft block loaded.
  out.nextn = geti(".nextn_predict_layers", 0);

  // The per-layer attention-type array: attention.head_count_kv, one int per layer. 0 marks an RDA
  // (linear) layer, nonzero a Gated-MLA layer — GLM's is_recr convention exactly
  // (glm_model.cu:568-570, glm_model.hpp:90). Raon's published split is 18 RDA / 7 MLA.
  out.head_count_kv.assign((size_t)out.n_layers, 0);
  const GgufValue* kv = file.find(arch + ".attention.head_count_kv");
  if (kv != nullptr && !kv->integers.empty()) {
    if ((int)kv->integers.size() != out.n_layers) {
      err = "raon1 geometry: attention.head_count_kv has " + std::to_string(kv->integers.size()) +
            " entries, expected " + std::to_string(out.n_layers);
      return false;
    }
    for (int il = 0; il < out.n_layers; ++il) out.head_count_kv[(size_t)il] = (int)kv->integers[(size_t)il];
  } else {
    // TODO(box): the released Raon-1-mini GGUF is expected to ship the per-layer array. If it does
    // not, the exact 18/7 RDA/MLA pattern must be filled in here from the model card and confirmed
    // against the real weights — do NOT invent a pattern. Refuse until then.
    err = "raon1 geometry: attention.head_count_kv (per-layer RDA/MLA map) is missing; the exact "
          "18/7 pattern must be confirmed on the box before serving (do not guess)";
    return false;
  }

  const int n_rda = [&] { int n = 0; for (int x : out.head_count_kv) n += (x == 0); return n; }();
  const int n_mla = out.n_layers - n_rda;
  (void)n_mla;  // the 18/7 expectation is checked at box bring-up against the parity oracle
  return true;
}

// ------------------------------------------------------------------------------------------------
// Load / state.
// ------------------------------------------------------------------------------------------------
bool Raon1Graph::load(const Geometry& common, std::uint32_t context, std::string& err) {
  context_ = context;
  // Map the guarded, PINNED common fields into the Raon geometry. The Raon-specific fields keep
  // their published defaults (the Raon1Geometry member initializers); the per-layer RDA/MLA map and
  // the exact LoRA/conv keys are read by Raon1Geometry::from_gguf, which needs the parsed GgufFile.
  // The factory's contract (make_raon1_graph) is handed only the guarded Geometry, so the GgufFile
  // reaches the graph through the CUDA dispatch seam (see make_raon1_graph's TODO). Until that seam
  // lands, from_gguf is NOT called here (it has no file) and head_count_kv stays empty.
  g_.n_embd = (int)common.embedding_length;
  g_.n_layers = (int)common.block_count;
  g_.n_head = (int)common.head_count;
  g_.head_dim = (int)common.head_dim;
  g_.v_head = (int)common.head_dim;
  g_.n_vocab = (int)common.vocab_size;
  g_.n_ff_dense = (int)common.feed_forward_length;
  g_.n_ff_exp = (int)common.expert_feed_forward_length;
  g_.n_expert = (int)common.expert_count;
  g_.n_exp_used = (int)common.expert_used_count;
  g_.n_shared = (int)common.expert_shared_count;
  g_.router = common.router;

  // TODO(box): the device-side load is the shared loader's job (T1.1/T1.2) — upload every tensor to
  // w_arena_, dequantizing/keeping-quantized per the shared policy, fill w_ (name -> device ptr),
  // register the 128 experts per MoE layer with u::ExpertTier, and carve the state_/sc_ arenas:
  //   * per RDA layer: recurrence S (n_head*head_dim*head_dim) + conv history (d_inner*(d_conv-1));
  //   * per Gated-MLA layer: the latent cache (context * kv_lora floats);
  //   * sc_: the per-forward activation/router/expert/logits scratch (sized from n_embd, n_ff_*,
  //     n_vocab and the max batch T).
  // This lane sizes and names the state offsets (rda_state_, rda_conv_, mla_latent_) so the layout
  // is reviewable; the allocation + upload land with the shared loader. Until that is wired, load()
  // returns false here on the box's first integration build (expected, not a bug).
  rda_state_.assign((size_t)g_.n_layers, -1);
  rda_conv_.assign((size_t)g_.n_layers, -1);
  mla_latent_.assign((size_t)g_.n_layers, -1);
  loaded_ = false;  // flipped true by the shared loader once the arenas and weights are in
  err = "raon1 load: device upload is wired by the shared loader (T1.1/T1.2); not linked in this lane";
  return false;
}

void Raon1Graph::reset_sequence() {
  pos_ = 0;
  // TODO(box): zero every RDA recurrence state + conv history and reset the MLA latent caches'
  // logical length (append-only, so the position alone restores them). cudaMemsetAsync over the
  // state_ ranges named by rda_state_/rda_conv_; the mla_latent_ caches are reused from position 0.
}

// ------------------------------------------------------------------------------------------------
// Per-layer mixers. Each writes its mixer output back into the residual scratch; the GLM analogy is
// named per step. sc_ slices (x, q, k, v, g, ...) are carved by the shared scratch layout (TODO box).
// ------------------------------------------------------------------------------------------------
bool Raon1Graph::layer_rda(int il, int T, std::string& err) {
  // GLM analogy: glm_model.cu KDA mixer. Pre-norm -> projections -> short conv (+SiLU) -> gate ->
  // gated-delta recurrence -> RMS out-gate -> output projection. NoPE: no rope anywhere.
  //
  //   1. rmsnorm(x, attn_norm.weight)                         u::k::rmsnorm
  //   2. project q, k, v, g (the gate pre-activation) and beta from the normed x
  //        q,k,v: matmul to (head_dim*n_head);  g: to d_inner;  beta: to n_head (per-head scalar)
  //        u::k::matmul / u::k::mmvq with blk(il,"attn_q.weight") etc. TODO(box): exact Raon names
  //   3. u::raon::rda_conv(x_proj=[q|k|v or the mixed proj], conv_w, conv_state, d_inner, d_conv,T)
  //        skipped when g_.d_conv <= 1 (see Raon1Geometry TODO)
  //   4. u::raon::rda_gate(g, decay_a=blk(il,"ssm_a"), g_.rda_lower_bound, head_dim, n_head, T, g1)
  //   5. u::raon::rda_recurrence(q, k, v, g1, beta, state_+rda_state_[il], n_head, head_dim, T, o)
  //   6. u::raon::rda_out_gate(o, norm_w=blk(il,"attn_out_norm"), g2, head_dim, n_head, T, eps, go)
  //   7. matmul(go -> n_embd) with blk(il,"attn_output.weight"); add into the residual
  //
  // TODO(box): confirm (a) the projection tensors and whether q/k/v share one fused proj like GLM's
  // packed KDA proj, (b) beta's projection + sigmoid, (c) the g2 (out-gate) source, (d) d_conv.
  (void)il; (void)T;
  err = "raon1 layer_rda: mixer wiring pending the shared scratch/weight layout (T1.1); kernels ready";
  return false;
}

bool Raon1Graph::layer_mla(int il, int T, std::string& err) {
  // GLM analogy: glm_model.cu DSA/MLA mixer, DENSE (no indexer) + NoPE. Pre-norm -> q/kv LoRA
  // projections -> absorb -> dense latent attention -> v-absorb -> gate -> output projection.
  //
  //   1. rmsnorm(x, attn_norm.weight)                         u::k::rmsnorm
  //   2. q:  matmul x -> q_a (q_lora); rmsnorm(q_a, attn_q_a_norm); matmul -> q (n_head*qk_nope)
  //      kv: matmul x -> kv_a (kv_lora); rmsnorm(kv_a, attn_kv_a_norm) = the latent for this token,
  //          APPENDED to the latent cache at state_+mla_latent_[il] + pos (append-only).
  //      NoPE: no rope split on q or on the latent (u_geometry pins RopeKind::nope).
  //   3. u::raon::mla_absorb_q(q, wk_b=blk(il,"attn_k_b.weight"), kv_lora, qk_nope, n_head, T, q_abs)
  //   4. u::raon::mla_attention(q_abs, latents=cache, d_pos_, wv_b=blk(il,"attn_v_b.weight"),
  //                             kv_lora, n_head, v_head, qk_nope, T, o)   // dense, online softmax
  //   5. u::raon::mla_out_gate(o, gate, v_head, n_head, T, go)   // the "Gated" in Gated-MLA
  //        TODO(box): confirm the gate's source/shape (a projection from the normed x, or absent).
  //   6. matmul(go [n_head*v_head] -> n_embd) with blk(il,"attn_output.weight"); add into residual
  //
  // TODO(box): confirm the kv_a/kv_b split (whether the cached latent is the post-norm kv_lora
  // vector, deepseek2/GLM style), the q_b up-projection width (n_head*qk_nope), and that Raon's MLA
  // is dense (no k-pool indexer). If an indexer ships, port glm_dsa pool/score/select ahead of (4).
  (void)il; (void)T;
  err = "raon1 layer_mla: mixer wiring pending the shared scratch/weight layout (T1.1); kernels ready";
  return false;
}

bool Raon1Graph::layer_ffn(int il, int T, std::string& err) {
  // Layer 0 (il < dense_lead): a plain dense SwiGLU MLP over n_ff_dense=12032.
  // Layers 1..24: sigmoid-routed MoE (128 experts, top-6) + 1 always-on shared expert over
  // n_ff_exp=1088. GLM analogy: glm_model.cu MoE tail (router_sigmoid + grouped experts + shexp).
  //
  //   pre-norm: rmsnorm(x, ffn_norm.weight)                               u::k::rmsnorm
  //
  //   dense (il < dense_lead):
  //     g = matmul(xn, ffn_gate.weight); u = matmul(xn, ffn_up.weight)
  //     h = u::k::swiglu(g, u, g_.swiglu_clamp, n_ff_dense)               // silu(g)*u
  //     y = matmul(h, ffn_down.weight); add into residual
  //
  //   MoE (il >= dense_lead):
  //     logits = matmul(xn, ffn_gate_inp.weight)            // [T, n_expert]
  //     u::k::router_sigmoid(logits, bias=blk(il,"exp_probs_b.bias"), T, n_expert, n_exp_used,
  //                          g_.router_renormalize, g_.w_scale, ids, w)   // top-6 ids + norm weights
  //     u::ExpertTier::apply(il, xn, ids, w, n_exp_used, T, y, stream)    // routed experts sum
  //     // shared expert (always on): SwiGLU over n_ff_exp with ffn_{gate,up,down}_shexp, add to y
  //     y += shexp(xn);  add y into residual
  //
  // TODO(box): confirm (a) the dense activation is SwiGLU (not GELU) and the clamp limit, (b) the
  // router bias tensor name, (c) that the shared expert uses the same n_ff_exp width, (d) whether
  // the routed-weight renormalize happens before or after the w_scale (GLM scales post-norm).
  (void)il; (void)T;
  err = "raon1 layer_ffn: FFN/MoE wiring pending u::ExpertTier integration (T1.2); structure above";
  return false;
}

bool Raon1Graph::forward(const std::int32_t* tokens, int n_tokens, std::string& err) {
  // The trunk, GLM's forward shape: embed -> for each layer {mixer (RDA|MLA) ; FFN (dense|MoE)} ->
  // final norm -> output head. State persists across calls (append tokens); reset per sequence.
  //
  //   embed: gather token_embd.weight rows for `tokens` into the residual x  (NoPE: no pos add)
  //   for il in [0, n_layers):
  //       if g_.is_rda(il)  layer_rda(il, n_tokens)   else  layer_mla(il, n_tokens)
  //       layer_ffn(il, n_tokens)       // dense when il < dense_lead, else MoE
  //   rmsnorm(x, output_norm.weight); logits = matmul(x_last, output.weight)  -> sc_ logits
  //
  // Position bookkeeping: d_pos_[t] = pos_ + t for the MLA cache visibility; pos_ += n_tokens.
  if (!loaded_) { err = "raon1 forward: graph not loaded"; return false; }
  for (int il = 0; il < g_.n_layers; ++il) {
    const bool ok = (g_.is_rda(il) ? layer_rda(il, n_tokens, err) : layer_mla(il, n_tokens, err)) &&
                    layer_ffn(il, n_tokens, err);
    if (!ok) return false;
  }
  pos_ += n_tokens;
  (void)tokens;
  return true;
}

// ------------------------------------------------------------------------------------------------
// The DFlash-style draft block (design decision 5: drafting is included in Plan 1, reusing GLM's
// NextN/DFlash; the fallback is "base graph parities first, drafting follows"). Written here as a
// documented structure only — the base RDA/MLA/MoE trunk above is what the first box parity gate
// checks; speculative decode is enabled once the trunk parities. GLM analogy: glm_fast_path.cu
// fast_mtp + the NextN block (one extra decoder layer at index n_layers + a draft head).
//
// TODO(box): if g_.nextn > 0, load the draft block's tensors (blk.<n_layers>.*: enorm/hnorm, the
// eh_proj, its own attn + ffn, the shared draft head) and, after forward() of position p with the
// chosen token for p+1, run the block at p to propose p+2 (greedy), then verify in the trunk. The
// exact DFlash chaining/verification is confirmed against the real Raon draft block — do not guess
// the proposal/accept rule here.
// ------------------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------------------
// FamilyGraph surface.
// ------------------------------------------------------------------------------------------------
Raon1Graph::~Raon1Graph() {
  // TODO(box): free w_arena_, state_, sc_, d_pos_ and release the ExpertTier registration.
  if (w_arena_) cudaFree(w_arena_);
  if (state_) cudaFree(state_);
  if (sc_) cudaFree(sc_);
  if (d_pos_) cudaFree(d_pos_);
}

std::string Raon1Graph::describe() const {
  return "raon1(Raon-1-mini: 25L, " + std::to_string(g_.n_head) + "h, hidden " +
         std::to_string(g_.n_embd) + ", 128x" + std::to_string(g_.n_exp_used) + "+" +
         std::to_string(g_.n_shared) + " MoE, RDA+GatedMLA, NoPE)";
}

bool Raon1Graph::generate(const Gen& request, const LineSink& sink, std::string& error) {
  // The serve loop (host-driven, device compute). GLM analogy: the maya serve loop over forward() +
  // the sampler. Steps:
  //   1. reset_sequence(); forward(request.ids) to consume the prompt, emitting PP progress.
  //   2. loop up to request.max_new: sample the last logits (u::k::sample with the request's
  //      params), emit "T <id>", append the token with forward({id}, 1), honor STOP/stop ids.
  //   3. emit the terminal DONE <produced> <prompt> <prompt_ms> <decode_ms> <finish> 0 0 0.
  // Speculative hits/steps stay 0 until the DFlash draft block is enabled (decision 5).
  if (!loaded_) {
    error = "raon1 generate: graph not loaded (device upload wired by the shared loader)";
    return false;
  }
  reset_sequence();
  if (request.ids.empty()) { error = "raon1 generate: empty prompt"; return false; }
  if (!forward(request.ids.data(), (int)request.ids.size(), error)) return false;

  // TODO(box): the sampling + emit loop against u::k::sample and the Gen params (temperature,
  // top_p, seed, stop ids) and the PP/T/DONE records (u_protocol). Structured, not yet wired to the
  // shared sampler; the trunk forward() above is the piece this lane owns. Fail closed until wired.
  (void)sink;
  error = "raon1 generate: decode loop pending the shared sampler integration (T1.1)";
  return false;
}

// ------------------------------------------------------------------------------------------------
// Factory.
// ------------------------------------------------------------------------------------------------
std::unique_ptr<FamilyGraph> make_raon1_graph(const Geometry& geom, std::uint32_t context,
                                              std::string& error) {
  error.clear();
  if (geom.family != FamilyId::raon1) {
    error = "make_raon1_graph: geometry is not raon1";
    return nullptr;
  }
  auto graph = std::unique_ptr<Raon1Graph>(new Raon1Graph());
  // TODO(box): load() needs the parsed GgufFile (weights + the raon1.* metadata the Raon1Geometry
  // reads). The host foundation's make_family_graph currently takes only the guarded Geometry; the
  // CUDA dispatch that calls this factory passes the GgufFile through (a shared-file change this
  // lane does not own). Until that seam lands, load() returns false and the graph reports
  // unavailable — expected on the first integration build, not a bug in this family.
  if (!graph->load(geom, context, error)) return nullptr;
  return graph;
}

}  // namespace u

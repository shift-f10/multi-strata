// engines/unified/src/kernels/qwen4exp_hc.cuh - Qwen3.8-Flash-Next hyper-connections, the gated
// residual that wraps EVERY layer (count 4, low_rank 320) in place of a plain pre-norm residual.
//
// PORTED FROM (reviewed, renamed into u::qwen4exp):
//   upstream/src/program/generate.cpp (the hc_attn_*/hc_ffn_* apply around each layer's mixer + MoE)
//   the hyper-connection tensors named in upstream/tools/iq_pack.py FORM (L75-77):
//     hc_attn_down/up/inject, hc_ffn_down/up/inject, output_hc_down/up/norm — all BF16.
// Reference: the gated-residual / hyper-connection formulation (ModelGeometry.hc / hc_lr,
// geometry.hpp L59-61; has_hyper_connections()).
//
// WHAT A HYPER-CONNECTION IS. Instead of `x = x + mixer(norm(x))`, qwen4exp keeps `hc`(=4) residual
// STREAMS and mixes them with a learned low-rank (`hc_lr`=320) gate around each sub-block (the
// attention mixer, and the MoE FFN). Per sub-block with input streams X (hc, n_embd):
//   in     = sum_s w_in[s] * X[s]                    (down-project the streams to the block input)
//   y      = block(norm(in))                          (the GDN/QSA mixer, or the MoE FFN)
//   X'[s]  = X[s] + inject[s] * y                     (up-project / inject the block output back)
// with w_in / inject produced by the low-rank hc projections (hc_*_down / hc_*_up / hc_*_inject).
// The analogue already in the unified tree is GLM's hyper-connection kernels
// (engines/unified/src/kernels/glm_hc.*) — the box should RECONCILE this module with glm_hc and, if
// the math matches, promote one shared u::hc:: facility (noted in qwen4exp_graph.cu).
//
// LAYOUT: f32 streams, ggml order; n_embd = 2560, hc = 4, hc_lr = 320. The streams live in the graph
// scratch as (hc, n_embd, T); these kernels do the down/inject mixing, the graph does the two low-rank
// GEMVs (via u::k::mmvq / BF16).
#pragma once

#include <cstdint>

namespace u::qwen4exp {

struct HcShapes final {
  int n_embd = 2560;
  int hc = 4;       // stream count
  int hc_lr = 320;  // low-rank width of the hc projections
};

// Combine the `hc` residual streams into one block input: in[e,t] = sum_s w_in[s,t] * X[s,e,t].
// `streams` is (hc, n_embd, T); `w_in` (hc, T) is the down-projection gate (the graph computes it from
// hc_*_down/up). Writes `block_in` (n_embd, T). Ported from the hc down-mix in generate.cpp.
void hc_combine_in(const float* streams, const float* w_in, const HcShapes& s, int T,
                   float* block_in, void* stream);

// Inject the block output back into each stream: X'[s,e,t] = X[s,e,t] + inject[s,t] * y[e,t].
// `streams` is updated in place; `y` (n_embd, T) is the mixer/MoE output; `inject` (hc, T) the
// up-projection gate. Ported from the hc inject in generate.cpp.
void hc_inject_out(float* streams, const float* y, const float* inject, const HcShapes& s, int T,
                   void* stream);

// At the end of the trunk, collapse the `hc` streams into the single hidden state the output norm +
// head read: out[e,t] = sum_s output_w[s] * X[s,e,t] (output_hc_down/up/norm). Ported from the
// output_hc_* apply in generate.cpp. `out` is (n_embd, T).
void hc_collapse(const float* streams, const float* output_w, const HcShapes& s, int T,
                 float* out, void* stream);

}  // namespace u::qwen4exp

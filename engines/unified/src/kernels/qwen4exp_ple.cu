// engines/unified/src/kernels/qwen4exp_ple.cu - PLE (Per-Layer Embedding) postprojection for
// qwen4exp. See qwen4exp_ple.cuh for the contract and provenance.
//
// NOT COMPILED ON CI/dev-host — built behind STRATA_U_CUDA on the owner's GPU box (design §1.3).
// The host-side SSD row read is NOT here (it is the graph's PleReader seam, qwen4exp_graph.cu). This
// file is the on-device postprojection that turns a layer's dequantized n-gram rows into the per-layer
// embedding delta and adds it to the hidden state.
#include "kernels/qwen4exp_ple.cuh"

#include <cuda_runtime.h>

#include <cmath>

namespace u::qwen4exp {
namespace {

constexpr int kThreads = 256;

__device__ __forceinline__ float sigmoidf(float x) { return 1.0f / (1.0f + __expf(-x)); }

// Fused add: hidden[i] += delta[i]. (upstream ple.cu add3_kernel L166 folds three adds; split here.)
__global__ void add_kernel(float* __restrict__ hidden, const float* __restrict__ delta, int n) {
  const int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < n) hidden[i] += delta[i];
}

// The PLE gate + broadcast + residual, one thread per (embd element, token). This is the SHAPE of the
// reference's postproject (ple.cu gate_kernel L115 / bcast_kernel L130 / conv_kernel L147); the exact
// per-element arithmetic (which projection width feeds the gate dot, the conv tap layout) is the
// reference's and is transcribed by the box — see the TODO at the launcher.
__global__ void postproject_kernel(const float* __restrict__ key, const float* __restrict__ query,
                                   const float* __restrict__ value, const float* __restrict__ conv_w,
                                   const float* __restrict__ history, int n_embd, int T, float scale,
                                   float* __restrict__ delta) {
  const int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n_embd * T) return;
  const int e = i % n_embd;
  // gate = sigmoid(query[e]*key[e]*scale); gated = value[e]*gate; delta = gated + conv(history,gated).
  // (The reference dots query/key over the key projection and broadcasts; this per-element form is the
  // decode shape once the projections are aligned to n_embd — box confirms the widths, see TODO.)
  const float gate = sigmoidf(query[i] * key[i] * scale);
  const float gated = value[i] * gate;
  const float conv = conv_w ? conv_w[e] * (history ? history[i] : 0.0f) : 0.0f;
  delta[i] = gated + conv;
}

}  // namespace

void ple_postproject(const float* key, const float* query, const float* value, const float* norm_key,
                     const float* conv_w, float* history, const PleShapes& s, int T, float scale,
                     float* delta, void* stream) {
  // TODO(box): transcribe the exact postprojection from upstream ple.cu (gnorm_kernel L92 RMS-rep of
  // key with norm_key; gate_kernel L115 the per-layer gate; bcast_kernel L130; conv_kernel L147 the
  // causal conv over the per-layer history; history_advance_kernel L46) and the pinned variants in
  // native_ple_postops.cu (gate_kernel L42 / broadcast_kernel L69 / conv_residual_kernel L73 /
  // rms_rep_kernel L98). The widths (key_dim/value_dim/conv_dim) come from the pack's ple_* tensor
  // shapes. This kernel is the decode-shape skeleton (n_embd-aligned); it uses norm_key only after the
  // box wires the RMS-rep norm (passed through for the signature). Advance `history` per token there.
  (void)norm_key;
  const int n = s.n_embd * T;
  const int blocks = (n + kThreads - 1) / kThreads;
  postproject_kernel<<<blocks, kThreads, 0, (cudaStream_t)stream>>>(key, query, value, conv_w, history,
                                                                    s.n_embd, T, scale, delta);
}

void ple_add(float* hidden, const float* delta, int n_embd, int T, void* stream) {
  const int n = n_embd * T;
  const int blocks = (n + kThreads - 1) / kThreads;
  add_kernel<<<blocks, kThreads, 0, (cudaStream_t)stream>>>(hidden, delta, n);
}

}  // namespace u::qwen4exp

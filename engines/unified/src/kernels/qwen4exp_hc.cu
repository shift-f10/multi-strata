// engines/unified/src/kernels/qwen4exp_hc.cu - hyper-connections (gated residual) for qwen4exp.
// See qwen4exp_hc.cuh for the contract and provenance.
//
// NOT COMPILED ON CI/dev-host — built behind STRATA_U_CUDA on the owner's GPU box (design §1.3).
// The low-rank gate GEMVs (hc_*_down/up/inject) are done by the graph (u::k::mmvq / the BF16 path);
// these kernels do the stream mixing. RECONCILE with engines/unified/src/kernels/glm_hc.* — if the
// math matches, promote one shared u::hc:: facility (box).
#include "kernels/qwen4exp_hc.cuh"

#include <cuda_runtime.h>

namespace u::qwen4exp {
namespace {

constexpr int kThreads = 256;

// in[e,t] = sum_s w_in[s,t] * streams[s,e,t]. One thread per (embd element, token).
__global__ void combine_in_kernel(const float* __restrict__ streams, const float* __restrict__ w_in,
                                  int n_embd, int hc, int T, float* __restrict__ block_in) {
  const int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n_embd * T) return;
  const int e = i % n_embd;
  const int t = i / n_embd;
  float acc = 0.0f;
  for (int s = 0; s < hc; ++s)
    acc += w_in[(size_t)s * T + t] * streams[((size_t)s * T + t) * n_embd + e];
  block_in[i] = acc;
}

// streams[s,e,t] += inject[s,t] * y[e,t]. One thread per (stream, embd element, token).
__global__ void inject_out_kernel(float* __restrict__ streams, const float* __restrict__ y,
                                  const float* __restrict__ inject, int n_embd, int hc, int T) {
  const int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= hc * n_embd * T) return;
  const int e = i % n_embd;
  const int rem = i / n_embd;
  const int t = rem % T;
  const int s = rem / T;
  streams[((size_t)s * T + t) * n_embd + e] += inject[(size_t)s * T + t] * y[(size_t)t * n_embd + e];
}

// out[e,t] = sum_s output_w[s] * streams[s,e,t]. One thread per (embd element, token).
__global__ void collapse_kernel(const float* __restrict__ streams, const float* __restrict__ output_w,
                                int n_embd, int hc, int T, float* __restrict__ out) {
  const int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n_embd * T) return;
  const int e = i % n_embd;
  const int t = i / n_embd;
  float acc = 0.0f;
  for (int s = 0; s < hc; ++s) acc += output_w[s] * streams[((size_t)s * T + t) * n_embd + e];
  out[i] = acc;
}

}  // namespace

void hc_combine_in(const float* streams, const float* w_in, const HcShapes& s, int T, float* block_in,
                   void* stream) {
  const int n = s.n_embd * T;
  const int blocks = (n + kThreads - 1) / kThreads;
  combine_in_kernel<<<blocks, kThreads, 0, (cudaStream_t)stream>>>(streams, w_in, s.n_embd, s.hc, T,
                                                                   block_in);
}

void hc_inject_out(float* streams, const float* y, const float* inject, const HcShapes& s, int T,
                   void* stream) {
  const int n = s.hc * s.n_embd * T;
  const int blocks = (n + kThreads - 1) / kThreads;
  inject_out_kernel<<<blocks, kThreads, 0, (cudaStream_t)stream>>>(streams, y, inject, s.n_embd, s.hc, T);
}

void hc_collapse(const float* streams, const float* output_w, const HcShapes& s, int T, float* out,
                 void* stream) {
  const int n = s.n_embd * T;
  const int blocks = (n + kThreads - 1) / kThreads;
  collapse_kernel<<<blocks, kThreads, 0, (cudaStream_t)stream>>>(streams, output_w, s.n_embd, s.hc, T,
                                                                 out);
  // TODO(box): the real hyper-connection also carries a per-stream norm (output_hc_norm) and the
  // low-rank down/up matrices (output_hc_down/up) before this collapse — wire those GEMVs in the graph
  // (generate.cpp output_hc_* apply) and keep this as the final weighted sum. Reconcile against
  // glm_hc.* (the GLM lineage's hyper-connection) and unify if identical.
}

}  // namespace u::qwen4exp

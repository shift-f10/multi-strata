// strata-unified-engine: Gemma-4-26B-A4B glue kernels (see gemma4_glue.cuh).
// Ported from engines/gemma4/src/g4_kernels.cu (read-only parity oracle); embed_q8 reads the GGUF
// Q8_0 layout directly (no repack) so the unified engine keeps one Q8_0 format end to end.
#include "gemma4_glue.cuh"

#include <cuda_fp16.h>
#include <cuda_runtime.h>

#include <cstddef>

namespace u::gemma4 {
namespace {

unsigned blocks(long long n, int per) { return static_cast<unsigned>((n + per - 1) / per); }

// g4_kernels.cu k_softcap (486-489).
__global__ void k_softcap(float* __restrict__ x, int n, float cap) {
  const int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < n) x[i] = cap * tanhf(x[i] / cap);
}

// One GGUF Q8_0 block: [__half d][32 x int8]. 34 bytes, no padding (the ggml block_q8_0 layout
// the unified Q8_1/MMVQ path is pinned to). Dequant of element i of a row: int8[i] * d(block i/32).
struct BlockQ80 {
  __half d;
  std::int8_t qs[32];
};

// g4_kernels.cu k_embed_q8 (207-214), reading the on-disk Q8_0 blocks instead of repacked planes.
__global__ void k_embed_q8(const int* __restrict__ ids, const BlockQ80* __restrict__ blocks_base, int n, float scale,
                           float* __restrict__ out) {
  const int t = blockIdx.y;
  const int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) return;
  const std::size_t nb = static_cast<std::size_t>(n) / 32;       // blocks per row
  const std::size_t row = static_cast<std::size_t>(ids[t]);
  const BlockQ80& blk = blocks_base[row * nb + static_cast<std::size_t>(i) / 32];
  const float d = __half2float(blk.d);
  out[static_cast<std::size_t>(t) * n + i] = float(blk.qs[i % 32]) * d * scale;
}

}  // namespace

void softcap(float* x, int n, float cap, void* stream) {
  k_softcap<<<blocks(n, 256), 256, 0, static_cast<cudaStream_t>(stream)>>>(x, n, cap);
}

void embed_q8(const int* ids, int T, const void* q8_blocks, int n, float scale, float* out, void* stream) {
  k_embed_q8<<<dim3(blocks(n, 256), static_cast<unsigned>(T)), 256, 0, static_cast<cudaStream_t>(stream)>>>(
      ids, static_cast<const BlockQ80*>(q8_blocks), n, scale, out);
}

}  // namespace u::gemma4

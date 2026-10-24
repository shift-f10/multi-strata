// engines/unified/src/kernels/qwen4exp_ple.cuh - Qwen3.8-Flash-Next PLE (Per-Layer Embedding), the
// n-gram per-layer embedding add applied on EVERY layer.
//
// PORTED FROM (reviewed, renamed into u::qwen4exp):
//   upstream/src/kernels/cuda/ple.cu                   (gnorm, gate, bcast, conv, add3, the postops)
//   upstream/src/kernels/cuda/native_ple_postops.cu    (the pinned postprojection arithmetic)
//   upstream/src/ngram/ple_reader.cpp                  (the HOST-side SSD row read — not a kernel)
// Reference: upstream/include/strata/kernels/ple.hpp, ref/ple.py.
//
// WHAT PLE IS. Qwen3.8-Flash-Next carries a 320M-row per-layer-embedding table (26.8 GB IQ4_NL / 51.2
// GB FP8) that is NEVER held in RAM. For each generated token and each of the 48 layers, an n-gram of
// the recent token ids indexes 16 rows (one per n-gram order) that are read straight from the SSD
// (upstream PleReader: issue() when the token id is known, collect() before the layer reads them), a
// postprojection turns those rows into a per-layer embedding vector, and it is added into that layer's
// hidden state. This module is the on-device POSTPROJECTION; the row read is host-side (the graph owns
// a PleReader seam — see qwen4exp_graph.cu, Qwen4ExpPleTable).
//
// THE POSTPROJECTION (ref/ple.py, ple.cu): from a layer's raw n-gram rows (dequantized key/value/conv
// projections), produce the per-layer embedding delta:
//   norm   = gnorm(key, ple_norm_key)                       RMS-rep norm
//   gate   = sigmoid( dot(query, key) * scale )             the per-layer gate (gate_kernel)
//   value' = broadcast(value) * gate                        (bcast_kernel)
//   delta  = conv1d(history, value', ple_conv1d) + value'   short causal conv over the n-gram history
//   hidden += delta                                         (add3_kernel)
// with a per-layer history advanced each token (history_advance_kernel). Exact widths/order are the
// reference's; this header gives the contract and qwen4exp_ple.cu transcribes the kernels with
// upstream file:line TODOs for the deep arithmetic.
//
// LAYOUT: f32, ggml order; n_embd = 2560. The raw rows arrive dequantized into `key`,`query`,`value`
// device buffers of the projection widths (ple_key/ple_value/ple_conv1d, from the pack's dense.bin).
#pragma once

#include <cstdint>

namespace u::qwen4exp {

struct PleShapes final {
  int n_embd = 2560;
  int key_dim = 0;    // ple_key width  — box: read from the pack tensor shape (blk.N.ple_key.weight)
  int value_dim = 0;  // ple_value width — box: read from blk.N.ple_value.weight
  int conv_dim = 0;   // ple_conv1d width — box: read from blk.N.ple_conv1d.weight
  int d_conv = 0;     // the PLE conv tap count
};

// The per-layer-embedding delta for one token (or T): from this layer's dequantized n-gram key/query/
// value projections, compute `delta` (n_embd, T) and advance the per-layer `history` in place.
//   gate  = sigmoid(dot(query,key)*scale);  gated = broadcast(value)*gate;
//   delta = conv1d(history, gated, conv_w) + gated
// Ported from upstream ple.cu gnorm_kernel L92 / gate_kernel L115 / bcast_kernel L130 / conv_kernel
// L147 / history_advance_kernel L46 (and native_ple_postops.cu for the pinned variants). `norm_key`,
// `conv_w` are the per-layer PLE weights.
void ple_postproject(const float* key, const float* query, const float* value, const float* norm_key,
                     const float* conv_w, float* history, const PleShapes& s, int T, float scale,
                     float* delta, void* stream);

// Fused add of the PLE delta into the layer hidden state: hidden[i] += delta[i] over n_embd*T
// (upstream ple.cu add3_kernel L166 — it adds the mixer output, the gated residual and the PLE delta
// in one pass; split out here, the graph adds the mixer/HC separately). `hidden` and `delta` are
// (n_embd, T); out may alias hidden.
void ple_add(float* hidden, const float* delta, int n_embd, int T, void* stream);

}  // namespace u::qwen4exp

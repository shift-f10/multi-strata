// strata-unified-engine: the Qwen3.8-Flash-Next (arch "qwen4exp") model graph — implementation.
//
// Ported from the MAIN upstream Strata engine: upstream/src/program/generate.cpp (the serve driver),
// upstream/src/core/{layer,graph,mtp,expert_source,expert_cache,native_head}.cpp, the
// upstream/src/kernels/cuda/* kernels, upstream/src/ngram/ple_reader.cpp, and upstream/tools/iq_pack.py
// (the pack format). The per-layer schedule and the GDN/QSA/PLE/HC pieces are qwen4exp's; everything
// generic rides the shared substrate (kernels/common.cuh u::k::, u_experts.hpp u::ExpertTier). The
// family-unique kernels are in src/kernels/qwen4exp_{gdn,qsa,ple,hc}.*.
//
// NOT COMPILED ON CI/dev-host. Built only behind STRATA_U_CUDA on the owner's GPU box (design §1.3);
// a host/CI build links the stub and u::make_family_graph returns it. Written for the box, which
// compiles, wires the shared loader seams below, and parities against the upstream engine.
//
// ============================================================================================
// SHARED SEAMS — reconcile with the landed substrate before the first box build. This lane uses the
// ACTUAL landed signatures (kernels/common.cuh u::k::, u_experts.hpp u::ExpertTier) where they exist.
// The seams this lane does NOT own, and the reconciliations the box must make, are centralized here:
//
// (A) THE GGUF + PACK HANDOFF. qwen4exp is not one GGUF: it is a --pack directory plus side GGUFs
//     (--native dense, --ple-gguf table, --embd-gguf, --mtp dir, --expert-profile). u::make_family_
//     graph (u_family.hpp) hands the factory only the guarded u::Geometry. The parsed GgufFile(s) AND
//     the pack paths must reach this graph through the CUDA dispatch seam (a shared-file change this
//     lane does not own — the same TODO the raon1/glm lanes carry). Until it lands, load() fills the
//     Qwen4ExpPack/Qwen4ExpPleTable descriptors structurally and returns false (expected, not a bug).
//
// (B) THE IQ_PACK <-> u::ExpertTier RECONCILIATION (the main new seam for this family). The pack's
//     experts.bin is a per-layer arena of 512 blobs [gate|up|down] (native_experts.txt gives per-layer
//     offset/blob_bytes/gate_off/up_off/down_off — iq_pack.py L430-488; FileExpertSource parses it,
//     expert_source.cpp L1370-1421). It maps onto u::ExpertTier like so:
//        tier.set_host_arena(pack.arena_base, pack.arena_bytes)   // experts.bin mmap'd+pinned
//        tier.warm_start(ranked_from(--expert-profile))           // STRP profile (u_experts.hpp)
//        tier.compute(layer, ids, weights, x, out, k, stream)     // routed experts' FFN + combine
//     TWO mismatches the box must close (ExpertTier is from the Maya lineage; the qwen pack differs):
//       1. PER-LAYER layout. ExpertTier::Config has ONE blob_bytes/gate_off/up_off/down_off and ONE
//          gate/up/down Quant for ALL layers; the qwen pack's blob size AND quant type vary PER LAYER
//          (iq_pack.py: attn_qkv alone is IQ4_XS on 13 layers, Q3_K on 18, Q4_K on 4, S2 on 1 —
//          layer.hpp L60-63). The box must extend ExpertTier to a per-layer Config (a vector of the
//          layout struct), or run one tier per distinct layout. load_pack() below records the per-layer
//          Qwen4ExpPackLayer table for exactly this.
//       2. THE QUANT SET. The pack uses i-quants (IQ1_M/IQ2_XS/IQ3_XXS/IQ3_S/Q2_0/IQ4_NL). The unified
//          substrate's k::Quant + MMVQ carry ONLY Q8_0/Q4_K/Q5_K/Q6_K/BF16/F32 (common.cuh L16-18
//          explicitly drops the iq_pack path). So the landed ExpertTier::compute CANNOT read the real
//          qwen4exp experts. The box closes this by porting the i-quant MMVQ/grouped-MoE kernels
//          (upstream src/kernels/cuda/iq_kernels.cu, s2_expert_grouped.cu, prefill/moe_mmq.cu) into the
//          shared kernel set and widening k::Quant — OR by serving a re-quantized pack in the carried
//          set. This is the single biggest qwen4exp box task; it is a SUBSTRATE change, flagged here.
//
// (C) THE PLE READER. The per-layer-embedding table is read from the SSD on demand (never in RAM) by a
//     host-side reader with a split issue()/collect() API (upstream/src/ngram/ple_reader.cpp;
//     PleReader::issue when the token id is known, collect before the layer reads the rows). The
//     unified substrate has no such reader yet. The box ports PleReader (or an equivalent DirectFile
//     row reader) and wires open_ple()/layer_ple() to it; the on-device postprojection is
//     kernels/qwen4exp_ple.*.
//
// (D) THE MTP DRAFT. The speculative draft layer is an external pack (--mtp, upstream/src/core/mtp.cpp,
//     tools/mtp_rt.py). Off by default; the serve loop reports spec_hits/spec_steps = 0 until the box
//     wires it (see the MTP section near generate()). The verify/accept rule is the reference's — do
//     NOT guess it.
//
// (E) THE SAMPLER / HEAD. The decode loop uses the landed u::k::sample_tokens + u::k::SamplerParams
//     (common.cuh L214-234) and an output head (either an own-path output.weight GEMV via u::k::mmvq,
//     or the upstream NativeHead served from --native, native_head.cpp L86). Mapped in generate().
// ============================================================================================
#include "family/qwen4exp_graph.hpp"

#include "kernels/common.cuh"
#include "kernels/qwen4exp_gdn.cuh"
#include "kernels/qwen4exp_hc.cuh"
#include "kernels/qwen4exp_ple.cuh"
#include "kernels/qwen4exp_qsa.cuh"
#include "u_experts.hpp"

#include <cuda_runtime.h>

#include <string>
#include <vector>

namespace u {
namespace {

// Per-layer weight-name prefix, llama.cpp/upstream convention ("blk.<il>."). The exact qwen4exp tensor
// base names are the upstream GGUF's (attn_qkv, ssm_*, hc_*, ple_*, ffn_gate_inp, *_exps, ...); the box
// confirms them against the real file. [[maybe_unused]]: the call sites live in the layer_*() bodies
// the box wires onto the shared scratch/weight layout, so -Werror would flag it until then.
[[maybe_unused]] std::string blk(int il, const char* suffix) {
  return "blk." + std::to_string(il) + "." + suffix;
}

}  // namespace

// ------------------------------------------------------------------------------------------------
// Geometry: the qwen4exp.* metadata beyond the common (guarded) u::Geometry.
// Mirrors upstream geometry_from_gguf (family_layout.hpp): a key the file carries replaces the
// kCompiledGeometry default; a key it omits keeps Flash-Next's value (every published file matches).
// ------------------------------------------------------------------------------------------------
bool Qwen4ExpGeometry::from_gguf(const GgufFile& file, const Geometry& common, Qwen4ExpGeometry& out,
                                 std::string& err) {
  out.n_embd = (int)common.embedding_length;
  out.n_vocab = (int)common.vocab_size;
  out.n_expert = (int)common.expert_count;
  out.n_exp_used = (int)common.expert_used_count;
  out.n_ff_exp = (int)common.expert_feed_forward_length;
  out.n_shared = (int)common.expert_shared_count;
  out.rope_freq_base = common.rope_freq_base;

  const std::string arch = common.arch;  // "qwen4exp"
  auto geti = [&](const char* suffix, int def) -> int {
    const GgufValue* v = file.find(arch + suffix);
    return (v != nullptr) ? (int)v->integer : def;
  };
  auto getf = [&](const char* suffix, float def) -> float {
    const GgufValue* v = file.find(arch + suffix);
    return (v != nullptr) ? (float)v->real : def;
  };

  const int block_count = geti(".block_count", (int)common.block_count);
  out.n_mtp_layers = geti(".nextn_predict_layers", 0);  // qwen4exp ships MTP externally => 0
  out.n_layers = block_count - out.n_mtp_layers;        // the trunk (upstream: n_layers = block - mtp)

  out.qsa_interval = geti(".full_attention_interval", 4);
  out.rms_eps = getf(".attention.layer_norm_rms_epsilon", 1e-6f);

  // GDN (ssm.*)
  out.ssm_state = geti(".ssm.state_size", 128);
  out.ssm_k_heads = geti(".ssm.group_count", 16);
  out.ssm_v_heads = geti(".ssm.time_step_rank", 48);
  out.ssm_d_conv = geti(".ssm.conv_kernel", 4);
  out.ssm_value_dim = geti(".ssm.inner_size", out.ssm_state * out.ssm_v_heads);
  out.ssm_conv_channels = 2 * out.ssm_state * out.ssm_k_heads + out.ssm_value_dim;

  // QSA
  out.n_head = geti(".attention.head_count", 24);
  out.n_head_kv = geti(".attention.head_count_kv", 2);
  out.head_dim = geti(".attention.key_length", (int)common.head_dim);
  out.n_rot = geti(".rope.dimension_count", 64);
  out.idx_q_heads = geti(".attention.indexer.head_count", 4);
  out.idx_key_dim = geti(".attention.indexer.key_length", 128);
  out.idx_top_k = geti(".attention.indexer.top_k", 2048);

  // hyper-connections
  out.hc = geti(".hyper_connection.count", 4);
  out.hc_lr = geti(".hyper_connection.low_rank", 320);

  // Faithful to upstream's guard (family_layout.hpp L80-96): fail closed on impossible shapes.
  if (out.n_layers <= 0 || out.n_embd <= 0 || out.n_head <= 0 || out.n_head_kv <= 0 || out.head_dim <= 0 ||
      out.n_expert <= 0 || out.n_exp_used <= 0 || out.n_exp_used > out.n_expert || out.n_ff_exp <= 0 ||
      out.ssm_state <= 0 || out.ssm_k_heads <= 0 || out.ssm_v_heads <= 0 || out.ssm_d_conv <= 0 ||
      out.qsa_interval < 2) {
    err = "qwen4exp geometry: a key is zero or out of range";
    return false;
  }
  if (out.ssm_value_dim != out.ssm_state * out.ssm_v_heads) {
    err = "qwen4exp geometry: ssm.inner_size != ssm.state_size * ssm.time_step_rank";
    return false;
  }
  if (out.n_head % out.n_head_kv != 0) {
    err = "qwen4exp geometry: head_count is not a multiple of head_count_kv";
    return false;
  }
  if (out.n_layers % out.qsa_interval != 0) {
    err = "qwen4exp geometry: layer count is not a multiple of full_attention_interval";
    return false;
  }
  return true;
}

// ------------------------------------------------------------------------------------------------
// Pack loaders (host). Parse the iq_pack directory into the per-layer expert layout and the side-file
// descriptors, map the arena, and configure u::ExpertTier. Structural with precise upstream TODOs.
// ------------------------------------------------------------------------------------------------
bool Qwen4ExpGraph::load_pack(const Qwen4ExpPack& pack_in, std::string& err) {
  pack_ = pack_in;
  // TODO(box): read <pack>/index.txt (the dense-tensor table: "name file kind off nbytes pool_off
  // dst_bytes ne0 ne1 ..." — iq_pack.py write_index L364-377; served-natively rows carry shape only)
  // and <pack>/native_experts.txt (per-layer "layer gu_type d_type offset blob_bytes gate_off up_off
  // down_off [shard]" — iq_pack.py expert_layout L430-488) into pack_.layers. The upstream reader is
  // FileExpertSource (expert_source.cpp L1370-1433): it validates that the per-layer offsets tile
  // experts.bin exactly (L1398-1420) and, when experts.bin is absent, maps the --native GGUF shards in
  // place ("CS-T", L1422-1433). Then mmap experts.bin (or the shards), pin it, and set
  // pack_.arena_base/arena_bytes.
  //
  // Reconcile with u::ExpertTier (seam B above). The landed ExpertTier::Config is UNIFORM; the qwen
  // pack is PER-LAYER and i-quant. The intended wiring, once the box extends ExpertTier to per-layer:
  //   ExpertTier::Config cfg;
  //   cfg.n_layers = g_.n_layers; cfg.n_expert = pack_.n_expert_in_pack; cfg.n_embd = g_.n_embd;
  //   cfg.n_ff = g_.n_ff_exp; cfg.has_shared_expert = (g_.n_shared > 0);
  //   // per-layer: cfg.layer[il] = { blob_bytes, gate/up/down off, gate/up/down Quant } from pack_.layers[il]
  //   cfg.vram_slots = <from --expert-cache auto / the card budget>;
  //   tier_.open(cfg, err); tier_.set_host_arena(pack_.arena_base, pack_.arena_bytes, err);
  //   // warm start from --expert-profile (STRP): read_expert_profile(pack_.expert_profile, ...) then
  //   // tier_.warm_start(ranked, err)   (u_experts.hpp L47-49, L110-111)
  // NOTE the i-quant blocker (seam B.2): until the shared MMVQ carries the pack's i-quants, open()
  // will reject the Config quant (ExpertTier::compute goes through k::mmvq, which is Q8_0/Q4_K/Q5_K/
  // Q6_K/BF16/F32 only). The box resolves that in the substrate, not here.
  (void)err;
  return true;  // structural: records the descriptor; the arena map + tier open land with seam A/B.
}

bool Qwen4ExpGraph::open_ple(std::string& err) {
  // TODO(box): validate the --ple-gguf table (PleTable::open: the tensor per_layer_token_embd.weight
  // gives table_offset + n_rows + row_bytes, and the table must fill the file from there — upstream
  // ple_reader.hpp). Store into ple_. Then open a host-side row reader (PleReader, seam C) with the
  // row cache (upstream default 1<<20 rows) and the keep-alive. The reader is HOST-side; the unified
  // substrate has none, so this is a substrate addition the box owns. layer_ple() consumes its rows.
  (void)err;
  return true;  // structural: records the descriptor; the reader lands with seam C.
}

// ------------------------------------------------------------------------------------------------
// Load / state.
// ------------------------------------------------------------------------------------------------
bool Qwen4ExpGraph::load(const Geometry& common, std::uint32_t context, std::string& err) {
  context_ = context;
  // Map the guarded common fields into the qwen4exp geometry. The qwen-specific fields keep their
  // kCompiledGeometry defaults (the member initializers); the exact ssm/qsa/hc/ple keys and the pack
  // are read once the dispatch seam (A) hands this graph the GgufFile(s) + pack paths. from_gguf is
  // therefore NOT called here yet (it has no file).
  g_.n_embd = (int)common.embedding_length;
  g_.n_layers = (int)common.block_count - g_.n_mtp_layers;
  g_.n_vocab = (int)common.vocab_size;
  g_.n_expert = (int)common.expert_count;
  g_.n_exp_used = (int)common.expert_used_count;
  g_.n_ff_exp = (int)common.expert_feed_forward_length;
  g_.n_shared = (int)common.expert_shared_count;
  g_.head_dim = (int)common.head_dim;
  g_.rope_freq_base = common.rope_freq_base;

  // Size the per-layer state offsets so the layout is reviewable (the allocation + device upload land
  // with the shared loader, seam A). GDN layers carry a recurrence state (S*S*v_heads f32) + a conv
  // history (conv_channels*(d_conv-1) f32); QSA layers carry a KV cache (context*kv_heads*head_dim f32
  // for K and for V) + the indexer pooled-key cache; MoE/PLE/HC scratch is per-forward in sc_.
  gdn_state_.assign((size_t)g_.n_layers, -1);
  gdn_conv_.assign((size_t)g_.n_layers, -1);
  qsa_cache_.assign((size_t)g_.n_layers, -1);
  // TODO(box): once the GgufFile + pack reach here (seam A):
  //   1. Qwen4ExpGeometry::from_gguf(file, common, g_, err)   // the exact ssm/qsa/hc keys
  //   2. load_pack(pack_in, err); open_ple(err)               // seams B / C
  //   3. upload the dense/norm/router/hc/ssm/qsa/ple-proj weights to w_arena_ + fill w_
  //   4. carve state_/qsa_kv_/sc_ from the geometry and context; register u::ExpertTier
  //   5. loaded_ = true
  loaded_ = false;
  err = "qwen4exp load: device upload + pack/PLE/ExpertTier wiring is the shared loader's job (seams "
        "A/B/C); not linked in this lane";
  return false;
}

void Qwen4ExpGraph::reset_sequence() {
  pos_ = 0;
  // TODO(box): cudaMemsetAsync the GDN recurrence + conv state (gdn_state_/gdn_conv_ ranges) and reset
  // the QSA KV / indexer pooled-key caches' logical length to 0 (append-only, so pos_ restores them),
  // and reset the PLE reader's per-layer history. The upstream reset is per sequence (generate.cpp).
}

// ------------------------------------------------------------------------------------------------
// Per-layer pieces. Each is structural: the step order + the exact shared/family kernel calls are
// named (the GLM/raon1 lanes carry the same shape), failing closed until the shared loader wires the
// scratch/weight layout. sc_ slices (streams, block_in, q/k/v, router, parts, ...) are carved by the
// shared scratch layout (seam A). The GDN/QSA/PLE/HC kernels themselves are ready (src/kernels).
// ------------------------------------------------------------------------------------------------
bool Qwen4ExpGraph::layer_gdn(int il, int T, std::string& err) {
  // GDN mixer (36 of 48 layers). The hyper-connection wrap + pre-norm are done by the caller
  // (forward); this is the mixer block over the normed block input `xn` (n_embd, T).
  //   1. qkv = mmvq(xn, blk(il,"ssm_in.weight"))             -> (conv_channels, T)   u::k::mmvq
  //   2. u::qwen4exp::gdn_conv_silu(qkv, blk(il,"ssm_conv1d.weight"), conv_state, shapes, T, h)
  //   3. u::qwen4exp::gdn_split_l2norm(h, shapes, T, eps, q, k, v)   // q,k L2-normed; v not
  //   4. alpha = mmvq/bf16(xn, ssm_alpha.weight); beta = mmvq/bf16(xn, ssm_beta.weight)   (BF16 path)
  //      u::qwen4exp::gdn_gates(alpha, beta, blk(il,"ssm_dt.bias"), blk(il,"ssm_a"), shapes, T, gate, beta2)
  //   5. u::qwen4exp::gdn_recurrence(state_+gdn_state_[il], q, k, v, gate, beta2, shapes, T, o)
  //   6. z = mmvq/bf16(xn, ssm_gate.weight)                                              (the out gate)
  //      u::qwen4exp::gdn_out_gate(o, blk(il,"ssm_norm.weight"), z, shapes, T, eps, y)   // SIGMOID gate
  //   7. mixer_out = mmvq(y, blk(il,"ssm_out.weight"))        -> (n_embd, T)
  // TODO(box): confirm the exact ssm_* tensor names + which GEMV activation each wants (layer.hpp
  // L28-33: ssm_in/ssm_gate/ssm_out are Q8_K, ssm_alpha/ssm_beta are BF16). GdnShapes from g_.
  (void)il; (void)T;
  err = "qwen4exp layer_gdn: mixer wiring pending the shared scratch/weight layout (seam A); kernels ready";
  return false;
}

bool Qwen4ExpGraph::layer_qsa(int il, int T, std::string& err) {
  // QSA mixer (12 of 48 layers, every 4th). Over the normed block input `xn` (n_embd, T):
  //   1. q = mmvq(xn, attn_q.weight) (hd*H); k,v = mmvq(xn, attn_{k,v}.weight) (hd*Hkv)
  //      q,k RMS-normed per head (attn_q_norm/attn_k_norm, F32) then
  //      u::qwen4exp::qsa_rope_neox(q,...), qsa_rope_neox(k,...)   // NEOX on the first n_rot of hd
  //      (or call u::k::rope_neox_base directly — identical; common.cuh L151)
  //   2. indexer: idx_q = mmvq(xn, indexer.q_proj) ; idx_k = mmvq(xn, indexer.k_proj) (BF16)
  //      u::qwen4exp::qsa_indexer_append(idx_k, indexer.k_norm, eps, d_pos_, shapes, T, pooled, cells)
  //      u::qwen4exp::qsa_select_cells(idx_q, pooled, shapes, cells, T, sel, sel_n)
  //   3. u::qwen4exp::qsa_kv_append(k, v, d_pos_, shapes, T, k_cache, v_cache)   // per-layer KV
  //   4. u::qwen4exp::qsa_attention(q, k_cache, v_cache, sel, sel_n, shapes, cells, T, 1/sqrt(hd), o)
  //   5. gate = mmvq(xn, attn_gate.weight); u::qwen4exp::qsa_out_gate(o, gate, shapes, T, y)
  //   6. mixer_out = mmvq(y, attn_output.weight)   -> (n_embd, T)
  // PARITY LADDER (qsa.cuh): first run with sel = all cells (dense) to validate against u::k::
  // attn_decode, then enable the indexer/select. TODO(box): confirm the QSA tensor names + the RoPE
  // base (g_.rope_freq_base) + whether v shares the n_rot rotation (it does not).
  (void)il; (void)T;
  err = "qwen4exp layer_qsa: mixer wiring pending the shared scratch/weight layout (seam A); kernels ready";
  return false;
}

bool Qwen4ExpGraph::layer_ple(int il, int T, std::string& err) {
  // Add this layer's per-layer embedding. The rows were issued (host PleReader) when the token id was
  // known and collected before this layer (seam C). Dequantize them into key/query/value buffers, then
  //   u::qwen4exp::ple_postproject(key, query, value, ple_norm_key, ple_conv1d, history, shapes, T, scale, delta)
  //   u::qwen4exp::ple_add(hidden, delta, n_embd, T)
  // TODO(box): the PLE row dequant (IQ4_NL/FP8 -> f32) + the exact postprojection widths come from the
  // pack's ple_* tensors (iq_pack.py FORM: ple_key/ple_value BF16, ple_conv1d F16, ple_norm_* F32).
  // The row read is the seam-C reader; this method is the on-device consume.
  (void)il; (void)T;
  err = "qwen4exp layer_ple: PLE reader (seam C) + postprojection wiring pending; kernels ready";
  return false;
}

bool Qwen4ExpGraph::layer_moe(int il, int T, std::string& err) {
  // MoE FFN (every layer): softmax top-10 router over 512 experts + 1 shared expert, n_ff_exp=640.
  // Over the normed block input `xn` (n_embd, T):
  //   logits = mmvq_bf16(xn, blk(il,"ffn_gate_inp.weight"))   // ROUTER weight is BF16 (layer.hpp L~)
  //   u::k::router_topk(logits, T, n_expert, n_exp_used, ids, weights, stream)   // softmax top-10
  //   // routed experts from the iq_pack arena via the shared tier (seam B):
  //   tier_.compute(il, ids_host, weights_host, xn, y, n_exp_used, stream, err)
  //   // shared expert (always on): SwiGLU over n_ff_exp with ffn_{gate,up,down}_shexp, add into y
  //   //   g = mmvq(xn, ffn_gate_shexp); u = mmvq(xn, ffn_up_shexp); u::k::swiglu(g,u,h,n_ff_exp)
  //   //   y += mmvq(h, ffn_down_shexp)      (ExpertTier::compute already folds a shared expert when
  //   //   has_shared_expert — reconcile: the qwen shared expert is a NAMED tensor, not blob n_expert;
  //   //   the box either feeds it as the tier's shared slot or runs it here — see seam B)
  // qwen4exp uses the SOFTMAX top-k router (u_geometry.cpp pins RouterKind::softmax for qwen4exp;
  // upstream router_top10.cu). ids/weights move host<->device as u::ExpertTier::compute expects HOST
  // ids/weights (u_experts.hpp L130-132) — the router writes device arrays, so copy back per step (or
  // the box adds a device-ids ExpertTier::compute overload).
  // TODO(box): confirm the router activation is BF16 (layer.hpp: "the highest-consequence rounding")
  // and the shared-expert tensor names/width (n_ff_shexp == n_ff_exp, read_geometry checks).
  (void)il; (void)T;
  err = "qwen4exp layer_moe: router+ExpertTier+shared wiring pending (seam B); structure above";
  return false;
}

bool Qwen4ExpGraph::forward(const std::int32_t* tokens, int n_tokens, std::string& err) {
  // The trunk, upstream's serve shape (generate.cpp "embed -> 48 captured layer graphs -> lm_head"):
  //
  //   embed: gather token_embd rows for `tokens` into the hc=4 residual streams (hc_dim = hc*n_embd).
  //          (upstream replicates the embedding across the hyper-connection streams.) When a PLE table
  //          is present, ISSUE this step's n-gram rows now (seam C), so the SSD reads hide behind the
  //          embedding + layer 0.
  //   for il in [0, n_layers):
  //       // attention sub-block, hyper-connection wrapped:
  //       hc_combine_in(streams, w_in_attn[il]) -> block_in ; rmsnorm(block_in, attn_norm[il]) -> xn
  //       if g_.is_qsa(il) layer_qsa(il,T) else layer_gdn(il,T)   // writes mixer_out
  //       hc_inject_out(streams, mixer_out, inject_attn[il])
  //       // PLE add (per layer): collect this layer's rows, postproject, add into the streams
  //       layer_ple(il, T)
  //       // MoE sub-block, hyper-connection wrapped:
  //       hc_combine_in(streams, w_in_ffn[il]) -> block_in ; rmsnorm(block_in, ffn_norm[il]) -> xn
  //       layer_moe(il, T) -> ffn_out
  //       hc_inject_out(streams, ffn_out, inject_ffn[il])
  //   hc_collapse(streams, output_hc) -> hidden ; rmsnorm(hidden, output_norm) ; keep the LAST token.
  //   logits = output.weight @ hidden_last   (own-path mmvq, or the NativeHead from --native)
  //
  // Position bookkeeping: d_pos_[t] = pos_ + t (QSA cache visibility + PLE n-gram position); pos_ += T.
  // TODO(box): the exact PLE placement (whether the delta enters the attention stream, the FFN stream,
  // or both) is the reference's — confirm from ref/ple.py / generate.cpp before the parity gate.
  if (!loaded_) { err = "qwen4exp forward: graph not loaded"; return false; }
  for (int il = 0; il < g_.n_layers; ++il) {
    const bool mixer = g_.is_qsa(il) ? layer_qsa(il, n_tokens, err) : layer_gdn(il, n_tokens, err);
    if (!mixer) return false;
    if (!layer_ple(il, n_tokens, err)) return false;
    if (!layer_moe(il, n_tokens, err)) return false;
  }
  pos_ += n_tokens;
  (void)tokens;
  return true;
}

// ------------------------------------------------------------------------------------------------
// The MTP draft layer (seam D). qwen4exp ships its MTP drafter as an external runtime pack (--mtp,
// upstream tools/mtp_rt.py / mtp_pack.py; the drafter is upstream/src/core/mtp.cpp MtpDrafter). It is
// one extra decoder-style block (pre_fc_norm_embedding/hidden, an eh_proj that mixes the last hidden
// with the next embedding, its own attention + MoE, a draft head over a token subset) that proposes
// the next token(s) the trunk then verifies (speculative decode).
//
// This lane leaves MTP as a documented structure: the base GDN/QSA/PLE/HC/MoE trunk above is what the
// first box parity gate checks; speculative decode is enabled once the trunk parities (the same
// decision-5 ordering the raon1 lane uses for its DFlash draft). TODO(box): load the --mtp runtime
// (MtpDrafter::load, mtp.cpp L251), and after forward() of position p with the chosen token, run the
// drafter (mtp_draft, mtp.cpp L63) to propose up to --spec tokens, verify them in the trunk, and
// report spec_hits/spec_steps in DONE. Do NOT guess the proposal/accept rule — it is mtp.cpp's.
// ------------------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------------------
// FamilyGraph surface.
// ------------------------------------------------------------------------------------------------
Qwen4ExpGraph::~Qwen4ExpGraph() {
  // TODO(box): also release the u::ExpertTier, the host PLE reader, the mapped experts.bin arena, and
  // the MTP drafter. The device arenas are freed here.
  if (w_arena_) cudaFree(w_arena_);
  if (state_) cudaFree(state_);
  if (qsa_kv_) cudaFree(qsa_kv_);
  if (sc_) cudaFree(sc_);
  if (d_pos_) cudaFree(d_pos_);
}

std::string Qwen4ExpGraph::describe() const {
  return "qwen4exp(Qwen3.8-Flash-Next: " + std::to_string(g_.n_layers) + "L [" +
         std::to_string(g_.n_gdn()) + " GDN + " + std::to_string(g_.n_qsa()) + " QSA], hidden " +
         std::to_string(g_.n_embd) + ", 512x" + std::to_string(g_.n_exp_used) + "+" +
         std::to_string(g_.n_shared) + " MoE (iq_pack), PLE n-gram, hyper-conn, MTP draft)";
}

bool Qwen4ExpGraph::generate(const Gen& request, const LineSink& sink, std::string& error) {
  // The serve loop (host-driven, device compute). Upstream analogy: generate.cpp's embed -> layers ->
  // head -> sample -> embed loop. Steps:
  //   1. reset_sequence(); forward(request.ids) to consume the prompt, emitting PP progress.
  //   2. loop up to request.max_new: sample the last logits with u::k::sample_tokens + a SamplerParams
  //      built from request.params (temperature/top_p/top_k/min_p/penalties/seed; common.cuh L214-234),
  //      emit "T <id>" via the sink (u_protocol Token), append the token with forward({id}, 1), honor
  //      STOP / the stop ids / nonfinite.
  //   3. emit DONE <produced> <prompt> <prompt_ms> <decode_ms> <finish> <spec_hits> <spec_steps> 0.
  // Speculative hits/steps stay 0 until the MTP draft (seam D) is enabled.
  if (!loaded_) {
    error = "qwen4exp generate: graph not loaded (device upload + pack/PLE wiring by the shared loader)";
    return false;
  }
  reset_sequence();
  if (request.ids.empty()) { error = "qwen4exp generate: empty prompt"; return false; }
  if (!forward(request.ids.data(), (int)request.ids.size(), error)) return false;

  // TODO(box): the sampling + emit loop against u::k::sample_tokens and the Gen params, and the
  // PP/T/DONE records (u_protocol). Structured, not yet wired to the shared sampler; the trunk
  // forward() above is this lane's piece. Fail closed until wired.
  (void)sink;
  error = "qwen4exp generate: decode loop pending the shared sampler integration (seam E)";
  return false;
}

// ------------------------------------------------------------------------------------------------
// Factory.
// ------------------------------------------------------------------------------------------------
std::unique_ptr<FamilyGraph> make_qwen4exp_graph(const Geometry& geom, std::uint32_t context,
                                                 std::string& error) {
  error.clear();
  if (geom.family != FamilyId::qwen4exp) {
    error = "make_qwen4exp_graph: geometry is not qwen4exp";
    return nullptr;
  }
  auto graph = std::unique_ptr<Qwen4ExpGraph>(new Qwen4ExpGraph());
  // TODO(box): load() needs the parsed GgufFile(s) AND the pack paths (--pack/--native/--ple-gguf/
  // --embd-gguf/--mtp/--expert-profile), which u::make_family_graph does not pass today (seam A). The
  // CUDA dispatch that calls this factory must thread them through (a shared-file change this lane does
  // not own). Until then load() returns false and the graph reports unavailable — expected on the first
  // integration build, not a bug in this family.
  if (!graph->load(geom, context, error)) return nullptr;
  return graph;
}

}  // namespace u

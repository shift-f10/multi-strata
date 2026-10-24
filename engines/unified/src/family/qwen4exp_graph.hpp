// strata-unified-engine: the Qwen3.8-Flash-Next (arch "qwen4exp") per-family model graph.
//
// qwen4exp is ported from the MAIN upstream Strata engine (upstream/src/program/generate.cpp, the
// "strata generate" driver) and its components under upstream/src/core/* and upstream/src/kernels/*.
// Unlike qwen35moe (which upstream serves from a self-contained src/qwen35/q36_engine.cu on a plain
// GGUF own-path), qwen4exp is served by the main engine over the IQ_PACK expert path: a prebuilt
// experts pack (experts.bin + index.txt + native_experts.txt, built by upstream/tools/iq_pack.py),
// a disk-backed PLE n-gram table (--ple-gguf), a committed expert-hit profile (--expert-profile), and
// an external MTP draft layer (--mtp runtime dir). This is the MAIN NEW SEAM for this family and the
// reason it does not share qwen35moe's loader (contract: §"IQ_PACK / ExpertTier seam" below).
//
// THE REAL GRAPH (NOT the one-line "full attention + MoE" summary in the design-doc §0 table). The
// published Flash-Next geometry (upstream/include/strata/core/geometry.hpp kCompiledGeometry) is a
// hybrid, and this port is faithful to it:
//   * 48 trunk layers; hidden 2560; vocab ~248320; rms_eps 1e-6.
//   * ATTENTION is a GDN / QSA hybrid, NOT uniform full attention:
//       - 36 layers are GDN  (Gated-DeltaNet linear attention, no KV cache) — ssm_state 128,
//         group_count 16, time_step_rank 48, conv_kernel 4, conv_channels 10240, value_dim 6144.
//       - 12 layers are QSA  (Qwen Sparse Attention: a sparse-indexer + selected-cell flash attn) —
//         every `full_attention_interval`(=4)th layer, i.e. layers 3,7,...,47. heads 24, kv_heads 2,
//         head_dim 256, n_rot 64 (NEOX RoPE on the first 64 of head_dim), indexer heads 4 /
//         key_dim 128 / block 4 / top_k 2048.
//   * PER-LAYER EMBEDDING (PLE): every layer adds an n-gram-indexed per-layer embedding row, read
//     from the 26.8 GB (IQ4_NL) / 51.2 GB (FP8) SSD table (never held in RAM), through the host-side
//     PleReader (upstream/src/ngram/ple_reader.cpp) + a small postprojection kernel.
//   * HYPER-CONNECTIONS: every layer is wrapped in a gated-residual hyper-connection (count 4,
//     low_rank 320) instead of a plain pre-norm residual.
//   * MoE on every layer: softmax top-10 router over 512 experts (pruned Coder variants ship fewer) +
//     1 shared expert, n_ff 640 — the routed experts come from the iq_pack arena via u::ExpertTier.
//   * MTP: a separate draft layer (upstream/src/core/mtp.cpp, tools/mtp_rt.py) proposes tokens the
//     trunk verifies (speculative decode). Loaded from --mtp; off by default (spec_hits/steps = 0).
//
// LEAN CUT (design goal i — we port only what we serve). Dropped from the upstream engine: vision /
// mmproj, multi-GPU layer-split, the CPU expert pool / PCIe-overlap / NUMA machinery, batch groups,
// EXL3 / NVFP4 / Hadamard-fold quant paths, conversation-cache/session-save, and the many A/B diag
// flags. Text serve path, single GPU, one sequence.
//
// HOST/BOX SPLIT (identical to the raon1/glm lanes). This header is host-includable (the dispatch in
// u_family.hpp calls make_qwen4exp_graph with only host types; device state is held as raw pointers).
// The method bodies and all CUDA live in qwen4exp_graph.cu + src/kernels/qwen4exp_*.cu, built ONLY
// behind STRATA_U_CUDA on the owner's GPU box (design §1.3). On a host/CI build this factory is not
// linked and u::make_family_graph returns the host stub.
#pragma once

#include "u_family.hpp"
#include "u_geometry.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace u {

// ================================================================================================
// Qwen4ExpGeometry — the qwen4exp dims the graph's kernels need, beyond the common u::Geometry.
//
// The common fields (block_count/embedding_length/head_count/key_length/expert_* /context/vocab) come
// from the guarded u::Geometry (u_geometry.cpp; qwen4exp uses the GENERIC ranges there, not exact()
// pins — a Flash-Next GGUF that omits a key keeps the published default, exactly as the upstream
// geometry_from_gguf does: upstream/include/strata/core/family_layout.hpp). The GDN/QSA/HC/PLE
// internals below are the kCompiledGeometry defaults (upstream/include/strata/core/geometry.hpp
// L21-72), read from the `qwen4exp.*` metadata where a file carries them.
// ================================================================================================
struct Qwen4ExpGeometry final {
  // --- common (mirrored from the guarded u::Geometry) ---
  int n_embd = 2560;      // embedding_length
  int n_layers = 48;      // block_count MINUS n_mtp_layers (the trunk; the in-file MTP block, if any)
  int n_vocab = 248320;   // tokenizer.ggml.tokens length (the guard reads vocab_size)
  int n_expert = 512;     // expert_count (Coder prune ships fewer)
  int n_exp_used = 10;    // expert_used_count — softmax top-10 router
  int n_ff_exp = 640;     // expert_feed_forward_length (MoE + shared-expert FFN width)
  int n_shared = 1;       // one always-on shared expert (expert_shared_feed_forward_length == n_ff_exp)
  float rms_eps = 1e-6f;  // attention.layer_norm_rms_epsilon

  // --- the GDN / QSA attention schedule ---
  int qsa_interval = 4;   // full_attention_interval: layer % qsa_interval == qsa_interval-1 is QSA
  // is_qsa(il) mirrors upstream is_qsa_layer (geometry.hpp L80): every 4th layer is full (QSA).
  [[nodiscard]] bool is_qsa(int il) const { return il % qsa_interval == qsa_interval - 1; }
  [[nodiscard]] int n_qsa() const { return n_layers / qsa_interval; }
  [[nodiscard]] int n_gdn() const { return n_layers - n_qsa(); }

  // --- GDN (Gated-DeltaNet linear attention) — ssm.* keys ---
  int ssm_state = 128;        // ssm.state_size: key head width AND value head width (S)
  int ssm_k_heads = 16;       // ssm.group_count (q/k head count)
  int ssm_v_heads = 48;       // ssm.time_step_rank (v head count)
  int ssm_d_conv = 4;         // ssm.conv_kernel (causal short-conv tap count)
  int ssm_conv_channels = 10240;  // 2*state*k_heads + state*v_heads = 2*128*16 + 128*48 (derived)
  int ssm_value_dim = 6144;   // ssm.inner_size = state*v_heads = 128*48

  // --- QSA (Qwen Sparse Attention) ---
  int n_head = 24;        // attention.head_count
  int n_head_kv = 2;      // attention.head_count_kv (GQA)
  int head_dim = 256;     // attention.key_length (== value_length; the guard reads key_length)
  int n_rot = 64;         // rope.dimension_count: the rotated slice of head_dim and of idx_key_dim
  int idx_q_heads = 4;    // attention.indexer.head_count
  int idx_key_dim = 128;  // attention.indexer.key_length
  int idx_block = 4;      // compress_ratios nonzero entry: one pooled key per 4 cells
  int idx_top_k = 2048;   // attention.indexer.top_k: selection budget (cells)
  double rope_freq_base = 0.0;  // rope.freq_base (from the guarded Geometry; qwen4exp is a RoPE family)

  // --- hyper-connections (gated residual, every layer) ---
  int hc = 4;        // hyper_connection.count
  int hc_lr = 320;   // hyper_connection.low_rank

  // --- MTP draft (external, --mtp) ---
  int n_mtp_layers = 0;  // in-file MTP blocks after the trunk (qwen4exp ships its MTP as an external
                         // pack, so this is 0; qwen35moe counts blk.40 here — kept for symmetry)

  // Reads the qwen4exp.* metadata (beyond the common u::Geometry) into `out`, applying the published
  // kCompiledGeometry defaults where a key is absent (upstream geometry_from_gguf behaviour). Fails
  // closed with `err` on a key present with an impossible value. Defined in qwen4exp_graph.cu.
  static bool from_gguf(const GgufFile& file, const Geometry& common, Qwen4ExpGeometry& out,
                        std::string& err);
};

// ================================================================================================
// The iq_pack descriptors — the structural model of the pack the upstream FileExpertSource loads.
//
// A qwen4exp model is NOT one GGUF: it is a PACK DIRECTORY plus side GGUFs (the frontend composes the
// args; upstream/setup.py ~L8810-8824):
//     --pack <dir>              index.txt + native_experts.txt + experts.bin + dense.bin + tokenizer/
//     --native <dense.gguf>     quantized dense tensors + token_embd + output, served from the GGUF
//     --ple-gguf <ple.gguf>     the per-layer-embedding n-gram table (per_layer_token_embd.weight)
//     --embd-gguf <embd.gguf>   optional BF16 token embedding
//     --mtp <rt dir>            the MTP draft layer runtime
//     --expert-profile <bin>    the committed STRP expert-hit profile for ExpertTier warm start
//
// These structs capture the layout the box's shared loader must parse; the parsers are sketched in
// qwen4exp_graph.cu with precise upstream TODOs (iq_pack.py writes these files; expert_source.cpp
// reads them).
// ================================================================================================

// One layer's routed-expert blob layout inside experts.bin, from native_experts.txt
// ("layer gu_type d_type offset blob_bytes gate_off up_off down_off [shard]" — iq_pack.py
// expert_layout(), upstream/tools/iq_pack.py L430-488; parsed by FileExpertSource,
// upstream/src/core/expert_source.cpp L1370-1421).
struct Qwen4ExpPackLayer final {
  std::int64_t offset = 0;      // absolute byte offset of this layer's 512 blobs inside experts.bin
  std::int64_t blob_bytes = 0;  // bytes of one expert blob (gate | up | down), per-layer (mixed quants)
  std::int32_t gu_type = 0;     // ggml type id of gate+up (IQ1_M/IQ2_XS/IQ3_XXS/IQ3_S/...)
  std::int32_t d_type = 0;      // ggml type id of down (Q2_0/IQ4_NL/...)
  std::int64_t gate_off = 0;    // byte offset of gate inside a blob (0)
  std::int64_t up_off = 0;      // byte offset of up inside a blob
  std::int64_t down_off = 0;    // byte offset of down inside a blob
};

// The whole experts pack: per-layer layout + the mapped arena base (experts.bin, or the --native GGUF
// shards read in place when experts.bin is absent — upstream "CS-T", expert_source.cpp L1422-1433).
struct Qwen4ExpPack final {
  std::string pack_dir;                      // --pack
  std::string dense_gguf;                    // --native
  std::string ple_gguf;                      // --ple-gguf
  std::string embd_gguf;                     // --embd-gguf (optional)
  std::string mtp_dir;                       // --mtp (optional)
  std::string expert_profile;                // --expert-profile (optional)
  int n_expert_in_pack = 512;                // router rows in the pack (N_EXPERT; Coder prune < 512)
  std::vector<Qwen4ExpPackLayer> layers;     // per trunk layer
  // the mapped RAM arena (experts.bin mmap/read, pinned), filled by the box's shared loader:
  const std::uint8_t* arena_base = nullptr;  // blob (layer,e) at arena_base + layers[layer].offset + e*blob_bytes
  std::int64_t arena_bytes = 0;
};

// The PLE n-gram table descriptor (PleTable::open: validated GGUF parse giving the byte offset and row
// count — upstream/include/strata/ngram/ple_reader.hpp; the rows are read on demand, never in RAM).
struct Qwen4ExpPleTable final {
  std::string path;              // the --ple-gguf file
  std::int64_t table_offset = 0; // byte offset of row 0
  std::int64_t n_rows = 0;       // row count (e.g. 320,001,536)
  std::uint32_t row_bytes = 90;  // 90 (IQ4_NL) or 160 (FP8 E4M3)
};

// ================================================================================================
// Qwen4ExpGraph — the Qwen3.8-Flash-Next graph on the shared substrate.
// ================================================================================================
class Qwen4ExpGraph final : public FamilyGraph {
 public:
  ~Qwen4ExpGraph() override;
  Qwen4ExpGraph(const Qwen4ExpGraph&) = delete;
  Qwen4ExpGraph& operator=(const Qwen4ExpGraph&) = delete;

  [[nodiscard]] FamilyId family() const override { return FamilyId::qwen4exp; }
  [[nodiscard]] std::uint32_t context() const override { return context_; }
  [[nodiscard]] bool available() const override { return loaded_; }
  [[nodiscard]] std::string describe() const override;
  [[nodiscard]] bool generate(const Gen& request, const LineSink& sink, std::string& error) override;

  Qwen4ExpGraph() = default;

 private:
  // All defined in qwen4exp_graph.cu (CUDA).
  bool load(const Geometry& common, std::uint32_t context, std::string& err);
  bool forward(const std::int32_t* tokens, int n_tokens, std::string& err);  // writes the last logits
  void reset_sequence();  // zero every GDN recurrence + conv state; drop the QSA KV / indexer caches

  // One decoder layer, wrapped in a hyper-connection: HC-split -> mixer (GDN|QSA) -> PLE add ->
  // MoE FFN (routed via ExpertTier + shared expert) -> HC-combine. Mirrors upstream's captured
  // per-layer graph (generate.cpp, the "48 captured layer graphs").
  bool layer_gdn(int il, int T, std::string& err);   // GDN linear-attention mixer (36 layers)
  bool layer_qsa(int il, int T, std::string& err);   // QSA sparse-attention mixer (12 layers)
  bool layer_ple(int il, int T, std::string& err);   // add this layer's PLE n-gram embedding
  bool layer_moe(int il, int T, std::string& err);   // router + routed experts + shared expert

  // Pack / side-file loaders (host; parse the iq_pack directory, map the arena, open the PLE table,
  // configure u::ExpertTier). Sketched with upstream TODOs in qwen4exp_graph.cu.
  bool load_pack(const Qwen4ExpPack& pack_in, std::string& err);
  bool open_ple(std::string& err);

  Qwen4ExpGeometry g_{};
  std::uint32_t context_ = 0;
  bool loaded_ = false;
  std::int64_t pos_ = 0;  // tokens consumed since the last reset (QSA cache / PLE n-gram position)

  Qwen4ExpPack pack_{};
  Qwen4ExpPleTable ple_{};

  // Device arenas (float*/void* held host-typed; populated on the box by the shared loader).
  std::map<std::string, const void*> w_;  // dense weight name -> device pointer (from --native/dense.bin)
  std::uint8_t* w_arena_ = nullptr;       // dense/norm/router/hc/ssm/qsa/ple-proj weights
  std::uint8_t* state_ = nullptr;         // GDN recurrence S + conv history (per GDN layer)
  std::uint8_t* qsa_kv_ = nullptr;        // QSA key/value cache + indexer pooled-key cache (per QSA layer)
  std::uint8_t* sc_ = nullptr;            // per-forward scratch (activations, router, expert parts, logits)
  int* d_pos_ = nullptr;                  // cache positions on device (QSA attention reads them)

  // Per-layer state byte offsets into state_/qsa_kv_ (-1 if the layer has no such state).
  std::vector<std::int64_t> gdn_state_, gdn_conv_, qsa_cache_;

  friend std::unique_ptr<FamilyGraph> make_qwen4exp_graph(const Geometry&, std::uint32_t, std::string&);
};

// The qwen4exp factory (design contract). Builds and loads the graph for a guarded geometry; returns
// nullptr with `error` set on a load failure. The dispatch wires this into the CUDA branch of
// u::make_family_graph for FamilyId::qwen4exp (a shared-file change this lane does not own).
[[nodiscard]] std::unique_ptr<FamilyGraph> make_qwen4exp_graph(const Geometry& geom,
                                                               std::uint32_t context, std::string& error);

}  // namespace u

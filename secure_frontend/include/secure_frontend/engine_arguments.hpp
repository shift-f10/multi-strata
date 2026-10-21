#pragma once

#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/model_inventory.hpp"
#include "secure_frontend/tokenizer_pack.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace secure_frontend {

// Which engine CLI the argv tail is built for.
enum class EngineArgumentsProfile { strata_0143, lighttransport_glm53 };

enum class EngineArgumentsErrorCode { owned_flag, unsupported_mode, invalid_value, model_not_found };

// `message` is a fixed string; it never contains user-supplied argument text or paths.
struct EngineArgumentsError final {
  EngineArgumentsErrorCode code;
  std::string message;
};

using EngineArgumentsResult = std::variant<std::vector<std::string>, EngineArgumentsError>;

// SP5 M1 Task 5 (parity row `effort_position`): reasoning.effort_position "end" composes the
// engine's --tail-role-token flag with the tokenizer's single "system" token id
// (effort_end_args serve/server.py:2836-2856, appended to the engine argv at :7966/:7977). The
// probe rules are the pin's: the engine binary must contain the flag literal, and the tokenizer's
// plain encoding of "system" must be exactly one token; otherwise nothing composes and `notice`
// carries the pin's fixed fallback line (:2853). A composed pair comes with the pin's fixed
// success line (:2856). Neither notice names a path.
struct EffortEndArguments final {
  std::vector<std::string> arguments;
  std::string_view notice;
};

[[nodiscard]] EffortEndArguments compose_effort_end_arguments(const std::filesystem::path& engine_binary,
                                                              const TokenizerPack& tokenizer);

// Builds the engine argv tail (everything after `--serve`).
//
// strata_0143: the user's pass-through arguments, validated, followed by
// `--native <models_root/relative_artifact_path>` for the selected manifest,
// where models_root is the canonical root the inventory used (defect e).
// Rejects any user argument that names a flag the frontend owns (--native,
// --serve) or a mode whose protocol the frontend does not speak (--batch,
// --slots, --vision), in both `--flag value` and `--flag=value` spellings.
// `--pack DIR` (the expert directory, loaded unconditionally by the engine,
// default cwd-relative `pack/full`) and every other weight flag (--ple-gguf,
// --embd-gguf, --native-head-gguf, --native-dense-gguf, --mtp) pass through:
// they are operator-supplied until SP1/SP5 model the whole launch.
// `--gpu` is owned too (spec §3.9): GPUs are selected only by the typed `gpus`
// list (engine.gpu), rendered `--gpu i,j` before `--native`; the engine sets
// CUDA_DEVICE_ORDER/CUDA_VISIBLE_DEVICES (or HIP) itself (upstream
// generate.cpp:2334-2352, usage :797, at v0.2.1.3), so the strata
// family's environment carries no GPU variable.
//
// lighttransport_glm53: the GLM runner's CLI is not characterized, so the
// user's arguments pass through unchanged and no model path is supplied; only
// `--serve` (inserted by the launcher) and `--gpu` (frontend-owned) are
// rejected, and a non-empty `gpus` list is refused (unsupported_mode).
//
// In both profiles, values containing NUL are rejected.
[[nodiscard]] EngineArgumentsResult build_engine_arguments(EngineArgumentsProfile profile,
                                                           const ModelManifest& selected,
                                                           const CanonicalRoot& models_root,
                                                           const std::vector<std::string>& user_arguments,
                                                           const std::vector<unsigned>& gpus = {},
                                                           bool mtp_on = true);

// SP5 M1 Task 6 (parity row mtp; strata_control/draft_layer.py): MTP_FLAGS verbatim —
// {"--mtp": value, "--spec-min-p": value, "--batch-mtp": no value} — and the pin's
// strip() rule: a value is consumed only when the next token is not another flag.
// Returns the draft layer's own flags the composition dropped (in order), for the pin's
// fixed startup line (serve/server.py:2925). `--spec` (prompt lookup) stays.
[[nodiscard]] std::vector<std::string> draft_layer_removed(const std::vector<std::string>& arguments);

// The same strip applied in place; returns the flags removed. The managed composition
// uses this directly (its argv tail is composed, not passed through build_engine_arguments).
[[nodiscard]] std::vector<std::string> strip_draft_layer_arguments(std::vector<std::string>& arguments);

// SP5 M1 Task 7 (parity rows vram_reserve_mib / vram_elastic / vram_segment_mib /
// layer_split / split_skip_if_fits): the typed values the pin renders into the engine's
// argv (runconfig.py:42-43; serve/server.py:2938-2948, 2896-2899). `user_arguments` is
// the operator's args: every rendered flag is skipped when the operator already owns it
// (the pin's "not in args" guards), and the layer-split gate needs the typed GPU count.
// Ruling T7-a: this family reaches the engine through argv only — no GPU/elastic
// environment variables (SP2 §3.9; the engine renders CUDA/HIP from --gpu itself).
struct VramGpuElasticArgs final {
  std::optional<std::int64_t> vram_reserve_mib;  // unset: the engine's own 700 stays
  bool vram_elastic{false};
  std::optional<std::int64_t> vram_segment_mib;  // unset: the engine's own 512 stays
  std::string layer_split{"auto"};               // already validated (layer_split_value grammar)
  bool split_skip_if_fits{false};
};

void append_vram_gpu_elastic_arguments(std::vector<std::string>& arguments, const VramGpuElasticArgs& vram,
                                       const std::vector<std::string>& user_arguments, const std::vector<unsigned>& gpus);

// engine.hip_ordinal (serve/server.py:3016-3030): the recorded HIP number wins over one
// (or zero) configured GPUs, never over several; it reaches the engine through --gpu
// (Ruling T7-f — our design owns the device list, the engine renders HIP from it).
[[nodiscard]] std::vector<unsigned> effective_gpu_list(const std::vector<unsigned>& gpus,
                                                       std::optional<std::int64_t> hip_ordinal);

// SP5 M1 Task 9 (parity rows expert_profile_save / expert_profile_save_every;
// serve/server.py:3000-3005): a configured learned-profile save path composes
// --expert-profile-save and the every-minutes re-save (the pin's default 10, 0 = at QUIT
// only, :2996). The pin's own guard is kept: no path, or an operator-owned
// --expert-profile-save in argv, leaves the arguments unchanged — not even the every (:3001).
struct ExpertProfileSaveArgs final {
  std::string path;                 // session.expert_profile_save (empty: no flags)
  std::int64_t every{10};           // session.expert_profile_save_every (minutes; 0 = at QUIT only)
};

void append_expert_profile_save_arguments(std::vector<std::string>& arguments, const ExpertProfileSaveArgs& save,
                                          const std::vector<std::string>& user_arguments);

// Parses the operator's --gpu value: comma-separated decimal device indices
// 0-255, no sign, spaces or leading zeros, distinct, 1-16 entries.
[[nodiscard]] std::optional<std::vector<unsigned>> parse_gpu_list(std::string_view value);

// Checks only the operator's pass-through arguments (no model needed): NUL,
// frontend-owned flags and unsupported modes for `profile`. build_engine_arguments
// calls it; the config validator calls it so a bad engine.args fails before startup.
[[nodiscard]] std::optional<EngineArgumentsError> validate_engine_user_arguments(
    EngineArgumentsProfile profile, const std::vector<std::string>& user_arguments);

}  // namespace secure_frontend

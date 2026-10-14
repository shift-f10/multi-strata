#pragma once

#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/model_inventory.hpp"

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
// generate.cpp:1844-1865, usage :706-708, at v0.1.44.1), so the strata
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
                                                           const std::vector<unsigned>& gpus = {});

// Parses the operator's --gpu value: comma-separated decimal device indices
// 0-255, no sign, spaces or leading zeros, distinct, 1-16 entries.
[[nodiscard]] std::optional<std::vector<unsigned>> parse_gpu_list(std::string_view value);

// Checks only the operator's pass-through arguments (no model needed): NUL,
// frontend-owned flags and unsupported modes for `profile`. build_engine_arguments
// calls it; the config validator calls it so a bad engine.args fails before startup.
[[nodiscard]] std::optional<EngineArgumentsError> validate_engine_user_arguments(
    EngineArgumentsProfile profile, const std::vector<std::string>& user_arguments);

}  // namespace secure_frontend

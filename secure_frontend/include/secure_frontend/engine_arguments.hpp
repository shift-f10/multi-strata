#pragma once

#include "secure_frontend/model_inventory.hpp"

#include <filesystem>
#include <string>
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
// `--native <models_root/relative_artifact_path>` for the selected manifest.
// Rejects any user argument that names a flag the frontend owns (--native,
// --serve) or a mode whose protocol the frontend does not speak (--batch,
// --slots, --vision), in both `--flag value` and `--flag=value` spellings.
// `--pack DIR` (the expert directory, loaded unconditionally by the engine,
// default cwd-relative `pack/full`) and every other weight flag (--ple-gguf,
// --embd-gguf, --native-head-gguf, --native-dense-gguf, --mtp) pass through:
// they are operator-supplied until SP1/SP5 model the whole launch.
//
// lighttransport_glm53: the GLM runner's CLI is not characterized, so the
// user's arguments pass through unchanged and no model path is supplied; only
// `--serve` (inserted by the launcher) is rejected.
//
// In both profiles, values containing NUL are rejected.
[[nodiscard]] EngineArgumentsResult build_engine_arguments(EngineArgumentsProfile profile,
                                                           const ModelManifest& selected,
                                                           const std::filesystem::path& models_root,
                                                           const std::vector<std::string>& user_arguments);

}  // namespace secure_frontend

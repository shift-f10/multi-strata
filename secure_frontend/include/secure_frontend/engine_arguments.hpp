#pragma once

#include "secure_frontend/model_inventory.hpp"

#include <filesystem>
#include <string>
#include <variant>
#include <vector>

namespace secure_frontend {

enum class EngineArgumentsErrorCode { owned_flag, unsupported_mode, invalid_value, model_not_found };

// `message` is a fixed string; it never contains user-supplied argument text or paths.
struct EngineArgumentsError final {
  EngineArgumentsErrorCode code;
  std::string message;
};

using EngineArgumentsResult = std::variant<std::vector<std::string>, EngineArgumentsError>;

// Builds the engine argv tail (everything after `--serve`): the user's
// pass-through arguments, validated, followed by `--native <models_root/relative_artifact_path>`
// for the selected manifest. Rejects any user argument that names a flag the
// frontend owns (--native, --pack, --serve) or a mode whose protocol the
// frontend does not speak (--batch, --slots, --vision), in both `--flag value`
// and `--flag=value` spellings. Values containing NUL are rejected.
[[nodiscard]] EngineArgumentsResult build_engine_arguments(const ModelManifest& selected,
                                                           const std::filesystem::path& models_root,
                                                           const std::vector<std::string>& user_arguments);

}  // namespace secure_frontend

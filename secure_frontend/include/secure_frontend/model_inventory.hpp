#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace secure_frontend {

// Data deliberately contains only local metadata. It is suitable for adapting
// to an OpenAI /v1/models response, but does not initiate loading, download,
// telemetry, or any other network operation.
struct ModelManifest final {
  std::string id;
  std::string object{"model"};
  std::string owned_by{"local"};
  std::string relative_artifact_path;
  std::uintmax_t artifact_size_bytes{};
};

enum class ModelInventoryErrorCode {
  invalid_model_id,
  invalid_artifact_path,
  model_root_unavailable,
  model_root_not_directory,
  inventory_read_failed,
  symbolic_link_not_allowed,
  artifact_path_escapes_root,
  duplicate_model_id,
};

struct ModelInventoryError final {
  ModelInventoryErrorCode code;
  std::string message;
};

using ModelIdValidation = std::variant<std::string, ModelInventoryError>;
using ArtifactPathValidation = std::variant<std::string, ModelInventoryError>;
using ModelInventoryResult = std::variant<std::vector<ModelManifest>, ModelInventoryError>;

// Model IDs use a portable filename-safe subset so the same inventory behaves
// identically on Windows and Linux. IDs are not paths.
[[nodiscard]] ModelIdValidation validate_model_id(std::string_view id);

// Artifact paths are portable relative paths below a configured model root.
// They reject traversal, absolute/UNC/device/drive/ADS forms, control
// characters, empty components, Windows-ambiguous trailing dot/space names,
// and Windows reserved device names.
[[nodiscard]] ArtifactPathValidation validate_local_artifact_path(std::string_view path);

// Recursively inventories regular *.gguf files beneath model_root. Symlinks
// are rejected rather than followed. The inventory reads directory metadata
// only: it never opens artifacts, invokes a subprocess, or makes a network
// request. Model IDs are derived from the artifact filename stem and duplicate
// IDs fail closed.
[[nodiscard]] ModelInventoryResult enumerate_local_models(const std::filesystem::path& model_root);

}  // namespace secure_frontend

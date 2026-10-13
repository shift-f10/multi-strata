#include "secure_frontend/model_inventory.hpp"

#include <algorithm>
#include <cctype>
#include <system_error>

namespace secure_frontend {
namespace {

[[nodiscard]] bool is_ascii_alphanumeric(const char value) {
  return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
         (value >= '0' && value <= '9');
}

[[nodiscard]] bool contains_ascii_control(const std::string_view value) {
  return std::any_of(value.begin(), value.end(), [](const unsigned char character) {
    return character <= 0x1FU || character == 0x7FU;
  });
}

[[nodiscard]] bool is_windows_reserved_device_name(std::string_view component) {
  while (!component.empty() && (component.back() == ' ' || component.back() == '.')) {
    component.remove_suffix(1U);
  }
  const auto extension = component.find('.');
  if (extension != std::string_view::npos) {
    component = component.substr(0U, extension);
  }
  std::string upper;
  upper.reserve(component.size());
  for (const unsigned char character : component) {
    upper.push_back(static_cast<char>(std::toupper(character)));
  }
  if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL") {
    return true;
  }
  return upper.size() == 4U && (upper.starts_with("COM") || upper.starts_with("LPT")) &&
         upper.back() >= '1' && upper.back() <= '9';
}

[[nodiscard]] bool has_windows_ambiguous_suffix(const std::string_view component) {
  return !component.empty() && (component.back() == ' ' || component.back() == '.');
}

[[nodiscard]] bool is_gguf_extension(const std::filesystem::path& path) {
  std::string extension = path.extension().string();
  std::transform(extension.begin(), extension.end(), extension.begin(), [](const unsigned char character) {
    return static_cast<char>(std::tolower(character));
  });
  return extension == ".gguf";
}

[[nodiscard]] ModelInventoryError filesystem_error(const ModelInventoryErrorCode code,
                                                    const std::string_view action,
                                                    const std::error_code& error) {
  return ModelInventoryError{code, std::string{action} + ": " + error.message()};
}

}  // namespace

ModelIdValidation validate_model_id(const std::string_view id) {
  if (id.empty() || id.size() > 128U || !is_ascii_alphanumeric(id.front()) ||
      contains_ascii_control(id)) {
    return ModelInventoryError{ModelInventoryErrorCode::invalid_model_id,
                               "model IDs must start with an ASCII letter or digit and be at most 128 characters"};
  }
  for (const char character : id) {
    if (!(is_ascii_alphanumeric(character) || character == '.' || character == '_' || character == '-')) {
      return ModelInventoryError{ModelInventoryErrorCode::invalid_model_id,
                                 "model IDs may contain only ASCII letters, digits, dot, underscore, and hyphen"};
    }
  }
  if (id.back() == '.' || is_windows_reserved_device_name(id)) {
    return ModelInventoryError{ModelInventoryErrorCode::invalid_model_id,
                               "model ID is not portable on Windows"};
  }
  return std::string{id};
}

ArtifactPathValidation validate_local_artifact_path(const std::string_view path) {
  if (path.empty() || contains_ascii_control(path) || path.front() == '/' || path.front() == '\\' ||
      path.find(':') != std::string_view::npos) {
    return ModelInventoryError{ModelInventoryErrorCode::invalid_artifact_path,
                               "artifact paths must be portable relative paths below the configured model root"};
  }
  std::size_t component_start = 0U;
  while (component_start < path.size()) {
    const auto component_end = path.find_first_of("/\\", component_start);
    const auto component = path.substr(component_start, component_end - component_start);
    if (component.empty() || component == "." || component == ".." ||
        has_windows_ambiguous_suffix(component) || is_windows_reserved_device_name(component)) {
      return ModelInventoryError{ModelInventoryErrorCode::invalid_artifact_path,
                                 "artifact paths must not contain unsafe path components"};
    }
    if (component_end == std::string_view::npos) {
      return std::string{path};
    }
    component_start = component_end + 1U;
  }
  return ModelInventoryError{ModelInventoryErrorCode::invalid_artifact_path,
                             "artifact path must contain a filename"};
}

ModelInventoryResult enumerate_local_models(const std::filesystem::path& model_root) {
  std::error_code error;
  const auto canonical_root = std::filesystem::weakly_canonical(model_root, error);
  if (error) {
    return filesystem_error(ModelInventoryErrorCode::model_root_unavailable,
                            "unable to resolve model root", error);
  }
  if (!std::filesystem::is_directory(canonical_root, error)) {
    if (error) {
      return filesystem_error(ModelInventoryErrorCode::model_root_unavailable,
                              "unable to inspect model root", error);
    }
    return ModelInventoryError{ModelInventoryErrorCode::model_root_not_directory,
                               "model root must be an existing directory"};
  }

  std::vector<ModelManifest> models;
  std::filesystem::recursive_directory_iterator iterator(
      canonical_root, std::filesystem::directory_options::none, error);
  if (error) {
    return filesystem_error(ModelInventoryErrorCode::inventory_read_failed,
                            "unable to enumerate model root", error);
  }
  const std::filesystem::recursive_directory_iterator end;
  while (iterator != end) {
    const auto entry = *iterator;
    const auto status = entry.symlink_status(error);
    if (error) {
      return filesystem_error(ModelInventoryErrorCode::inventory_read_failed,
                              "unable to inspect model artifact", error);
    }
    if (std::filesystem::is_symlink(status)) {
      return ModelInventoryError{ModelInventoryErrorCode::symbolic_link_not_allowed,
                                 "symbolic links are not allowed in the model inventory"};
    }
    if (std::filesystem::is_regular_file(status) && is_gguf_extension(entry.path())) {
      const auto relative = entry.path().lexically_relative(canonical_root).generic_string();
      const auto validated_path = validate_local_artifact_path(relative);
      if (const auto* validation_error = std::get_if<ModelInventoryError>(&validated_path)) {
        return *validation_error;
      }
      const auto canonical_artifact = std::filesystem::weakly_canonical(entry.path(), error);
      if (error) {
        return filesystem_error(ModelInventoryErrorCode::inventory_read_failed,
                                "unable to resolve model artifact", error);
      }
      const auto resolved_relative = canonical_artifact.lexically_relative(canonical_root);
      if (resolved_relative.empty() || resolved_relative == "." || resolved_relative.is_absolute() ||
          resolved_relative.begin() == resolved_relative.end() || *resolved_relative.begin() == "..") {
        return ModelInventoryError{ModelInventoryErrorCode::artifact_path_escapes_root,
                                   "model artifact resolves outside the configured model root"};
      }
      const std::string id = entry.path().stem().string();
      const auto validated_id = validate_model_id(id);
      if (const auto* validation_error = std::get_if<ModelInventoryError>(&validated_id)) {
        return *validation_error;
      }
      const auto size = entry.file_size(error);
      if (error) {
        return filesystem_error(ModelInventoryErrorCode::inventory_read_failed,
                                "unable to determine model artifact size", error);
      }
      models.push_back(ModelManifest{.id = id,
                                     .relative_artifact_path = std::get<std::string>(validated_path),
                                     .artifact_size_bytes = size});
    }
    iterator.increment(error);
    if (error) {
      return filesystem_error(ModelInventoryErrorCode::inventory_read_failed,
                              "unable to continue model inventory enumeration", error);
    }
  }

  std::sort(models.begin(), models.end(), [](const ModelManifest& left, const ModelManifest& right) {
    return left.id < right.id;
  });
  for (std::size_t index = 1U; index < models.size(); ++index) {
    if (models[index - 1U].id == models[index].id) {
      return ModelInventoryError{ModelInventoryErrorCode::duplicate_model_id,
                                 "multiple local artifacts resolve to the same model ID"};
    }
  }
  return models;
}

}  // namespace secure_frontend

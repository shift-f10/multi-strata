#include "secure_frontend/model_inventory.hpp"
#include "support/test_support.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <variant>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

template <typename Result>
bool has_error(const Result& result, const secure_frontend::ModelInventoryErrorCode expected) {
  const auto* error = std::get_if<secure_frontend::ModelInventoryError>(&result);
  return error != nullptr && error->code == expected;
}

std::filesystem::path unique_temp_directory() {
  return secure_frontend_test::make_scratch_directory();
}

// Creates each missing directory one level at a time, owner-only (0700 /
// protected DACL), below an existing scratch root.
void make_private_directories(const std::filesystem::path& directory) {
  if (directory.empty() || std::filesystem::exists(directory)) return;
  make_private_directories(directory.parent_path());
  secure_frontend_test::make_private_directory(directory);
}

void write_file(const std::filesystem::path& path, const std::string_view contents) {
  make_private_directories(path.parent_path());
  std::ofstream stream(path, std::ios::binary);
  stream << contents;
}

void validates_portable_model_ids() {
  for (const auto id : {"Qwen3-30B-A3B-Q4_K_M", "llama.3.3", "Model1"}) {
    const auto result = secure_frontend::validate_model_id(id);
    expect(std::holds_alternative<std::string>(result), "expected valid model ID: " + std::string{id});
  }
  for (const auto id : {"", ".hidden", "model/other", "model\\other", "model:ads", "model ",
                        "NUL", "COM1", "model.", "model\nnext"}) {
    expect(has_error(secure_frontend::validate_model_id(id),
                     secure_frontend::ModelInventoryErrorCode::invalid_model_id),
           "expected invalid model ID: " + std::string{id});
  }
}

void validates_portable_artifact_paths() {
  const auto valid = secure_frontend::validate_local_artifact_path("qwen/Qwen3-30B-Q4_K_M.gguf");
  expect(std::holds_alternative<std::string>(valid), "valid nested artifact path should be accepted");
  for (const auto path : {"", "../model.gguf", "models/../model.gguf", "/models/model.gguf",
                          "C:\\models\\model.gguf", "\\\\server\\share\\model.gguf",
                          "model.gguf:ads", "models//model.gguf", "NUL/model.gguf",
                          "models./model.gguf", "models /model.gguf"}) {
    expect(has_error(secure_frontend::validate_local_artifact_path(path),
                     secure_frontend::ModelInventoryErrorCode::invalid_artifact_path),
           "expected invalid artifact path: " + std::string{path});
  }
}

void inventories_only_local_gguf_artifacts() {
  const auto root = unique_temp_directory();
  write_file(root / "zeta.gguf", "abc");
  write_file(root / "nested" / "Alpha-Q4_K_M.gguf", "abcdef");
  write_file(root / "notes.txt", "not a model");
  const auto result = secure_frontend::enumerate_local_models(root);
  const auto* models = std::get_if<std::vector<secure_frontend::ModelManifest>>(&result);
  expect(models != nullptr, "regular local GGUF artifacts should inventory without networking");
  if (models != nullptr) {
    expect(models->size() == 2U, "only GGUF artifacts should be returned");
    expect((*models)[0].id == "Alpha-Q4_K_M" && (*models)[0].object == "model" &&
               (*models)[0].owned_by == "local" &&
               (*models)[0].relative_artifact_path == "nested/Alpha-Q4_K_M.gguf" &&
               (*models)[0].artifact_size_bytes == 6U,
           "manifest should have stable local /v1/models-compatible metadata");
    expect((*models)[1].id == "zeta", "inventory should sort models by stable ID");
  }
  std::filesystem::remove_all(root);
}

void rejects_duplicate_ids_and_symlinks() {
  const auto duplicate_root = unique_temp_directory();
  write_file(duplicate_root / "same.gguf", "a");
  write_file(duplicate_root / "nested" / "same.gguf", "b");
  expect(has_error(secure_frontend::enumerate_local_models(duplicate_root),
                   secure_frontend::ModelInventoryErrorCode::duplicate_model_id),
         "duplicate filename-derived IDs must fail closed");
  std::filesystem::remove_all(duplicate_root);

#ifndef _WIN32
  const auto link_root = unique_temp_directory();
  write_file(link_root / "real.gguf", "a");
  std::filesystem::create_symlink(link_root / "real.gguf", link_root / "linked.gguf");
  expect(has_error(secure_frontend::enumerate_local_models(link_root),
                   secure_frontend::ModelInventoryErrorCode::symbolic_link_not_allowed),
         "inventory must reject, not follow, symbolic links");
  std::filesystem::remove_all(link_root);
#endif
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"validates_portable_model_ids", validates_portable_model_ids},
      {"validates_portable_artifact_paths", validates_portable_artifact_paths},
      {"inventories_only_local_gguf_artifacts", inventories_only_local_gguf_artifacts},
      {"rejects_duplicate_ids_and_symlinks", rejects_duplicate_ids_and_symlinks},
  }, failures);
}

#pragma once

#include "secure_frontend/canonical_path.hpp"

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace secure_frontend {

struct ModelRootFile final {
  std::string path;  // '/'-separated, relative to roots.models
  std::uint64_t size;
};

// Spec §4.9 delta b: every regular file below roots.models with its size, for
// list --all and doctor. Derives no model IDs, so the same shard name in
// current, retired and orphaned versions is fine. Links/junctions and other
// entries are skipped and never followed. Sorted by path.
[[nodiscard]] std::variant<std::vector<ModelRootFile>, PathError> scan_model_root_files(const CanonicalRoot& root);

}  // namespace secure_frontend

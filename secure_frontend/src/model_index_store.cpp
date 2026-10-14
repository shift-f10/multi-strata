#include "secure_frontend/model_index_store.hpp"

#include <algorithm>
#include <optional>
#include <utility>

namespace secure_frontend {

std::variant<std::vector<ModelRootFile>, PathError> scan_model_root_files(const CanonicalRoot& root) {
  std::vector<ModelRootFile> files;
  std::vector<std::optional<RelativePath>> pending{std::nullopt};
  while (!pending.empty()) {
    const auto directory = std::move(pending.back());
    pending.pop_back();
    auto listed = list_directory(root, directory);
    if (auto* failure = std::get_if<PathError>(&listed)) return *failure;
    for (const auto& entry : std::get<std::vector<DirectoryEntry>>(listed)) {
      const std::string text = directory ? directory->generic() + "/" + entry.name : entry.name;
      auto relative = parse_relative_path(text);
      if (!std::holds_alternative<RelativePath>(relative)) continue;  // not P1-portable: not ours
      if (entry.type == EntryType::directory) pending.emplace_back(std::get<RelativePath>(std::move(relative)));
      else if (entry.type == EntryType::regular_file) files.push_back(ModelRootFile{text, entry.size});
    }
  }
  std::sort(files.begin(), files.end(), [](const ModelRootFile& a, const ModelRootFile& b) { return a.path < b.path; });
  return files;
}

}  // namespace secure_frontend

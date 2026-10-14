#pragma once
#include "secure_frontend/canonical_path.hpp"

#include <memory>
#include <string>
#include <utility>

namespace secure_frontend::detail {

struct PathFactory final {
  static CanonicalRoot root(std::filesystem::path path, const NativeHandle handle, const std::uint64_t device) {
    return CanonicalRoot{std::move(path), std::make_shared<const OwnedHandle>(handle), device};
  }
  static CanonicalFile file(std::filesystem::path path) { return CanonicalFile{std::move(path)}; }
};

inline PathError path_error(const PathErrorCode code, std::string message) { return PathError{code, std::move(message)}; }

// Opens an existing root (platform files); open_root() wraps it.
std::variant<CanonicalRoot, PathError> open_existing_root(const std::filesystem::path& requested);

}  // namespace secure_frontend::detail

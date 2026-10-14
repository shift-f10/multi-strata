#if !defined(_WIN32)
#include "canonical_path_internal.hpp"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace secure_frontend {

OwnedHandle::~OwnedHandle() {
  if (handle_ >= 0) ::close(handle_);
}

NativeHandle OwnedHandle::release() noexcept {
  const NativeHandle kept = handle_;
  handle_ = -1;
  return kept;
}

namespace detail {

std::variant<CanonicalRoot, PathError> open_existing_root(const std::filesystem::path& requested) {
  const std::string text = requested.string();
  if (text.empty() || text.find('\0') != std::string::npos) return path_error(PathErrorCode::empty, "the root path is empty");
  if (!requested.is_absolute()) return path_error(PathErrorCode::not_absolute, "roots must be absolute paths");
  char* resolved = ::realpath(text.c_str(), nullptr);
  if (resolved == nullptr) {
    return path_error(PathErrorCode::root_unavailable, "the root does not exist or cannot be resolved");
  }
  const std::string canonical{resolved};
  std::free(resolved);
#if defined(O_PATH)
  const int fd = ::open(canonical.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
#else
  const int fd = ::open(canonical.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
#endif
  if (fd < 0) {
    return path_error(errno == ENOTDIR ? PathErrorCode::not_directory : PathErrorCode::root_unavailable,
                      "the root could not be opened as a directory");
  }
  struct stat st {};
  if (::fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
    ::close(fd);
    return path_error(PathErrorCode::not_directory, "the root is not a directory");
  }
  if (st.st_uid != ::geteuid() && st.st_uid != 0) {
    ::close(fd);
    return path_error(PathErrorCode::untrusted_owner, "the root must be owned by the current user or root");
  }
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
    ::close(fd);
    return path_error(PathErrorCode::shared_writable, "the root must not be writable by group or others");
  }
  return PathFactory::root(std::filesystem::path{canonical}, fd, static_cast<std::uint64_t>(st.st_dev));
}

}  // namespace detail

std::variant<CanonicalFile, PathError> open_executable(const std::filesystem::path& requested) {
  using detail::path_error;
  const std::string text = requested.string();
  if (text.empty() || !requested.is_absolute()) {
    return path_error(PathErrorCode::not_absolute, "the engine executable must be an absolute path");
  }
  char* resolved = ::realpath(text.c_str(), nullptr);
  if (resolved == nullptr) return path_error(PathErrorCode::not_found, "the engine executable does not exist");
  const std::string canonical{resolved};
  std::free(resolved);
  struct stat st {};
  if (::stat(canonical.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
    return path_error(PathErrorCode::not_regular_file, "the engine executable must be a regular file");
  }
  if (st.st_uid != ::geteuid() && st.st_uid != 0) {
    return path_error(PathErrorCode::untrusted_owner, "the engine executable must be owned by the current user or root");
  }
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
    return path_error(PathErrorCode::shared_writable, "the engine executable must not be writable by group or others");
  }
  const std::filesystem::path canonical_path{canonical};
  struct stat parent {};
  if (::stat(canonical_path.parent_path().c_str(), &parent) != 0 || (parent.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
      (parent.st_uid != ::geteuid() && parent.st_uid != 0)) {
    return path_error(PathErrorCode::shared_writable,
                      "the engine executable's directory must be private (owned by you or root, not group/other-writable)");
  }
  return detail::PathFactory::file(canonical_path);
}

bool is_within(const std::filesystem::path& root, const std::filesystem::path& candidate) noexcept {
  const std::filesystem::path base = root.has_filename() ? root : root.parent_path();
  auto r = base.begin();
  auto c = candidate.begin();
  for (; r != base.end(); ++r, ++c) {
    if (c == candidate.end() || *r != *c) return false;
  }
  return true;
}

}  // namespace secure_frontend
#endif

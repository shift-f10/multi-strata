#if defined(_WIN32)
#include "canonical_path_internal.hpp"
#include "windows_security.hpp"

#include <algorithm>

namespace secure_frontend {
namespace ws = windows_security;

OwnedHandle::~OwnedHandle() {
  if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
}

NativeHandle OwnedHandle::release() noexcept {
  const NativeHandle kept = handle_;
  handle_ = nullptr;
  return kept;
}

void OpenedFile::close_now() noexcept {
  if (owns_ && handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
  owns_ = false;
}

std::variant<std::size_t, PathError> OpenedFile::read_some(char* const buffer, const std::size_t capacity) const {
  DWORD count = 0;
  const DWORD request = static_cast<DWORD>(std::min<std::size_t>(capacity, 1U << 20U));
  if (ReadFile(handle_, buffer, request, &count, nullptr) == 0) {
    return detail::path_error(PathErrorCode::read_failed, "the file could not be read");
  }
  return static_cast<std::size_t>(count);
}

namespace detail {

std::variant<CanonicalRoot, PathError> open_existing_root(const std::filesystem::path& requested) {
  const std::wstring text = requested.wstring();
  if (auto error = check_windows_root_form(text)) return *error;
  std::wstring full(32768, L'\0');
  const DWORD length = GetFullPathNameW(text.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
  if (length == 0U || length >= full.size()) return path_error(PathErrorCode::root_unavailable, "the root cannot be resolved");
  full.resize(length);
  // No FILE_FLAG_OPEN_REPARSE_POINT: the root itself may be a junction or symlink.
  HANDLE handle = CreateFileW(ws::extended_path(full).c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (handle == INVALID_HANDLE_VALUE) return path_error(PathErrorCode::root_unavailable, "the root does not exist or cannot be opened");
  OwnedHandle guard(handle);
  FILE_ATTRIBUTE_TAG_INFO tag{};
  if (GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) == 0 ||
      (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U) {
    return path_error(PathErrorCode::not_directory, "the root is not a directory");
  }
  auto classified = classify_final_path(ws::final_path_for_handle(handle));
  if (auto* error = std::get_if<PathError>(&classified)) return *error;
  switch (ws::write_access_is_private(handle)) {
    case ws::Trust::trusted: break;
    case ws::Trust::untrusted_owner:
      return path_error(PathErrorCode::untrusted_owner, "the root must be owned by you, SYSTEM or Administrators");
    case ws::Trust::shared_writable:
      return path_error(PathErrorCode::shared_writable, "the root must not be writable by other users");
    case ws::Trust::unreadable:
      return path_error(PathErrorCode::root_unavailable, "the root's security settings cannot be read");
  }
  // Ownership moves to the CanonicalRoot.
  return PathFactory::root(std::filesystem::path{std::get<std::wstring>(classified)}, guard.release(), 0U);
}

}  // namespace detail

std::variant<CanonicalFile, PathError> open_executable(const std::filesystem::path& requested) {
  using detail::path_error;
  const std::wstring text = requested.wstring();
  if (auto error = check_windows_root_form(text)) return *error;
  // \\?\ disables Win32 normalization ('/' separators, '.' and '..'), so the
  // path is made full and normalized first, exactly as open_existing_root does.
  std::wstring full(32768, L'\0');
  const DWORD length = GetFullPathNameW(text.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
  if (length == 0U || length >= full.size()) {
    return path_error(PathErrorCode::not_found, "the engine executable path cannot be resolved");
  }
  full.resize(length);
  HANDLE handle = CreateFileW(ws::extended_path(full).c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (handle == INVALID_HANDLE_VALUE) return path_error(PathErrorCode::not_found, "the engine executable does not exist");
  OwnedHandle guard(handle);
  FILE_ATTRIBUTE_TAG_INFO tag{};
  if (GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) == 0 ||
      (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U || GetFileType(handle) != FILE_TYPE_DISK) {
    return path_error(PathErrorCode::not_regular_file, "the engine executable must be a regular file");
  }
  auto classified = classify_final_path(ws::final_path_for_handle(handle));
  if (auto* error = std::get_if<PathError>(&classified)) return *error;
  if (ws::write_access_is_private(handle) != ws::Trust::trusted) {
    return path_error(PathErrorCode::shared_writable, "the engine executable must not be writable by other users");
  }
  const std::filesystem::path canonical{std::get<std::wstring>(classified)};
  auto parent = detail::open_existing_root(canonical.parent_path());
  if (std::holds_alternative<PathError>(parent)) {
    return path_error(PathErrorCode::shared_writable, "the engine executable's folder must not be writable by other users");
  }
  return detail::PathFactory::file(canonical);
}

bool is_within(const std::filesystem::path& root, const std::filesystem::path& candidate) noexcept {
  std::wstring base = root.wstring();
  const std::wstring text = candidate.wstring();
  while (base.size() > 3U && (base.back() == L'\\' || base.back() == L'/')) base.pop_back();
  if (base.empty() || text.size() < base.size() ||
      CompareStringOrdinal(base.c_str(), static_cast<int>(base.size()), text.c_str(), static_cast<int>(base.size()), TRUE) !=
          CSTR_EQUAL) {
    return false;
  }
  return text.size() == base.size() || base.back() == L'\\' || text[base.size()] == L'\\' || text[base.size()] == L'/';
}

}  // namespace secure_frontend
#endif

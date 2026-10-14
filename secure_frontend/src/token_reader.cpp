#include "secure_frontend/token_reader.hpp"

#include <array>
#include <cerrno>
#include <cstdlib>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#ifdef _WIN32
#include "secure_frontend/win32_prelude.hpp"
#include "windows_security.hpp"
#include <aclapi.h>
#include <sddl.h>
#endif

namespace secure_frontend {
namespace {

constexpr std::size_t kMaximumTokenBytes = 1024U * 1024U;

TokenReadError error(const TokenReadErrorCode code, std::string message) {
  return TokenReadError{.code = code, .message = std::move(message)};
}

bool contains_control_character(const std::string_view value) {
  for (const unsigned char character : value) {
    if (character <= 0x1FU || character == 0x7FU) return true;
  }
  return false;
}

#ifndef _WIN32
TokenReadResult read_protected_file(const SecretSource& source, const CanonicalRoot& root) {
  const auto parsed = parse_relative_path(source.location());
  const auto* relative = std::get_if<RelativePath>(&parsed);
  if (relative == nullptr) return error(TokenReadErrorCode::read_failed, "The protected token file path is not valid.");
  auto opened = open_beneath(root, *relative,
                             OpenOptions{.kind = OpenKind::regular_file, .trust = FileTrust::owner_only,
                                         .reject_hard_links = true});
  if (const auto* failure = std::get_if<PathError>(&opened)) return token_error_from(*failure);
  const auto& file = std::get<OpenedFile>(opened);
  if (file.size() > kMaximumTokenBytes) return error(TokenReadErrorCode::token_too_large, "The protected token exceeds the size limit.");
  auto text = file.read_all(kMaximumTokenBytes);
  if (std::holds_alternative<PathError>(text)) return error(TokenReadErrorCode::read_failed, "The protected token file could not be read.");
  std::string token = std::get<std::string>(std::move(text));
  if (token.empty()) return error(TokenReadErrorCode::empty_token, "The resolved token must not be empty.");
  if (contains_control_character(token)) {
    return error(TokenReadErrorCode::invalid_token, "The resolved token must not contain control characters.");
  }
  return token;
}
#else

using namespace secure_frontend::windows_security;

// Removed in Task 11 together with read_protected_file_windows.
std::filesystem::path source_relative_path(const std::string_view location) {
  std::filesystem::path result;
  std::size_t start = 0U;
  while (start < location.size()) {
    const std::size_t end = location.find_first_of("\\/", start);
    result /= location.substr(start, end - start);
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 1U;
  }
  return result;
}

class WindowsHandle final {
 public:
  explicit WindowsHandle(const HANDLE handle = INVALID_HANDLE_VALUE) noexcept : handle_(handle) {}
  ~WindowsHandle() {
    if (handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(handle_);
    }
  }
  WindowsHandle(const WindowsHandle&) = delete;
  WindowsHandle& operator=(const WindowsHandle&) = delete;
  [[nodiscard]] HANDLE get() const noexcept { return handle_; }
  [[nodiscard]] bool valid() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }

 private:
  HANDLE handle_;
};

bool is_below_or_equal_final_path(const std::wstring& root, const std::wstring& candidate) {
  if (root.empty() || candidate.size() < root.size() ||
      CompareStringOrdinal(root.c_str(), static_cast<int>(root.size()), candidate.c_str(),
                           static_cast<int>(root.size()), TRUE) != CSTR_EQUAL) {
    return false;
  }
  return candidate.size() == root.size() || root.back() == L'\\' || candidate[root.size()] == L'\\';
}

TokenReadResult read_protected_file_windows(const SecretSource& source,
                                            const std::filesystem::path& requested_root) {
  std::error_code filesystem_error;
  const std::filesystem::path absolute_root = std::filesystem::absolute(requested_root, filesystem_error);
  if (filesystem_error || absolute_root.empty()) {
    return error(TokenReadErrorCode::secret_root_unavailable,
                 "The configured protected-file root is unavailable.");
  }

  WindowsHandle root(CreateFileW(absolute_root.c_str(), FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!root.valid() || is_reparse_point(root.get())) {
    return error(TokenReadErrorCode::secret_root_unavailable,
                 "The configured protected-file root could not be opened safely.");
  }
  const std::wstring root_final_path = final_path_for_handle(root.get());
  if (root_final_path.empty()) {
    return error(TokenReadErrorCode::secret_root_unavailable,
                 "The configured protected-file root could not be canonicalized safely.");
  }

  std::array<std::byte, SECURITY_MAX_SID_SIZE> current_user_storage{};
  PSID current_user = nullptr;
  if (!current_user_sid(current_user_storage, &current_user) ||
      !has_private_owner_dacl(root.get(), current_user)) {
    return error(TokenReadErrorCode::insecure_file_permissions,
                 "The protected-file root must have a protected owner-only access control list.");
  }

  std::filesystem::path current_path = absolute_root;
  const std::filesystem::path relative = source_relative_path(source.location());
  for (auto component = relative.begin(); component != relative.end(); ++component) {
    current_path /= *component;
    // std::next, not std::prev(end()): libc++ tags path::iterator as an input
    // iterator, so prev() is ill-formed there.
    const bool is_final = std::next(component) == relative.end();
    WindowsHandle opened(CreateFileW(current_path.c_str(), is_final ? GENERIC_READ : FILE_READ_ATTRIBUTES,
                                     FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                     (is_final ? 0U : FILE_FLAG_BACKUP_SEMANTICS) |
                                         FILE_FLAG_OPEN_REPARSE_POINT,
                                     nullptr));
    if (!opened.valid()) {
      return error(TokenReadErrorCode::token_not_found, "The protected token file does not exist.");
    }
    if (is_reparse_point(opened.get())) {
      return error(TokenReadErrorCode::symlink_not_allowed,
                   "Protected token file paths may not include reparse points.");
    }
    const std::wstring opened_final_path = final_path_for_handle(opened.get());
    if (!is_below_or_equal_final_path(root_final_path, opened_final_path)) {
      return error(TokenReadErrorCode::path_escapes_root,
                   "The protected token file resolves outside the configured root.");
    }
    if (!has_private_owner_dacl(opened.get(), current_user)) {
      return error(TokenReadErrorCode::insecure_file_permissions,
                   "Protected token paths must have protected owner-only access control lists.");
    }
    if (!is_final) {
      FILE_ATTRIBUTE_TAG_INFO attributes{};
      if (GetFileInformationByHandleEx(opened.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) == 0 ||
          (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U) {
        return error(TokenReadErrorCode::not_regular_file,
                     "Protected token path components must be directories.");
      }
      continue;
    }

    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (GetFileType(opened.get()) != FILE_TYPE_DISK ||
        GetFileInformationByHandleEx(opened.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) == 0 ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) {
      return error(TokenReadErrorCode::not_regular_file, "The protected token path must be a regular file.");
    }

    LARGE_INTEGER size{};
    if (GetFileSizeEx(opened.get(), &size) == 0 || size.QuadPart < 0 ||
        static_cast<unsigned long long>(size.QuadPart) > kMaximumTokenBytes) {
      return error(TokenReadErrorCode::token_too_large, "The protected token exceeds the size limit.");
    }
    std::string token;
    token.reserve(static_cast<std::size_t>(size.QuadPart));
    std::array<char, 4096> buffer{};
    while (true) {
      DWORD bytes_read = 0U;
      if (ReadFile(opened.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_read, nullptr) == 0) {
        return error(TokenReadErrorCode::read_failed, "The protected token file could not be read.");
      }
      if (bytes_read == 0U) {
        break;
      }
      if (token.size() + bytes_read > kMaximumTokenBytes) {
        return error(TokenReadErrorCode::token_too_large, "The protected token exceeds the size limit.");
      }
      token.append(buffer.data(), bytes_read);
    }
    if (token.empty()) {
      return error(TokenReadErrorCode::empty_token, "The resolved token must not be empty.");
    }
    if (contains_control_character(token)) {
      return error(TokenReadErrorCode::invalid_token, "The resolved token must not contain control characters.");
    }
    return token;
  }
  return error(TokenReadErrorCode::read_failed, "The protected token file path could not be processed.");
}
#endif

TokenReadResult read_environment_token(const SecretSource& source) {
  const char* const value = std::getenv(source.location().c_str());
  if (value == nullptr) {
    return error(TokenReadErrorCode::environment_variable_not_set,
                 "The configured token environment variable is not set.");
  }
  if (*value == '\0') {
    return error(TokenReadErrorCode::empty_token, "The resolved token must not be empty.");
  }
  if (contains_control_character(value)) {
    return error(TokenReadErrorCode::invalid_token, "The resolved token must not contain control characters.");
  }
  return std::string{value};
}

}  // namespace

TokenReadError token_error_from(const PathError& failure) {
  switch (failure.code) {
    case PathErrorCode::symlink_not_allowed: return error(TokenReadErrorCode::symlink_not_allowed, "Protected token paths may not include links or reparse points.");
    case PathErrorCode::escapes_root:
    case PathErrorCode::cross_device: return error(TokenReadErrorCode::path_escapes_root, "The protected token file resolves outside the configured root.");
    case PathErrorCode::not_found: return error(TokenReadErrorCode::token_not_found, "The protected token file does not exist.");
    case PathErrorCode::not_directory:
    case PathErrorCode::not_regular_file: return error(TokenReadErrorCode::not_regular_file, "The protected token path must be a regular file.");
    case PathErrorCode::not_owned_by_user: return error(TokenReadErrorCode::file_not_owned_by_current_user, "The protected token file must be owned by the current user.");
    case PathErrorCode::permissions_too_broad:
    case PathErrorCode::untrusted_owner:
    case PathErrorCode::shared_writable: return error(TokenReadErrorCode::insecure_file_permissions, "The protected token file must not grant access to other users.");
    case PathErrorCode::hard_link_not_allowed: return error(TokenReadErrorCode::hard_link_not_allowed, "The protected token file must not have other hard links.");
    case PathErrorCode::not_absolute:
    case PathErrorCode::unsupported_root_form:
    case PathErrorCode::network_location:
    case PathErrorCode::root_unavailable: return error(TokenReadErrorCode::secret_root_unavailable, "The configured protected-file root is unavailable.");
    default: return error(TokenReadErrorCode::read_failed, "The protected token file could not be opened safely.");
  }
}

TokenReadResult read_token(const SecretSource& source, const CanonicalRoot& protected_file_root) {
  if (source.kind() == SecretSourceKind::environment_variable) return read_environment_token(source);
#ifdef _WIN32
  return read_protected_file_windows(source, protected_file_root.path());  // Task 11 switches to the module
#else
  return read_protected_file(source, protected_file_root);
#endif
}

TokenReadResult read_token(const SecretSource& source, const std::filesystem::path& protected_file_root) {
  if (source.kind() == SecretSourceKind::environment_variable) return read_environment_token(source);
#ifdef _WIN32
  return read_protected_file_windows(source, protected_file_root);
#else
  auto root = open_root(protected_file_root);
  if (const auto* failure = std::get_if<PathError>(&root)) return token_error_from(*failure);
  return read_protected_file(source, std::get<CanonicalRoot>(root));
#endif
}

}  // namespace secure_frontend

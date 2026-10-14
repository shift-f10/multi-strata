#pragma once

#include "secure_frontend/secret_source.hpp"
#include "secure_frontend/canonical_path.hpp"

#include <filesystem>
#include <string>
#include <variant>

namespace secure_frontend {

enum class TokenReadErrorCode {
  environment_variable_not_set,
  empty_token,
  invalid_token,
  secret_root_unavailable,
  token_not_found,
  path_escapes_root,
  symlink_not_allowed,
  not_regular_file,
  insecure_file_permissions,
  file_not_owned_by_current_user,
  read_failed,
  token_too_large,
  hard_link_not_allowed,
};

struct TokenReadError final {
  TokenReadErrorCode code;
  std::string message;
};

// The successful value is intentionally short-lived. Callers must pass it directly
// to the authentication component, redact it from logs/errors, and overwrite it
// as soon as their allocator/API permits.
using TokenReadResult = std::variant<std::string, TokenReadError>;

// Resolves a SecretSource at the last responsible moment. For a protected file
// the root is opened once (open_root) and the file is opened below it with
// open_beneath (no symlink, no mount crossing, no second hard link); on Linux
// it must then be owned by the effective user with no group/other bits.
//
// On Windows the root and every path component are opened with
// FILE_FLAG_OPEN_REPARSE_POINT and rejected if they carry
// FILE_ATTRIBUTE_REPARSE_POINT (a reparse-point root is secret_root_unavailable;
// a reparse-point component is symlink_not_allowed). Each handle's final path
// (GetFinalPathNameByHandleW) must lie at or below the root's final path
// (path_escapes_root). The root, every intermediate directory, and the token file
// must each be owned by the current process user and carry a protected DACL
// (SE_DACL_PROTECTED, so nothing is inherited from the parent) whose only
// allow-ACEs name that user, LocalSystem, or Administrators (deny-ACEs are
// permitted; any other ACE type is rejected); otherwise the result is
// insecure_file_permissions (a wrong owner is reported this way on Windows, not
// as file_not_owned_by_current_user).
// Intermediate components must be directories and the final component a regular
// disk file. These checks cannot be substituted by std::filesystem permissions on
// Windows. They compile in the llvm-mingw cross build but have no runtime test yet:
// secure_frontend_token_reader_tests is built only on UNIX, so not even the
// windows-msys2-clang CI job exercises them (and wine does not model DACLs
// faithfully). Every Windows failure mode fails closed.
[[nodiscard]] TokenReadResult read_token(const SecretSource& source, const CanonicalRoot& protected_file_root);
// Opens `protected_file_root` with open_root first; used where only a path is known.
[[nodiscard]] TokenReadResult read_token(const SecretSource& source,
                                         const std::filesystem::path& protected_file_root);
// Maps a canonical-path failure to the token reader's fixed codes and messages.
[[nodiscard]] TokenReadError token_error_from(const PathError& error);

}  // namespace secure_frontend

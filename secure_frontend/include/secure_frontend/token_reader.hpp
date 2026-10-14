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
// On Windows the root and every component are opened with READ_CONTROL |
// FILE_READ_ATTRIBUTES and FILE_FLAG_OPEN_REPARSE_POINT; a reparse point is
// symlink_not_allowed; each handle's final path must lie at or below the
// root's (path_escapes_root); the root, every directory and the file must be
// owned by the current user with a protected DACL whose only allow-ACEs name
// that user, SYSTEM or Administrators (insecure_file_permissions); a file with
// more than one hard link is rejected. Runtime-tested only by the
// windows-msys2-clang job (label windows-runtime).
[[nodiscard]] TokenReadResult read_token(const SecretSource& source, const CanonicalRoot& protected_file_root);
// Opens `protected_file_root` with open_root first; used where only a path is known.
[[nodiscard]] TokenReadResult read_token(const SecretSource& source,
                                         const std::filesystem::path& protected_file_root);
// Maps a canonical-path failure to the token reader's fixed codes and messages.
[[nodiscard]] TokenReadError token_error_from(const PathError& error);

}  // namespace secure_frontend

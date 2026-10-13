#pragma once

#include "secure_frontend/secret_source.hpp"

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
  protected_file_unsupported_on_platform,
};

struct TokenReadError final {
  TokenReadErrorCode code;
  std::string message;
};

// The successful value is intentionally short-lived. Callers must pass it directly
// to the authentication component, redact it from logs/errors, and overwrite it
// as soon as their allocator/API permits.
using TokenReadResult = std::variant<std::string, TokenReadError>;

// Resolves a SecretSource at the last responsible moment. For a protected file on
// Linux this canonicalizes the root and target, verifies target containment, then
// opens every path component with O_NOFOLLOW. It accepts only a regular file owned
// by the effective user with no group/world permission bits.
//
// Windows builds support environment sources. Protected-file sources deliberately
// return protected_file_unsupported_on_platform until the Windows implementation is
// added and runtime-tested. That implementation must: canonicalize with a handle
// (GetFinalPathNameByHandleW), compare the final path below the root's final path,
// reject FILE_ATTRIBUTE_REPARSE_POINT on every component, require a regular file,
// and verify an owner-only DACL for the current user. These checks cannot be
// substituted by std::filesystem permissions on Windows.
[[nodiscard]] TokenReadResult read_token(const SecretSource& source,
                                         const std::filesystem::path& protected_file_root);

}  // namespace secure_frontend

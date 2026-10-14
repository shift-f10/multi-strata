#include "secure_frontend/token_reader.hpp"

#include "secure_frontend/secret_bytes.hpp"

#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"

#include <wincrypt.h>
#include <dpapi.h>
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
#if defined(_WIN32)
  if (token.rfind(kDpapiTokenMagic, 0) == 0) {
    DATA_BLOB input{static_cast<DWORD>(token.size() - kDpapiTokenMagic.size()),
                    reinterpret_cast<BYTE*>(token.data() + kDpapiTokenMagic.size())};
    DATA_BLOB output{};
    const BOOL ok = CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output);
    secure_wipe(token.data(), token.size());
    if (ok == 0) return error(TokenReadErrorCode::invalid_token, "The token file could not be decrypted for the current user.");
    token.assign(reinterpret_cast<const char*>(output.pbData), output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
  }
#endif
  if (token.empty()) return error(TokenReadErrorCode::empty_token, "The resolved token must not be empty.");
  if (contains_control_character(token)) {
    return error(TokenReadErrorCode::invalid_token, "The resolved token must not contain control characters.");
  }
  return token;
}

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
  return read_protected_file(source, protected_file_root);
}

TokenReadResult read_token(const SecretSource& source, const std::filesystem::path& protected_file_root) {
  if (source.kind() == SecretSourceKind::environment_variable) return read_environment_token(source);
  auto root = open_root(protected_file_root);
  if (const auto* failure = std::get_if<PathError>(&root)) return token_error_from(*failure);
  return read_protected_file(source, std::get<CanonicalRoot>(root));
}

}  // namespace secure_frontend

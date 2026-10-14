#include "secure_frontend/token_store.hpp"

#include "secure_frontend/token_generator.hpp"

#include <cerrno>
#include <cstdio>
#include <string>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace secure_frontend {
namespace {

// [[maybe_unused]]: only the POSIX definitions below use these until Task 17
// adds the Windows ones; -Werror=unused-function would otherwise fail llvm-mingw.
[[maybe_unused]] TokenStoreError fail(const TokenStoreErrorCode code, const char* message) {
  return TokenStoreError{code, message};
}

[[maybe_unused]] std::string random_suffix() {
  unsigned char nonce[8] = {};
  if (!fill_random(nonce, sizeof(nonce))) return {};
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  for (const unsigned char b : nonce) { out.push_back(kHex[b >> 4U]); out.push_back(kHex[b & 15U]); }
  return out;
}

#if !defined(_WIN32)
int publish_without_replacing(const int dir, const char* temp, const char* name) {
#if defined(RENAME_NOREPLACE)
  if (::renameat2(dir, temp, dir, name, RENAME_NOREPLACE) == 0) return 0;
  if (errno != ENOSYS && errno != EINVAL) return -1;
#endif
  if (::linkat(dir, temp, dir, name, 0) != 0) return -1;  // EEXIST if the name is taken
  ::unlinkat(dir, temp, 0);
  return 0;
}
#endif

}  // namespace

#if !defined(_WIN32)
std::optional<TokenStoreError> write_private_file(const CanonicalRoot& root, const RelativePath& file,
                                                  const std::string_view bytes, const TokenStoreMode mode) {
  const auto& parts = file.components();
  int dir = -1;
  if (parts.size() == 1U) {
    dir = ::openat(root.handle(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  } else {
    std::string parent;
    for (std::size_t i = 0; i + 1U < parts.size(); ++i) parent += (parent.empty() ? "" : "/") + parts[i];
    auto opened = open_beneath(root, std::get<RelativePath>(parse_relative_path(parent)), OpenOptions{.kind = OpenKind::directory});
    if (std::holds_alternative<PathError>(opened)) return fail(TokenStoreErrorCode::unsafe_location, "the directory for the file cannot be opened safely");
    dir = ::fcntl(std::get<OpenedFile>(opened).native(), F_DUPFD_CLOEXEC, 0);
  }
  if (dir < 0) return fail(TokenStoreErrorCode::write_failed, "the directory for the file cannot be opened");
  OwnedHandle dir_guard(dir);
  struct stat ds {};
  if (::fstat(dir, &ds) != 0 || ds.st_uid != ::geteuid() || (ds.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
    return fail(TokenStoreErrorCode::unsafe_location, "the directory holding the file must be owned by you with mode 0700");
  }
  const std::string& name = parts.back();
  struct stat existing {};
  if (::fstatat(dir, name.c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0) {
    if (!S_ISREG(existing.st_mode)) return fail(TokenStoreErrorCode::unsafe_location, "the target exists and is not a regular file");
    if (mode == TokenStoreMode::create_new) return fail(TokenStoreErrorCode::already_exists, "the file already exists");
  } else if (errno != ENOENT) {
    // Only "absent" lets the write go ahead; any other failure fails closed.
    return fail(TokenStoreErrorCode::unsafe_location, "the target cannot be inspected");
  }
  const std::string suffix = random_suffix();
  if (suffix.empty()) return fail(TokenStoreErrorCode::write_failed, "no randomness for the temporary file name");
  const std::string temp = "." + name + ".tmp-" + suffix;
  const int fd = ::openat(dir, temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) return fail(TokenStoreErrorCode::write_failed, "the temporary file cannot be created");
  bool ok = ::fchmod(fd, 0600) == 0;
  std::size_t written = 0U;
  while (ok && written < bytes.size()) {
    const ssize_t count = ::write(fd, bytes.data() + written, bytes.size() - written);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) ok = false;
    else written += static_cast<std::size_t>(count);
  }
  ok = ok && ::fsync(fd) == 0;
  ok = ::close(fd) == 0 && ok;
  if (!ok) {
    ::unlinkat(dir, temp.c_str(), 0);
    return fail(TokenStoreErrorCode::write_failed, "the file could not be written");
  }
  const int published = mode == TokenStoreMode::create_new ? publish_without_replacing(dir, temp.c_str(), name.c_str())
                                                           : ::renameat(dir, temp.c_str(), dir, name.c_str());
  const int saved = errno;
  if (published != 0) {
    ::unlinkat(dir, temp.c_str(), 0);
    return fail(saved == EEXIST ? TokenStoreErrorCode::already_exists : TokenStoreErrorCode::write_failed,
                "the file could not be put in place");
  }
  (void)::fsync(dir);
  return std::nullopt;
}

std::optional<TokenStoreError> store_token(const CanonicalRoot& secret_root, const RelativePath& file,
                                           const SecretBytes& token, const TokenStoreMode mode) {
  SecretBytes content;
  if (!content.assign(token.view()) || !content.append("\n")) return fail(TokenStoreErrorCode::write_failed, "the token is too long");
  return write_private_file(secret_root, file, content.view(), mode);
}
#endif

}  // namespace secure_frontend

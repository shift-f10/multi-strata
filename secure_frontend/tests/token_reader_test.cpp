#include "secure_frontend/secret_source.hpp"
#include "secure_frontend/token_reader.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <variant>

namespace {

int failures = 0;

void expect(const bool condition, const std::string_view message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

class TemporaryDirectory final {
 public:
  TemporaryDirectory() {
    std::array<char, 64> template_path{};
    const std::string prefix = "/tmp/secure-frontend-token-reader-XXXXXX";
    std::copy(prefix.begin(), prefix.end(), template_path.begin());
    char* const created = mkdtemp(template_path.data());
    if (created == nullptr) {
      std::cerr << "mkdtemp failed: " << std::strerror(errno) << '\n';
      std::exit(EXIT_FAILURE);
    }
    path_ = created;
  }

  ~TemporaryDirectory() { std::filesystem::remove_all(path_); }
  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

secure_frontend::TokenReadResult read_file_source(
    const std::filesystem::path& root, const std::string_view path) {
  const auto source = secure_frontend::make_protected_file_secret_source(path);
  const auto* protected_source = std::get_if<secure_frontend::SecretSource>(&source);
  if (protected_source == nullptr) {
    std::cerr << "test fixture produced an invalid protected source\n";
    std::exit(EXIT_FAILURE);
  }
  return secure_frontend::read_token(*protected_source, root);
}

void writes_file(const std::filesystem::path& path, const std::string_view content, const mode_t mode) {
  std::ofstream output(path, std::ios::binary);
  output << content;
  output.close();
  if (chmod(path.c_str(), mode) != 0) {
    std::cerr << "chmod failed: " << std::strerror(errno) << '\n';
    std::exit(EXIT_FAILURE);
  }
}

void reads_an_owner_only_regular_file_below_the_root() {
  TemporaryDirectory directory;
  const auto token = directory.path() / "token";
  writes_file(token, "file-token", 0600);

  const auto result = read_file_source(directory.path(), "token");
  const auto* value = std::get_if<std::string>(&result);
  expect(value != nullptr && *value == "file-token", "owner-only regular file should be read");
}

void reads_the_named_environment_variable() {
  if (setenv("SECURE_FRONTEND_TOKEN_READER_TEST", "environment-token", 1) != 0) {
    std::cerr << "setenv failed\n";
    std::exit(EXIT_FAILURE);
  }
  const auto source = secure_frontend::make_environment_secret_source("SECURE_FRONTEND_TOKEN_READER_TEST");
  const auto* environment_source = std::get_if<secure_frontend::SecretSource>(&source);
  if (environment_source == nullptr) {
    std::cerr << "test fixture produced an invalid environment source\n";
    std::exit(EXIT_FAILURE);
  }
  const auto result = secure_frontend::read_token(*environment_source, ".");
  const auto* value = std::get_if<std::string>(&result);
  expect(value != nullptr && *value == "environment-token", "environment source should be read");
  unsetenv("SECURE_FRONTEND_TOKEN_READER_TEST");
}

void rejects_control_characters_in_resolved_tokens() {
  if (setenv("SECURE_FRONTEND_TOKEN_READER_TEST", "bad\nvalue", 1) != 0) {
    std::cerr << "setenv failed\n";
    std::exit(EXIT_FAILURE);
  }
  const auto environment_source = secure_frontend::make_environment_secret_source("SECURE_FRONTEND_TOKEN_READER_TEST");
  const auto* source = std::get_if<secure_frontend::SecretSource>(&environment_source);
  const auto environment_result = secure_frontend::read_token(*source, ".");
  const auto* environment_error = std::get_if<secure_frontend::TokenReadError>(&environment_result);
  expect(environment_error != nullptr && environment_error->code == secure_frontend::TokenReadErrorCode::invalid_token,
         "control characters in an environment token must be rejected");
  unsetenv("SECURE_FRONTEND_TOKEN_READER_TEST");

  TemporaryDirectory directory;
  writes_file(directory.path() / "token", "bad\nvalue", 0600);
  const auto file_result = read_file_source(directory.path(), "token");
  const auto* file_error = std::get_if<secure_frontend::TokenReadError>(&file_result);
  expect(file_error != nullptr && file_error->code == secure_frontend::TokenReadErrorCode::invalid_token,
         "control characters in a protected-file token must be rejected");
}

void rejects_a_group_or_world_accessible_file() {
  TemporaryDirectory directory;
  writes_file(directory.path() / "token", "insecure", 0640);
  const auto result = read_file_source(directory.path(), "token");
  const auto* error = std::get_if<secure_frontend::TokenReadError>(&result);
  expect(error != nullptr && error->code == secure_frontend::TokenReadErrorCode::insecure_file_permissions,
         "group-readable token file should be rejected");
}

void rejects_a_symlink_that_escapes_the_root() {
  TemporaryDirectory directory;
  TemporaryDirectory outside;
  writes_file(outside.path() / "token", "outside", 0600);
  std::filesystem::create_symlink(outside.path() / "token", directory.path() / "token");
  const auto result = read_file_source(directory.path(), "token");
  const auto* error = std::get_if<secure_frontend::TokenReadError>(&result);
  expect(error != nullptr && error->code == secure_frontend::TokenReadErrorCode::path_escapes_root,
         "symlink escaping the configured root should be rejected");
}

void rejects_a_non_regular_file() {
  TemporaryDirectory directory;
  if (mkfifo((directory.path() / "token").c_str(), 0600) != 0) {
    std::cerr << "mkfifo failed: " << std::strerror(errno) << '\n';
    std::exit(EXIT_FAILURE);
  }
  const auto result = read_file_source(directory.path(), "token");
  const auto* error = std::get_if<secure_frontend::TokenReadError>(&result);
  expect(error != nullptr && error->code == secure_frontend::TokenReadErrorCode::not_regular_file,
         "FIFO should be rejected before any read attempt");
}

}  // namespace

int main() {
  reads_an_owner_only_regular_file_below_the_root();
  reads_the_named_environment_variable();
  rejects_control_characters_in_resolved_tokens();
  rejects_a_group_or_world_accessible_file();
  rejects_a_symlink_that_escapes_the_root();
  rejects_a_non_regular_file();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

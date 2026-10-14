#include "secure_frontend/token_generator.hpp"
#include "secure_frontend/token_store.hpp"
#include "support/test_support.hpp"

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <variant>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

namespace {
int failures = 0;
// The helpers are [[maybe_unused]]: on Windows this task registers no case (Task 17
// adds the Windows ones), and -Werror would otherwise reject the unused functions.
[[maybe_unused]] void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}

[[maybe_unused]] secure_frontend::CanonicalRoot root_at(const std::filesystem::path& path) {
  return std::get<secure_frontend::CanonicalRoot>(secure_frontend::open_root(path));
}
[[maybe_unused]] secure_frontend::RelativePath rel(const char* text) {
  return std::get<secure_frontend::RelativePath>(secure_frontend::parse_relative_path(text));
}
[[maybe_unused]] secure_frontend::SecretBytes fresh_token() {
  return std::get<secure_frontend::SecretBytes>(secure_frontend::generate_token());
}

#if !defined(_WIN32)
void token_store_creates_0600_file_in_0700_dir() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  const auto token = fresh_token();
  expect(!secure_frontend::store_token(root_at(dir), rel("token"), token, secure_frontend::TokenStoreMode::create_new),
         "a token is stored in a 0700 directory");
  struct stat st {};
  stat((dir / "token").c_str(), &st);
  expect((st.st_mode & 0777) == 0600 && st.st_uid == geteuid(), "the file is 0600 and owned by the user");
  expect(secure_frontend_test::read_file(dir / "token") == std::string{token.view()} + "\n", "token plus one LF");
  std::size_t entries = 0;
  for ([[maybe_unused]] const auto& entry : std::filesystem::directory_iterator(dir)) ++entries;
  expect(entries == 1U, "no temporary file is left behind");
  const auto again = secure_frontend::store_token(root_at(dir), rel("token"), fresh_token(), secure_frontend::TokenStoreMode::create_new);
  expect(again.has_value() && again->code == secure_frontend::TokenStoreErrorCode::already_exists, "create_new never overwrites");
  const auto shared = secure_frontend_test::make_scratch_directory();
  chmod(shared.c_str(), 0750);
  const auto unsafe = secure_frontend::store_token(root_at(shared), rel("token"), token, secure_frontend::TokenStoreMode::create_new);
  expect(unsafe.has_value() && unsafe->code == secure_frontend::TokenStoreErrorCode::unsafe_location,
         "a directory with group access is refused");
}

void token_store_rotate_is_atomic() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  const auto first = fresh_token();
  const auto second = fresh_token();
  const std::string a = std::string{first.view()} + "\n";
  const std::string b = std::string{second.view()} + "\n";
  expect(!secure_frontend::store_token(root_at(dir), rel("token"), first, secure_frontend::TokenStoreMode::create_new), "initial");
  std::atomic<bool> stop{false};
  std::atomic<int> torn{0};
  std::thread reader([&] {
    while (!stop) {
      const std::string seen = secure_frontend_test::read_file(dir / "token");
      if (seen != a && seen != b) ++torn;
    }
  });
  for (int i = 0; i < 200; ++i) {
    (void)secure_frontend::store_token(root_at(dir), rel("token"), i % 2 == 0 ? second : first, secure_frontend::TokenStoreMode::replace);
  }
  stop = true;
  reader.join();
  expect(torn == 0, "a concurrent reader always sees the old or the new token, never a partial file");
}

void token_store_refuses_symlinked_target() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  const auto outside = secure_frontend_test::make_scratch_directory();
  secure_frontend_test::write_file(outside / "victim", "unchanged");
  std::filesystem::create_symlink(outside / "victim", dir / "token");
  const auto result = secure_frontend::store_token(root_at(dir), rel("token"), fresh_token(), secure_frontend::TokenStoreMode::replace);
  expect(result.has_value() && result->code == secure_frontend::TokenStoreErrorCode::unsafe_location, "a symlinked target is refused");
  expect(secure_frontend_test::read_file(outside / "victim") == "unchanged", "the link target is untouched");
  expect(std::filesystem::is_symlink(dir / "token"), "the symlink itself is not replaced either");
}
#endif
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
#if !defined(_WIN32)
      {"token_store_creates_0600_file_in_0700_dir", token_store_creates_0600_file_in_0700_dir},
      {"token_store_rotate_is_atomic", token_store_rotate_is_atomic},
      {"token_store_refuses_symlinked_target", token_store_refuses_symlinked_target},
#endif
  }, failures);
}

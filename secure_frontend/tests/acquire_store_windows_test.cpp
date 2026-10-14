#include "acquire_cases.hpp"
#include "secure_frontend/models_store.hpp"
#include "support/expect.hpp"
#include "support/test_support.hpp"

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"

#include <cstdint>
#include <filesystem>
#include <variant>

namespace acquire_cases {

using secure_frontend::must_rel;
using secure_frontend_test::expect;

void store_primitives_windows() {
  auto opened = secure_frontend::open_root(secure_frontend_test::make_scratch_directory());
  const auto root = std::get<secure_frontend::CanonicalRoot>(std::move(opened));
  const secure_frontend::StoreEnvironment env;
  auto lock = secure_frontend::lock_models_root(root);
  expect(std::holds_alternative<secure_frontend::ModelsLock>(lock), "LockFileEx exclusive");
  const auto busy = secure_frontend::lock_models_root(root);
  expect(std::holds_alternative<secure_frontend::AcquireError>(busy) &&
             std::get<secure_frontend::AcquireError>(busy).reason == secure_frontend::AcquireReason::models_busy,
         "LOCKFILE_FAIL_IMMEDIATELY → models_busy");
  expect(!secure_frontend::ensure_directory(root, must_rel("v/w")), "private directories");
  {
    auto part = secure_frontend::open_part_file(root, must_rel("v/w/a.part"), secure_frontend::PartOpen::create_new, env);
    auto& file = std::get<secure_frontend::PartFile>(part);
    expect(!file.preallocate(4096) && file.size() == 0, "FileAllocationInfo keeps the length");
    expect(!file.append("abc") && !file.sync() && file.size() == 3, "append + FlushFileBuffers");
    expect(!file.truncate_to_zero() && !file.append("xy") && file.size() == 2, "truncate then append");
  }
  expect(!secure_frontend::write_new_file(root, must_rel("v/w/b"), "B"), "second file");
  expect(secure_frontend::rename_within(root, must_rel("v/w/a.part"), must_rel("v/w/b"), env).has_value(), "no replace");
  expect(!secure_frontend::rename_within(root, must_rel("v/w/a.part"), must_rel("v/w/a"), env), "rename");
  // A process holding the file without FILE_SHARE_DELETE makes deletion fail after the retries.
  const auto held_path = root.join(must_rel("v/w/a"));
  HANDLE held = CreateFileW(held_path.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
  expect(held != INVALID_HANDLE_VALUE, "engine-like open handle");
  expect(secure_frontend::remove_file_within(root, must_rel("v/w/a")).has_value(), "sharing violation → error after retries");
  CloseHandle(held);
  const auto outside = secure_frontend_test::make_scratch_directory();
  secure_frontend_test::write_file(outside / "keep.txt", "keep");
  expect(secure_frontend_test::create_junction(root.join(must_rel("v/j")), outside), "junction");
  expect(!secure_frontend::remove_tree_within(root, must_rel("v")), "tree removed; the junction itself, never its target");
  expect(std::filesystem::exists(outside / "keep.txt") && !secure_frontend::exists_within(root, must_rel("v")), "target intact");
  expect(std::holds_alternative<std::uint64_t>(env.free_bytes(root)), "GetDiskFreeSpaceExW");
  expect(std::get<secure_frontend::FileSystemKind>(env.file_system_kind(root)) == secure_frontend::FileSystemKind::other, "NTFS");
}

}  // namespace acquire_cases
#endif

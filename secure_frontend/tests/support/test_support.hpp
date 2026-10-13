#pragma once
// Shared by every secure_frontend test binary (SP1 §3.10): a framework-free
// case runner -- `<binary> --case <name> [args...]` runs one case, no
// arguments runs all, `--list` prints the names -- plus owner-only scratch
// directories below the build tree.
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#include <sddl.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace secure_frontend_test {

struct Case final {
  std::string_view name;
  std::function<void()> run;
};

// Arguments after `--case <name>` (the ARGS of secure_frontend_add_cases).
inline std::vector<std::string>& extra_arguments() {
  static std::vector<std::string> arguments;
  return arguments;
}

inline std::vector<std::filesystem::path>& scratch_registry() {
  static std::vector<std::filesystem::path> directories;
  return directories;
}

#if defined(_WIN32)
// CreateDirectoryW with an explicit, protected DACL: full control for the
// current user, LocalSystem and Administrators, nothing inherited. %TEMP% is
// not trusted to be private -- on GitHub's setup-msys2 runners TEMP lives under
// D:\a\_temp, whose ACL can grant Authenticated Users write, and an inherited
// ACE like that would make every open_root(scratch) report shared_writable.
// Returns ERROR_SUCCESS, or the GetLastError() value captured immediately after
// the failing call (before any LocalFree/CloseHandle can overwrite it).
inline DWORD create_private_directory_w(const std::wstring& path) {
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == 0) return GetLastError();
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<unsigned char> buffer(size);
  const bool have_user = size != 0 && GetTokenInformation(token, TokenUser, buffer.data(), size, &size) != 0;
  const DWORD token_error = have_user ? ERROR_SUCCESS : GetLastError();
  CloseHandle(token);
  if (!have_user) return token_error != ERROR_SUCCESS ? token_error : ERROR_INVALID_DATA;
  wchar_t* sid_text = nullptr;
  if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid_text) == 0) {
    return GetLastError();
  }
  // D:P = protected DACL; OICI = inherited by files and subdirectories; FA = full access.
  const std::wstring sddl = std::wstring{L"D:P(A;OICI;FA;;;"} + sid_text + L")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
  LocalFree(sid_text);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr) == 0) {
    return GetLastError();
  }
  SECURITY_ATTRIBUTES attributes{static_cast<DWORD>(sizeof(SECURITY_ATTRIBUTES)), descriptor, FALSE};
  const DWORD error = CreateDirectoryW(path.c_str(), &attributes) != 0 ? ERROR_SUCCESS : GetLastError();
  LocalFree(descriptor);
  return error;
}
#endif

// A fresh, empty directory only the current user can use. POSIX: mkdtemp
// (mode 0700) below $SECURE_FRONTEND_TEST_TMP, which secure_frontend_add_cases
// points at <build>/test-tmp. Windows: below %TEMP%, created with an explicit
// protected DACL (user, SYSTEM, Administrators) instead of inheriting %TEMP%'s.
inline std::filesystem::path make_scratch_directory() {
#if defined(_WIN32)
  const std::filesystem::path base = std::filesystem::temp_directory_path();
  static unsigned counter = 0;
  DWORD last_error = ERROR_SUCCESS;
  for (int attempt = 0; attempt < 1000; ++attempt) {
    const auto candidate = base / ("sf-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(++counter) +
                                   "-" + std::to_string(GetTickCount64()));
    last_error = create_private_directory_w(L"\\\\?\\" + std::filesystem::absolute(candidate).wstring());
    if (last_error == ERROR_SUCCESS) {
      scratch_registry().push_back(candidate);
      return candidate;
    }
  }
  std::cerr << "unable to create a scratch directory below " << base.string() << ": error " << last_error << '\n';
  std::exit(EXIT_FAILURE);
#else
  const char* configured = std::getenv("SECURE_FRONTEND_TEST_TMP");
  const std::filesystem::path base = configured != nullptr && *configured != '\0'
                                         ? std::filesystem::path{configured}
                                         : std::filesystem::temp_directory_path();
  std::error_code ignored;
  std::filesystem::create_directories(base, ignored);
  std::string pattern = (base / "sf-XXXXXX").string();
  if (mkdtemp(pattern.data()) == nullptr) {
    std::cerr << "mkdtemp failed below " << base.string() << ": " << std::strerror(errno) << '\n';
    std::exit(EXIT_FAILURE);
  }
  scratch_registry().emplace_back(pattern);
  return std::filesystem::path{pattern};
#endif
}

// mkdir with mode 0700 (the umask cannot widen it), or CreateDirectoryW with
// the same explicit protected DACL as make_scratch_directory (never inherited).
inline void make_private_directory(const std::filesystem::path& path) {
#if defined(_WIN32)
  const std::wstring extended = L"\\\\?\\" + std::filesystem::absolute(path).wstring();
  const DWORD error = create_private_directory_w(extended);
  if (error != ERROR_SUCCESS && error != ERROR_ALREADY_EXISTS) {
    std::cerr << "CreateDirectoryW failed: " << path.string() << ": error " << error << '\n';
    std::exit(EXIT_FAILURE);
  }
#else
  if (mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) {
    std::cerr << "mkdir failed: " << path.string() << ": " << std::strerror(errno) << '\n';
    std::exit(EXIT_FAILURE);
  }
#endif
}

// Writes bytes (replacing the file) and, on POSIX, sets `mode` exactly.
inline void write_file(const std::filesystem::path& path, const std::string_view bytes, const unsigned mode = 0600) {
#if defined(_WIN32)
  (void)mode;
  const std::wstring extended = L"\\\\?\\" + std::filesystem::absolute(path).wstring();
  HANDLE file = CreateFileW(extended.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    std::cerr << "CreateFileW failed: " << path.string() << ": error " << error << '\n';
    std::exit(EXIT_FAILURE);
  }
  DWORD written = 0;
  const bool ok = bytes.empty() || (WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) != 0 &&
                                    written == bytes.size());
  const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
  CloseHandle(file);
  if (!ok) {
    std::cerr << "WriteFile failed: " << path.string() << ": error " << error << '\n';
    std::exit(EXIT_FAILURE);
  }
#else
  {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  if (chmod(path.c_str(), static_cast<mode_t>(mode)) != 0) {
    std::cerr << "chmod failed: " << path.string() << ": " << std::strerror(errno) << '\n';
    std::exit(EXIT_FAILURE);
  }
#endif
}

inline std::string read_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return std::string{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

inline void remove_scratch_directories() {
  for (const auto& directory : scratch_registry()) {
    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
  }
  scratch_registry().clear();
}

// `failures` is the calling file's own counter (files whose expect() throws pass a zero).
inline int run_cases(const int argc, char** argv, const std::initializer_list<Case> cases, const int& failures) {
  // Cleanup also runs on std::exit() from a helper, so a setup failure cannot
  // leave scratch directories behind (a no-op after the normal-path cleanup).
  // The registry is constructed first so it outlives the atexit handler.
  scratch_registry();
  static const bool cleanup_registered = std::atexit(remove_scratch_directories) == 0;
  (void)cleanup_registered;
  std::vector<const Case*> selected;
  if (argc >= 2 && std::string_view{argv[1]} == "--list") {
    for (const auto& c : cases) std::cout << c.name << '\n';
    return EXIT_SUCCESS;
  }
  if (argc >= 3 && std::string_view{argv[1]} == "--case") {
    for (int index = 3; index < argc; ++index) extra_arguments().emplace_back(argv[index]);
    for (const auto& c : cases) if (c.name == std::string_view{argv[2]}) selected.push_back(&c);
    if (selected.empty()) { std::cerr << "unknown case: " << argv[2] << '\n'; return EXIT_FAILURE; }
  } else if (argc == 1) {
    for (const auto& c : cases) selected.push_back(&c);
  } else {
    std::cerr << "usage: " << argv[0] << " [--list | --case <name> [args...]]\n";
    return EXIT_FAILURE;
  }
  for (const Case* c : selected) {
    try {
      c->run();
    } catch (const std::exception& error) {
      std::cerr << "FAILED: " << c->name << ": " << error.what() << '\n';
      remove_scratch_directories();
      return EXIT_FAILURE;
    } catch (...) {
      std::cerr << "FAILED: " << c->name << ": unknown exception\n";
      remove_scratch_directories();
      return EXIT_FAILURE;
    }
  }
  remove_scratch_directories();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

}  // namespace secure_frontend_test

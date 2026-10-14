#include "secure_frontend/engine_environment.hpp"

#include <array>
#include <cstddef>
#include <system_error>
#include <utility>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#include "windows_security.hpp"
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace secure_frontend {
namespace {

std::string native(const std::filesystem::path& path) {
  auto copy = path;
  copy.make_preferred();
  const auto text = copy.u8string();
  return std::string(reinterpret_cast<const char*>(text.data()), text.size());
}

std::string join(const std::vector<std::filesystem::path>& paths, const char separator) {
  std::string joined;
  for (const auto& path : paths) {
    if (!joined.empty()) joined += separator;
    joined += native(path);
  }
  return joined;
}

void add_optional(EnvironmentBlock& block, const EngineEnvironment& environment) {
  if (environment.hipblaslt_tuning) block.emplace("STRATA_HIPBLASLT_TUNING", native(*environment.hipblaslt_tuning));
  if (environment.watchdog_s) block.emplace("STRATA_WATCHDOG_S", std::to_string(*environment.watchdog_s));
  if (environment.watchdog_io_s) block.emplace("STRATA_WATCHDOG_IO_S", std::to_string(*environment.watchdog_io_s));
}

// The per-family tables. strata forces nothing: its rendering is exactly the
// §3.9 allowlist. glm stays empty until SP6 fills it (§4.9: STRATA_GLM_* safety
// constants, STRATA_WATCHDOG_S=0, the CUDA selectors); no GLM value renders yet.
constexpr std::array<ForcedEnvironmentValue, 0> kStrataForced{};
constexpr std::array<ForcedEnvironmentValue, 0> kGlmForced{};

constexpr bool contains(const std::span<const std::string_view> names, const std::string_view name) noexcept {
  for (const auto candidate : names) {
    if (candidate == name) return true;
  }
  return false;
}

// The same validation for every table, shipped or test-only (R5 requirement 2).
constexpr bool forced_environment_is_valid(const std::span<const ForcedEnvironmentValue> forced) noexcept {
  for (std::size_t i = 0; i < forced.size(); ++i) {
    const auto& entry = forced[i];
    if (!contains(kFamilyForcibleEnvironment, entry.name)) return false;
    if (contains(kNeverForwardedEnvironment, entry.name) && !contains(kFamilyGpuSelectors, entry.name)) return false;
    if (entry.value.find('\0') != std::string_view::npos) return false;
    for (std::size_t j = 0; j < i; ++j) {
      if (forced[j].name == entry.name) return false;
    }
  }
  return true;
}

static_assert(forced_environment_is_valid(kStrataForced) && forced_environment_is_valid(kGlmForced),
              "every shipped family table passes the forced-values validation");

// Never fails for a shipped table (static_assert above); a rejected table
// would render nothing at all rather than a partial environment.
EnvironmentBlock with_family(EnvironmentBlock block, const EngineFamily family) {
  if (!merge_forced_environment(block, family_forced_environment(family))) return {};
  return block;
}

}  // namespace

std::span<const ForcedEnvironmentValue> family_forced_environment(const EngineFamily family) noexcept {
  switch (family) {
    case EngineFamily::strata:
      return kStrataForced;
    case EngineFamily::glm:
      return kGlmForced;
  }
  return {};
}

bool merge_forced_environment(EnvironmentBlock& block, const std::span<const ForcedEnvironmentValue> forced) {
  if (!forced_environment_is_valid(forced)) return false;
  for (const auto& entry : forced) block.insert_or_assign(std::string(entry.name), std::string(entry.value));
  return true;
}

EnvironmentBlock render_posix_environment(const EngineEnvironment& environment) {
  EnvironmentBlock block;
  block.emplace("PATH", "/usr/bin:/bin");
  if (!environment.lib_dirs.empty()) block.emplace("LD_LIBRARY_PATH", join(environment.lib_dirs, ':'));
  block.emplace("TMPDIR", native(environment.temp_dir));
  block.emplace("CUDA_CACHE_PATH", native(environment.cuda_cache_dir));
  add_optional(block, environment);
  return with_family(std::move(block), environment.family);
}

EnvironmentBlock render_windows_environment(const EngineEnvironment& environment, const WindowsSystemValues& system) {
  EnvironmentBlock block;
  std::string path = join(environment.lib_dirs, ';');
  if (!path.empty()) path += ';';
  path += system.system_root + "\\System32";
  block.emplace("PATH", path);
  block.emplace("TEMP", native(environment.temp_dir));
  block.emplace("TMP", native(environment.temp_dir));
  block.emplace("CUDA_CACHE_PATH", native(environment.cuda_cache_dir));
  block.emplace("SystemRoot", system.system_root);
  block.emplace("WINDIR", system.system_root);
  block.emplace("SystemDrive", system.system_drive);
  block.emplace("NUMBER_OF_PROCESSORS", std::to_string(system.processors));
  add_optional(block, environment);
  return with_family(std::move(block), environment.family);
}

WindowsSystemValues query_windows_system_values() {
  WindowsSystemValues values;
#if defined(_WIN32)
  wchar_t buffer[MAX_PATH + 1]{};
  const UINT length = GetSystemWindowsDirectoryW(buffer, MAX_PATH + 1);
  if (length > 0 && length <= MAX_PATH) {
    const int size = WideCharToMultiByte(CP_UTF8, 0, buffer, static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    values.system_root.assign(static_cast<std::size_t>(size > 0 ? size : 0), '\0');
    if (size > 0) (void)WideCharToMultiByte(CP_UTF8, 0, buffer, static_cast<int>(length), values.system_root.data(), size, nullptr, nullptr);
  }
  values.system_drive = values.system_root.substr(0, 2);
  SYSTEM_INFO info{};
  GetSystemInfo(&info);
  values.processors = info.dwNumberOfProcessors;
#endif
  return values;
}

EnvironmentBlock render_engine_environment(const EngineEnvironment& environment) {
#if defined(_WIN32)
  return render_windows_environment(environment, query_windows_system_values());
#else
  return render_posix_environment(environment);
#endif
}

bool is_owner_only_directory(const std::filesystem::path& path) {
#if defined(_WIN32)
  std::error_code error;
  const auto status = std::filesystem::symlink_status(path, error);
  return !error && std::filesystem::is_directory(status);
#else
  struct stat info {};
  if (lstat(path.c_str(), &info) != 0) return false;
  return S_ISDIR(info.st_mode) && info.st_uid == geteuid() && (info.st_mode & 077) == 0;
#endif
}

bool is_private_state_root(const std::filesystem::path& path) {
#if defined(_WIN32)
  namespace ws = windows_security;
  std::error_code error;
  const auto absolute = std::filesystem::absolute(path, error);
  if (error) return false;
  HANDLE handle = CreateFileW(ws::extended_path(absolute.wstring()).c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (handle == INVALID_HANDLE_VALUE) return false;
  FILE_ATTRIBUTE_TAG_INFO tag{};
  std::array<std::byte, SECURITY_MAX_SID_SIZE> user_storage{};
  PSID user = nullptr;
  const bool directory = GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) != 0 &&
                         (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U;
  const bool owner_only = directory && !ws::is_reparse_point(handle) && ws::current_user_sid(user_storage, &user) &&
                          ws::has_private_owner_dacl(handle, user);
  CloseHandle(handle);
  return owner_only;
#else
  return is_owner_only_directory(path);
#endif
}

EngineEnvironment engine_environment_for(const std::filesystem::path& state_dir, const std::optional<std::filesystem::path>& cache_root,
                                         std::vector<std::filesystem::path> lib_dirs) {
  EngineEnvironment environment;
  environment.lib_dirs = std::move(lib_dirs);
  environment.temp_dir = state_dir / "engine-tmp";
  environment.cuda_cache_dir = cache_root ? *cache_root / "cuda" : state_dir / "cache" / "cuda";
  return environment;
}

bool create_owner_only_directory(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error) return false;
#if !defined(_WIN32)
  if (chmod(path.c_str(), 0700) != 0) return false;
#endif
  return is_owner_only_directory(path);
}

bool clear_directory_contents(const std::filesystem::path& directory) noexcept {
  try {
    std::error_code error;
    bool cleared = true;
    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
      std::error_code remove_error;
      std::filesystem::remove_all(entry.path(), remove_error);  // a symlink entry is removed, not followed
      cleared = cleared && !remove_error;
    }
    return cleared && !error;
  } catch (...) {
    return false;
  }
}

}  // namespace secure_frontend

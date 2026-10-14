#pragma once

#include <array>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace secure_frontend {

// Spec §3.9: the engine's environment is a closed type rendered by the
// frontend. Every value is generated or comes from validated configuration
// (SP1); nothing is copied from the parent environment by name.
// The optional members carry `{}` so designated initializers that name only
// the required three (as the tests and the server do) compile under -Werror.
struct EngineEnvironment final {
  std::vector<std::filesystem::path> lib_dirs;              // POSIX LD_LIBRARY_PATH; Windows head of PATH
  std::filesystem::path temp_dir;                           // TMPDIR | TEMP + TMP
  std::filesystem::path cuda_cache_dir;                     // CUDA_CACHE_PATH (replaces ~/.nv/ComputeCache; HOME is unset)
  std::optional<std::filesystem::path> hipblaslt_tuning{};  // STRATA_HIPBLASLT_TUNING (under the install root)
  std::optional<unsigned> watchdog_s{};                     // STRATA_WATCHDOG_S
  std::optional<unsigned> watchdog_io_s{};                  // STRATA_WATCHDOG_IO_S
};

// Windows values from GetSystemWindowsDirectoryW / GetSystemInfo, never from the environment.
struct WindowsSystemValues final {
  std::string system_root;   // e.g. C:\Windows
  std::string system_drive;  // e.g. C:
  unsigned processors{1};
};

using EnvironmentBlock = std::map<std::string, std::string, std::less<>>;

// Names the engine never receives (spec §3.9); tests assert their absence. The
// token variable named by --token-env and every other STRATA_* are excluded too.
inline constexpr std::array<std::string_view, 16> kNeverForwardedEnvironment{
    "STRATA_API_KEY", "LD_PRELOAD",  "LD_AUDIT",    "CUDA_LAUNCH_BLOCKING", "HOME",       "USERPROFILE",
    "APPDATA",        "HTTP_PROXY",  "HTTPS_PROXY", "ALL_PROXY",            "http_proxy", "https_proxy",
    "all_proxy",      "CUDA_VISIBLE_DEVICES", "CUDA_DEVICE_ORDER", "HIP_VISIBLE_DEVICES"};

[[nodiscard]] EnvironmentBlock render_posix_environment(const EngineEnvironment& environment);
[[nodiscard]] EnvironmentBlock render_windows_environment(const EngineEnvironment& environment, const WindowsSystemValues& system);
[[nodiscard]] WindowsSystemValues query_windows_system_values();
// The native rendering (POSIX or Windows).
[[nodiscard]] EnvironmentBlock render_engine_environment(const EngineEnvironment& environment);
// The engine environment for a validated config: temp root <state>/engine-tmp,
// CUDA cache <cache root>/cuda when roots.cache is set, else <state>/cache/cuda.
[[nodiscard]] EngineEnvironment engine_environment_for(const std::filesystem::path& state_dir,
                                                       const std::optional<std::filesystem::path>& cache_root,
                                                       std::vector<std::filesystem::path> lib_dirs);

// POSIX: creates `path` (and parents) and makes it 0700; true only if it is
// then an owner-only directory. Windows: creates it (DACL checks are SP1's).
[[nodiscard]] bool create_owner_only_directory(const std::filesystem::path& path);
// POSIX: a real directory (not a symlink), owned by the effective uid, no group/other bits.
// Windows: a directory that is not a symlink.
[[nodiscard]] bool is_owner_only_directory(const std::filesystem::path& path);
// The --state-dir (roots.state) check, run by serve before anything is spawned.
// POSIX: is_owner_only_directory (lstat checks only the final component).
// Windows: opened with FILE_FLAG_OPEN_REPARSE_POINT, so a junction or symlink
// root is refused, and SP1's has_private_owner_dacl must hold: owner is the
// current user, protected DACL, allow-ACEs only for the user, SYSTEM and
// Administrators (a read ACE for anyone else is refused too).
[[nodiscard]] bool is_private_state_root(const std::filesystem::path& path);
// Removes every entry below `directory` (a symlink entry itself, never its
// target), keeping `directory`. Used at startup on <state>/engine-tmp: temp
// directories of generations that ended with a previous frontend never leak.
bool clear_directory_contents(const std::filesystem::path& directory) noexcept;

}  // namespace secure_frontend

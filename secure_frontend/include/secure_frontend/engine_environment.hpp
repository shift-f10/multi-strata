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

// SP6 §4.9 (mechanism, R5): which engine family the environment is rendered
// for. A family's hook may force and suppress rows (family_environment_rows).
// `strata` has no rows, so it renders exactly the §3.9 allowlist. `glm` is
// reserved for SP6: it currently renders strata rows, is not reachable from
// config, and SP6 fills its table.
enum class EngineFamily { strata, glm };

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
  EngineFamily family{EngineFamily::strata};                // SP6 §4.9: selects the forced-values table
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
// RF9: this is the "never inherited from the parent" list. A family's forced
// values are rendered by the frontend; of this list they may set only the two
// CUDA selectors (kFamilyGpuSelectors). The N1 assertion applies to EngineFamily::strata.
inline constexpr std::array<std::string_view, 16> kNeverForwardedEnvironment{
    "STRATA_API_KEY", "LD_PRELOAD",  "LD_AUDIT",    "CUDA_LAUNCH_BLOCKING", "HOME",       "USERPROFILE",
    "APPDATA",        "HTTP_PROXY",  "HTTPS_PROXY", "ALL_PROXY",            "http_proxy", "https_proxy",
    "all_proxy",      "CUDA_VISIBLE_DEVICES", "CUDA_DEVICE_ORDER", "HIP_VISIBLE_DEVICES"};

// One variable a family forces (owning: a hook may derive the value from the
// EngineEnvironment, e.g. SP6's CUDA_VISIBLE_DEVICES from the gpu list).
struct ForcedEnvironmentValue final {
  std::string name;
  std::string value;
};

// What a family's hook returns for one rendering: rows to force (replace or
// add) and generic optional rows to suppress.
struct FamilyEnvironmentRows final {
  std::vector<ForcedEnvironmentValue> forced{};
  std::vector<std::string> suppressed{};
};

// The family hook: derives the family's rows from the environment. The
// production hook is family_environment_rows; tests inject their own.
using FamilyEnvironmentHook = FamilyEnvironmentRows (*)(const EngineEnvironment& environment);

// The closed list of names a family may force (controller ruling, SP6 §4.9):
// the glm safety constants, the watchdog override and the two GPU selectors.
inline constexpr std::array<std::string_view, 7> kFamilyForcibleEnvironment{
    "STRATA_GLM_SLOTS",  "STRATA_GLM_LOOP_THINK", "STRATA_GLM_LOOP_ANSWER", "STRATA_GLM_SPLIT",
    "STRATA_WATCHDOG_S", "CUDA_DEVICE_ORDER",     "CUDA_VISIBLE_DEVICES"};
// The never-list names a family may still render (RF9): GPU selection by environment.
inline constexpr std::array<std::string_view, 2> kFamilyGpuSelectors{"CUDA_DEVICE_ORDER", "CUDA_VISIBLE_DEVICES"};
// The generic optional rows a family may suppress (controller ruling); no other.
inline constexpr std::array<std::string_view, 3> kFamilySuppressibleEnvironment{"STRATA_WATCHDOG_IO_S", "STRATA_HIPBLASLT_TUNING",
                                                                                "STRATA_WATCHDOG_S"};

// The production hook: the rows of `environment.family`. strata: none.
// glm currently renders strata rows; not reachable from config; SP6 fills its table.
[[nodiscard]] FamilyEnvironmentRows family_environment_rows(const EngineEnvironment& environment);
// Applies `rows` to `block`: suppressed names are removed, then each forced
// name replaces the rendered value or is added. All-or-nothing: false, with
// `block` unchanged, when a forced name is not on kFamilyForcibleEnvironment or
// is on kNeverForwardedEnvironment without being a GPU selector, a forced value
// contains a NUL, a suppressed name is not on kFamilySuppressibleEnvironment,
// or any name appears twice (forced twice, suppressed twice, or both). The
// result does not depend on the rows' order.
[[nodiscard]] bool merge_forced_environment(EnvironmentBlock& block, const FamilyEnvironmentRows& rows);
// The family step on a generic rendering: nullopt when the hook's rows are
// refused (the caller must not spawn; never an empty or partial environment).
[[nodiscard]] std::optional<EnvironmentBlock> apply_family_environment(EnvironmentBlock generic, const EngineEnvironment& environment,
                                                                       FamilyEnvironmentHook hook = family_environment_rows);
// The native generic rendering followed by the family step: what the engine is spawned with.
[[nodiscard]] std::optional<EnvironmentBlock> render_family_environment(const EngineEnvironment& environment,
                                                                        FamilyEnvironmentHook hook = family_environment_rows);

// The generic §3.9 rows (exactly the strata rendering). They do not apply the
// family; the spawn path uses render_family_environment.
[[nodiscard]] EnvironmentBlock render_posix_environment(const EngineEnvironment& environment);
[[nodiscard]] EnvironmentBlock render_windows_environment(const EngineEnvironment& environment, const WindowsSystemValues& system);
[[nodiscard]] WindowsSystemValues query_windows_system_values();
// The native generic rendering (POSIX or Windows).
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

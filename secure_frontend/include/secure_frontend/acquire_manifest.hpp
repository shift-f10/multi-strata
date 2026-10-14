#pragma once

#include "secure_frontend/acquire_reason.hpp"
#include "secure_frontend/engine_version.hpp"
#include "secure_frontend/test_hooks.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace secure_frontend {

enum class ManifestProfile { qwen, glm53, raw };  // raw: SECURE_FRONTEND_TEST_HOOKS builds only
enum class EngineFamily { strata, glm, none };
enum class FileRole { weights, pack, tokenizer };

struct ManifestLicense final {
  std::string id;
  std::string url;
  bool bundle_allowed{false};
  std::string notice;
};

struct ManifestFile final {
  std::string path;  // '/'-separated, relative to the version directory
  FileRole role{FileRole::weights};
  std::uint64_t size{0};
  std::string sha256;
  std::vector<std::string> sources;  // empty: arrives only by import (§2.7)
  std::optional<ManifestLicense> license;
};

struct ManifestLaunch final {
  std::optional<std::string> native;
  std::optional<std::string> ple_gguf;
  std::optional<std::string> pack;
  std::optional<std::string> tokenizer_pack;
};

// Schema version 1 (spec §2.2). Identity is the SHA-256 of the exact bytes (Task 14).
struct AcquireManifest final {
  std::string name;
  std::string tag;
  std::string version;
  std::uint32_t sequence{0};
  ManifestProfile profile{ManifestProfile::qwen};
  EngineFamily family{EngineFamily::strata};
  EngineVersion min_version;
  ManifestLicense license;
  std::vector<std::string> hosts;
  std::vector<std::string> redirect_hosts;
  std::vector<ManifestFile> files;
  ManifestLaunch launch;
};

inline constexpr std::uint64_t kDefaultMaxTotalBytes = std::uint64_t{1} << 40U;  // pull.max_total_bytes default
inline constexpr std::size_t kManifestMaxFiles = 4096;
inline constexpr std::size_t kManifestMaxSources = 8;
inline constexpr std::size_t kManifestMaxHosts = 16;
inline constexpr std::size_t kManifestMaxStringBytes = 1024;
inline constexpr std::size_t kManifestMaxNoticeBytes = 512;
inline constexpr std::uint64_t kManifestMaxFileBytes = std::uint64_t{1} << 40U;
inline constexpr std::string_view kPartSuffix = ".part";
inline constexpr std::array<std::string_view, 5> kReservedTopLevelNames{"manifest.json", "manifest", "strata-bundle",
                                                                        "sha256sums", "missing"};

struct ManifestRules final {
  bool allow_raw_profile{kTestHooksEnabled};
  std::uint64_t max_total_bytes{kDefaultMaxTotalBytes};
};

// key_path names the offending key ("files[3].sources[0]"); message is fixed text.
struct ManifestIssue final {
  AcquireReason reason;
  std::string key_path;
  std::string_view message;
};

// Every struct-level rule of spec §2.1-§2.4. Returns the first issue.
[[nodiscard]] std::optional<ManifestIssue> validate_manifest(const AcquireManifest& manifest, const ManifestRules& rules);

[[nodiscard]] std::string ascii_lower(std::string_view text);
// [a-z0-9][a-z0-9._-]{0,127}, not a Windows device name (with any extension),
// no trailing '.', not "index.json". Callers lowercase first.
[[nodiscard]] bool is_valid_model_name(std::string_view name) noexcept;

struct ModelReference final {
  std::string name;
  std::optional<std::string> tag;
};
// "name" or "name:tag", ASCII-lowercased, both parts valid model names.
[[nodiscard]] std::optional<ModelReference> parse_model_reference(std::string_view text);
[[nodiscard]] std::string model_ref_text(std::string_view name, std::string_view tag);

[[nodiscard]] std::uint64_t total_bytes(const AcquireManifest& manifest) noexcept;
[[nodiscard]] const ManifestLicense& effective_license(const AcquireManifest& manifest, std::size_t file_index) noexcept;
[[nodiscard]] bool bundle_allowed(const AcquireManifest& manifest) noexcept;
[[nodiscard]] bool has_sourceless_files(const AcquireManifest& manifest) noexcept;
[[nodiscard]] std::string_view profile_name(ManifestProfile profile) noexcept;
[[nodiscard]] std::string_view family_name(EngineFamily family) noexcept;
[[nodiscard]] std::string_view role_name(FileRole role) noexcept;

}  // namespace secure_frontend

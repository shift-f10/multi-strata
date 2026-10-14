#pragma once

#include "secure_frontend/frontend_config.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <variant>

namespace secure_frontend {

inline constexpr std::size_t kMaxConfigFileBytes = 64U * 1024U;

// Converts config file text into a draft without touching the filesystem.
// Every JSON or shape problem becomes a ConfigIssue; values are never echoed.
[[nodiscard]] std::variant<FrontendConfigDraft, ConfigErrors> parse_config_text(
    std::string_view text, const std::filesystem::path& config_directory);

// Reads a config file (bounded at kMaxConfigFileBytes) and parses it; the
// file's directory becomes the draft's config_directory. Task 12 replaces the
// read with a trusted, handle-based open.
[[nodiscard]] std::variant<FrontendConfigDraft, ConfigErrors> read_config_file(const std::filesystem::path& file);

// Overlays command-line entries on a file draft: flags win, and every key set
// in both is listed in overridden_by_command_line.
[[nodiscard]] FrontendConfigDraft merge_drafts(FrontendConfigDraft file, const FrontendConfigDraft& flags);

// Strict JSON, two-space indent, keys nested by section; values exactly as in
// the draft. The inverse of parse_config_text for the draft's entries.
[[nodiscard]] std::string render_config_document(const FrontendConfigDraft& draft);

}  // namespace secure_frontend

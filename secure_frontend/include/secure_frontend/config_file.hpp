#pragma once

#include "secure_frontend/frontend_config.hpp"

#include <cstddef>
#include <filesystem>
#include <string_view>
#include <variant>

namespace secure_frontend {

inline constexpr std::size_t kMaxConfigFileBytes = 64U * 1024U;

// Converts config file text into a draft without touching the filesystem.
// Every JSON or shape problem becomes a ConfigIssue; values are never echoed.
[[nodiscard]] std::variant<FrontendConfigDraft, ConfigErrors> parse_config_text(
    std::string_view text, const std::filesystem::path& config_directory);

}  // namespace secure_frontend

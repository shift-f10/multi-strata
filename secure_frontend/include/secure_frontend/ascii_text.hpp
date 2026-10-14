#pragma once

#include <string>
#include <string_view>

namespace secure_frontend {

// The one ASCII lower-casing helper (A-Z only; every other byte unchanged).
// Header-only so the HTTP layer (http_request_head.hpp) and the SP4 manifest
// code (acquire_manifest.hpp) share it without a library dependency.
[[nodiscard]] inline std::string ascii_lower(const std::string_view text) {
  std::string out{text};
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

}  // namespace secure_frontend

#pragma once
// The built-in chat page (listener.web_ui; owner request 2026-10-21, session log step 12).
// Three bundled files from secure_frontend/web/, embedded at configure time (CMake), so the
// server reads nothing from disk to serve them. They hold no secret and reach no route: the
// API key is typed into the page and kept in that tab, and every API route still needs it
// (listener.loopback_without_key aside). Served only at these exact GET targets.

#include <span>
#include <string_view>

namespace secure_frontend {

struct WebAsset final {
  std::string_view target;        // the exact request target, e.g. "/"
  std::string_view content_type;
  std::string_view body;
};

// The page's own policy: scripts, styles and fetches from this origin only; no frames, no
// form targets, no base URI. Every other response keeps default-src 'none'.
inline constexpr std::string_view kWebUiContentSecurityPolicy =
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src data:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// "/", "/ui/app.js", "/ui/app.css", bodies as bundled (generated from web/ by CMake).
[[nodiscard]] std::span<const WebAsset> web_ui_assets() noexcept;
// The asset served at exactly `target` (no query, no folding), or nullptr.
[[nodiscard]] const WebAsset* find_web_asset(std::string_view target) noexcept;

}  // namespace secure_frontend

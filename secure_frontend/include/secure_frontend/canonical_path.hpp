#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace secure_frontend {

enum class PathErrorCode {
  empty, too_long, component_too_long, absolute, traversal, invalid_character, control_character, reserved_name,
  trailing_dot_or_space, short_name_alias, invalid_utf8, drive_or_stream,
  not_absolute, unsupported_root_form, network_location, root_unavailable, untrusted_owner, shared_writable,
  not_found, not_directory, not_regular_file, not_owned_by_user, permissions_too_broad, symlink_not_allowed,
  escapes_root, cross_device, hard_link_not_allowed, open_failed, read_failed, too_large, create_failed,
};

// `message` is fixed text that never contains the path or any part of it.
struct PathError final {
  PathErrorCode code;
  std::string message;
};

// The one portable relative-path grammar (SP1 P1). Input may use '/' or '\';
// components are 1-255 bytes of valid UTF-8, the whole path at most 1024
// bytes. Rejected: empty components, "." and "..", a leading separator,
// ':' anywhere (drives, alternate data streams), < > " | ? *, bytes below
// 0x20 and 0x7F (NUL included), a trailing dot or space, Windows reserved
// device names with any extension (CON PRN AUX NUL COM0-9 LPT0-9 incl. the
// superscript digits, CONIN$ CONOUT$ CLOCK$), and 8.3 aliases ('~' + digit).
class RelativePath final {
 public:
  [[nodiscard]] const std::string& generic() const noexcept { return generic_; }
  [[nodiscard]] const std::vector<std::string>& components() const noexcept { return components_; }

 private:
  friend std::variant<RelativePath, PathError> parse_relative_path(std::string_view text);
  RelativePath(std::string generic, std::vector<std::string> components)
      : generic_(std::move(generic)), components_(std::move(components)) {}
  std::string generic_;
  std::vector<std::string> components_;
};

[[nodiscard]] std::variant<RelativePath, PathError> parse_relative_path(std::string_view text);

// The single reserved-device-name list (also used for model IDs).
[[nodiscard]] bool is_windows_reserved_component(std::string_view component) noexcept;

// UTF-8 <-> std::filesystem::path without the Windows ANSI code page.
[[nodiscard]] std::filesystem::path path_from_utf8(std::string_view text);
[[nodiscard]] std::string path_to_utf8(const std::filesystem::path& path);

}  // namespace secure_frontend

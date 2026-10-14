#include "secure_frontend/canonical_path.hpp"

#include <optional>
#include <string>
#include <utility>

namespace secure_frontend {
namespace {

PathError fail(const PathErrorCode code, std::string message) { return PathError{code, std::move(message)}; }

char ascii_upper(const char c) { return c >= 'a' && c <= 'z' ? static_cast<char>(c - ('a' - 'A')) : c; }

bool valid_utf8(const std::string_view text) {
  for (std::size_t i = 0; i < text.size();) {
    const auto b = static_cast<unsigned char>(text[i]);
    std::size_t length = 0;
    std::uint32_t point = 0;
    if (b < 0x80U) { ++i; continue; }
    if (b >= 0xc2U && b <= 0xdfU) { length = 2; point = b & 0x1fU; }
    else if (b >= 0xe0U && b <= 0xefU) { length = 3; point = b & 0x0fU; }
    else if (b >= 0xf0U && b <= 0xf4U) { length = 4; point = b & 0x07U; }
    else return false;
    if (text.size() - i < length) return false;
    for (std::size_t k = 1; k < length; ++k) {
      const auto c = static_cast<unsigned char>(text[i + k]);
      if ((c & 0xc0U) != 0x80U) return false;
      point = (point << 6U) | (c & 0x3fU);
    }
    if ((length == 3 && point < 0x800U) || (length == 4 && (point < 0x10000U || point > 0x10ffffU)) ||
        (point >= 0xd800U && point <= 0xdfffU)) return false;
    i += length;
  }
  return true;
}

std::optional<PathError> check_component(const std::string_view c) {
  if (c.empty()) return fail(PathErrorCode::empty, "path components must not be empty");
  if (c.size() > 255U) return fail(PathErrorCode::component_too_long, "a path component is longer than 255 bytes");
  if (c == "." || c == "..") return fail(PathErrorCode::traversal, "path components must not be . or ..");
  for (const char ch : c) {
    const auto b = static_cast<unsigned char>(ch);
    if (b < 0x20U || b == 0x7fU) return fail(PathErrorCode::control_character, "paths must not contain control bytes");
    if (ch == ':') return fail(PathErrorCode::drive_or_stream, "paths must not contain ':' (drives, streams)");
    if (ch == '<' || ch == '>' || ch == '"' || ch == '|' || ch == '?' || ch == '*') {
      return fail(PathErrorCode::invalid_character, "paths must not contain < > \" | ? *");
    }
  }
  if (c.back() == '.' || c.back() == ' ') {
    return fail(PathErrorCode::trailing_dot_or_space, "path components must not end with a dot or space");
  }
  if (is_windows_reserved_component(c)) return fail(PathErrorCode::reserved_name, "Windows reserved device names are not allowed");
  for (std::size_t i = 0; i + 1 < c.size(); ++i) {
    if (c[i] == '~' && c[i + 1] >= '0' && c[i + 1] <= '9') {
      return fail(PathErrorCode::short_name_alias, "8.3 short-name aliases (~1) are not allowed");
    }
  }
  return std::nullopt;
}

}  // namespace

bool is_windows_reserved_component(const std::string_view component) noexcept {
  std::string_view base = component.substr(0, component.find('.'));
  while (!base.empty() && base.back() == ' ') base.remove_suffix(1);
  std::string upper;
  for (const char c : base) upper.push_back(ascii_upper(c));
  if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL" || upper == "CONIN$" ||
      upper == "CONOUT$" || upper == "CLOCK$") return true;
  if (upper.size() >= 4U && (upper.rfind("COM", 0) == 0 || upper.rfind("LPT", 0) == 0)) {
    const std::string_view suffix = std::string_view{upper}.substr(3);
    if (suffix.size() == 1U && suffix[0] >= '0' && suffix[0] <= '9') return true;
    if (suffix == "\xC2\xB9" || suffix == "\xC2\xB2" || suffix == "\xC2\xB3") return true;  // superscript 1 2 3
  }
  return false;
}

std::variant<RelativePath, PathError> parse_relative_path(const std::string_view text) {
  if (text.empty()) return fail(PathErrorCode::empty, "the path is empty");
  if (text.size() > 1024U) return fail(PathErrorCode::too_long, "the path is longer than 1024 bytes");
  if (text.front() == '/' || text.front() == '\\') return fail(PathErrorCode::absolute, "the path must be relative");
  if (!valid_utf8(text)) return fail(PathErrorCode::invalid_utf8, "the path is not valid UTF-8");
  std::vector<std::string> components;
  std::size_t start = 0;
  while (true) {
    const auto end = text.find_first_of("/\\", start);
    const auto component = text.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
    if (auto error = check_component(component)) return *error;
    components.emplace_back(component);
    if (end == std::string_view::npos) break;
    start = end + 1U;
  }
  std::string generic;
  for (const auto& component : components) generic += (generic.empty() ? "" : "/") + component;
  return RelativePath{std::move(generic), std::move(components)};
}

std::filesystem::path path_from_utf8(const std::string_view text) {
  const std::u8string utf8(text.begin(), text.end());
  return std::filesystem::path{utf8};
}

std::string path_to_utf8(const std::filesystem::path& path) {
  const std::u8string utf8 = path.u8string();
  return std::string(utf8.begin(), utf8.end());
}

}  // namespace secure_frontend

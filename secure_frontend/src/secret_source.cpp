#include "secure_frontend/secret_source.hpp"

#include <cctype>
#include <utility>

namespace secure_frontend {
namespace {

bool is_ascii_letter(const char value) {
  return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
}

bool is_ascii_digit(const char value) {
  return value >= '0' && value <= '9';
}

bool is_ascii_space(const char value) {
  return value == ' ' || value == '\t' || value == '\n' || value == '\r' || value == '\f' || value == '\v';
}

bool contains_ascii_control(std::string_view value) {
  for (const unsigned char character : value) {
    if (character <= 0x1FU || character == 0x7FU) {
      return true;
    }
  }
  return false;
}

bool is_blank(std::string_view value) {
  if (value.empty()) {
    return true;
  }

  for (const char character : value) {
    if (!is_ascii_space(character)) {
      return false;
    }
  }
  return true;
}

bool is_valid_environment_variable_name(std::string_view name) {
  if (name.empty() || !(is_ascii_letter(name.front()) || name.front() == '_')) {
    return false;
  }

  for (const char character : name) {
    if (!(is_ascii_letter(character) || is_ascii_digit(character) || character == '_')) {
      return false;
    }
  }
  return true;
}

bool is_windows_reserved_device_name(std::string_view component) {
  while (!component.empty() && (component.back() == ' ' || component.back() == '.')) {
    component.remove_suffix(1U);
  }
  const std::size_t extension = component.find('.');
  if (extension != std::string_view::npos) {
    component = component.substr(0U, extension);
  }
  std::string upper;
  upper.reserve(component.size());
  for (const unsigned char character : component) {
    upper.push_back(static_cast<char>(std::toupper(character)));
  }
  if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL") {
    return true;
  }
  if (upper.size() == 4U && (upper.starts_with("COM") || upper.starts_with("LPT"))) {
    return upper.back() >= '1' && upper.back() <= '9';
  }
  return false;
}

bool is_safe_relative_protected_file_path(const std::string_view path) {
  if (is_blank(path) || contains_ascii_control(path) || path.front() == '/' || path.front() == '\\' ||
      path.find(':') != std::string_view::npos) {
    return false;
  }

  std::size_t component_start = 0U;
  while (component_start < path.size()) {
    const std::size_t component_end = path.find_first_of("/\\", component_start);
    const std::string_view component = path.substr(component_start, component_end - component_start);
    if (component.empty() || component == "." || component == ".." ||
        is_windows_reserved_device_name(component)) {
      return false;
    }
    if (component_end == std::string_view::npos) {
      return true;
    }
    component_start = component_end + 1U;
  }
  return false;
}

}  // namespace

SecretSource::SecretSource(const SecretSourceKind kind, std::string location)
    : kind_(kind), location_(std::move(location)) {}

SecretSourceKind SecretSource::kind() const noexcept {
  return kind_;
}

const std::string& SecretSource::location() const noexcept {
  return location_;
}

SecretSourceValidation make_environment_secret_source(const std::string_view environment_variable_name) {
  if (!is_valid_environment_variable_name(environment_variable_name)) {
    return SecretSourceError{.code = SecretSourceErrorCode::invalid_environment_variable_name,
                             .message = "Environment variable names must use [A-Za-z_][A-Za-z0-9_]*."};
  }

  return SecretSource{SecretSourceKind::environment_variable, std::string{environment_variable_name}};
}

SecretSourceValidation make_protected_file_secret_source(const std::string_view protected_file_path) {
  if (!is_safe_relative_protected_file_path(protected_file_path)) {
    return SecretSourceError{.code = SecretSourceErrorCode::invalid_protected_file_path,
                             .message = "Protected-file paths must be safe relative paths below the configured secret root."};
  }

  return SecretSource{SecretSourceKind::protected_file, std::string{protected_file_path}};
}

}  // namespace secure_frontend

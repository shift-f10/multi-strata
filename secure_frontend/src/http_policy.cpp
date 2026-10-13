#include "secure_frontend/http_policy.hpp"

#include <algorithm>
#include <cstdint>

namespace secure_frontend {
namespace {

bool has_control_or_non_ascii(std::string_view value) {
  return std::any_of(value.begin(), value.end(), [](char character) {
    const auto byte = static_cast<unsigned char>(character);
    return byte <= 0x1fU || byte == 0x7fU || byte > 0x7fU;
  });
}

bool is_decimal_port(std::string_view value) {
  if (value.empty() || value.size() > 5U) return false;
  std::uint32_t port = 0;
  for (const char character : value) {
    if (character < '0' || character > '9') return false;
    port = (port * 10U) + static_cast<std::uint32_t>(character - '0');
  }
  return port > 0U && port <= 65535U;
}

bool is_valid_ipv4(std::string_view value) {
  std::uint32_t parts = 0;
  std::size_t start = 0;
  while (start < value.size()) {
    const std::size_t end = value.find('.', start);
    const std::string_view part = value.substr(start, end - start);
    if (part.empty() || part.size() > 3U || (part.size() > 1U && part.front() == '0')) return false;
    std::uint32_t number = 0;
    for (const char character : part) {
      if (character < '0' || character > '9') return false;
      number = (number * 10U) + static_cast<std::uint32_t>(character - '0');
    }
    if (number > 255U || ++parts > 4U) return false;
    if (end == std::string_view::npos) break;
    start = end + 1U;
  }
  return parts == 4U;
}

bool is_valid_hostname(std::string_view value) {
  if (value.empty() || value.size() > 253U || value.back() == '.') return false;
  const bool only_digits_and_dots = std::all_of(value.begin(), value.end(), [](char character) {
    return (character >= '0' && character <= '9') || character == '.';
  });
  if (only_digits_and_dots) return is_valid_ipv4(value);
  std::size_t start = 0;
  while (start < value.size()) {
    const std::size_t end = value.find('.', start);
    const std::string_view label = value.substr(start, end - start);
    if (label.empty() || label.size() > 63U || label.front() == '-' || label.back() == '-') return false;
    for (const char character : label) {
      const bool alphanumeric = (character >= 'A' && character <= 'Z') ||
                                (character >= 'a' && character <= 'z') ||
                                (character >= '0' && character <= '9');
      if (!alphanumeric && character != '-') return false;
    }
    if (end == std::string_view::npos) break;
    start = end + 1U;
  }
  return true;
}

bool is_hexadecimal(std::string_view value) {
  return !value.empty() && value.size() <= 4U && std::all_of(value.begin(), value.end(), [](char character) {
    return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
           (character >= 'A' && character <= 'F');
  });
}

bool is_valid_ipv6(std::string_view value) {
  if (value.empty() || value.find(":::") != std::string_view::npos) return false;
  const std::size_t compression = value.find("::");
  if (compression != std::string_view::npos && value.find("::", compression + 2U) != std::string_view::npos) return false;
  std::uint32_t groups = 0;
  std::size_t start = 0;
  while (start < value.size()) {
    const std::size_t end = value.find(':', start);
    const std::string_view group = value.substr(start, end - start);
    if (!group.empty() && (!is_hexadecimal(group) || ++groups > 8U)) return false;
    if (end == std::string_view::npos) break;
    start = end + 1U;
  }
  return compression == std::string_view::npos ? groups == 8U : groups < 8U;
}

bool is_allowed(const std::vector<std::string>& values, std::string_view candidate) {
  return std::any_of(values.begin(), values.end(), [candidate](const std::string& value) { return value == candidate; });
}

HttpPolicyDecision reject(HttpPolicyError error) {
  return {.allowed = false, .error = error, .access_control_allow_origin = std::nullopt};
}

}  // namespace

bool is_valid_host_header(std::string_view value) {
  if (value.empty() || has_control_or_non_ascii(value)) return false;
  if (value.front() == '[') {
    const std::size_t close = value.find(']');
    if (close == std::string_view::npos || !is_valid_ipv6(value.substr(1U, close - 1U))) return false;
    const std::string_view suffix = value.substr(close + 1U);
    return suffix.empty() || (suffix.front() == ':' && is_decimal_port(suffix.substr(1U)));
  }
  if (value.find(':') != std::string_view::npos) {
    const std::size_t separator = value.rfind(':');
    return value.find(':') == separator && is_valid_hostname(value.substr(0U, separator)) &&
           is_decimal_port(value.substr(separator + 1U));
  }
  return is_valid_hostname(value);
}

bool is_valid_origin_header(std::string_view value) {
  if (value.empty() || has_control_or_non_ascii(value)) return false;
  const std::size_t scheme_end = value.find("://");
  if (scheme_end == std::string_view::npos) return false;
  const std::string_view scheme = value.substr(0U, scheme_end);
  if (scheme != "http" && scheme != "https") return false;
  const std::string_view authority = value.substr(scheme_end + 3U);
  return authority.find_first_of("/?#@") == std::string_view::npos && is_valid_host_header(authority);
}

HttpPolicyDecision validate_http_request_headers(const HttpPolicy& policy,
                                                 const std::vector<std::string_view>& hosts,
                                                 const std::vector<std::string_view>& origins) {
  if (hosts.empty()) return reject(HttpPolicyError::missing_host);
  if (hosts.size() != 1U) return reject(HttpPolicyError::duplicate_host);
  if (!is_valid_host_header(hosts.front())) return reject(HttpPolicyError::invalid_host);
  if (!is_allowed(policy.allowed_hosts, hosts.front())) return reject(HttpPolicyError::untrusted_host);
  if (origins.empty()) return {.allowed = true, .error = std::nullopt, .access_control_allow_origin = std::nullopt};
  if (origins.size() != 1U) return reject(HttpPolicyError::duplicate_origin);
  const std::string_view origin = origins.front();
  if (!is_valid_origin_header(origin)) return reject(HttpPolicyError::invalid_origin);
  if (is_allowed(policy.same_origin_origins, origin)) {
    return {.allowed = true, .error = std::nullopt, .access_control_allow_origin = std::nullopt};
  }
  if (policy.cors_enabled && is_allowed(policy.cors_allowed_origins, origin)) {
    return {.allowed = true, .error = std::nullopt, .access_control_allow_origin = std::string{origin}};
  }
  return reject(HttpPolicyError::untrusted_origin);
}

}  // namespace secure_frontend

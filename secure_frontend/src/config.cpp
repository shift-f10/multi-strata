#include "secure_frontend/config.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace secure_frontend {
namespace {

[[nodiscard]] bool is_blank(const std::string_view value) {
  return std::all_of(value.begin(), value.end(), [](const unsigned char character) {
    return std::isspace(character) != 0;
  });
}

[[nodiscard]] bool is_ipv4(const std::string_view host) {
  in_addr address{};
  const std::string candidate{host};
  return inet_pton(AF_INET, candidate.c_str(), &address) == 1;
}

[[nodiscard]] bool is_ipv6(const std::string_view host) {
  in6_addr address{};
  const std::string candidate{host};
  return inet_pton(AF_INET6, candidate.c_str(), &address) == 1;
}

[[nodiscard]] bool is_dns_label(const std::string_view label) {
  if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') {
    return false;
  }
  return std::all_of(label.begin(), label.end(), [](const unsigned char character) {
    return std::isalnum(character) != 0 || character == '-';
  });
}

[[nodiscard]] bool is_dns_hostname(const std::string_view host) {
  if (host.empty() || host.size() > 253 || host.back() == '.') {
    return false;
  }

  std::size_t label_start = 0;
  while (label_start < host.size()) {
    const auto label_end = host.find('.', label_start);
    const auto length = (label_end == std::string_view::npos ? host.size() : label_end) - label_start;
    if (!is_dns_label(host.substr(label_start, length))) {
      return false;
    }
    if (label_end == std::string_view::npos) {
      return true;
    }
    label_start = label_end + 1;
  }
  return false;
}

[[nodiscard]] bool is_numeric_address_candidate(const std::string_view host) {
  return std::all_of(host.begin(), host.end(), [](const unsigned char character) {
    return std::isdigit(character) != 0 || character == '.';
  });
}

[[nodiscard]] bool is_loopback_host(const std::string_view host) {
  if (host == "::1") {
    return true;
  }
  if (!is_ipv4(host)) {
    return false;
  }
  return host.starts_with("127.");
}

[[nodiscard]] bool is_wildcard_host(const std::string_view host) {
  return host == "0.0.0.0" || host == "::";
}

}  // namespace

bool is_valid_host(const std::string_view host) {
  return is_ipv4(host) || is_ipv6(host) ||
         (!is_numeric_address_candidate(host) && is_dns_hostname(host));
}

ConfigValidation validate_config(const ConfigInput& input) {
  const std::string host = input.host.value_or(std::string{kDefaultHost});
  const std::uint32_t requested_port = input.port.value_or(kDefaultPort);

  if (!is_valid_host(host)) {
    return ConfigError{ConfigErrorCode::invalid_host, "host must be an IP literal or DNS hostname"};
  }
  if (requested_port == 0 || requested_port > 65535) {
    return ConfigError{ConfigErrorCode::invalid_port, "port must be in the TCP range 1-65535"};
  }

  const bool loopback = is_loopback_host(host);
  if (!loopback && !input.allow_remote) {
    return ConfigError{ConfigErrorCode::remote_not_enabled,
                       "a non-loopback bind requires explicit remote-listening opt-in"};
  }
  if (is_wildcard_host(host) && !input.allow_wildcard_bind) {
    return ConfigError{ConfigErrorCode::wildcard_bind_not_enabled,
                       "a wildcard bind requires explicit wildcard-listening opt-in"};
  }
  const bool has_api_key = input.api_key.has_value() && !is_blank(*input.api_key);
  if (!has_api_key) {
    return ConfigError{ConfigErrorCode::api_key_required,
                       "a nonempty API key is required for every listener"};
  }

  // The authentication layer, not the long-lived validated configuration,
  // owns the secret. This boundary retains only evidence that validation saw a
  // non-blank key and deliberately discards its plaintext copy.
  return Config{host, static_cast<std::uint16_t>(requested_port), has_api_key, loopback,
                input.allow_remote, input.allow_wildcard_bind};
}

}  // namespace secure_frontend

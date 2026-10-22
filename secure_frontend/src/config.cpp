#include "secure_frontend/config.hpp"

#include <algorithm>
#include <cstring>
#include <string_view>

#ifdef _WIN32
#include "secure_frontend/win32_prelude.hpp"
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace secure_frontend {
namespace {

[[nodiscard]] bool is_blank(const std::string_view value) {
  return std::all_of(value.begin(), value.end(), [](const unsigned char character) {
    return character == ' ' || character == '\t' || character == '\n' || character == '\r' || character == '\f' ||
           character == '\v';
  });
}

[[nodiscard]] bool is_localhost(const std::string_view text) {
  constexpr std::string_view kLocalhost{"localhost"};
  if (text.size() != kLocalhost.size()) return false;
  for (std::size_t index = 0; index < text.size(); ++index) {
    const char c = text[index];
    const char lowered = c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
    if (lowered != kLocalhost[index]) return false;
  }
  return true;
}

}  // namespace

std::optional<IpAddress> parse_listener_address(const std::string_view text) {
  if (text.empty() || text.size() > 64U || text.find('\0') != std::string_view::npos) return std::nullopt;
  const std::string candidate = is_localhost(text) ? std::string{"127.0.0.1"} : std::string{text};
  IpAddress address;
  in_addr v4{};
  in6_addr v6{};
  if (inet_pton(AF_INET, candidate.c_str(), &v4) == 1) {
    address.family_ = IpFamily::v4;
    std::memcpy(address.bytes_.data(), &v4, 4U);
  } else if (inet_pton(AF_INET6, candidate.c_str(), &v6) == 1) {
    unsigned char raw[16];
    std::memcpy(raw, &v6, 16U);
    const bool v4_mapped = std::all_of(raw, raw + 10, [](const unsigned char b) { return b == 0U; }) &&
                           raw[10] == 0xffU && raw[11] == 0xffU;
    if (v4_mapped) {
      address.family_ = IpFamily::v4;
      std::memcpy(address.bytes_.data(), raw + 12, 4U);
    } else {
      address.family_ = IpFamily::v6;
      std::memcpy(address.bytes_.data(), raw, 16U);
    }
  } else {
    return std::nullopt;
  }
  const auto& b = address.bytes_;
  if (address.family_ == IpFamily::v4) {
    const bool unspecified = b[0] == 0U && b[1] == 0U && b[2] == 0U && b[3] == 0U;
    address.scope_ = b[0] == 127U ? AddressScope::loopback : unspecified ? AddressScope::wildcard : AddressScope::remote;
  } else {
    const bool leading_zero = std::all_of(b.begin(), b.begin() + 15, [](const unsigned char x) { return x == 0U; });
    address.scope_ = leading_zero && b[15] == 0U   ? AddressScope::wildcard   // IN6_IS_ADDR_UNSPECIFIED
                     : leading_zero && b[15] == 1U ? AddressScope::loopback   // IN6_IS_ADDR_LOOPBACK
                                                   : AddressScope::remote;
  }
  char buffer[INET6_ADDRSTRLEN] = {};
  const int family = address.family_ == IpFamily::v4 ? AF_INET : AF_INET6;
  if (inet_ntop(family, address.bytes_.data(), buffer, sizeof(buffer)) == nullptr) return std::nullopt;
  address.text_ = buffer;
  return address;
}

bool is_valid_host(const std::string_view host) { return parse_listener_address(host).has_value(); }

ConfigValidation validate_config(const ConfigInput& input) {
  const std::string host_text = input.host.value_or(std::string{kDefaultHost});
  const std::uint32_t requested_port = input.port.value_or(kDefaultPort);

  const auto address = parse_listener_address(host_text);
  if (!address.has_value()) {
    return ConfigError{ConfigErrorCode::invalid_host, "host must be an IP literal or localhost"};
  }
  if (requested_port == 0 || requested_port > 65535) {
    return ConfigError{ConfigErrorCode::invalid_port, "port must be in the TCP range 1-65535"};
  }
  const bool loopback = address->scope() == AddressScope::loopback;
  if (!loopback && !input.allow_remote) {
    return ConfigError{ConfigErrorCode::remote_not_enabled,
                       "a non-loopback bind requires explicit remote-listening opt-in"};
  }
  if (address->scope() == AddressScope::wildcard && !input.allow_wildcard_bind) {
    return ConfigError{ConfigErrorCode::wildcard_bind_not_enabled,
                       "a wildcard bind requires explicit wildcard-listening opt-in"};
  }
  const bool has_api_key = input.api_key.has_value() && !input.api_key->empty() && !is_blank(*input.api_key);
  // listener.loopback_without_key (owner decision 2026-10-21): the one keyless listener needs
  // the explicit opt-in AND a loopback address; a remote or wildcard bind always needs the key.
  const bool keyless = !has_api_key && input.allow_loopback_without_key && loopback;
  if (!has_api_key && !keyless) {
    return ConfigError{ConfigErrorCode::api_key_required,
                       "a nonempty API key is required for every listener but an opted-in loopback one"};
  }
  // The authentication layer, not the long-lived validated configuration,
  // owns the secret. Only evidence that validation saw a non-blank key is kept.
  return Config{address->canonical_text(), static_cast<std::uint16_t>(requested_port), has_api_key, loopback,
                input.allow_remote, input.allow_wildcard_bind, keyless};
}

}  // namespace secure_frontend

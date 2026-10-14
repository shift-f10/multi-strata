#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace secure_frontend {

inline constexpr std::string_view kDefaultHost{"127.0.0.1"};
inline constexpr std::uint16_t kDefaultPort{8080};

enum class IpFamily { v4, v6 };
enum class AddressScope { loopback, wildcard, remote };

// A listener address parsed once from text into bytes. Scope and canonical
// text are derived from the bytes, never from the spelling (NET-01..03).
// Built only by parse_listener_address.
class IpAddress final {
 public:
  [[nodiscard]] IpFamily family() const noexcept { return family_; }
  [[nodiscard]] const std::array<unsigned char, 16>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] AddressScope scope() const noexcept { return scope_; }
  // inet_ntop text of the bytes: what is bound and logged. IPv4-mapped IPv6
  // input (::ffff:a.b.c.d) is canonicalized to its IPv4 form.
  [[nodiscard]] const std::string& canonical_text() const noexcept { return text_; }

 private:
  friend std::optional<IpAddress> parse_listener_address(std::string_view text);
  IpAddress() = default;
  IpFamily family_{IpFamily::v4};
  std::array<unsigned char, 16> bytes_{};
  AddressScope scope_{AddressScope::remote};
  std::string text_;
};

// Accepts an IPv4 or IPv6 literal, or exactly "localhost" (ASCII
// case-insensitive), which maps to 127.0.0.1 with no resolver call. Every
// other hostname is rejected: the listener never resolves names.
[[nodiscard]] std::optional<IpAddress> parse_listener_address(std::string_view text);

struct ConfigInput final {
  std::optional<std::string> host;
  std::optional<std::uint32_t> port;
  std::optional<std::string> api_key;
  bool allow_remote{false};
  bool allow_wildcard_bind{false};
};

struct Config final {
  std::string host;
  std::uint16_t port;
  bool has_api_key;
  bool is_loopback;
  bool allow_remote;
  bool allow_wildcard_bind;
};

enum class ConfigErrorCode {
  invalid_host,
  invalid_port,
  api_key_required,
  remote_not_enabled,
  wildcard_bind_not_enabled,
};

struct ConfigError final {
  ConfigErrorCode code;
  std::string message;
};

using ConfigValidation = std::variant<Config, ConfigError>;

[[nodiscard]] ConfigValidation validate_config(const ConfigInput& input);
[[nodiscard]] bool is_valid_host(std::string_view host);

}  // namespace secure_frontend

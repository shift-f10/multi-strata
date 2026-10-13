#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace secure_frontend {

inline constexpr std::string_view kDefaultHost{"127.0.0.1"};
inline constexpr std::uint16_t kDefaultPort{8080};

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

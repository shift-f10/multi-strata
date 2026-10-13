#include "secure_frontend/engine_arguments.hpp"

#include <array>
#include <string_view>

namespace secure_frontend {
namespace {
constexpr std::array<std::string_view, 3> kOwnedFlags{"--native", "--pack", "--serve"};
constexpr std::array<std::string_view, 3> kUnsupportedModes{"--batch", "--slots", "--vision"};

std::string_view flag_name(const std::string_view argument) {
  const auto equals = argument.find('=');
  return equals == std::string_view::npos ? argument : argument.substr(0, equals);
}
}  // namespace

EngineArgumentsResult build_engine_arguments(const ModelManifest& selected, const std::filesystem::path& models_root,
                                             const std::vector<std::string>& user_arguments) {
  std::vector<std::string> arguments;
  arguments.reserve(user_arguments.size() + 2);
  for (const auto& argument : user_arguments) {
    if (argument.find('\0') != std::string::npos) {
      return EngineArgumentsError{EngineArgumentsErrorCode::invalid_value, "engine argument contains NUL"};
    }
    const auto name = flag_name(argument);
    for (const auto owned : kOwnedFlags) {
      if (name == owned) {
        return EngineArgumentsError{EngineArgumentsErrorCode::owned_flag, "engine argument is owned by the frontend"};
      }
    }
    for (const auto mode : kUnsupportedModes) {
      if (name == mode) {
        return EngineArgumentsError{EngineArgumentsErrorCode::unsupported_mode,
                                    "engine mode is not supported by the frontend"};
      }
    }
    arguments.push_back(argument);
  }
  const auto path = validate_local_artifact_path(selected.relative_artifact_path);
  if (!std::holds_alternative<std::string>(path)) {
    return EngineArgumentsError{EngineArgumentsErrorCode::invalid_value, "selected model has an invalid artifact path"};
  }
  // Native separators throughout: on Windows `root / "a/b"` would otherwise mix `\` and `/`.
  auto model_path = models_root / std::get<std::string>(path);
  model_path.make_preferred();
  arguments.emplace_back("--native");
  arguments.push_back(model_path.string());
  return arguments;
}

}  // namespace secure_frontend

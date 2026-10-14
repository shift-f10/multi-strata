#include "secure_frontend/engine_arguments.hpp"

#include <array>
#include <string_view>

namespace secure_frontend {
namespace {
// --pack (the expert directory) and the other weight sources (--ple-gguf, --embd-gguf, --native-head-gguf,
// --native-dense-gguf, --mtp) are operator-supplied and pass through; only shard 1 (--native) is frontend-owned.
constexpr std::array<std::string_view, 2> kOwnedFlags{"--native", "--serve"};
constexpr std::array<std::string_view, 3> kUnsupportedModes{"--batch", "--slots", "--vision"};

std::string_view flag_name(const std::string_view argument) {
  const auto equals = argument.find('=');
  return equals == std::string_view::npos ? argument : argument.substr(0, equals);
}
}  // namespace

std::optional<EngineArgumentsError> validate_engine_user_arguments(const EngineArgumentsProfile profile,
                                                                   const std::vector<std::string>& user_arguments) {
  for (const auto& argument : user_arguments) {
    if (argument.find('\0') != std::string::npos) {
      return EngineArgumentsError{EngineArgumentsErrorCode::invalid_value, "engine argument contains NUL"};
    }
    const auto name = flag_name(argument);
    if (profile == EngineArgumentsProfile::lighttransport_glm53) {
      if (name == "--serve") {
        return EngineArgumentsError{EngineArgumentsErrorCode::owned_flag, "engine argument is owned by the frontend"};
      }
      continue;
    }
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
  }
  return std::nullopt;
}

EngineArgumentsResult build_engine_arguments(const EngineArgumentsProfile profile, const ModelManifest& selected,
                                             const CanonicalRoot& models_root,
                                             const std::vector<std::string>& user_arguments) {
  if (auto rejected = validate_engine_user_arguments(profile, user_arguments)) return *rejected;
  std::vector<std::string> arguments = user_arguments;
  if (profile == EngineArgumentsProfile::lighttransport_glm53) return arguments;
  const auto parsed = parse_relative_path(selected.relative_artifact_path);
  const auto* relative = std::get_if<RelativePath>(&parsed);
  if (relative == nullptr) {
    return EngineArgumentsError{EngineArgumentsErrorCode::invalid_value, "selected model has an invalid artifact path"};
  }
  // The engine receives the canonical root the inventory used, never the raw
  // configured string (defect e).
  arguments.emplace_back("--native");
  // UTF-8, never path::string(): on Windows that narrows through the ANSI code
  // page, and the engine launcher decodes every argument as UTF-8.
  arguments.push_back(path_to_utf8(models_root.join(*relative)));
  return arguments;
}

}  // namespace secure_frontend

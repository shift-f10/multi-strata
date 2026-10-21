#include "secure_frontend/engine_arguments.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace secure_frontend {
namespace {
// --pack (the expert directory) and the other weight sources (--ple-gguf, --embd-gguf, --native-head-gguf,
// --native-dense-gguf, --mtp) are operator-supplied and pass through; only shard 1 (--native) is frontend-owned.
// --gpu is frontend-owned too: GPUs are chosen only by the typed engine.gpu list (spec §3.9).
constexpr std::array<std::string_view, 3> kOwnedFlags{"--native", "--serve", "--gpu"};
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
      // GLM CLI is not characterized: pass through unchanged; only the
      // launcher-owned --serve and the frontend-owned --gpu (GPUs are chosen
      // only by the typed list, spec §3.9) are refused.
      if (name == "--serve" || name == "--gpu") {
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

namespace {

// SP5 M1 Task 6 (parity row mtp): the draft layer's own options — strata_control/
// draft_layer.py MTP_FLAGS verbatim: flag -> takes a value. `--spec` (prompt lookup)
// is NOT here: "why --spec stays and only the draft layer's own options go".
constexpr std::array<std::pair<std::string_view, bool>, 3> kMtpFlags{
    std::pair{"--mtp", true}, std::pair{"--spec-min-p", true}, std::pair{"--batch-mtp", false}};

// draft_layer.strip() verbatim: drop each flag, and consume the following token as its
// value only when it is not another flag.
void strip_mtp_flags(std::vector<std::string>& arguments, std::vector<std::string>* removed) {
  std::vector<std::string> kept;
  kept.reserve(arguments.size());
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const auto flag = std::find_if(kMtpFlags.begin(), kMtpFlags.end(),
                                   [&arguments, i](const auto& entry) { return arguments[i] == entry.first; });
    if (flag == kMtpFlags.end()) {
      kept.push_back(arguments[i]);
      continue;
    }
    if (removed != nullptr) removed->emplace_back(flag->first);
    if (flag->second && i + 1 < arguments.size() && arguments[i + 1].rfind("--", 0) != 0) ++i;  // the value goes too
  }
  arguments = std::move(kept);
}

}  // namespace

EngineArgumentsResult build_engine_arguments(const EngineArgumentsProfile profile, const ModelManifest& selected,
                                             const CanonicalRoot& models_root,
                                             const std::vector<std::string>& user_arguments,
                                             const std::vector<unsigned>& gpus, bool mtp_on) {
  if (auto rejected = validate_engine_user_arguments(profile, user_arguments)) return *rejected;
  std::vector<std::string> arguments = user_arguments;
  if (profile == EngineArgumentsProfile::lighttransport_glm53) {
    if (!gpus.empty()) {
      return EngineArgumentsError{EngineArgumentsErrorCode::unsupported_mode,
                                  "GPU selection is not supported by this engine profile"};
    }
    return arguments;
  }
  const auto parsed = parse_relative_path(selected.relative_artifact_path);
  // SP5 M1 Task 6 (parity row mtp, runconfig.py:36 + draft_layer.is_off): an explicit
  // false strips the draft layer's own options at every start, before anything else is
  // composed. The GLM profile returns above: its runner does not speak these flags.
  if (!mtp_on) strip_mtp_flags(arguments, nullptr);
  const auto* relative = std::get_if<RelativePath>(&parsed);
  if (relative == nullptr) {
    return EngineArgumentsError{EngineArgumentsErrorCode::invalid_value, "selected model has an invalid artifact path"};
  }
  // The engine's own --gpu sets CUDA_DEVICE_ORDER/CUDA_VISIBLE_DEVICES (or
  // HIP) inside the engine (upstream generate.cpp:2334-2352 at v0.2.1.3), so
  // the strata family's environment carries no GPU variable.
  if (!gpus.empty()) {
    std::string list;
    for (const unsigned device : gpus) {
      if (!list.empty()) list += ',';
      list += std::to_string(device);
    }
    arguments.emplace_back("--gpu");
    arguments.push_back(std::move(list));
  }
  // The engine receives the canonical root the inventory used, never the raw
  // configured string (defect e).
  arguments.emplace_back("--native");
  // UTF-8, never path::string(): on Windows that narrows through the ANSI code
  // page, and the engine launcher decodes every argument as UTF-8.
  arguments.push_back(path_to_utf8(models_root.join(*relative)));
  return arguments;
}

// SP5 M1 Task 6: the flags an mtp=false composition drops, for the pin's fixed startup
// line (serve/server.py:2925). The frontend only ever passes user arguments through, so
// the removals can only come from them — the same view build_engine_arguments applies.
std::vector<std::string> strip_draft_layer_arguments(std::vector<std::string>& arguments) {
  std::vector<std::string> removed;
  strip_mtp_flags(arguments, &removed);
  return removed;
}

std::vector<std::string> draft_layer_removed(const std::vector<std::string>& arguments) {
  std::vector<std::string> copy = arguments;
  return strip_draft_layer_arguments(copy);
}

EffortEndArguments compose_effort_end_arguments(const std::filesystem::path& engine_binary, const TokenizerPack& tokenizer) {
  // The pin greps the engine binary for the flag literal (:2849) and encodes "system" expecting a
  // single token (:2850); either failure means the pin's one fixed fallback line and no argument.
  constexpr std::string_view kFlag = "--tail-role-token";
  constexpr std::string_view kFallback =
      "effort_position \"end\" needs engine 0.1.39 or newer (--tail-role-token): the reasoning effort stays at the top of the prompt";
  constexpr std::string_view kSuccess =
      "effort_position end: a request's non-default reasoning effort goes right before the answer, so changing it keeps the cached conversation";
  EffortEndArguments result;
  bool known = false;
  std::ifstream in(engine_binary, std::ios::binary);
  if (in) {
    std::string window;
    std::vector<char> block(64U * 1024U);
    while (!known && in) {
      in.read(block.data(), static_cast<std::streamsize>(block.size()));
      const std::streamsize got = in.gcount();
      if (got <= 0) break;
      window.append(block.data(), static_cast<std::size_t>(got));
      if (window.find(kFlag) != std::string::npos) {
        known = true;
        break;
      }
      // Keep the overlap so a flag literal split across block boundaries is still found.
      if (window.size() >= kFlag.size()) window.erase(0, window.size() - (kFlag.size() - 1U));
    }
  }
  const auto encoded = encode_text(tokenizer, "system");
  const auto* ids = std::get_if<std::vector<std::size_t>>(&encoded);
  if (!known || ids == nullptr || ids->size() != 1U) {
    result.notice = kFallback;
    return result;
  }
  result.arguments = {std::string(kFlag), std::to_string((*ids)[0])};
  result.notice = kSuccess;
  return result;
}

std::optional<std::vector<unsigned>> parse_gpu_list(const std::string_view value) {
  if (value.empty() || value.size() > 64U) return std::nullopt;
  std::vector<unsigned> devices;
  std::size_t begin = 0;
  for (;;) {
    const auto comma = value.find(',', begin);
    const auto item = value.substr(begin, comma == std::string_view::npos ? std::string_view::npos : comma - begin);
    if (item.empty() || item.size() > 3U || (item.size() > 1U && item.front() == '0')) return std::nullopt;
    unsigned device = 0;
    const auto [end, error] = std::from_chars(item.data(), item.data() + item.size(), device);
    if (error != std::errc{} || end != item.data() + item.size() || device > 255U) return std::nullopt;
    if (std::find(devices.begin(), devices.end(), device) != devices.end() || devices.size() == 16U) return std::nullopt;
    devices.push_back(device);
    if (comma == std::string_view::npos) return devices;
    begin = comma + 1U;
  }
}

}  // namespace secure_frontend

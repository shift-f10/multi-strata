#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "support/test_support.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

namespace {
int failures = 0;
constexpr auto kStrata = secure_frontend::EngineArgumentsProfile::strata_0143;
constexpr auto kGlm = secure_frontend::EngineArgumentsProfile::lighttransport_glm53;
void expect(bool c, const std::string& m) { if (!c) { ++failures; std::cerr << "FAILED: " << m << '\n'; } }

secure_frontend::ModelManifest manifest() {
  secure_frontend::ModelManifest m; m.id = "qwen-local"; m.relative_artifact_path = "qwen/model-00001-of-00004.gguf"; return m;
}

// A private scratch directory opened as a canonical root (the module's only way to make one).
secure_frontend::CanonicalRoot models_root() {
  auto root = secure_frontend::open_root(secure_frontend_test::make_scratch_directory());
  if (const auto* error = std::get_if<secure_frontend::PathError>(&root)) {
    std::cerr << "scratch root rejected: " << error->message << '\n';
    std::exit(EXIT_FAILURE);
  }
  return std::get<secure_frontend::CanonicalRoot>(root);
}

// UTF-8, never the Windows ANSI code page: the engine decodes every argument as UTF-8.
std::string native_path(const secure_frontend::CanonicalRoot& root) {
  return secure_frontend::path_to_utf8((root.path() / "qwen" / "model-00001-of-00004.gguf").make_preferred());
}

void engine_receives_model_path_from_inventory() {
  const auto root = models_root();
  const auto result = secure_frontend::build_engine_arguments(kStrata, manifest(), root, {"--max-context", "8192"});
  const auto* args = std::get_if<std::vector<std::string>>(&result);
  expect(args != nullptr, "valid pass-through must build");
  if (!args) return;
  const std::vector<std::string> expected{"--max-context", "8192", "--native", native_path(root)};
  expect(*args == expected, "frontend must append --native from the inventory, last");
}

// Review Focus 4: a non-ASCII models root (C:/Users/José/models) must reach the
// engine as UTF-8. path::string() narrows through the ANSI code page on Windows,
// which the engine's UTF-8 decode (MB_ERR_INVALID_CHARS) refuses.
void engine_native_path_is_utf8_for_non_ascii_root() {
  const auto dir = secure_frontend_test::make_scratch_directory() / secure_frontend::path_from_utf8("Jos\xC3\xA9-models");
  secure_frontend_test::make_private_directory(dir);
  auto opened = secure_frontend::open_root(dir);
  if (const auto* error = std::get_if<secure_frontend::PathError>(&opened)) {
    expect(false, "non-ASCII scratch root rejected: " + error->message);
    return;
  }
  const auto root = std::get<secure_frontend::CanonicalRoot>(opened);
  const auto result = secure_frontend::build_engine_arguments(kStrata, manifest(), root, {});
  const auto* args = std::get_if<std::vector<std::string>>(&result);
  expect(args != nullptr && args->size() == 2U, "--native and its value");
  if (args == nullptr || args->size() != 2U) return;
  const auto& value = args->back();
  expect(value.find("Jos\xC3\xA9-models") != std::string::npos, "the root's non-ASCII name is UTF-8 in --native");
  expect(value == native_path(root), "--native is path_to_utf8 of the canonical model path");
}

void engine_args_reject_owned_and_network_flags() {
  const auto root = models_root();
  for (const std::string bad : {"--native", "--native=/x.gguf", "--serve", "--serve=1", "--batch", "--batch=2", "--slots", "--slots=4", "--vision", "--vision=/m.gguf"}) {
    const auto r = secure_frontend::build_engine_arguments(kStrata, manifest(), root, {bad, "value"});
    const auto* e = std::get_if<secure_frontend::EngineArgumentsError>(&r);
    expect(e != nullptr, "must reject " + bad);
    if (e) expect(e->code == secure_frontend::EngineArgumentsErrorCode::owned_flag || e->code == secure_frontend::EngineArgumentsErrorCode::unsupported_mode, "code for " + bad);
  }
  const auto nul = secure_frontend::build_engine_arguments(kStrata, manifest(), root, {std::string("--gpu\0 0", 8)});
  expect(std::holds_alternative<secure_frontend::EngineArgumentsError>(nul), "NUL in an argument must be rejected");
  const auto empty = secure_frontend::build_engine_arguments(kStrata, manifest(), root, {});
  expect(std::holds_alternative<std::vector<std::string>>(empty), "no pass-through arguments is valid: the frontend supplies the model");
}

void strata_profile_passes_pack_and_weight_flags_through() {
  // --pack is the expert directory (loaded unconditionally, default cwd-relative pack/full) and the
  // other weight sources are operator-supplied; only --native comes from the inventory.
  const auto root = models_root();
  const std::vector<std::string> user{"--pack", "/w/pack", "--ple-gguf", "/w/ple.gguf", "--max-context", "8192"};
  const auto result = secure_frontend::build_engine_arguments(kStrata, manifest(), root, user);
  const auto* args = std::get_if<std::vector<std::string>>(&result);
  expect(args != nullptr, "--pack and weight flags must pass through");
  if (!args) return;
  auto expected = user;
  expected.emplace_back("--native");
  expected.push_back(native_path(root));
  expect(*args == expected, "pass-through unchanged, --native appended last");
  for (const std::string flag : {"--pack=/w/pack", "--embd-gguf", "--native-head-gguf", "--native-dense-gguf", "--mtp"}) {
    const auto r = secure_frontend::build_engine_arguments(kStrata, manifest(), root, {flag, "/w/x"});
    expect(std::holds_alternative<std::vector<std::string>>(r), "weight flag must pass through: " + flag);
  }
}

void rejects_invalid_relative_artifact_path() {
  const auto root = models_root();
  for (const std::string bad : {"../x.gguf", "/abs.gguf"}) {
    auto m = manifest();
    m.relative_artifact_path = bad;
    const auto r = secure_frontend::build_engine_arguments(kStrata, m, root, {"--max-context", "8192"});
    const auto* e = std::get_if<secure_frontend::EngineArgumentsError>(&r);
    expect(e != nullptr, "invalid artifact path must be rejected: " + bad);
    if (e) expect(e->code == secure_frontend::EngineArgumentsErrorCode::invalid_value, "invalid_value for " + bad);
    if (const auto* a = std::get_if<std::vector<std::string>>(&r)) {
      for (const auto& x : *a) expect(x != "--native", "no --native for " + bad);
    }
  }
}

void glm_profile_passes_arguments_through_without_native() {
  const auto root = models_root();
  const std::vector<std::string> user{"--model", "/x/glm.gguf", "--tokens", "/x/tok"};
  const auto result = secure_frontend::build_engine_arguments(kGlm, manifest(), root, user);
  const auto* args = std::get_if<std::vector<std::string>>(&result);
  expect(args != nullptr, "GLM pass-through must build");
  if (args) expect(*args == user, "GLM arguments must pass through unchanged with no --native");
  for (const std::string bad : {"--serve", "--serve=1"}) {
    const auto r = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {bad});
    const auto* e = std::get_if<secure_frontend::EngineArgumentsError>(&r);
    expect(e != nullptr && e->code == secure_frontend::EngineArgumentsErrorCode::owned_flag, "GLM must reject " + bad);
  }
  const auto nul = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {std::string("--gpu\0 0", 8)});
  expect(std::holds_alternative<secure_frontend::EngineArgumentsError>(nul), "GLM: NUL in an argument must be rejected");
  const auto batch = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {"--batch", "2"});
  expect(std::holds_alternative<std::vector<std::string>>(batch), "GLM: the Strata deny-list does not apply");
}

// Spec §3.9: GPUs are selected only by the typed list, rendered as the engine's own --gpu before --native.
void engine_args_render_typed_gpu_and_deny_gpu_passthrough() {
  const auto root = models_root();
  const auto result = secure_frontend::build_engine_arguments(kStrata, manifest(), root, {"--max-context", "8192"}, {0U, 2U});
  const auto* args = std::get_if<std::vector<std::string>>(&result);
  expect(args != nullptr, "typed GPUs build");
  if (args) {
    const std::vector<std::string> expected{"--max-context", "8192", "--gpu", "0,2", "--native", native_path(root)};
    expect(*args == expected, "--gpu comes from the typed list, before --native");
  }
  for (const std::string bad : {"--gpu", "--gpu=0"}) {
    const auto r = secure_frontend::build_engine_arguments(kStrata, manifest(), root, {bad, "1"});
    const auto* e = std::get_if<secure_frontend::EngineArgumentsError>(&r);
    expect(e != nullptr && e->code == secure_frontend::EngineArgumentsErrorCode::owned_flag, "--gpu is owned by the frontend: " + bad);
    expect(secure_frontend::validate_engine_user_arguments(kStrata, {bad, "1"}).has_value(),
           "engine.args with --gpu fails validation, before anything is spawned: " + bad);
  }
  const auto glm = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {"--model", "/x"}, {0U});
  const auto* glm_error = std::get_if<secure_frontend::EngineArgumentsError>(&glm);
  expect(glm_error != nullptr && glm_error->code == secure_frontend::EngineArgumentsErrorCode::unsupported_mode,
         "GPU selection is refused for the uncharacterized GLM CLI");
  // The GLM branch passes unknown arguments through, but --gpu is frontend-owned for every profile.
  for (const std::string bad : {"--gpu", "--gpu=0"}) {
    const auto r = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {"--model", "/x", bad, "1"});
    const auto* e = std::get_if<secure_frontend::EngineArgumentsError>(&r);
    expect(e != nullptr && e->code == secure_frontend::EngineArgumentsErrorCode::owned_flag, "GLM: --gpu via --engine-arg is refused: " + bad);
  }
}

// Review Focus 4: a malformed --gpu value never reaches the engine.
void gpu_list_rejects_malformed_values() {
  for (const std::string bad : {"0,0", "-1", "1,,2", " 1", "1 ", "256", "01", "", ",", "1,", "+1", "a",
                                "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"}) {
    expect(!secure_frontend::parse_gpu_list(bad).has_value(), "--gpu must reject '" + bad + "'");
  }
  expect(secure_frontend::parse_gpu_list("0") == std::vector<unsigned>{0U}, "a single device");
  expect(secure_frontend::parse_gpu_list("3,1,255") == std::vector<unsigned>{3U, 1U, 255U}, "order is kept");
  expect(secure_frontend::parse_gpu_list("0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15").has_value(), "16 devices are allowed");
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"engine_receives_model_path_from_inventory", engine_receives_model_path_from_inventory},
      {"engine_native_path_is_utf8_for_non_ascii_root", engine_native_path_is_utf8_for_non_ascii_root},
      {"engine_args_reject_owned_and_network_flags", engine_args_reject_owned_and_network_flags},
      {"strata_profile_passes_pack_and_weight_flags_through", strata_profile_passes_pack_and_weight_flags_through},
      {"rejects_invalid_relative_artifact_path", rejects_invalid_relative_artifact_path},
      {"glm_profile_passes_arguments_through_without_native", glm_profile_passes_arguments_through_without_native},
      {"engine_args_render_typed_gpu_and_deny_gpu_passthrough", engine_args_render_typed_gpu_and_deny_gpu_passthrough},
      {"gpu_list_rejects_malformed_values", gpu_list_rejects_malformed_values},
  }, failures);
}

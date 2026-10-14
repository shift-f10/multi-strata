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

std::string native_path(const secure_frontend::CanonicalRoot& root) {
  return (root.path() / "qwen" / "model-00001-of-00004.gguf").make_preferred().string();
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
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"engine_receives_model_path_from_inventory", engine_receives_model_path_from_inventory},
      {"engine_args_reject_owned_and_network_flags", engine_args_reject_owned_and_network_flags},
      {"strata_profile_passes_pack_and_weight_flags_through", strata_profile_passes_pack_and_weight_flags_through},
      {"rejects_invalid_relative_artifact_path", rejects_invalid_relative_artifact_path},
      {"glm_profile_passes_arguments_through_without_native", glm_profile_passes_arguments_through_without_native},
  }, failures);
}

#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/launch_composition.hpp"
#include "support/cli_harness.hpp"
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

// SP4 Task 24b. The expected argv for the fixture model m:t installed in `h`.
std::vector<std::string> managed_argv(secure_frontend_test::cli::CliHarness& h, const secure_frontend::IndexEntry& entry) {
  const auto base = h.models().path() / "m" / "t" / entry.dir;
  const auto utf8 = [](std::filesystem::path p) { return secure_frontend::path_to_utf8(p.make_preferred()); };
  return {"--native", utf8(base / "weights" / "fx-00001-of-00002.gguf"), "--pack", utf8(base / "pack"),
          "--ple-gguf", utf8(base / "weights" / "fx-00002-of-00002.gguf")};
}

// Spec §4.9 delta c: the managed launch comes from the manifest's launch block.
void launch_composed_from_manifest_qwen() {
  secure_frontend_test::cli::CliHarness h;
  const auto entry = secure_frontend_test::cli::install(h);
  h.make_managed("m:t");
  const auto config = h.validated_config();
  const auto composed = secure_frontend::compose_engine_launch(config.get(), false);
  const auto* launch = std::get_if<secure_frontend::ComposedLaunch>(&composed);
  expect(launch != nullptr && launch->managed, "managed launch");
  if (launch == nullptr) {
    for (const auto& m : std::get<secure_frontend::LaunchFailure>(composed).messages) std::cerr << "  " << m << '\n';
    return;
  }
  const auto base = h.models().path() / "m" / "t" / entry.dir;
  expect(launch->engine_args == managed_argv(h, entry), "--native/--pack/--ple-gguf joined to the canonical version directory (SP1 P7)");
  expect(launch->tokenizer_root && launch->tokenizer_root->path() == base / "pack" / "tokenizer", "frontend tokenizer root from the manifest");
  expect((launch->served_models == std::vector<std::string>{"m:t"}), "/v1/models lists the managed model");
  expect(launch->model_id == "m:t" && launch->profile == secure_frontend::EngineProfile::qwen, "profile from the manifest");
  // A bare name resolves the single installed tag.
  std::string text = secure_frontend_test::read_file(h.config);
  text.replace(text.find("\"m:t\""), 5, "\"M\"");
  secure_frontend_test::write_file(h.config, text);
  const auto bare = secure_frontend::compose_engine_launch(h.validated_config().get(), false);
  const auto* bare_launch = std::get_if<secure_frontend::ComposedLaunch>(&bare);
  expect(bare_launch != nullptr && bare_launch->model_id == "m:t", "a bare (case-folded) name serves its one installed tag as name:tag");
}

// F-7 (SP1 rule, engine_arguments.cpp): every engine argv path is UTF-8, never path::string().
void managed_launch_argv_is_utf8_for_non_ascii_models_root() {
  secure_frontend_test::cli::CliHarness h("Jos\xC3\xA9-models");
  const auto entry = secure_frontend_test::cli::install(h);
  h.make_managed("m:t");
  const auto composed = secure_frontend::compose_engine_launch(h.validated_config().get(), false);
  const auto* launch = std::get_if<secure_frontend::ComposedLaunch>(&composed);
  expect(launch != nullptr, "a non-ASCII roots.models launches");
  if (launch == nullptr) return;
  expect(launch->engine_args.size() == 6U && launch->engine_args[1].find("Jos\xC3\xA9-models") != std::string::npos &&
             launch->engine_args[3].find("Jos\xC3\xA9-models") != std::string::npos,
         "the root's non-ASCII name is UTF-8 in --native and --pack");
  expect(launch->engine_args == managed_argv(h, entry), "every argv path is path_to_utf8 of the canonical path");
}

// Spec §2.3: a model the index names but whose files are not runnable never reaches the engine.
void launch_refuses_model_not_installed() {
  secure_frontend_test::cli::CliHarness h;
  h.make_managed("absent:t");
  const auto composed = secure_frontend::compose_engine_launch(h.validated_config().get(), false);
  const auto* failure = std::get_if<secure_frontend::LaunchFailure>(&composed);
  expect(failure != nullptr && failure->exit == secure_frontend::ExitCode::manifest &&
             failure->messages.front().find("absent:t") != std::string::npos &&
             failure->messages.front().find("strata pull") != std::string::npos,
         "an uninstalled model names itself and how to install it (exit 5)");
}

void engine_args_reject_weight_flags_for_managed_model() {
  secure_frontend_test::cli::CliHarness h;
  (void)secure_frontend_test::cli::install(h);
  h.make_managed("m:t", ", \"args\": [\"--pack=/elsewhere\"]");
  const auto config = h.validated_config();
  const auto composed = secure_frontend::compose_engine_launch(config.get(), false);
  const auto* failure = std::get_if<secure_frontend::LaunchFailure>(&composed);
  expect(failure != nullptr && failure->exit == secure_frontend::ExitCode::usage &&
             failure->messages.front().find("engine.args") != std::string::npos,
         "weight flags are refused for a managed model (--flag=value spelling too)");
  const auto expert = secure_frontend::compose_engine_launch(config.get(), true);
  expect(std::holds_alternative<secure_frontend::LaunchFailure>(expert) &&
             std::get<secure_frontend::LaunchFailure>(expert).messages.front().find("roots.tokenizer_pack") != std::string::npos,
         "--expert is the operator path and needs the operator's roots.tokenizer_pack");
  // --native is already refused by validate() (frontend-owned since SP1); the other six, both spellings.
  for (const std::string flag : {"--pack", "--ple-gguf", "--embd-gguf", "--native-head-gguf", "--native-dense-gguf", "--mtp"}) {
    for (const std::string& args : {"\"" + flag + "\", \"x\"", "\"" + flag + "=x\""}) {
      h.write_config("");
      h.make_managed("m:t", ", \"args\": [\"--max-context\", \"8192\", " + args + "]");
      const auto issues = secure_frontend::managed_config_issues(h.validated_config().get());
      expect(issues.size() == 1U && issues.front().rfind("engine.args", 0) == 0, "weight flag refused: " + args);
    }
  }
  h.write_config("");
  h.make_managed("m:t", ", \"args\": [\"--max-context\", \"8192\", \"--packet\", \"x\"]");
  expect(secure_frontend::managed_config_issues(h.validated_config().get()).empty(), "a flag that only starts like one is not a weight flag");
}

void launch_refuses_engine_too_old() {
  secure_frontend::AcquireManifest future;
  future.profile = secure_frontend::ManifestProfile::qwen;
  future.family = secure_frontend::EngineFamily::strata;
  future.min_version = *secure_frontend::parse_engine_version("99.0.0");
  const auto gate = secure_frontend::engine_gate(future);
  expect(gate && gate->reason == secure_frontend::AcquireReason::engine_too_old &&
             secure_frontend::exit_class(gate->reason) == secure_frontend::ExitCode::engine, "exit 11");
  future.profile = secure_frontend::ManifestProfile::glm53;
  future.family = secure_frontend::EngineFamily::glm;
  const auto glm = secure_frontend::engine_gate(future);
  expect(glm && glm->reason == secure_frontend::AcquireReason::engine_profile_unavailable, "glm53 until SP6");
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
      {"launch_composed_from_manifest_qwen", launch_composed_from_manifest_qwen},
      {"managed_launch_argv_is_utf8_for_non_ascii_models_root", managed_launch_argv_is_utf8_for_non_ascii_models_root},
      {"launch_refuses_model_not_installed", launch_refuses_model_not_installed},
      {"engine_args_reject_weight_flags_for_managed_model", engine_args_reject_weight_flags_for_managed_model},
      {"launch_refuses_engine_too_old", launch_refuses_engine_too_old},
  }, failures);
}

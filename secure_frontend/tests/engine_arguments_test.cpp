#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/launch_composition.hpp"
#include "support/cli_harness.hpp"
#include "support/test_support.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
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

// SP5 M2 Task 7 (D-8): the old "glm_profile_passes_arguments_through_without_native"
// case retired with the pass-through; glm_rejects_every_engine_argument replaces it
// (every former pass-through form is now a named error).

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
  const auto glm = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {}, {0U});
  const auto* glm_error = std::get_if<secure_frontend::EngineArgumentsError>(&glm);
  expect(glm_error != nullptr && glm_error->code == secure_frontend::EngineArgumentsErrorCode::unsupported_mode,
         "GPU selection is refused for the GLM profile (the typed glm.gpu list rides the child environment, Task 4)");
  // SP5 M2 Task 7 (D-8, C-5): engine.args is refused outright under glm53 — including the
  // frontend-owned --gpu forms the retired pass-through used to reject by name.
  for (const std::string bad : {"--gpu", "--gpu=0"}) {
    const auto r = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {bad, "1"});
    const auto* e = std::get_if<secure_frontend::EngineArgumentsError>(&r);
    expect(e != nullptr && e->code == secure_frontend::EngineArgumentsErrorCode::not_accepted,
           "GLM: engine.args is refused outright, --gpu included: " + bad);
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

// SP5 M1 Task 11 (D-9; Rulings T11-aa/T11-bb): compose-time vision wiring — enabled with a
// manifest that declares no mmproj artifact fails closed naming it; a declared mmproj is
// carried on ComposedLaunch and the engine receives --vision (the pin's section gate,
// serve/server.py:2926-2931); lazy_load + an image-reading model is the pin's config
// conflict (runconfig.py:97-98 — pin wins); --expert has no manifest, so vision fails there by name.
void vision_compose_rules() {
  const auto enable_vision = [](secure_frontend_test::cli::CliHarness& h, const std::string& body) {
    std::string text = secure_frontend_test::read_file(h.config);
    text.insert(text.find("\"pull\""), "\"vision\": " + body + ", ");
    secure_frontend_test::write_file(h.config, text);
  };
  {  // enabled, but the manifest has no mmproj artifact: fail closed (exit 5).
    secure_frontend_test::cli::CliHarness h;
    (void)secure_frontend_test::cli::install(h);
    h.make_managed("m:t");
    enable_vision(h, "{\"enabled\": true}");
    const auto composed = secure_frontend::compose_engine_launch(h.validated_config().get(), false);
    const auto* failure = std::get_if<secure_frontend::LaunchFailure>(&composed);
    expect(failure != nullptr && failure->exit == secure_frontend::ExitCode::manifest &&
               failure->messages.front().find("mmproj") != std::string::npos,
           "vision on a manifest without mmproj fails closed (T11-aa)");
  }
  {  // a declared mmproj: carried on the composition; the engine gets --vision.
    secure_frontend_test::cli::CliHarness h;
    const auto entry = secure_frontend_test::cli::install(h, 1, "", secure_frontend::ModelOrigin::third_party, "m", "t", true);
    h.make_managed("m:t");
    enable_vision(h, "{\"enabled\": true}");
    const auto composed = secure_frontend::compose_engine_launch(h.validated_config().get(), false);
    const auto* launch = std::get_if<secure_frontend::ComposedLaunch>(&composed);
    if (launch == nullptr) {
      for (const auto& m : std::get<secure_frontend::LaunchFailure>(composed).messages) std::cerr << "  " << m << '\n';
      return;
    }
    const auto base = h.models().path() / "m" / "t" / entry.dir;
    expect(launch->vision_mmproj == secure_frontend::path_to_utf8((base / "mmproj" / "mmproj.gguf").make_preferred()) &&
               launch->vision_model == secure_frontend::path_to_utf8((base / "weights" / "fx-00001-of-00002.gguf").make_preferred()),
         "ComposedLaunch carries the encoder artifact and the weights, same join as --native");
    expect(std::count(launch->engine_args.begin(), launch->engine_args.end(), "--vision") == 1,
           "the engine receives --vision, like the pin's vision-section gate (:2930)");
  }
  {  // the pin's conflict: "lazy loading is text-only, and this model reads images".
    secure_frontend_test::cli::CliHarness h;
    (void)secure_frontend_test::cli::install(h, 1, "", secure_frontend::ModelOrigin::third_party, "m", "t", true);
    h.make_managed("m:t", ", \"lazy_load\": true");
    enable_vision(h, "{\"enabled\": true}");
    const auto conflict = secure_frontend::compose_engine_launch(h.validated_config().get(), false);
    const auto* failure = std::get_if<secure_frontend::LaunchFailure>(&conflict);
    expect(failure != nullptr && failure->messages.front().find("images") != std::string::npos,
           "lazy_load + an image-reading model is refused at compose (runconfig.py:97-98)");
  }
  {  // --expert is the operator path: no manifest, no mmproj — vision fails by name.
    secure_frontend_test::cli::CliHarness h;
    enable_vision(h, "{\"enabled\": true}");
    const auto expert = secure_frontend::compose_engine_launch(h.validated_config().get(), true);
    const auto* failure = std::get_if<secure_frontend::LaunchFailure>(&expert);
    expect(failure != nullptr && failure->messages.front().find("vision") != std::string::npos,
           "vision needs a managed model; --expert fails by name");
  }
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
  future.family = secure_frontend::ManifestFamily::strata;
  future.min_version = *secure_frontend::parse_engine_version("99.0.0");
  const auto gate = secure_frontend::engine_gate(future);
  expect(gate && gate->reason == secure_frontend::AcquireReason::engine_too_old &&
             secure_frontend::exit_class(gate->reason) == secure_frontend::ExitCode::engine, "exit 11");
  future.profile = secure_frontend::ManifestProfile::glm53;
  future.family = secure_frontend::ManifestFamily::glm;
  const auto glm = secure_frontend::engine_gate(future);
  expect(glm && glm->reason == secure_frontend::AcquireReason::engine_profile_unavailable, "glm53 until SP6");
}

// Merge sp4-acquire into SP2 run 2: the managed launch keeps SP2's typed GPU
// list (spec §3.9); --gpu is still refused in engine.args.
void managed_launch_renders_typed_gpu_list() {
  secure_frontend_test::cli::CliHarness h;
  const auto entry = secure_frontend_test::cli::install(h);
  h.make_managed("m:t", ", \"gpu\": \"0,2\"");
  const auto composed = secure_frontend::compose_engine_launch(h.validated_config().get(), false);
  const auto* launch = std::get_if<secure_frontend::ComposedLaunch>(&composed);
  expect(launch != nullptr, "managed launch with engine.gpu");
  if (launch == nullptr) return;
  auto expected = managed_argv(h, entry);
  expected.insert(expected.end(), {"--gpu", "0,2", "--layer-split", "auto"});  // two GPUs compose the split (:2938)
  expect(launch->engine_args == expected, "the typed engine.gpu list becomes the engine's own --gpu");
}

// SP5 M2 Task 7 (D-8): the GLM launch is composed, not passed through — Maya's launcher
// base (maya.py:2228-2230) plus --parallel last (set_arg :2291; choices 1..8 :3885).
// The manifest's model directory is the pack (--glm-pack is the pack root; Maya puts the
// tokenizer at <pack>/tokenizer, maya.py:2231).
void glm_launch_argv_matches_mayas_launcher_form() {
  const auto root = models_root();
  const std::vector<std::string> base{"--glm-pack", secure_frontend::path_to_utf8((root.path() / "qwen").make_preferred()),
                                      "--max-context", "32768", "--prefill", "auto", "--kv-streaming", "on"};
  const secure_frontend::Glm53LaunchArgs defaults;  // Maya's DEFAULT_CONTEXT and parallel 1
  const auto result = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {}, {}, true, defaults);
  const auto* args = std::get_if<std::vector<std::string>>(&result);
  expect(args != nullptr, "the composed GLM launch builds");
  if (args != nullptr) {
    expect(*args == base, "the argv equals Maya's launcher form (maya.py:2228-2230), --parallel absent at 1");
    expect(std::find(args->begin(), args->end(), "--serve") == args->end(), "no --serve in the argv tail (:4 inserts it)");
    for (const std::string owned : {"--native", "--pack", "--gpu", "--dflash", "--expert-profile", "--batch", "--slots"})
      expect(std::find(args->begin(), args->end(), owned) == args->end(), "no owned or §4 flag appears: " + owned);
  }
  auto parallel = defaults;
  parallel.parallel = 2;
  const auto with_parallel = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {}, {}, true, parallel);
  auto expected = base;
  expected.insert(expected.end(), {"--parallel", "2"});
  expect(std::holds_alternative<std::vector<std::string>>(with_parallel) &&
             std::get<std::vector<std::string>>(with_parallel) == expected,
         "replicas.parallel 2 renders --parallel last (maya.py:2291)");
}

// The bounds Maya's launcher enforces: --context is a positive token count and
// --parallel only ever reaches its config through choices 1-8 (maya.py:3885).
void glm_context_and_parallel_bounds_enforced() {
  const auto root = models_root();
  for (const std::int64_t count : {0, 9, 100}) {
    secure_frontend::Glm53LaunchArgs args;
    args.parallel = count;
    const auto r = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {}, {}, true, args);
    expect(std::holds_alternative<secure_frontend::EngineArgumentsError>(r), "parallel out of Maya's 1-8 is refused: " + std::to_string(count));
  }
  for (const std::int64_t ctx : {0, 1048577}) {
    secure_frontend::Glm53LaunchArgs args;
    args.max_context = ctx;
    const auto r = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {}, {}, true, args);
    expect(std::holds_alternative<secure_frontend::EngineArgumentsError>(r), "max_context out of bounds is refused: " + std::to_string(ctx));
  }
  for (const std::int64_t count : {1, 2, 8}) {
    secure_frontend::Glm53LaunchArgs args;
    args.parallel = count;
    expect(std::holds_alternative<std::vector<std::string>>(
               secure_frontend::build_engine_arguments(kGlm, manifest(), root, {}, {}, true, args)),
           "parallel within 1-8 builds: " + std::to_string(count));
  }
  secure_frontend::Glm53LaunchArgs edge;
  edge.max_context = 1048576;
  expect(std::holds_alternative<std::vector<std::string>>(
             secure_frontend::build_engine_arguments(kGlm, manifest(), root, {}, {}, true, edge)),
         "the schema's top context builds");
}

// D-8 (C-5): the SP1 pass-through is retired — every engine.args entry under the glm53
// profile fails by name, so no free --flag can reach the Maya engine's CLI.
void glm_rejects_every_engine_argument() {
  const auto root = models_root();
  const std::vector<std::string> retired{"--model", "/x/glm.gguf", "--tokens", "/x/tok", "--batch", "2", "--max-context", "32768",
                                         "--serve", "--serve=1", "--gpu", "--gpu=0", std::string("--gpu\0 0", 8)};
  for (const auto& argument : retired) {
    const auto r = secure_frontend::build_engine_arguments(kGlm, manifest(), root, {argument});
    const auto* e = std::get_if<secure_frontend::EngineArgumentsError>(&r);
    expect(e != nullptr, "glm53 refuses every engine argument: " + argument);
  }
  expect(secure_frontend::validate_engine_user_arguments(kGlm, {"--max-context", "32768"}).has_value(),
         "engine.args with glm53 fails validation before startup (config load)");
  expect(!secure_frontend::validate_engine_user_arguments(kGlm, {}).has_value(),
         "no engine.args with glm53 validates (the composition needs none)");
}

// Ruling R-T3-a: the config accepts glm.* rows while engine.profile is absent because a
// managed model's manifest decides the profile; the launch refuses the rows for a qwen
// manifest by name (Task 7).
void managed_glm_rows_refused_for_qwen_manifest() {
  secure_frontend_test::cli::CliHarness h;
  (void)secure_frontend_test::cli::install(h);
  h.make_managed("m:t");
  std::string text = secure_frontend_test::read_file(h.config);
  text.insert(text.find("\"pull\""), "\"glm\": {\"thinking_budget\": 4096, \"model_name\": \"glm\"}, ");
  secure_frontend_test::write_file(h.config, text);
  const auto composed = secure_frontend::compose_engine_launch(h.validated_config().get(), false);
  const auto* failure = std::get_if<secure_frontend::LaunchFailure>(&composed);
  expect(failure != nullptr && !failure->messages.empty() && failure->messages.front().find("glm.") != std::string::npos,
         "glm.* rows with a qwen-managed model fail closed by name");
}

// SP5 M1 Task 5 (parity rows reasoning_* / fit_max_tokens). Only ONE of the pin's reasoning values
// reaches the engine launch: effort_position "end" composes --tail-role-token with the tokenizer's
// single "system" token id (effort_end_args serve/server.py:2836-2856, appended to the engine argv at
// :7966/:7977), and its probe rules are the pin's: the engine binary must contain the flag literal,
// and tok.encode("system") must be exactly one token, else one fixed warning and no argument.
// The other reasoning rows are service-object values in the pin and reach NOTHING in argv/env:
// reasoning_effort :8035-8041, reasoning_budget_tokens :8120-8127, reasoning_close_retry :8015,
// reasoning_loop_recovery :8129-8136, anthropic_thinking :8102-8104, fit_max_tokens :7996.
void reasoning_config_reaches_engine_launch_and_env() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  const auto binary = dir / "strata-engine";
  const std::string with_flag = std::string("engine-bytes --tail-role-token trailing");
  const std::string without_flag = std::string("engine-bytes --something-else trailing");
  {
    std::ofstream out(binary, std::ios::binary);
    out.write(with_flag.data(), static_cast<std::streamsize>(with_flag.size()));
  }
  secure_frontend::TokenizerPack pack;  // "system" encodes to one token through a merge chain
  pack.tokens_by_id = {"s", "y", "t", "e", "m", "sy", "sys", "syst", "syste", "system"};
  pack.merges_by_rank = {{"s", "y"}, {"sy", "s"}, {"sys", "t"}, {"syst", "e"}, {"syste", "m"}};
  pack.token_types = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  const auto composed = secure_frontend::compose_effort_end_arguments(binary, pack);
  expect(composed.arguments == std::vector<std::string>{"--tail-role-token", "9"},
         "the flag plus the single 'system' token id (:2857)");
  expect(composed.notice.find("effort_position end:") == 0U, "the pin's fixed success line (:2856)");
  {
    std::ofstream out(binary, std::ios::binary);
    out.write(without_flag.data(), static_cast<std::streamsize>(without_flag.size()));
  }
  const auto probe_miss = secure_frontend::compose_effort_end_arguments(binary, pack);
  expect(probe_miss.arguments.empty(), "an engine without the flag composes nothing (:2849-2855)");
  expect(probe_miss.notice.find("needs engine 0.1.39 or newer") != std::string_view::npos,
         "the pin's fixed fallback line (:2853)");
  secure_frontend::TokenizerPack multi;  // "system" is six ordinary characters: not one token
  multi.tokens_by_id = {"s", "y", "t", "e", "m"};
  multi.token_types = {1, 1, 1, 1, 1};
  {
    std::ofstream out(binary, std::ios::binary);
    out.write(with_flag.data(), static_cast<std::streamsize>(with_flag.size()));
  }
  const auto role_miss = secure_frontend::compose_effort_end_arguments(binary, multi);
  expect(role_miss.arguments.empty(), "a multi-token 'system' composes nothing (:2850)");
  expect(role_miss.notice.find("needs engine 0.1.39 or newer") != std::string_view::npos,
         "the same fixed fallback line (:2853)");
}

// SP5 M1 Task 6 (parity row mtp; runconfig.py:36, strata_control/draft_layer.py): an explicit
// engine.mtp=false strips the draft layer's own options from the engine arguments at every
// start — MTP_FLAGS verbatim {"--mtp" value, "--spec-min-p" value, "--batch-mtp" no value} —
// while prompt-lookup --spec stays (draft_layer.py: "why --spec stays"). Absent or true keeps
// today's launch. Only the strata profile: the GLM runner does not speak these flags.
void mtp_false_drops_the_mtp_arg() {
  const auto root = models_root();
  const std::vector<std::string> user{"--mtp", "mtp/rt", "--spec-min-p", "0.3", "--batch-mtp", "--spec", "4"};
  const auto on = secure_frontend::build_engine_arguments(kStrata, manifest(), root, user);
  const auto* kept = std::get_if<std::vector<std::string>>(&on);
  expect(kept != nullptr, "default mtp composes");
  if (kept == nullptr) return;
  expect(std::count(kept->begin(), kept->end(), "--mtp") == 1 && std::count(kept->begin(), kept->end(), "--spec-min-p") == 1 &&
             std::count(kept->begin(), kept->end(), "--batch-mtp") == 1,
         "mtp true leaves every flag");
  const auto off = secure_frontend::build_engine_arguments(kStrata, manifest(), root, user, {}, false);
  const auto* cut = std::get_if<std::vector<std::string>>(&off);
  expect(cut != nullptr, "mtp false composes");
  if (cut == nullptr) return;
  expect(std::none_of(cut->begin(), cut->end(), [](const std::string& a) { return a == "--mtp" || a == "--spec-min-p" || a == "--batch-mtp"; }),
         "mtp false drops the draft layer's flags");
  const auto spec = std::find(cut->begin(), cut->end(), "--spec");
  expect(spec != cut->end() && std::next(spec) != cut->end() && *std::next(spec) == "4", "--spec and its value stay (prompt lookup)");
  // The pin consumes the value only when the next token is not another flag (:draft_layer.strip).
  const auto edge = secure_frontend::build_engine_arguments(kStrata, manifest(), root, {"--mtp", "--spec", "4"}, {}, false);
  const auto* edge_args = std::get_if<std::vector<std::string>>(&edge);
  expect(edge_args != nullptr, "flag-after-flag still composes");
  if (edge_args != nullptr) {
    expect(std::none_of(edge_args->begin(), edge_args->end(), [](const std::string& a) { return a == "--mtp"; }), "the bare --mtp goes");
    const auto kept_spec = std::find(edge_args->begin(), edge_args->end(), "--spec");
    expect(kept_spec != edge_args->end() && std::next(kept_spec) != edge_args->end() && *std::next(kept_spec) == "4",
           "--spec was not eaten as --mtp's value");
  }
  // The composition reports what was removed for the pin's fixed startup line (:2925).
  const auto removed = secure_frontend::draft_layer_removed(user);
  expect(removed == std::vector<std::string>{"--mtp", "--spec-min-p", "--batch-mtp"}, "the removed list names the flags in order");
}

// SP5 M1 Task 7 (parity row vram_reserve_mib; runconfig.py:42-43 renders --vram-reserve-mib
// from the config unless the args already carry it). Unset composes nothing; the engine's
// own default (700) then applies.
void vram_reserve_mib_becomes_the_pinned_flag() {
  secure_frontend::VramGpuElasticArgs vram;
  std::vector<std::string> user;
  std::vector<std::string> args;
  secure_frontend::append_vram_gpu_elastic_arguments(args, vram, user, {});
  expect(std::find(args.begin(), args.end(), "--vram-reserve-mib") == args.end(), "unset: no flag is composed");
  vram.vram_reserve_mib = 700;
  secure_frontend::append_vram_gpu_elastic_arguments(args, vram, user, {});
  const auto flag = std::find(args.begin(), args.end(), "--vram-reserve-mib");
  expect(flag != args.end() && std::next(flag) != args.end() && *std::next(flag) == "700", "set: --vram-reserve-mib 700");
  user.emplace_back("--vram-reserve-mib");  // the pin's "not in args" guard (:2930 for vision, same shape)
  user.emplace_back("900");
  std::vector<std::string> kept;
  secure_frontend::append_vram_gpu_elastic_arguments(kept, vram, user, {});
  expect(std::count(kept.begin(), kept.end(), "--vram-reserve-mib") == 0, "the operator's own flag is never doubled");
}

// SP5 M1 Task 7 (parity rows vram_elastic/vram_segment_mib/layer_split/split_skip_if_fits/
// hip_ordinal; serve/server.py:2943-2948, :2938-2942, :3016-3030): every value reaches the
// engine through argv only (Ruling T7-a — no GPU/elastic engine-env variables, SP2 §3.9).
void gpu_and_elastic_rows_reach_the_engine_argv() {
  secure_frontend::VramGpuElasticArgs vram;
  std::vector<std::string> user;
  const auto compose = [&](const std::vector<unsigned>& gpus) {
    std::vector<std::string> args;
    secure_frontend::append_vram_gpu_elastic_arguments(args, vram, user, gpus);
    return args;
  };
  vram.vram_segment_mib = 512;
  const auto segment_alone = compose({});
  expect(std::find(segment_alone.begin(), segment_alone.end(), "--vram-segment-mib") == segment_alone.end(),
         "a segment size without vram_elastic composes nothing (the pin nests it in the elastic branch)");
  vram.vram_elastic = true;
  const auto elastic = compose({});
  const auto segment = std::find(elastic.begin(), elastic.end(), "--vram-segment-mib");
  expect(std::find(elastic.begin(), elastic.end(), "--vram-elastic") != elastic.end() && segment != elastic.end() &&
             std::next(segment) != elastic.end() && *std::next(segment) == "512",
         "vram_elastic renders --vram-elastic and the segment size beside it");
  vram.vram_segment_mib = std::nullopt;
  const auto bare_elastic = compose({});
  expect(std::find(bare_elastic.begin(), bare_elastic.end(), "--vram-elastic") != bare_elastic.end() &&
             std::find(bare_elastic.begin(), bare_elastic.end(), "--vram-segment-mib") == bare_elastic.end(),
         "the engine's own 512 default applies when the size is unset");
  const auto single = compose({});
  expect(std::find(single.begin(), single.end(), "--layer-split") == single.end(),
         "one GPU (or none): no layer split — the pin gates it on several GPUs (:2896-2899)");
  const auto split = compose({0, 1});
  const auto split_flag = std::find(split.begin(), split.end(), "--layer-split");
  expect(split_flag != split.end() && std::next(split_flag) != split.end() && *std::next(split_flag) == "auto",
         "several GPUs compose --layer-split auto (the pin default)");
  vram.layer_split = "24";
  const auto manual = compose({0, 1});
  const auto manual_flag = std::find(manual.begin(), manual.end(), "--layer-split");
  expect(manual_flag != manual.end() && std::next(manual_flag) != manual.end() && *std::next(manual_flag) == "24",
         "the manual first-layer list renders verbatim");
  user = {"--peer-device", "1"};
  const auto peer = compose({0, 1});
  expect(std::find(peer.begin(), peer.end(), "--layer-split") == peer.end(),
         "--peer-device in the args means the later card is an expert tier, not a split (:2898)");
  user = {"--layer-split", "18"};
  const auto owned = compose({0, 1});
  expect(std::count(owned.begin(), owned.end(), "--layer-split") == 0, "the operator's --layer-split is never doubled");
  user.clear();
  vram.split_skip_if_fits = true;
  const auto one_gpu = compose({0});
  const auto two_gpus = compose({0, 1});
  expect(std::find(one_gpu.begin(), one_gpu.end(), "--split-skip-if-fits") == one_gpu.end() &&
             std::find(two_gpus.begin(), two_gpus.end(), "--split-skip-if-fits") != two_gpus.end(),
         "split_skip_if_fits rides the same layer-split gate (:2941)");
  // hip_visible (:3023-3029): the recorded ordinal wins over one (or zero) configured GPUs,
  // never over several; it reaches the engine through --gpu (Ruling T7-f).
  expect(secure_frontend::effective_gpu_list({5}, 1) == std::vector<unsigned>{1}, "one card: the ordinal wins");
  expect(secure_frontend::effective_gpu_list({}, 1) == std::vector<unsigned>{1}, "no card: the ordinal selects it");
  expect(secure_frontend::effective_gpu_list({0, 1}, 1) == (std::vector<unsigned>{0, 1}), "several cards: the list stands");
  expect(secure_frontend::effective_gpu_list({2, 3}, std::nullopt) == (std::vector<unsigned>{2, 3}), "unset: unchanged");
}

// SP5 M1 Task 10 (parity row parallel; serve/server.py:2955-2975): replicas.parallel rides
// as ONE engine flag, --batch N — the pin's own rendering ("parallel" in, --batch out;
// llama.cpp's historical name, :2975). One at a time at <=1 (the pin's docstring); an
// operator --batch or --slots in the engine args silences the composition (:2961); past the
// 8-row batch window (PARALLEL_MAX, :2954) the value rides on — the engine warns and adjusts,
// recommend never force (:2969-2974).
void parallel_reaches_the_engine_within_one_child() {
  const auto compose = [](secure_frontend::ParallelBatchArgs p, const std::vector<std::string>& user) {
    std::vector<std::string> args = {"--ngl", "99"};
    secure_frontend::append_parallel_batch_arguments(args, p, user);
    return args;
  };
  expect(compose({1}, {}).size() == 2U, "1 (the default): one request at a time, no flag (:2966-2968)");
  expect(compose({0}, {}).size() == 2U, "0: not more than one, no flag (the pin treats <=1 as absent)");
  const auto four = compose({4}, {});
  const auto batch = std::find(four.begin(), four.end(), "--batch");
  expect(batch != four.end() && std::next(batch) != four.end() && *std::next(batch) == "4",
         "four requests decode together through --batch 4 (the pin's rendering, :2975)");
  const auto big = compose({20}, {});
  expect(std::count(big.begin(), big.end(), "--batch") == 1 && std::count(big.begin(), big.end(), "20") == 1,
         "past the 8-row window the value rides on: the engine warns and adjusts (:2969-2974)");
  expect(compose({4}, {"--batch", "8"}).size() == 2U, "an operator --batch in the engine args wins (:2961)");
  expect(compose({4}, {"--slots", "8"}).size() == 2U, "an operator --slots wins too (:2961)");
}

// SP5 M1 Task 9 (parity rows expert_profile_save / expert_profile_save_every;
// serve/server.py:3000-3005): a configured learned-profile save path composes
// --expert-profile-save plus the every-minutes re-save (the pin's default 10, :2996; 0 = at
// QUIT only). An operator's own --expert-profile-save in argv wins and nothing is appended —
// not even the every (:3001); no path composes nothing.
void expert_profile_flags_reach_launch() {
  secure_frontend::ExpertProfileSaveArgs save;
  expect(save.every == 10, "the typed default is the pin's 10 minutes (:2996)");
  const auto compose = [&](const std::vector<std::string>& user) {
    std::vector<std::string> args = {"--pack", "x"};
    secure_frontend::append_expert_profile_save_arguments(args, save, user);
    return args;
  };
  expect(compose({}).size() == 2U, "no save path: the args stand unchanged (:3001)");
  save.path = "/state/learned.bin";
  const auto learned = compose({});
  const auto at = std::find(learned.begin(), learned.end(), "--expert-profile-save");
  expect(at != learned.end() && std::next(at) != learned.end() && *std::next(at) == "/state/learned.bin" &&
             std::find(learned.begin(), learned.end(), "--expert-profile-save-every") != learned.end(),
         "the path composes the pair, the default 10 riding along (:3002-3005)");
  save.every = 0;
  const auto quit_only = compose({});
  const auto every = std::find(quit_only.begin(), quit_only.end(), "--expert-profile-save-every");
  expect(every != quit_only.end() && std::next(every) != quit_only.end() && *std::next(every) == "0",
         "0 keeps the pin's QUIT-only re-save (:2996)");
  const auto operator_kept = compose({"--expert-profile-save", "/operator/path.bin"});
  expect(operator_kept.size() == 2U &&
             std::find(operator_kept.begin(), operator_kept.end(), "--expert-profile-save") == operator_kept.end(),
         "an operator --expert-profile-save in argv wins; no doubling, no every (:3001)");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"engine_receives_model_path_from_inventory", engine_receives_model_path_from_inventory},
      {"engine_native_path_is_utf8_for_non_ascii_root", engine_native_path_is_utf8_for_non_ascii_root},
      {"engine_args_reject_owned_and_network_flags", engine_args_reject_owned_and_network_flags},
      {"strata_profile_passes_pack_and_weight_flags_through", strata_profile_passes_pack_and_weight_flags_through},
      {"rejects_invalid_relative_artifact_path", rejects_invalid_relative_artifact_path},
      {"engine_args_render_typed_gpu_and_deny_gpu_passthrough", engine_args_render_typed_gpu_and_deny_gpu_passthrough},
      {"gpu_list_rejects_malformed_values", gpu_list_rejects_malformed_values},
      {"launch_composed_from_manifest_qwen", launch_composed_from_manifest_qwen},
      {"vision_compose_rules", vision_compose_rules},
      {"managed_launch_argv_is_utf8_for_non_ascii_models_root", managed_launch_argv_is_utf8_for_non_ascii_models_root},
      {"launch_refuses_model_not_installed", launch_refuses_model_not_installed},
      {"engine_args_reject_weight_flags_for_managed_model", engine_args_reject_weight_flags_for_managed_model},
      {"launch_refuses_engine_too_old", launch_refuses_engine_too_old},
      {"managed_launch_renders_typed_gpu_list", managed_launch_renders_typed_gpu_list},
      {"glm_launch_argv_matches_mayas_launcher_form", glm_launch_argv_matches_mayas_launcher_form},
      {"glm_context_and_parallel_bounds_enforced", glm_context_and_parallel_bounds_enforced},
      {"glm_rejects_every_engine_argument", glm_rejects_every_engine_argument},
      {"managed_glm_rows_refused_for_qwen_manifest", managed_glm_rows_refused_for_qwen_manifest},
      {"reasoning_config_reaches_engine_launch_and_env", reasoning_config_reaches_engine_launch_and_env},
      {"mtp_false_drops_the_mtp_arg", mtp_false_drops_the_mtp_arg},
      {"vram_reserve_mib_becomes_the_pinned_flag", vram_reserve_mib_becomes_the_pinned_flag},
      {"gpu_and_elastic_rows_reach_the_engine_argv", gpu_and_elastic_rows_reach_the_engine_argv},
      {"expert_profile_flags_reach_launch", expert_profile_flags_reach_launch},
      {"parallel_reaches_the_engine_within_one_child", parallel_reaches_the_engine_within_one_child},
  }, failures);
}

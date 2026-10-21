#include "secure_frontend/launch_composition.hpp"

#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/model_index_store.hpp"
#include "secure_frontend/model_inventory.hpp"

#include <algorithm>
#include <filesystem>
#include <string>
#include <utility>

namespace secure_frontend {
namespace {

LaunchFailure config_failure(std::vector<std::string> messages) { return LaunchFailure{ExitCode::usage, std::move(messages)}; }

LaunchFailure store_failure(const AcquireError& error) { return LaunchFailure{exit_class(error.reason), {format_error(error)}}; }

bool is_weight_flag(const std::string& argument) {
  return std::any_of(kWeightFlags.begin(), kWeightFlags.end(), [&](const std::string_view flag) {
    return argument == flag || (argument.size() > flag.size() && argument.starts_with(flag) && argument[flag.size()] == '=');
  });
}

std::variant<ComposedLaunch, LaunchFailure> expert_launch(const FrontendConfig& config) {
  if (auto issues = launch_config_issues(config, true); !issues.empty()) return config_failure(std::move(issues));
  const EngineProfile profile = config.engine.profile.value_or(EngineProfile::qwen);
  auto models = enumerate_local_models(config.roots.models);
  if (const auto* failure = std::get_if<ModelInventoryError>(&models)) {
    return config_failure({"Unable to inventory local models (roots.models): " + failure->message});
  }
  const auto& list = std::get<std::vector<ModelManifest>>(models);
  const std::string& id = config.engine.model_id.value();
  const auto selected = std::find_if(list.begin(), list.end(), [&](const ModelManifest& m) { return m.id == id; });
  if (selected == list.end()) return config_failure({"Selected model is not present in roots.models."});
  const auto arguments_profile =
      profile == EngineProfile::glm53 ? EngineArgumentsProfile::lighttransport_glm53 : EngineArgumentsProfile::strata_0143;
  // SP5 M1 Task 7 (engine.hip_ordinal, serve/server.py:3023-3029): the recorded HIP number
  // wins over a single (or absent) card — for the strata profile; the GLM runner takes no
  // --gpu at all. Same rule at the managed path.
  const std::vector<unsigned> gpus =
      profile == EngineProfile::glm53 ? config.engine.gpus : effective_gpu_list(config.engine.gpus, config.engine.hip_ordinal);
  auto args = build_engine_arguments(arguments_profile, *selected, config.roots.models, config.engine.args, gpus,
                                     config.engine.mtp);
  if (const auto* failure = std::get_if<EngineArgumentsError>(&args)) {
    return config_failure({"Engine arguments rejected: " + failure->message});
  }
  auto argv = std::get<std::vector<std::string>>(std::move(args));
  if (profile != EngineProfile::glm53) {  // Ruling T7-a: this family reaches the engine through argv only
    const VramGpuElasticArgs vram{.vram_reserve_mib = config.engine.vram_reserve_mib,
                                  .vram_elastic = config.engine.vram_elastic,
                                  .vram_segment_mib = config.engine.vram_segment_mib,
                                  .layer_split = config.engine.layer_split,
                                  .split_skip_if_fits = config.engine.split_skip_if_fits};
    append_vram_gpu_elastic_arguments(argv, vram, config.engine.args, gpus);
    // SP5 M1 Task 9 (serve/server.py:3000-3005): the learned-profile save pair, guarded by
    // the pin's operator-owns check.
    append_expert_profile_save_arguments(
        argv, ExpertProfileSaveArgs{config.session.expert_profile_save, config.session.expert_profile_save_every},
        config.engine.args);
  }
  std::vector<std::string> served;  // SP1's /v1/models lists the whole inventory; --expert keeps that (SP3 decides later)
  served.reserve(list.size());
  for (const auto& model : list) served.push_back(model.id);
  // SP5 M1 Task 6 (parity row mtp): the removals can only come from the operator args.
  // The GLM profile keeps its arguments verbatim (its runner does not speak these flags).
  std::vector<std::string> mtp_removed;
  if (!config.engine.mtp && profile != EngineProfile::glm53) mtp_removed = draft_layer_removed(config.engine.args);
  return ComposedLaunch{profile, std::move(argv), *config.roots.tokenizer_pack, id, std::move(served), false,
                        std::move(mtp_removed)};
}

// <models>/<version_dir>/<relative> through the P1 grammar; nullopt if the joined path is not P1-valid.
std::optional<std::filesystem::path> in_version(const CanonicalRoot& models, const RelativePath& version_dir,
                                                const std::string& relative) {
  const auto parsed = parse_relative_path(version_dir.generic() + "/" + relative);
  const auto* path = std::get_if<RelativePath>(&parsed);
  if (path == nullptr) return std::nullopt;
  return models.join(*path);
}

}  // namespace

std::vector<std::string> launch_config_issues(const FrontendConfig& config, const bool expert) {
  std::vector<std::string> issues;
  if (expert) {
    if (!config.roots.tokenizer_pack) issues.emplace_back("roots.tokenizer_pack: required with --expert");
    return issues;
  }
  if (config.engine.profile) {
    issues.emplace_back(
        "engine.profile: engine_profile_conflicts_with_manifest (the model's manifest sets the profile; only --expert takes it)");
  }
  if (config.roots.tokenizer_pack) {
    issues.emplace_back("roots.tokenizer_pack: a managed model brings its own tokenizer; only --expert takes this key");
  }
  if (std::any_of(config.engine.args.begin(), config.engine.args.end(), is_weight_flag)) {
    issues.emplace_back("engine.args: weight flags (--native, --pack, --ple-gguf, --embd-gguf, --native-head-gguf, "
                        "--native-dense-gguf, --mtp) come from the manifest; only --expert takes them");
  }
  if (!parse_model_reference(config.engine.model_id.value())) {
    issues.emplace_back("engine.model_id: must be name or name:tag of an installed model (lowercase, not index.json)");
  }
  return issues;
}

std::vector<std::string> managed_config_issues(const FrontendConfig& config) { return launch_config_issues(config, false); }

std::variant<ComposedLaunch, LaunchFailure> compose_engine_launch(const FrontendConfig& config, const bool expert) {
  if (expert) return expert_launch(config);
  if (auto issues = managed_config_issues(config); !issues.empty()) return config_failure(std::move(issues));
  const auto reference = parse_model_reference(config.engine.model_id.value());  // valid: checked above
  auto read = read_model_index(config.roots.models);
  if (const auto* failure = std::get_if<AcquireError>(&read)) return store_failure(*failure);
  auto found = find_installed(std::get<ModelIndex>(read), *reference);  // F-58: the one lookup
  if (const auto* failure = std::get_if<AcquireError>(&found)) {
    if (failure->reason == AcquireReason::model_unknown) {
      return LaunchFailure{exit_class(failure->reason), {format_error(*failure) + "; install it with strata pull or strata import"}};
    }
    return LaunchFailure{ExitCode::usage, {"engine.model_id: " + format_error(*failure)}};
  }
  const auto& entry = std::get<IndexEntry>(found);
  auto loaded = load_installed(config.roots.models, entry);
  if (const auto* failure = std::get_if<AcquireError>(&loaded)) return store_failure(*failure);
  const auto& model = std::get<InstalledModel>(loaded);
  const auto& m = model.manifest.manifest;
  if (auto gate = engine_gate(m)) return LaunchFailure{ExitCode::engine, {format_error(*gate)}};
  const std::string ref = model_ref_text(entry.name, entry.tag);
  const auto inconsistent = [&ref] {
    return store_failure(AcquireError{AcquireReason::index_inconsistent, ref + ": launch paths"});
  };
  // qwen manifests always carry native, pack and tokenizer_pack (manifest rules); fail closed anyway.
  if (!m.launch.native || !m.launch.pack || !m.launch.tokenizer_pack) return inconsistent();
  const auto native = in_version(config.roots.models, model.version_dir, *m.launch.native);
  const auto pack = in_version(config.roots.models, model.version_dir, *m.launch.pack);
  const auto tokenizer = in_version(config.roots.models, model.version_dir, *m.launch.tokenizer_pack);
  const auto ple = m.launch.ple_gguf ? in_version(config.roots.models, model.version_dir, *m.launch.ple_gguf) : std::nullopt;
  if (!native || !pack || !tokenizer || (m.launch.ple_gguf && !ple)) return inconsistent();
  // UTF-8, never path::string(): on Windows that narrows through the ANSI code
  // page, and the engine launcher decodes every argument as UTF-8 (SP1 rule, F-7).
  std::vector<std::string> args{"--native", path_to_utf8(*native), "--pack", path_to_utf8(*pack)};
  if (ple) {
    args.emplace_back("--ple-gguf");
    args.push_back(path_to_utf8(*ple));
  }
  if (const auto rejected = validate_engine_user_arguments(EngineArgumentsProfile::strata_0143, config.engine.args)) {
    return config_failure({"engine.args: " + rejected->message});
  }
  args.insert(args.end(), config.engine.args.begin(), config.engine.args.end());
  // SP5 M1 Task 6 (parity row mtp; pin :2922 "applied at every start"): an explicit
  // false drops the draft layer's own options from the composed argv, and the removed
  // flags are reported once at startup.
  std::vector<std::string> mtp_removed;
  if (!config.engine.mtp) mtp_removed = strip_draft_layer_arguments(args);
  // SP2 spec §3.9: GPUs come only from the typed engine.gpu list (--gpu is
  // frontend-owned, so validate_engine_user_arguments refused it in engine.args).
  // SP5 M1 Task 7: engine.hip_ordinal wins over a single (or absent) card (:3025).
  const std::vector<unsigned> gpus = effective_gpu_list(config.engine.gpus, config.engine.hip_ordinal);
  if (!gpus.empty()) {
    std::string list;
    for (const unsigned device : gpus) {
      if (!list.empty()) list += ',';
      list += std::to_string(device);
    }
    args.emplace_back("--gpu");
    args.push_back(std::move(list));
  }
  // SP5 M1 Task 7 (parity rows vram_reserve_mib / vram_elastic / vram_segment_mib /
  // layer_split / split_skip_if_fits): the family renders after the composed tail, gated
  // per the pin (several GPUs for the split pair, the elastic branch nesting the size).
  const VramGpuElasticArgs vram{.vram_reserve_mib = config.engine.vram_reserve_mib,
                                .vram_elastic = config.engine.vram_elastic,
                                .vram_segment_mib = config.engine.vram_segment_mib,
                                .layer_split = config.engine.layer_split,
                                .split_skip_if_fits = config.engine.split_skip_if_fits};
  append_vram_gpu_elastic_arguments(args, vram, config.engine.args, gpus);
  // SP5 M1 Task 9 (serve/server.py:3000-3005): the learned-profile save pair, guarded by
  // the pin's operator-owns check.
  append_expert_profile_save_arguments(
      args, ExpertProfileSaveArgs{config.session.expert_profile_save, config.session.expert_profile_save_every},
      config.engine.args);
  // Opened once, on the path (F-7), and only if it stays below roots.models.
  auto opened = open_root(*tokenizer);
  auto* root = std::get_if<CanonicalRoot>(&opened);
  if (root == nullptr || !is_within(config.roots.models.path(), root->path())) {
    return LaunchFailure{ExitCode::verification,
                         {"Unable to load local tokenizer pack: the model's tokenizer directory cannot be opened safely"}};
  }
  return ComposedLaunch{EngineProfile::qwen, std::move(args), std::move(*root), ref, std::vector<std::string>{ref}, true,
                        std::move(mtp_removed)};
}

}  // namespace secure_frontend

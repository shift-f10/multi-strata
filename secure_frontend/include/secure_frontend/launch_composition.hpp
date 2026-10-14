#pragma once

#include "secure_frontend/acquire_manifest.hpp"
#include "secure_frontend/acquire_reason.hpp"
#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/engine_gate.hpp"  // engine_gate (F-58: one gate, in secure_frontend_model_store)
#include "secure_frontend/frontend_config.hpp"

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace secure_frontend {

// Spec §4.9 delta c: engine weight flags a managed model's manifest owns.
inline constexpr std::array<std::string_view, 7> kWeightFlags{"--native", "--pack", "--ple-gguf", "--embd-gguf",
                                                              "--native-head-gguf", "--native-dense-gguf", "--mtp"};

struct ComposedLaunch final {
  EngineProfile profile;
  std::vector<std::string> engine_args;         // argv tail after --serve; paths are UTF-8 (never path::string())
  std::optional<CanonicalRoot> tokenizer_root;  // opened once; set on success (never re-opened by path)
  std::string model_id;                         // the model chat requests must name
  std::vector<std::string> served_models;       // /v1/models: SP1's whole inventory under --expert, else {model_id}
  bool managed;                                 // false only with --expert
};

struct LaunchFailure final {
  ExitCode exit;
  std::vector<std::string> messages;  // key paths and fixed reasons; never configured values
};

// Spec §4.9 c/d: the launch-related config errors, without touching roots.models.
// Managed (expert == false): engine.profile set, roots.tokenizer_pack set, a weight
// flag in engine.args (`--flag value` and `--flag=value`), and an engine.model_id
// that is not a name[:tag] reference. --expert: roots.tokenizer_pack must be set.
// Each message starts with the key path. Shared by compose_engine_launch and
// strata-secure-server --check (F-8), so --check reports what serve refuses.
[[nodiscard]] std::vector<std::string> launch_config_issues(const FrontendConfig& config, bool expert);
// launch_config_issues(config, false).
[[nodiscard]] std::vector<std::string> managed_config_issues(const FrontendConfig& config);

// Managed (default): engine.model_id is name[:tag] in the index; profile, weights and
// tokenizer come from the installed manifest, gated by engine_gate (exit 11).
// --expert: SP1's operator path unchanged (inventory, roots.tokenizer_pack, engine.profile).
[[nodiscard]] std::variant<ComposedLaunch, LaunchFailure> compose_engine_launch(const FrontendConfig& config, bool expert);

}  // namespace secure_frontend

#include "secure_frontend/engine_arguments.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

namespace {
int failures = 0;
void expect(bool c, const std::string& m) { if (!c) { ++failures; std::cerr << "FAILED: " << m << '\n'; } }

secure_frontend::ModelManifest manifest() {
  secure_frontend::ModelManifest m; m.id = "qwen-local"; m.relative_artifact_path = "qwen/model-00001-of-00004.gguf"; return m;
}

void engine_receives_model_path_from_inventory() {
  const auto result = secure_frontend::build_engine_arguments(manifest(), "/models", {"--max-context", "8192"});
  const auto* args = std::get_if<std::vector<std::string>>(&result);
  expect(args != nullptr, "valid pass-through must build");
  if (!args) return;
  const std::vector<std::string> expected{"--max-context", "8192", "--native", std::filesystem::path("/models/qwen/model-00001-of-00004.gguf").make_preferred().string()};
  expect(*args == expected, "frontend must append --native from the inventory, last");
}

void engine_args_reject_owned_and_network_flags() {
  for (const std::string bad : {"--native", "--native=/x.gguf", "--pack", "--pack=dir", "--serve", "--batch", "--batch=2", "--slots", "--vision"}) {
    const auto r = secure_frontend::build_engine_arguments(manifest(), "/models", {bad, "value"});
    const auto* e = std::get_if<secure_frontend::EngineArgumentsError>(&r);
    expect(e != nullptr, "must reject " + bad);
    if (e) expect(e->code == secure_frontend::EngineArgumentsErrorCode::owned_flag || e->code == secure_frontend::EngineArgumentsErrorCode::unsupported_mode, "code for " + bad);
  }
  const auto nul = secure_frontend::build_engine_arguments(manifest(), "/models", {std::string("--gpu\0 0", 8)});
  expect(std::holds_alternative<secure_frontend::EngineArgumentsError>(nul), "NUL in an argument must be rejected");
  const auto empty = secure_frontend::build_engine_arguments(manifest(), "/models", {});
  expect(std::holds_alternative<std::vector<std::string>>(empty), "no pass-through arguments is valid: the frontend supplies the model");
}
}  // namespace

int main() {
  engine_receives_model_path_from_inventory();
  engine_args_reject_owned_and_network_flags();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

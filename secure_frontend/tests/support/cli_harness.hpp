#pragma once
// SP4 Task 23: drives run_strata in-process against a private scratch tree.
#include "secure_frontend/strata_cli.hpp"
#include "support/acquire_fixtures.hpp"

#include <sstream>

namespace secure_frontend_test::cli {

// A private scratch tree with roots.models, a tokenizer root, a fake engine
// file and a config whose pull.downloader does not exist (local verbs never need it).
struct CliHarness final {
  CliHarness() : scratch(secure_frontend_test::make_scratch_directory()) {
    models_path = scratch / "models";
    secure_frontend_test::make_private_directory(models_path);
    secure_frontend_test::make_private_directory(scratch / "tokenizer");
    secure_frontend_test::make_private_directory(scratch / "bin");
    secure_frontend_test::write_file(scratch / "bin" / "engine", "#!/bin/sh\n", 0700);
    config = scratch / "config.json";
    write_config("");
  }

  // An absolute path that does not exist (local verbs never touch the downloader).
  std::string missing_downloader() const {
    std::string out;
    for (const char c : std::filesystem::absolute(scratch / "missing" / "curl").generic_string()) out += c == '\\' ? std::string{"\\\\"} : std::string(1, c);
    return "\"" + out + "\"";
  }

  void write_config(const std::string& extra_members) {
    const auto quote = [](const std::filesystem::path& p) {
      std::string text = std::filesystem::canonical(p).generic_string();
      std::string out;
      for (const char c : text) out += c == '\\' ? std::string{"\\\\"} : std::string(1, c);
      return "\"" + out + "\"";
    };
    secure_frontend_test::write_file(config, "{\n  \"schema_version\": 1,\n  \"roots\": {\"models\": " + quote(models_path) +
                                                 ", \"tokenizer_pack\": " + quote(scratch / "tokenizer") + "},\n"
                                                 "  \"token\": {\"source\": \"env:STRATA_TEST_TOKEN\"},\n"
                                                 "  \"engine\": {\"executable\": " + quote(scratch / "bin" / "engine") +
                                                 ", \"model_id\": \"m\"},\n"
                                                 "  \"pull\": {\"downloader\": " + missing_downloader() + extra_members + "}\n}\n");
  }

  // strata --config <config> <args...>
  int run(std::vector<std::string> args, const std::string& input = "", const bool interactive = false) {
    std::vector<std::string> full{"--config", config.string()};
    full.insert(full.end(), args.begin(), args.end());
    return run_raw(full, input, interactive);
  }

  // strata <args...> (no --config added)
  int run_raw(const std::vector<std::string>& args, const std::string& input = "", const bool interactive = false) {
    std::istringstream in(input);
    std::ostringstream o;
    std::ostringstream e;
    secure_frontend::CliStreams streams{in, o, e, interactive};
    const int code = secure_frontend::run_strata(args, streams, services);
    out = o.str();
    err = e.str();
    return code;
  }

  secure_frontend::CanonicalRoot models() const { return secure_frontend_test::acquire::models_root(models_path); }

  std::filesystem::path scratch;
  std::filesystem::path models_path;
  std::filesystem::path config;
  secure_frontend::CliServices services;
  std::string out;
  std::string err;
};

// Publishes a fixture model <name>:<tag> (sequence `sequence`) straight into the harness's roots.models.
inline secure_frontend::IndexEntry install(CliHarness& h, const std::uint32_t sequence = 1, const std::string_view salt = "",
                                           const secure_frontend::ModelOrigin origin = secure_frontend::ModelOrigin::third_party,
                                           const std::string_view name = "m", const std::string_view tag = "t") {
  namespace fx = secure_frontend_test::acquire;
  const auto root = h.models();
  const auto manifest = fx::trusted(fx::manifest_text(name, tag, sequence, fx::qwen_payload(salt)), origin);
  fx::stage(root, manifest, fx::qwen_payload(salt));
  fx::FakeLoaded nobody;
  const secure_frontend::StoreEnvironment env;
  return std::get<secure_frontend::PublishResult>(
             secure_frontend::publish_staged(root, secure_frontend::staging_key(manifest.parsed.sha256), manifest, nobody, env, true))
      .entry;
}

}  // namespace secure_frontend_test::cli

#pragma once
// SP4 test fixtures: small qwen-profile payloads whose tokenizer passes SP1's
// load_local_tokenizer_pack, manifests built from them, and staging helpers.
#include "secure_frontend/acquire_publish.hpp"
#include "secure_frontend/manifest_trust.hpp"
#include "secure_frontend/models_store.hpp"
#include "secure_frontend/sha256.hpp"
#include "support/test_support.hpp"

#include <filesystem>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace secure_frontend_test::acquire {

struct PayloadFile final {
  std::string path;
  secure_frontend::FileRole role;
  std::string bytes;
};

inline std::vector<PayloadFile> qwen_payload(const std::string_view salt = "") {
  using secure_frontend::FileRole;
  const std::string s{salt};
  return {{"weights/fx-00001-of-00002.gguf", FileRole::weights, "shard one " + s},
          {"weights/fx-00002-of-00002.gguf", FileRole::weights, "shard two " + s},
          {"pack/index.txt", FileRole::pack, "index " + s},
          {"pack/dense.bin", FileRole::pack, "dense " + s},
          {"pack/native_experts.txt", FileRole::pack, "experts " + s},
          {"pack/conversions.json", FileRole::pack, "{}\n"},
          {"pack/tokenizer/vocab.json", FileRole::tokenizer, "{\"a\":0,\"b\":1,\"ab\":2}"},
          {"pack/tokenizer/merges.txt", FileRole::tokenizer, "a b\n"},
          {"pack/tokenizer/token_type.json", FileRole::tokenizer, "[1,1,1]"},
          {"pack/tokenizer/tokenizer.json", FileRole::tokenizer, "{}\n"}};
}

inline std::string manifest_text(const std::string_view name, const std::string_view tag, const std::uint32_t sequence,
                                 const std::vector<PayloadFile>& files, const bool with_sources = true,
                                 const bool bundle_allowed = true, const std::string_view host = "fixture.example") {
  std::string out = "{\"format\":\"strata-model-manifest\",\"schema_version\":1,\"name\":\"" + std::string{name} +
                    "\",\"tag\":\"" + std::string{tag} + "\",\"version\":\"2026.10.14." + std::to_string(sequence) +
                    "\",\"sequence\":" + std::to_string(sequence) +
                    ",\"profile\":\"qwen\",\"engine\":{\"family\":\"strata\",\"min_version\":\"0.1.43\"},"
                    "\"license\":{\"id\":\"Apache-2.0\",\"url\":\"https://" + std::string{host} + "/l\",\"bundle_allowed\":" +
                    (bundle_allowed ? "true" : "false") + ",\"notice\":\"Fixture.\"},\"hosts\":[\"" + std::string{host} +
                    "\"],\"redirect_hosts\":[\"*.cdn." + std::string{host} + "\"],\"files\":[";
  for (std::size_t i = 0; i < files.size(); ++i) {
    const auto& f = files[i];
    out += (i ? "," : "") + std::string{"{\"path\":\""} + f.path + "\",\"role\":\"" + std::string{secure_frontend::role_name(f.role)} +
           "\",\"size\":" + std::to_string(f.bytes.size()) + ",\"sha256\":\"" + secure_frontend::to_hex(secure_frontend::sha256(f.bytes)) +
           "\",\"sources\":[" + (with_sources ? "\"https://" + std::string{host} + "/fx/" + f.path + "\"" : std::string{}) + "]}";
  }
  out += "],\"launch\":{\"native\":\"weights/fx-00001-of-00002.gguf\",\"ple_gguf\":\"weights/fx-00002-of-00002.gguf\","
         "\"pack\":\"pack\",\"tokenizer_pack\":\"pack/tokenizer\"}}\n";
  return out;
}

inline secure_frontend::TrustedManifest trusted(const std::string& text, const secure_frontend::ModelOrigin origin) {
  auto parsed = secure_frontend::parse_manifest(text, secure_frontend::ManifestRules{});
  if (!std::holds_alternative<secure_frontend::ParsedManifest>(parsed)) throw std::runtime_error("fixture manifest invalid");
  return secure_frontend::TrustedManifest{std::get<secure_frontend::ParsedManifest>(std::move(parsed)), origin};
}

inline secure_frontend::CanonicalRoot models_root(const std::filesystem::path& path) {
  auto opened = secure_frontend::open_root(path);
  if (!std::holds_alternative<secure_frontend::CanonicalRoot>(opened)) throw std::runtime_error("scratch root not private");
  return std::get<secure_frontend::CanonicalRoot>(std::move(opened));
}

// .staging/<key>/MANIFEST + every payload file under its final name.
inline void stage(const secure_frontend::CanonicalRoot& root, const secure_frontend::TrustedManifest& manifest,
                  const std::vector<PayloadFile>& files) {
  using secure_frontend::must_rel;
  const auto key = secure_frontend::staging_key(manifest.parsed.sha256);
  const auto dir = secure_frontend::staging_dir_path(key);
  if (secure_frontend::ensure_directory(root, dir)) throw std::runtime_error("stage dir");
  if (secure_frontend::write_new_file(root, secure_frontend::join_rel(dir, "MANIFEST"), manifest.parsed.bytes)) throw std::runtime_error("MANIFEST");
  for (const auto& f : files) {
    const auto path = secure_frontend::join_rel(dir, f.path);
    const auto parent = path.generic().substr(0, path.generic().rfind('/'));
    if (secure_frontend::ensure_directory(root, must_rel(parent)) || secure_frontend::write_new_file(root, path, f.bytes)) {
      throw std::runtime_error("stage file");
    }
  }
}

class FakeLoaded final : public secure_frontend::LoadedVersions {
 public:
  std::set<std::string> held;
  bool is_held(const std::string_view name, const std::string_view tag, const std::string_view dir) override {
    return held.contains(std::string{name} + "/" + std::string{tag} + "/" + std::string{dir});
  }
};

}  // namespace secure_frontend_test::acquire

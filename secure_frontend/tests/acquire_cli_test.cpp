// SP4 Task 23 (spec §1.5, §4.5, §4.8, §6.2): the strata CLI's local verbs.
#include "acquire_cases.hpp"
#include "secure_frontend/model_index_store.hpp"
#include "secure_frontend/test_hooks.hpp"
#include "support/cli_harness.hpp"
#include "support/expect.hpp"

#include <memory>
#include <string>

namespace acquire_cases {
namespace {

using secure_frontend_test::expect;
using secure_frontend_test::cli::CliHarness;

class HeldLoaded final : public secure_frontend::LoadedVersions {
 public:
  explicit HeldLoaded(std::string held) : held_(std::move(held)) {}
  bool is_held(const std::string_view name, const std::string_view tag, const std::string_view dir) override {
    return held_ == std::string{name} + "/" + std::string{tag} + "/" + std::string{dir};
  }

 private:
  std::string held_;
};

// Publishes m:t v2 while v1 is held, so v1 stays in the index's retired list.
void publish_v2_while_v1_held(CliHarness& h, const secure_frontend::IndexEntry& v1) {
  namespace fx = secure_frontend_test::acquire;
  const auto root = h.models();
  const auto manifest = fx::trusted(fx::manifest_text("m", "t", 2, fx::qwen_payload("2")), secure_frontend::ModelOrigin::third_party);
  fx::stage(root, manifest, fx::qwen_payload("2"));
  HeldLoaded held("m/t/" + v1.dir);
  const secure_frontend::StoreEnvironment env;
  (void)secure_frontend::publish_staged(root, secure_frontend::staging_key(manifest.parsed.sha256), manifest, held, env, true);
}

std::string replaced(std::string text, const std::string& from, const std::string& to) {
  text.replace(text.find(from), from.size(), to);
  return text;
}

}  // namespace

void program_update_exits_12_without_network() {
  CliHarness h;
  bool network_seam_used = false;
  h.services.transport = [&](const secure_frontend::FrontendConfig&) {
    network_seam_used = true;
    return std::unique_ptr<secure_frontend::HopTransport>{};
  };
  h.services.probe = [&](const secure_frontend::FrontendConfig&) {
    network_seam_used = true;
    return std::unique_ptr<secure_frontend::DownloaderProbe>{};
  };
  h.services.resolver = [&]() {
    network_seam_used = true;
    return std::unique_ptr<secure_frontend::Resolver>{};
  };
  const int code = h.run_raw({"update"});
  expect(code == 12, "program update exits 12");
  expect(h.out.find("program update not available in this release; install the new release manually") != std::string::npos, "message");
  expect(!network_seam_used, "no transport, downloader probe or resolver is created (§6.2: no network access)");
  // Controller note 16 / C7 with note 2's mandatory --config: the documented form.
  expect(h.run({"update"}) == 12, "strata --config <f> update exits 12: " + h.err);
  expect(h.out.find("program update not available in this release; install the new release manually") != std::string::npos,
         "message with --config");
  expect(!network_seam_used, "--config update creates no seam either");
  expect(h.run({"update", "--models"}) != 12, "update --models is the models part, not the program update");
}

void cli_requires_config_and_known_verb() {
  CliHarness h;
  expect(h.run_raw({"list"}) == 1 && h.err.find("--config") != std::string::npos, "config is required (no default location yet)");
  expect(h.run_raw({"--config"}) == 1, "--config without a file and verb: exit 1");
  expect(h.run_raw({"--config", (h.scratch / "absent.json").string(), "list"}) == 1, "unreadable config: exit 1");
  expect(h.run({"frobnicate"}) == 1, "unknown verb: usage, exit 1");
  expect(h.run({"list", "--bogus"}) == 1, "unknown option: exit 1");
  expect(h.run({"show"}) == 1 && h.run({"rm", "--partials"}) == 1, "missing operand or option value: exit 1");
  expect(h.run({"verify", "b", "--trust-manifest", "sha256:XYZ"}) == 1, "malformed --trust-manifest: exit 1");
  expect(h.run_raw({"--help"}) == 0 && h.out.find("strata --config <file> <verb>") != std::string::npos, "--help prints usage, exit 0");
  if (secure_frontend::kTestHooksEnabled) expect(h.err.find("SECURE_FRONTEND_TEST_HOOKS_COMPILED_IN") != std::string::npos, "hooks banner");
}

void list_and_show_report_installed_models() {
  CliHarness h;
  const auto entry = secure_frontend_test::cli::install(h);
  expect(h.run({"list"}) == 0, "list");
  expect(h.out.find("m:t") != std::string::npos && h.out.find("third_party") != std::string::npos && h.out.find("runnable") != std::string::npos,
         "name:tag, origin, state");
  expect(h.run({"show", "m:t"}) == 0 && h.out.find("--native m/t/" + entry.dir + "/weights/fx-00001-of-00002.gguf") != std::string::npos,
         "show prints the engine arguments the manifest implies, relative to roots.models");
  expect(h.out.find(h.models_path.string()) == std::string::npos, "never an absolute path outside the data dir");
  expect(h.run({"show", "m:t", "--digests"}) == 0 && h.out.find("  weights/fx-00001-of-00002.gguf") != std::string::npos,
         "--digests prints sha256sum lines");
  expect(h.run({"show", "nope:t"}) == 5, "unknown model: exit 5");
  expect(h.run({"show", "m"}) == 0, "a single installed tag is found by name alone");
  // A second model whose manifest needs a newer engine than this release (§2.3, §4.5 list state).
  {
    namespace fx = secure_frontend_test::acquire;
    const auto root = h.models();
    const auto manifest = fx::trusted(replaced(fx::manifest_text("m", "u", 1, fx::qwen_payload("u")), "\"min_version\":\"0.1.43\"",
                                               "\"min_version\":\"9.0.0\""),
                                      secure_frontend::ModelOrigin::third_party);
    fx::stage(root, manifest, fx::qwen_payload("u"));
    fx::FakeLoaded nobody;
    const secure_frontend::StoreEnvironment env;
    (void)secure_frontend::publish_staged(root, secure_frontend::staging_key(manifest.parsed.sha256), manifest, nobody, env, true);
  }
  expect(h.run({"list"}) == 0 && h.out.find("needs engine strata >= 9.0.0") != std::string::npos, "list: needs engine <family> >= <version>");
  // A glm53 / family glm model (SP6): the state names its family (F-58: the gate honours family).
  {
    namespace fx = secure_frontend_test::acquire;
    const std::string text =
        "{\"format\":\"strata-model-manifest\",\"schema_version\":1,\"name\":\"g\",\"tag\":\"t\",\"version\":\"2026.10.14.1\","
        "\"sequence\":1,\"profile\":\"glm53\",\"engine\":{\"family\":\"glm\",\"min_version\":\"0.0.1\"},"
        "\"license\":{\"id\":\"MIT\",\"url\":\"https://h.example/l\",\"bundle_allowed\":true},\"hosts\":[\"h.example\"],"
        "\"files\":[{\"path\":\"w.gguf\",\"role\":\"weights\",\"size\":1,"
        "\"sha256\":\"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\",\"sources\":[]}],"
        "\"launch\":{\"native\":\"w.gguf\"}}";
    const auto root = h.models();
    const auto manifest = fx::trusted(text, secure_frontend::ModelOrigin::third_party);
    fx::stage(root, manifest, {{"w.gguf", secure_frontend::FileRole::weights, "a"}});
    fx::FakeLoaded nobody;
    const secure_frontend::StoreEnvironment env;
    expect(std::holds_alternative<secure_frontend::PublishResult>(secure_frontend::publish_staged(
               root, secure_frontend::staging_key(manifest.parsed.sha256), manifest, nobody, env, true)),
           "test setup: glm53 model published");
  }
  expect(h.run({"list"}) == 0 && h.out.find("needs engine glm >= 0.0.1") != std::string::npos, "list: glm family named: " + h.out);
  expect(h.run({"show", "g:t"}) == 0 && h.out.find("needs engine glm >= 0.0.1") != std::string::npos, "show: same state");
  expect(h.run({"show", "m"}) == 1 && h.err.find("several tags installed") != std::string::npos, "an ambiguous name is a usage error");
}

void list_all_reports_retired_orphaned_and_staging() {
  CliHarness h;
  const auto v1 = secure_frontend_test::cli::install(h, 1, "1");
  publish_v2_while_v1_held(h, v1);
  (void)secure_frontend::ensure_directory(h.models(), secure_frontend::must_rel("x/t/v9-aaaaaaaaaaaa"));
  (void)secure_frontend::write_new_file(h.models(), secure_frontend::must_rel("x/t/v9-aaaaaaaaaaaa/w.gguf"), "orphan");
  (void)secure_frontend::ensure_directory(h.models(), secure_frontend::must_rel(".staging/" + std::string(32, 'b')));
  (void)secure_frontend::write_new_file(h.models(), secure_frontend::must_rel(".staging/" + std::string(32, 'b') + "/x.part"), "12345");
#if !defined(_WIN32)
  // Task 15 carry: scan_model_root_files skips links and non-portable names; list --all counts them.
  std::filesystem::create_directory_symlink(h.scratch, h.models_path / "link");
#endif
  expect(h.run({"list", "--all"}) == 0, "list --all");
  expect(h.out.find("orphaned x/t/v9-aaaaaaaaaaaa 6 bytes") != std::string::npos, "orphaned version reported with its size");
  expect(h.out.find("staging " + std::string(32, 'b') + " 5 bytes") != std::string::npos, "staging usage per key");
  expect(h.out.find("retired m/t/" + v1.dir + " ") != std::string::npos, "retired version reported with its size");
  expect(h.out.find("never loaded") != std::string::npos, "the orphan line says what it is and how to clear it");
#if !defined(_WIN32)
  expect(h.out.find("skipped 1 entry") != std::string::npos, "skipped (non-P1 / link) entries are counted, never followed");
#endif
}

void rm_refuses_loaded_model() {
  CliHarness h;
  const auto entry = secure_frontend_test::cli::install(h);
  h.services.loaded = [entry](const secure_frontend::FrontendConfig&) {
    return std::make_unique<HeldLoaded>("m/t/" + entry.dir);
  };
  expect(h.run({"rm", "m:t"}) == 7 && h.err.find("models_busy") != std::string::npos, "a loaded version is refused (exit 7)");
  expect(h.run({"rm", "m:t", "--force"}) == 0, "--force after stop");
  expect(std::get<secure_frontend::ModelIndex>(secure_frontend::read_model_index(h.models())).models.empty(), "removed from the index");
  expect(!std::filesystem::exists(h.models_path / "m" / "t" / entry.dir), "deleted bottom-up");
  expect(h.run({"rm", "m:t"}) == 5, "rm of a model no longer installed: model_unknown (exit 5)");
}

void rm_retired_deletes_unheld_versions() {
  CliHarness h;
  const auto v1 = secure_frontend_test::cli::install(h, 1, "1");
  publish_v2_while_v1_held(h, v1);
  expect(std::get<secure_frontend::ModelIndex>(secure_frontend::read_model_index(h.models())).retired.size() == 1, "retired");
  expect(h.run({"rm", "--retired"}) == 0, "rm --retired");
  expect(std::get<secure_frontend::ModelIndex>(secure_frontend::read_model_index(h.models())).retired.empty() &&
             !std::filesystem::exists(h.models_path / "m" / "t" / v1.dir),
         "unheld retired versions deleted");
}

void rm_partials_deletes_other_staging() {
  CliHarness h;
  namespace fx = secure_frontend_test::acquire;
  const auto manifest = fx::manifest_text("m", "t", 3, fx::qwen_payload("p"));
  const auto key = secure_frontend::staging_key(secure_frontend::to_hex(secure_frontend::sha256(manifest)));
  (void)secure_frontend::ensure_directory(h.models(), secure_frontend::must_rel(".staging/" + key));
  (void)secure_frontend::write_new_file(h.models(), secure_frontend::must_rel(".staging/" + key + "/MANIFEST"), manifest);
  const auto other = fx::manifest_text("n", "t", 1, fx::qwen_payload("q"));
  const auto other_key = secure_frontend::staging_key(secure_frontend::to_hex(secure_frontend::sha256(other)));
  (void)secure_frontend::ensure_directory(h.models(), secure_frontend::must_rel(".staging/" + other_key));
  (void)secure_frontend::write_new_file(h.models(), secure_frontend::must_rel(".staging/" + other_key + "/MANIFEST"), other);
  expect(h.run({"rm", "--partials", "m"}) == 1, "rm --partials needs <name:tag>");
  expect(h.run({"rm", "--partials", "m:t"}) == 0, "rm --partials");
  expect(!std::filesystem::exists(h.models_path / ".staging" / key) && std::filesystem::exists(h.models_path / ".staging" / other_key),
         "only m:t partials deleted");
}

#if defined(SECURE_FRONTEND_TEST_HOOKS)
void list_outdated_uses_catalog_sequence() {
  CliHarness h;
  // An older catalog release's fixture-qwen:t1 (sequence 1); this binary's catalog has sequence 2.
  (void)secure_frontend_test::cli::install(h, 1, "", secure_frontend::ModelOrigin::catalog, "fixture-qwen", "t1");
  expect(h.run({"list", "--outdated"}) == 0, "list --outdated");
  expect(h.out.find("fixture-qwen:t1 sequence 1 -> 2") != std::string::npos, "answered offline from the embedded catalog");
}
#endif

}  // namespace acquire_cases

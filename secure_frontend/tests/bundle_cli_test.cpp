// SP4 Task 23 (spec §5): strata import / verify / export through the CLI.
#include "bundle_cases.hpp"
#include "secure_frontend/model_index_store.hpp"
#include "support/cli_harness.hpp"
#include "support/expect.hpp"

namespace bundle_cases {
namespace {

using secure_frontend_test::expect;
using secure_frontend_test::cli::CliHarness;

// Every write fails once a file holds `limit` bytes (disk_space, exit 6).
class FailingWrites final : public secure_frontend::StoreEnvironment {
 public:
  [[nodiscard]] std::optional<std::uint64_t> fail_writes_after_bytes() const override { return 0; }
};

}  // namespace

void import_works_without_downloader() {
  CliHarness online;
  const auto entry = secure_frontend_test::cli::install(online);
  const auto bundle = online.scratch / "usb-bundle";
  expect(online.run({"export", "m:t", bundle.string()}) == 0, "export");
  CliHarness offline;  // pull.downloader = <scratch>/missing/curl
  expect(offline.run({"import", bundle.string(), "--trust-manifest", "sha256:" + entry.manifest_sha256, "--yes"}) == 0,
         "import needs no downloader");
  expect(std::get<secure_frontend::ModelIndex>(secure_frontend::read_model_index(offline.models())).models.size() == 1, "installed");
}

void cli_verify_export_import_round_trip() {
  CliHarness online;
  const auto entry = secure_frontend_test::cli::install(online);
  const auto bundle = online.scratch / "b";
  expect(online.run({"export", "m:t", bundle.string()}) == 0, "export");
  expect(online.run({"export", "m:t", bundle.string()}) == 7, "export into a non-empty directory: bundle_target_not_empty (exit 7)");
  CliHarness offline;
  expect(offline.run({"verify", bundle.string()}) == 5, "verify without trust: manifest_untrusted (exit 5)");
  expect(offline.run({"verify", bundle.string(), "--trust-manifest", "sha256:" + entry.manifest_sha256}) == 0, "verify: exit 0");
  expect(offline.run({"import", bundle.string(), "--trust-manifest", "sha256:" + entry.manifest_sha256}) == 2,
         "non-interactive import without --yes is declined (exit 2)");
  expect(offline.run({"import", bundle.string(), "--trust-manifest", "sha256:" + entry.manifest_sha256}, "", true) == 2,
         "interactive EOF is No (exit 2)");
  expect(offline.run({"import", bundle.string(), "--trust-manifest", "sha256:" + entry.manifest_sha256}, "y\n", true) == 0,
         "interactive y imports");
  expect(offline.run({"import", bundle.string(), "--trust-manifest", "sha256:" + entry.manifest_sha256, "--yes"}) == 0 &&
             offline.out.find("already installed") != std::string::npos, "re-import: already installed");
}

// Task 20 carry: a failed export leaves the target directory; the CLI says to remove it.
void failed_export_says_to_remove_target() {
  CliHarness h;
  (void)secure_frontend_test::cli::install(h);
  const FailingWrites failing;
  h.services.store = &failing;
  const auto bundle = h.scratch / "half";
  expect(h.run({"export", "m:t", bundle.string()}) == 6, "a write failure mid-export: disk_space (exit 6)");
  expect(std::filesystem::exists(bundle), "the target directory stays behind");
  expect(h.err.find("remove the target directory") != std::string::npos, "the error text says to remove it before retrying: " + h.err);
  expect(h.run({"export", "m:t", (h.scratch / "fresh").string()}) == 6 && h.run({"export", "m:t", bundle.string()}) == 7 &&
             h.err.find("remove the target directory") == std::string::npos,
         "a target that was not empty before is not ours to remove: no hint");
}

// Task 19 carry: a version directory the index does not name, whose manifest differs,
// blocks publish ("target exists"); the CLI says how to clear it.
void import_blocked_by_orphan_says_how_to_clear_it() {
  CliHarness online;
  const auto entry = secure_frontend_test::cli::install(online);
  const auto bundle = online.scratch / "b";
  expect(online.run({"export", "m:t", bundle.string()}) == 0, "export");
  CliHarness offline;
  const auto dir = "m/t/" + entry.dir;
  (void)secure_frontend::ensure_directory(offline.models(), secure_frontend::must_rel(dir));
  (void)secure_frontend::write_new_file(offline.models(), secure_frontend::must_rel(dir + "/manifest.json"), "{}\n");
  expect(offline.run({"import", bundle.string(), "--trust-manifest", "sha256:" + entry.manifest_sha256, "--yes"}) == 7,
         "publish over an orphan directory: publish_failed (exit 7): " + offline.err);
  expect(offline.err.find("target exists") != std::string::npos && offline.err.find("strata list --all") != std::string::npos &&
             offline.err.find("delete it by hand") != std::string::npos,
         "the error says how to clear the orphan: " + offline.err);
}

}  // namespace bundle_cases

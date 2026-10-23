// Model downloads (plan 2026-10-23-model-downloads Task 4): the server's download manager over a
// scripted `strata` child and a fake disk. The catalog's cards and the free-space refusal (O2),
// the pull's argv and the manifest it is given (O4 through hf_source), progress, failure and
// cancel, Maya's "main" pins resolved and checked, and a pasted link (O3) checked then started.
#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/download_manager.hpp"
#include "secure_frontend/manifest_json.hpp"
#include "secure_frontend/sha256.hpp"
#include "support/test_support.hpp"

#include <atomic>
#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

int failures = 0;
void expect(const bool value, const std::string_view message) {
  if (!value) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

using secure_frontend::DownloadManager;

constexpr std::string_view kCommit = "0123456789abcdef0123456789abcdef01234567";
const std::string kShaA(64, 'a');
const std::string kShaB(64, 'b');

struct Script final {
  std::vector<std::string> lines;
  int exit_code{0};
  bool hang{false};  // after its lines, never ends until killed
};

struct Recorded final {
  secure_frontend::EngineCommand command;
};

class FakeChild final : public secure_frontend::LineChild {
 public:
  FakeChild(Script script, std::shared_ptr<std::atomic<bool>> killed) : script_(std::move(script)), killed_(std::move(killed)) {}
  std::optional<std::string> next_line(const std::chrono::milliseconds timeout) override {
    // "#sleep <ms>": the child is quiet that long (a rate needs a second between readings).
    while (next_ < script_.lines.size() && script_.lines[next_].rfind("#sleep ", 0) == 0U) {
      std::this_thread::sleep_for(std::chrono::milliseconds(std::stoi(script_.lines[next_++].substr(7))));
    }
    if (next_ < script_.lines.size()) return script_.lines[next_++];
    std::this_thread::sleep_for(std::min(timeout, std::chrono::milliseconds(5)));
    return std::nullopt;
  }
  bool ended() override { return next_ >= script_.lines.size() && (!script_.hang || killed_->load()); }
  int exit_code() override { return killed_->load() ? -1 : script_.exit_code; }
  void kill() override { killed_->store(true); }

 private:
  Script script_;
  std::size_t next_{0};
  std::shared_ptr<std::atomic<bool>> killed_;
};

// Hands out scripts by verb (hf-info or pull) and records every command.
struct Spawner final {
  std::mutex mutex;
  std::deque<Script> hf;
  std::deque<Script> pulls;
  std::vector<Recorded> recorded;
  std::shared_ptr<std::atomic<bool>> killed = std::make_shared<std::atomic<bool>>(false);
  secure_frontend::DownloadSeams seams(std::uint64_t free_bytes) {
    secure_frontend::DownloadSeams s;
    s.spawn = [this](const secure_frontend::EngineCommand& command) -> std::unique_ptr<secure_frontend::LineChild> {
      std::lock_guard lock(mutex);
      recorded.push_back(Recorded{command});
      const bool info = std::find(command.arguments.begin(), command.arguments.end(), "hf-info") != command.arguments.end();
      auto& queue = info ? hf : pulls;
      if (queue.empty()) return nullptr;
      Script script = queue.front();
      queue.pop_front();
      return std::make_unique<FakeChild>(std::move(script), killed);
    };
    s.disk = [free_bytes](const std::filesystem::path&) {
      return std::optional<secure_frontend::DiskSpace>{secure_frontend::DiskSpace{free_bytes, free_bytes * 2U}};
    };
    return s;
  }
};

std::string catalog_text() {
  return "{\"schema_version\":1,\"models\":["
         "{\"id\":\"qwen-small\",\"name\":\"Qwen small\",\"source\":\"strata\",\"family\":\"qwen\",\"engine\":\"qwen\","
         "\"about\":\"a test model\",\"repo\":\"acme/Qwen-GGUF\",\"revision\":\"" +
         std::string{kCommit} +
         "\",\"files\":[{\"path\":\"Q/m-00001-of-00002.gguf\",\"size\":1000,\"sha256\":\"" + kShaA +
         "\"},{\"path\":\"Q/m-00002-of-00002.gguf\",\"size\":2000,\"sha256\":\"" + kShaB +
         "\"}],\"prepare\":\"iq_pack\",\"pack_args\":[],\"expert_profile\":\"expert-profile.bin\",\"mmproj\":null},"
         "{\"id\":\"glm-small\",\"name\":\"GLM small\",\"source\":\"maya\",\"family\":\"glm53\",\"engine\":\"glm53\","
         "\"about\":\"\",\"repo\":\"acme/GLM-GGUF\",\"revision\":\"main\",\"files\":[{\"path\":\"S/g-00001-of-00001.gguf\",\"size\":null,"
         "\"sha256\":\"" + kShaA + "\"}],\"prepare\":\"unsupported\",\"pack_args\":[],\"expert_profile\":null,\"mmproj\":null}]}";
}

struct Fixture final {
  std::filesystem::path dir = secure_frontend_test::make_scratch_directory();
  Spawner spawner;
  std::unique_ptr<DownloadManager> manager;
  void start(const std::uint64_t free_bytes) {
    for (const char* name : {"downloads", "work", "cards"}) secure_frontend_test::make_private_directory(dir / name);
    secure_frontend::DownloadSettings settings;
    settings.catalog = secure_frontend::parse_download_catalog(catalog_text());
    settings.strata_executable = dir / "strata.exe";
    settings.config_file = dir / "config.json";
    settings.downloads_root = dir / "downloads";
    settings.work_dir = dir / "work";
    settings.cards_dir = dir / "cards";
    settings.child_environment = {{"SystemRoot", "C:\\Windows"}};
    settings.margin_bytes = 100;
    settings.log = [](std::string_view) {};
    settings.seams = spawner.seams(free_bytes);
    manager = std::make_unique<DownloadManager>(std::move(settings));
  }
};

std::vector<std::string> pull_lines(const std::string& name) {
  return {"MANIFEST " + name + ":download " + std::string(64, 'c'), "FILE Q/m-00001-of-00002.gguf 1000",
          "BYTES Q/m-00001-of-00002.gguf 500 1000", "BYTES Q/m-00001-of-00002.gguf 1000 1000", "FINISHED Q/m-00001-of-00002.gguf ok",
          "FILE Q/m-00002-of-00002.gguf 2000", "BYTES Q/m-00002-of-00002.gguf 2000 2000", "FINISHED Q/m-00002-of-00002.gguf ok",
          "RESULT ok"};
}

bool has(const std::string& text, const std::string& part) { return text.find(part) != std::string::npos; }

void catalog_cards_and_the_disk_check() {
  Fixture f;
  f.start(1000);
  const std::string listed = f.manager->list_json();
  expect(has(listed, "\"id\":\"qwen-small\"") && has(listed, "\"id\":\"glm-small\"") && has(listed, "\"free_bytes\":1000"),
         "the cards and the free space are listed: " + listed);
  expect(has(listed, "\"size_bytes\":3000") && has(listed, "\"needed_bytes\":3100") && has(listed, "\"fits\":false"),
         "a card that does not fit says so (size, needed with the margin): " + listed);
  const auto refused = f.manager->start("qwen-small");
  expect(refused && refused->status == 507 && refused->code == "insufficient_storage", "a start that does not fit is refused (O2)");
  const auto unknown = f.manager->start("nothing");
  expect(unknown && unknown->status == 404, "an unknown card");
  expect(f.spawner.recorded.empty(), "a refusal spawns nothing");
  expect(has(listed, "the GLM-5.3 engine is not built"), "a GLM card says it is download only");
}

void pull_runs_strata_and_tracks_progress() {
  Fixture f;
  f.spawner.pulls.push_back(Script{pull_lines("qwen-small")});
  f.start(1U << 30U);
  expect(!f.manager->start("qwen-small").has_value(), "the start is accepted");
  expect(f.manager->wait_idle(std::chrono::seconds(10)), "the download ends");
  const std::string listed = f.manager->list_json();
  expect(has(listed, "\"id\":\"qwen-small\"") && has(listed, "\"state\":\"installed\"") && has(listed, "\"bytes\":3000"),
         "the card is installed (no prepare step configured): " + listed);
  expect(f.spawner.recorded.size() == 1U, "one child");
  if (f.spawner.recorded.size() != 1U) return;
  const auto& command = f.spawner.recorded[0].command;
  const auto manifest_path = f.dir / "work" / "qwen-small.manifest.json";
  std::ifstream in(manifest_path, std::ios::binary);
  std::ostringstream text;
  text << in.rdbuf();
  const std::string digest = secure_frontend::to_hex(secure_frontend::sha256(text.str()));
  const std::vector<std::string> expected{"--config",
                                          secure_frontend::path_to_utf8(f.dir / "config.json"),
                                          "pull",
                                          "--manifest",
                                          secure_frontend::path_to_utf8(manifest_path),
                                          "--trust-manifest",
                                          "sha256:" + digest,
                                          "--yes",
                                          "--progress-lines"};
  expect(command.executable == f.dir / "strata.exe" && command.arguments == expected && !command.insert_serve &&
             command.environment.size() == 1U && command.working_directory == f.dir / "work",
         "strata pull with the written manifest, trusted by its digest, a closed environment");
  secure_frontend::ManifestRules release;
  release.allow_raw_profile = false;
  const auto parsed = secure_frontend::parse_manifest(text.str(), release);
  const auto* manifest = std::get_if<secure_frontend::ParsedManifest>(&parsed);
  expect(manifest != nullptr && manifest->manifest.profile == secure_frontend::ManifestProfile::gguf &&
             manifest->manifest.hosts == std::vector<std::string>{"huggingface.co"} &&
             manifest->manifest.files.size() == 2U &&
             manifest->manifest.files[0].sources ==
                 std::vector<std::string>{"https://huggingface.co/acme/Qwen-GGUF/resolve/" + std::string{kCommit} +
                                          "/Q/m-00001-of-00002.gguf"},
         "the manifest: gguf, Hugging Face only, the pinned commit");
}

void failures_and_cancel() {
  Fixture f;
  f.spawner.pulls.push_back(Script{{"MANIFEST qwen-small:download x", "FILE Q/m-00001-of-00002.gguf 1000", "RESULT digest_mismatch"}, 3});
  f.spawner.pulls.push_back(Script{{"MANIFEST qwen-small:download x", "FILE Q/m-00001-of-00002.gguf 1000",
                                    "BYTES Q/m-00001-of-00002.gguf 10 1000"},
                                   0, true});
  f.start(1U << 30U);
  expect(!f.manager->start("qwen-small").has_value() && f.manager->wait_idle(std::chrono::seconds(10)), "the first attempt runs");
  const std::string failed = f.manager->list_json();
  expect(has(failed, "\"state\":\"failed\"") && has(failed, "SHA-256"), "a digest mismatch fails with a reason: " + failed);
  expect(!f.manager->start("qwen-small").has_value(), "a failed card starts again");
  for (int i = 0; i < 200 && !has(f.manager->list_json(), "\"state\":\"downloading\""); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  expect(has(f.manager->list_json(), "\"active\":{\"id\":\"qwen-small\""), "the active transfer is reported");
  expect(!f.manager->cancel("qwen-small").has_value(), "a cancel is accepted");
  expect(f.manager->wait_idle(std::chrono::seconds(10)), "the cancel ends the transfer");
  expect(has(f.manager->list_json(), "\"state\":\"cancelled\"") && f.spawner.killed->load(), "cancelled, the child killed");
}

void maya_main_is_resolved_and_checked() {
  Fixture f;
  f.spawner.hf.push_back(Script{{"{\"repo\":\"acme/GLM-GGUF\",\"commit\":\"" + std::string{kCommit} +
                                 "\",\"files\":[{\"path\":\"S/g-00001-of-00001.gguf\",\"size\":4000,\"sha256\":\"" + kShaA + "\"}]}"}});
  f.spawner.pulls.push_back(Script{{"RESULT ok"}});
  f.spawner.hf.push_back(Script{{"{\"repo\":\"acme/GLM-GGUF\",\"commit\":\"" + std::string{kCommit} +
                                 "\",\"files\":[{\"path\":\"S/g-00001-of-00001.gguf\",\"size\":4000,\"sha256\":\"" + kShaB + "\"}]}"}});
  f.start(1U << 30U);
  expect(!f.manager->start("glm-small").has_value() && f.manager->wait_idle(std::chrono::seconds(10)), "a Maya card runs");
  expect(f.spawner.recorded.size() == 2U && f.spawner.recorded[0].command.arguments.back() ==
                                                "https://huggingface.co/acme/GLM-GGUF/resolve/main/S/g-00001-of-00001.gguf",
         "main is looked up first through strata hf-info");
  std::ifstream in(f.dir / "work" / "glm-small.manifest.json", std::ios::binary);
  std::ostringstream text;
  text << in.rdbuf();
  expect(has(text.str(), "/resolve/" + std::string{kCommit} + "/S/g-00001-of-00001.gguf") && has(text.str(), "\"size\":4000") &&
             has(text.str(), "\"profile\":\"glm53\""),
         "the manifest pins the resolved commit and size: " + text.str());
  expect(has(f.manager->list_json(), "\"state\":\"installed\""), "installed (GLM: download only)");
  // A second start whose lookup reports another SHA-256 refuses before any pull.
  Fixture g;
  g.spawner.hf.push_back(Script{{"{\"repo\":\"acme/GLM-GGUF\",\"commit\":\"" + std::string{kCommit} +
                                 "\",\"files\":[{\"path\":\"S/g-00001-of-00001.gguf\",\"size\":4000,\"sha256\":\"" + kShaB + "\"}]}"}});
  g.start(1U << 30U);
  expect(!g.manager->start("glm-small").has_value() && g.manager->wait_idle(std::chrono::seconds(10)), "the second runs");
  const std::string listed = g.manager->list_json();
  expect(has(listed, "\"state\":\"failed\"") && has(listed, "no longer match") && g.spawner.recorded.size() == 1U,
         "a changed file is refused before any pull: " + listed);
}

// O2 for Maya's cards: their sizes are known only once "main" is resolved at start, so the free
// space is checked again then, before any pull. A paused Maya download keeps the commit it
// resolved: the resume pulls the same manifest (so the same partial files), with no new lookup.
void maya_sizes_meet_the_free_space_and_resume_keeps_the_commit() {
  const std::string answer = "{\"repo\":\"acme/GLM-GGUF\",\"commit\":\"" + std::string{kCommit} +
                             "\",\"files\":[{\"path\":\"S/g-00001-of-00001.gguf\",\"size\":4000,\"sha256\":\"" + kShaA + "\"}]}";
  Fixture f;
  f.spawner.hf.push_back(Script{{answer}});
  f.start(3000);
  expect(!f.manager->start("glm-small").has_value() && f.manager->wait_idle(std::chrono::seconds(10)), "the start is accepted (no size yet)");
  const std::string refused = f.manager->list_json();
  expect(has(refused, "\"state\":\"failed\"") && has(refused, "Insufficient disk space") && f.spawner.recorded.size() == 1U,
         "the resolved size does not fit: failed before any pull: " + refused);

  Fixture g;
  g.spawner.hf.push_back(Script{{answer}});
  g.spawner.pulls.push_back(Script{{"MANIFEST glm-small:download x", "FILE S/g-00001-of-00001.gguf 4000", "BYTES S/g-00001-of-00001.gguf 900 4000"},
                                   0, true});
  g.spawner.pulls.push_back(Script{{"RESULT ok"}});
  g.start(1U << 30U);
  expect(!g.manager->start("glm-small").has_value(), "a Maya download starts");
  for (int i = 0; i < 200 && !has(g.manager->list_json(), "\"bytes\":900"); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  expect(!g.manager->pause("glm-small").has_value() && g.manager->wait_idle(std::chrono::seconds(10)), "it pauses");
  g.spawner.killed->store(false);  // the fake's kill flag is shared by its children
  expect(!g.manager->start("glm-small").has_value() && g.manager->wait_idle(std::chrono::seconds(10)), "it resumes");
  expect(has(g.manager->list_json(), "\"state\":\"installed\""), "the resumed download completes: " + g.manager->list_json());
  expect(g.spawner.recorded.size() == 3U && g.spawner.recorded[1].command.arguments == g.spawner.recorded[2].command.arguments,
         "one lookup, then the same pull twice (" + std::to_string(g.spawner.recorded.size()) + " children)");
}

// After a Resume the rate counts from the bytes already kept, not from zero (else the first
// MB/s and ETA after a resume would count the whole kept part as one second's transfer).
void a_resume_counts_its_rate_from_the_kept_bytes() {
  Fixture f;
  f.spawner.pulls.push_back(Script{{"MANIFEST qwen-small:download x", "FILE Q/m-00001-of-00002.gguf 1000",
                                    "BYTES Q/m-00001-of-00002.gguf 900 1000"},
                                   0, true});
  f.spawner.pulls.push_back(Script{{"MANIFEST qwen-small:download x", "FILE Q/m-00001-of-00002.gguf 1000",
                                    "BYTES Q/m-00001-of-00002.gguf 900 1000", "#sleep 1100", "BYTES Q/m-00001-of-00002.gguf 950 1000"},
                                   0, true});
  f.start(1U << 30U);
  expect(!f.manager->start("qwen-small").has_value(), "the download starts");
  for (int i = 0; i < 200 && !has(f.manager->list_json(), "\"bytes\":900"); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  expect(!f.manager->pause("qwen-small").has_value() && f.manager->wait_idle(std::chrono::seconds(10)), "it pauses at 900 bytes");
  f.spawner.killed->store(false);
  expect(!f.manager->start("qwen-small").has_value(), "it resumes");
  std::string listed;
  for (int i = 0; i < 300 && !has(listed = f.manager->list_json(), "\"bytes\":950"); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  const auto at = listed.find("\"rate_bps\":");
  const double rate = at == std::string::npos ? -1.0 : std::stod(listed.substr(at + 11U));
  expect(rate > 0.0 && rate < 200.0, "about 50 bytes in 1.1 s, not the kept 950: " + listed.substr(0, 300));
  expect(!f.manager->cancel("qwen-small").has_value() && f.manager->wait_idle(std::chrono::seconds(10)), "a cancel ends it");
}

void pasted_links() {
  Fixture f;
  f.spawner.hf.push_back(Script{{"{\"repo\":\"someone/Model-GGUF\",\"commit\":\"" + std::string{kCommit} +
                                 "\",\"files\":[{\"path\":\"model-Q4.gguf\",\"size\":5000,\"sha256\":\"" + kShaA + "\"}]}"}});
  f.spawner.pulls.push_back(Script{{"RESULT ok"}});
  f.start(1U << 30U);
  const auto refused = f.manager->check_link("https://example.com/someone/Model-GGUF/resolve/main/model-Q4.gguf");
  expect(refused.refusal && refused.refusal->status == 400 && !refused.reason.empty() && f.spawner.recorded.empty(),
         "a link off Hugging Face is refused in the server, before any child (O4)");
  const auto not_gguf = f.manager->check_link("https://huggingface.co/someone/Model/resolve/main/model.safetensors");
  expect(not_gguf.refusal && not_gguf.refusal->status == 400 && f.spawner.recorded.empty(), "a file that is not a .gguf (O4)");
  const std::string link = "https://huggingface.co/someone/Model-GGUF/resolve/main/model-Q4.gguf";
  expect(f.manager->start_link(link).has_value(), "a link must be checked before it starts");
  const auto checked = f.manager->check_link(link);
  expect(checked.confirm_json && has(*checked.confirm_json, "\"commit\":\"" + std::string{kCommit} + "\"") &&
             has(*checked.confirm_json, "\"size_bytes\":5000") && has(*checked.confirm_json, "\"fits\":true"),
         "the confirmation: commit, files, size, fits");
  expect(!f.manager->start_link(link).has_value() && f.manager->wait_idle(std::chrono::seconds(10)), "the confirmed link downloads");
  const std::string listed = f.manager->list_json();
  expect(has(listed, "\"source\":\"custom\"") && has(listed, "\"state\":\"installed\""), "a custom card, installed: " + listed);
  // It survives a restart (custom.json under the work folder).
  f.manager.reset();
  secure_frontend::DownloadSettings again;
  again.catalog = secure_frontend::parse_download_catalog(catalog_text());
  again.strata_executable = f.dir / "strata.exe";
  again.config_file = f.dir / "config.json";
  again.downloads_root = f.dir / "downloads";
  again.work_dir = f.dir / "work";
  again.cards_dir = f.dir / "cards";
  again.log = [](std::string_view) {};
  again.seams = f.spawner.seams(1U << 30U);
  DownloadManager restarted(std::move(again));
  expect(has(restarted.list_json(), "\"id\":\"hf-model-gguf-model-q4\""), "the custom card is back after a restart");
}


// Owner: "Have a download pause and resume functionality". Pause stops the transfer and keeps
// the partial files (SP4's pull resumes from them); Resume is a start of the same manifest (the
// same digest, so the same staging); Cancel stops and discards the partials (`strata rm
// --partials <id>:download`).
void pause_resume_and_cancel_discards() {
  Fixture f;
  f.spawner.pulls.push_back(Script{{"MANIFEST qwen-small:download x", "FILE Q/m-00001-of-00002.gguf 1000",
                                    "BYTES Q/m-00001-of-00002.gguf 400 1000"},
                                   0, true});
  f.spawner.pulls.push_back(Script{pull_lines("qwen-small")});
  f.start(1U << 30U);
  expect(!f.manager->start("qwen-small").has_value(), "the download starts");
  for (int i = 0; i < 200 && !has(f.manager->list_json(), "\"bytes\":400"); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  expect(!f.manager->pause("qwen-small").has_value() && f.manager->wait_idle(std::chrono::seconds(10)), "a pause is accepted");
  const std::string paused = f.manager->list_json();
  expect(has(paused, "\"state\":\"paused\"") && has(paused, "\"bytes\":400") && f.spawner.killed->load(),
         "paused: the child stopped, the bytes kept: " + paused);
  f.spawner.killed->store(false);
  expect(!f.manager->start("qwen-small").has_value() && f.manager->wait_idle(std::chrono::seconds(10)), "a resume is a start");
  expect(has(f.manager->list_json(), "\"state\":\"installed\""), "the resumed download completes");
  expect(f.spawner.recorded.size() == 2U && f.spawner.recorded[0].command.arguments == f.spawner.recorded[1].command.arguments,
         "the resume pulls the same manifest (the same digest, so the same partial files)");
  const auto refused = f.manager->pause("qwen-small");
  expect(refused && refused->status == 409, "nothing to pause once installed");

  Fixture g;
  g.spawner.pulls.push_back(Script{{"MANIFEST qwen-small:download x", "FILE Q/m-00001-of-00002.gguf 1000"}, 0, true});
  g.spawner.pulls.push_back(Script{{"removed"}});  // the rm --partials child
  g.start(1U << 30U);
  expect(!g.manager->start("qwen-small").has_value(), "a second download starts");
  for (int i = 0; i < 200 && !has(g.manager->list_json(), "\"state\":\"downloading\""); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  expect(!g.manager->cancel("qwen-small").has_value() && g.manager->wait_idle(std::chrono::seconds(10)), "a cancel is accepted");
  const std::string cancelled = g.manager->list_json();
  expect(has(cancelled, "\"state\":\"cancelled\"") && has(cancelled, "\"bytes\":0"), "cancelled: nothing kept: " + cancelled);
  const bool discarded = g.spawner.recorded.size() == 2U && g.spawner.recorded[1].command.arguments ==
                                                               std::vector<std::string>{"--config",
                                                                                        secure_frontend::path_to_utf8(g.dir / "config.json"),
                                                                                        "rm", "--partials", "qwen-small:download"};
  expect(discarded, "the partial files are discarded by strata rm --partials");
}


// The download routes' JSON (the plan's contract): the list, a start by id or by a confirmed
// link, pause, cancel and the link check, each refusal an ApiError row.
void download_routes_answer_the_contract() {
  using secure_frontend::RouteId;
  Fixture f;
  f.spawner.pulls.push_back(Script{{"MANIFEST qwen-small:download x", "FILE Q/m-00001-of-00002.gguf 1000"}, 0, true});
  f.spawner.hf.push_back(Script{{"{\"repo\":\"someone/Model-GGUF\",\"commit\":\"" + std::string{kCommit} +
                                 "\",\"files\":[{\"path\":\"model-Q4.gguf\",\"size\":5000,\"sha256\":\"" + kShaA + "\"}]}"}});
  f.start(1U << 30U);
  auto& m = *f.manager;
  const auto answer = [&m](const RouteId route, const std::string& body) {
    return secure_frontend::download_route_answer(m, route, body);
  };
  const auto list = answer(RouteId::strata_downloads, "");
  expect(list.status == 200 && has(list.body, "\"object\":\"list\"") && has(list.body, "\"id\":\"qwen-small\""), "the list: " + list.body);
  expect(list.header_value("Content-Type") == std::optional<std::string_view>{"application/json; charset=utf-8"}, "served as JSON");
  const auto bad_json = answer(RouteId::strata_download_start, "{");
  expect(bad_json.status == 400 && has(bad_json.body, "\"code\":\"invalid_json\""), "a start body is JSON: " + bad_json.body);
  const auto no_id = answer(RouteId::strata_download_start, "{\"name\":\"qwen-small\"}");
  expect(no_id.status == 400 && has(no_id.body, "\"code\":\"invalid_request\""), "a start names an id or a url: " + no_id.body);
  const auto unknown = answer(RouteId::strata_download_start, "{\"id\":\"nope\"}");
  expect(unknown.status == 404 && has(unknown.body, "\"code\":\"model_not_found\""), "an unknown id: " + unknown.body);
  const auto started = answer(RouteId::strata_download_start, "{\"id\":\"qwen-small\"}");
  expect(started.status == 202 && has(started.body, "\"state\":\"queued\"") && has(started.body, "\"id\":\"qwen-small\""),
         "a start: 202 queued: " + started.body);
  const auto twice = answer(RouteId::strata_download_start, "{\"id\":\"qwen-small\"}");
  expect(twice.status == 409 && has(twice.body, "\"code\":\"download_in_progress\""), "already downloading: " + twice.body);
  for (int i = 0; i < 200 && !has(m.list_json(), "\"state\":\"downloading\""); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  const auto paused = answer(RouteId::strata_download_pause, "{\"id\":\"qwen-small\"}");
  expect(paused.status == 202 && has(paused.body, "\"state\":\"paused\""), "a pause: 202: " + paused.body);
  expect(m.wait_idle(std::chrono::seconds(10)) && has(m.list_json(), "\"state\":\"paused\""), "the card is paused");
  const auto again = answer(RouteId::strata_download_pause, "{\"id\":\"qwen-small\"}");
  expect(again.status == 409 && has(again.body, "\"code\":\"download_not_active\""), "nothing to pause: " + again.body);
  const auto cancelled = answer(RouteId::strata_download_cancel, "{\"id\":\"qwen-small\"}");
  expect(cancelled.status == 202 && has(cancelled.body, "\"state\":\"cancelled\"") && has(m.list_json(), "\"state\":\"cancelled\""),
         "a cancel of a paused download: 202: " + cancelled.body);
  const auto off_host = answer(RouteId::strata_download_link, "{\"url\":\"https://example.com/a/b/resolve/main/m.gguf\"}");
  expect(off_host.status == 400 && has(off_host.body, "\"code\":\"invalid_request\"") && has(off_host.body, "\"reason\":\""),
         "a link off Hugging Face: 400 with the fixed reason (O4): " + off_host.body);
  const std::string link = "https://huggingface.co/someone/Model-GGUF/resolve/main/model-Q4.gguf";
  const auto unconfirmed = answer(RouteId::strata_download_start, "{\"url\":\"" + link + "\"}");
  expect(unconfirmed.status == 400, "a link starts only with confirm true: " + unconfirmed.body);
  const auto checked = answer(RouteId::strata_download_link, "{\"url\":\"" + link + "\"}");
  expect(checked.status == 200 && has(checked.body, "\"confirm\":{") && has(checked.body, "\"size_bytes\":5000"), "the link check: " + checked.body);
  f.spawner.pulls.push_back(Script{{"RESULT ok"}});
  const auto custom = answer(RouteId::strata_download_start, "{\"url\":\"" + link + "\",\"confirm\":true}");
  expect(custom.status == 202 && has(custom.body, "\"id\":\"hf-model-gguf-model-q4\""), "the confirmed link starts: " + custom.body);
  expect(m.wait_idle(std::chrono::seconds(10)), "the custom download ends");
  const auto wrong_route = answer(RouteId::health, "");
  expect(wrong_route.status == 500, "another route is an internal error");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"catalog_cards_and_the_disk_check", catalog_cards_and_the_disk_check},
      {"pull_runs_strata_and_tracks_progress", pull_runs_strata_and_tracks_progress},
      {"failures_and_cancel", failures_and_cancel},
      {"maya_main_is_resolved_and_checked", maya_main_is_resolved_and_checked},
      {"pasted_links", pasted_links},
      {"a_resume_counts_its_rate_from_the_kept_bytes", a_resume_counts_its_rate_from_the_kept_bytes},
      {"maya_sizes_meet_the_free_space_and_resume_keeps_the_commit", maya_sizes_meet_the_free_space_and_resume_keeps_the_commit},
      {"pause_resume_and_cancel_discards", pause_resume_and_cancel_discards},
      {"download_routes_answer_the_contract", download_routes_answer_the_contract},
  }, failures);
}

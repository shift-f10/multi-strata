// SP4 Task 27 (spec §1.3, §1.5, §6.1, §8.3, D6/C6): the strata network verbs in-process.
#include "acquire_cases.hpp"
#include "secure_frontend/model_index_store.hpp"
#include "support/cli_harness.hpp"
#include "support/expect.hpp"
#include "support/fake_curl_support.hpp"
#include "support/pull_harness.hpp"

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#endif

namespace acquire_cases {
namespace {

namespace fx = secure_frontend_test::acquire;
using secure_frontend_test::expect;
using secure_frontend_test::cli::CliHarness;

// In-process network seams: a scripted transport serving `payload`, a fake probe, a scripted resolver.
struct NetworkSeams final {
  NetworkSeams(CliHarness& h, const std::vector<fx::PayloadFile>& payload) {
    std::string scenario;
    std::map<std::string, std::string> fixtures;
    for (const auto& f : payload) {
      scenario += "response https://fixture.example/fx/" + f.path + "\nstatus 200 OK\nbody-file " + f.path + "\nend\n";
      fixtures[f.path] = f.bytes;
    }
    transport = std::make_shared<secure_frontend_test::ScriptedTransport>(*secure_frontend_test::curl::parse_scenario(scenario), fixtures);
    probe = std::make_shared<secure_frontend_test::pull::FakeProbe>();
    h.services.transport = [t = transport](const secure_frontend::FrontendConfig&) {
      return std::unique_ptr<secure_frontend::HopTransport>(std::make_unique<secure_frontend_test::pull::ForwardTransport>(*t));
    };
    h.services.probe = [p = probe](const secure_frontend::FrontendConfig&) {
      return std::unique_ptr<secure_frontend::DownloaderProbe>(std::make_unique<secure_frontend_test::pull::ForwardProbe>(*p));
    };
    h.services.resolver = [] {
      auto r = std::make_unique<secure_frontend_test::ScriptedResolver>();
      r->answers["fixture.example"] = {secure_frontend::make_ipv4(93, 184, 216, 34)};
      return std::unique_ptr<secure_frontend::Resolver>(std::move(r));
    };
    h.services.clock = &clock;
  }
  std::shared_ptr<secure_frontend_test::ScriptedTransport> transport;
  std::shared_ptr<secure_frontend_test::pull::FakeProbe> probe;
  secure_frontend_test::ManualClock clock;
};

std::string write_manifest(CliHarness& h, const std::string& text) {
  const auto path = h.scratch / "third-party.json";
  secure_frontend_test::write_file(path, text);
  return path.string();
}

}  // namespace

void pull_cli_prints_summary_and_installs() {
  CliHarness h;
  NetworkSeams seams(h, fx::qwen_payload());
  const auto text = fx::manifest_text("m", "t", 1, fx::qwen_payload());
  const std::string digest = secure_frontend::to_hex(secure_frontend::sha256(text));
  const int code = h.run({"pull", "--manifest", write_manifest(h, text), "--trust-manifest", "sha256:" + digest, "--yes"});
  expect(code == 0, "pull exits 0: " + h.err);
  expect(h.out.find("manifest sha256: " + digest) != std::string::npos && h.out.find("hosts: fixture.example") != std::string::npos,
         "summary: full manifest digest, hosts only");
  expect(h.out.find("The source host sees your IP address and which files you download.") != std::string::npos, "privacy sentence");
  expect(h.out.find("https://fixture.example/fx/") == std::string::npos, "never a source URL, only hosts");
  expect(seams.probe->calls == 1, "probe ran after confirmation");
  const auto index = std::get<secure_frontend::ModelIndex>(secure_frontend::read_model_index(h.models()));
  expect(index.models.size() == 1 && index.models.front().name == "m", "installed and indexed");
}

void run_missing_model_non_interactive_exits_2() {
  CliHarness h;
  NetworkSeams seams(h, fx::qwen_payload());
  const int code = h.run({"run", "fixture-qwen:t1"});
  expect(code == 2 && seams.probe->calls == 0 && seams.transport->argvs.empty(), "non-interactive No: exit 2, nothing spawned");
  expect(h.out.find("fixture-qwen:t1 is not installed") != std::string::npos, "says why it asks");
}

void run_missing_model_prompts_and_decline_exits_2() {
  CliHarness h;
  NetworkSeams seams(h, fx::qwen_payload());
  const int code = h.run({"run", "fixture-qwen:t1"}, "n\n", true);
  expect(code == 2 && h.out.find("[y/N]") != std::string::npos, "the same confirmation prompt; n declines");
  expect(seams.transport->argvs.empty(), "no transfer after No");
}

void run_installed_model_needs_no_network() {
  CliHarness h;
  NetworkSeams seams(h, fx::qwen_payload());
  (void)secure_frontend_test::cli::install(h);
  expect(h.run({"run", "m:t"}) == 0 && h.out.find("model ready: m:t") != std::string::npos, "ready");
  expect(seams.probe->calls == 0 && seams.transport->argvs.empty(), "run with the model installed is local");
  // Ruling R11: neither installed nor in this release's catalog: model_unknown (exit 5) plus the import hint.
  expect(h.run({"run", "nosuch:t"}) == 5 && h.err.find("error: model_unknown: nosuch:t") != std::string::npos &&
             h.err.find("strata import") != std::string::npos,
         "unknown model: fixed reason, exit 5, import hint");
  expect(seams.probe->calls == 0 && seams.transport->argvs.empty(), "an unknown model spawns nothing");
}

void run_refuses_glm53_without_engine() {
  CliHarness h;
  NetworkSeams seams(h, fx::qwen_payload());
  const std::string glm =
      "{\"format\":\"strata-model-manifest\",\"schema_version\":1,\"name\":\"g\",\"tag\":\"t\",\"version\":\"2026.10.14.1\","
      "\"sequence\":1,\"profile\":\"glm53\",\"engine\":{\"family\":\"glm\",\"min_version\":\"0.0.1\"},"
      "\"license\":{\"id\":\"MIT\",\"url\":\"https://fixture.example/l\",\"bundle_allowed\":true},\"hosts\":[\"fixture.example\"],"
      "\"files\":[{\"path\":\"w.gguf\",\"role\":\"weights\",\"size\":1,"
      "\"sha256\":\"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\",\"sources\":[]}],"
      "\"launch\":{\"native\":\"w.gguf\"}}";
  const auto root = h.models();
  const auto manifest = fx::trusted(glm, secure_frontend::ModelOrigin::third_party);
  const auto key = secure_frontend::staging_key(manifest.parsed.sha256);
  (void)secure_frontend::ensure_directory(root, secure_frontend::staging_dir_path(key));
  (void)secure_frontend::write_new_file(root, secure_frontend::join_rel(secure_frontend::staging_dir_path(key), "MANIFEST"), glm);
  (void)secure_frontend::write_new_file(root, secure_frontend::join_rel(secure_frontend::staging_dir_path(key), "w.gguf"), "a");
  fx::FakeLoaded nobody;
  const secure_frontend::StoreEnvironment env;
  (void)secure_frontend::publish_staged(root, key, manifest, nobody, env, true);
  expect(h.run({"run", "g:t"}) == 11 && h.err.find("engine_profile_unavailable") != std::string::npos, "exit 11 until SP6");
}

#if defined(SECURE_FRONTEND_TEST_HOOKS)
void update_models_pulls_outdated_catalog_models() {
  CliHarness h;
  // fixture-qwen:t1 sequence 1 "from an older release"; this binary's catalog has sequence 2 with the committed payload.
  (void)secure_frontend_test::cli::install(h, 1, "", secure_frontend::ModelOrigin::catalog, "fixture-qwen", "t1");
  const std::filesystem::path payload_dir = secure_frontend_test::extra_arguments().at(0);
  std::vector<fx::PayloadFile> served;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(payload_dir)) {
    if (!entry.is_regular_file()) continue;
    served.push_back({entry.path().lexically_relative(payload_dir).generic_string(), secure_frontend::FileRole::pack,
                      secure_frontend_test::read_file(entry.path())});
  }
  NetworkSeams seams(h, served);
  // The committed catalog fixture's license url and notice differ from the installed one, so
  // §6.1 (F-21) asks for an interactive y even with --yes: answer it.
  const int code = h.run({"update", "--models", "--yes"}, "y\n", true);
  expect(code == 0, "update --models: " + h.err);
  expect(h.out.find("The license of fixture-qwen:t1 changes") != std::string::npos, "license change asked interactively");
  const auto index = std::get<secure_frontend::ModelIndex>(secure_frontend::read_model_index(h.models()));
  expect(index.models.size() == 1 && index.models.front().sequence == 2, "the catalog's newer manifest is installed");
  expect(h.out.find("version: 2026.10.14.1 (sequence 1) -> 2026.10.14.2 (sequence 2)") != std::string::npos, "diff printed first");
}
#endif

#if !defined(_WIN32) && defined(SECURE_FRONTEND_TEST_HOOKS)
namespace {

// §8.3 on Linux, end to end: a real `strata` child (args[0]) with the fake curl (args[1]) as
// pull.downloader, signalled from outside like a terminal or a service manager would.
struct StrataChild final {
  StrataChild() : fake(install()) {}

  secure_frontend_test::FakeCurlInstall install() {
    const auto& args = secure_frontend_test::extra_arguments();
    const auto payload = fx::qwen_payload();
    std::string scenario = "probe 8.4.0 OpenSSL/3.0.13\n";
    std::vector<std::pair<std::string, std::string>> fixtures;
    for (const auto& f : payload) {
      std::string name = f.path;
      std::replace(name.begin(), name.end(), '/', '_');
      fixtures.emplace_back(name, f.bytes);
      scenario += "response https://fixture.example/fx/" + f.path + "\nstatus 200 OK\nbody-file " + name + "\n" +
                  (f.path == payload[0].path ? std::string{"delay-ms 20000\n"} : std::string{}) + "end\n";
    }
    auto installed = secure_frontend_test::install_fake_curl(h.scratch, args.at(1), scenario, fixtures);
    std::string text = secure_frontend_test::read_file(h.config);
    text.replace(text.find(h.missing_downloader()), h.missing_downloader().size(), "\"" + installed.executable.generic_string() + "\"");
    // No DNS in a test: with pull.proxy set the hop goes to the (never contacted) proxy literal.
    text.replace(text.find("}\n}\n"), 4, ", \"proxy\": \"http://127.0.0.1:9\"}\n}\n");
    secure_frontend_test::write_file(h.config, text);
    manifest = fx::manifest_text("m", "t", 1, payload);
    secure_frontend_test::write_file(h.scratch / "m.json", manifest);
    return installed;
  }

  // strata --test-record-file <record> --config <config> pull --manifest ... [--yes]; stdin is
  // `stdin_fd` (or /dev/null), stdout and stderr go to files in the scratch tree.
  void start(const bool yes, const int stdin_fd = -1) {
    std::vector<std::string> argv{secure_frontend_test::extra_arguments().at(0), "--test-record-file", record().string(), "--config",
                                  h.config.string(), "pull", "--manifest", (h.scratch / "m.json").string(), "--trust-manifest",
                                  "sha256:" + secure_frontend::to_hex(secure_frontend::sha256(manifest))};
    if (yes) argv.emplace_back("--yes");
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    if (stdin_fd >= 0) posix_spawn_file_actions_adddup2(&actions, stdin_fd, 0);
    else posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&actions, 1, (h.scratch / "strata.out").c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    posix_spawn_file_actions_addopen(&actions, 2, (h.scratch / "strata.err").c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    std::vector<char*> raw;
    for (auto& a : argv) raw.push_back(a.data());
    raw.push_back(nullptr);
    char* envp[] = {nullptr};
    started = posix_spawn(&pid, argv[0].c_str(), &actions, nullptr, raw.data(), envp) == 0;
    posix_spawn_file_actions_destroy(&actions);
  }

  [[nodiscard]] std::filesystem::path record() const { return h.scratch / "downloader-record.log"; }
  [[nodiscard]] std::string out() const { return secure_frontend_test::read_file(h.scratch / "strata.out"); }
  [[nodiscard]] std::string err() const { return secure_frontend_test::read_file(h.scratch / "strata.err"); }

  // Waits up to `seconds` for exit; re-sends `signal` every 200 ms while waiting (0: none).
  // -1: still running (then killed); otherwise the exit status or 128 + the terminating signal.
  int wait_for_exit(const int signal, const int seconds) {
    for (int i = 0; i < seconds * 5; ++i) {
      int status = 0;
      const pid_t done = ::waitpid(pid, &status, WNOHANG);
      if (done == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
      if (signal != 0) ::kill(pid, signal);
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    ::kill(pid, SIGKILL);
    ::waitpid(pid, nullptr, 0);
    return -1;
  }

  // Any live process whose executable is the fake curl.
  [[nodiscard]] bool curl_alive() const {
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
      std::error_code ec;
      const auto exe = std::filesystem::read_symlink(entry.path() / "exe", ec);
      if (!ec && exe == fake.executable) return true;
    }
    return false;
  }

  CliHarness h;
  std::string manifest;  // before `fake`: install() writes it
  secure_frontend_test::FakeCurlInstall fake;
  pid_t pid{-1};
  bool started{false};
};

void signal_during_download(const int signal) {
  StrataChild child;
  child.start(true);
  expect(child.started, "strata starts");
  if (!child.started) return;
  for (int i = 0; i < 200 && secure_frontend_test::read_record_lines(child.record()).size() < 2; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  expect(secure_frontend_test::read_record_lines(child.record()).size() == 2, "probe + the first (delayed) transfer started");
  expect(child.curl_alive(), "positive control: the delayed downloader is running and is detected");
  ::kill(child.pid, signal);
  const int code = child.wait_for_exit(0, 15);
  expect(code == 8, "interrupted: exit 8 (got " + std::to_string(code) + "): " + child.err());
  expect(child.err().find("error: interrupted") != std::string::npos, "fixed reason");
  expect(child.out().find("run the same strata pull --manifest command again to resume") != std::string::npos, "resume hint");
  expect(!std::filesystem::exists(child.h.models_path / "index.json"), "never indexed");
  expect(!child.curl_alive(), "no downloader survives");
}

}  // namespace

void dl04_sigint_during_download_exits_8() { signal_during_download(SIGINT); }
void dl04_sigterm_during_download_exits_8() { signal_during_download(SIGTERM); }

// §8.2 (controller ruling): SIGINT at a pending [y/N] is `interrupted` (exit 8) with nothing
// spawned; Ctrl-D (EOF) there stays a plain No (exit 2).
void interrupt_at_confirmation_prompt_exits_8() {
  for (const bool eof : {false, true}) {
    StrataChild child;
    const int master = ::posix_openpt(O_RDWR | O_NOCTTY);
    expect(master >= 0 && ::grantpt(master) == 0 && ::unlockpt(master) == 0, "a pseudo-terminal for an interactive stdin");
    if (master < 0) return;
    const int terminal = ::open(::ptsname(master), O_RDWR | O_NOCTTY);
    child.start(false, terminal);
    ::close(terminal);
    expect(child.started, "strata starts");
    if (!child.started) {
      ::close(master);
      return;
    }
    for (int i = 0; i < 200 && child.out().find("[y/N]") == std::string::npos; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    expect(child.out().find("[y/N]") != std::string::npos, "blocked at the confirmation prompt");
    int code = -1;
    if (eof) {
      expect(::write(master, "\x04", 1) == 1, "Ctrl-D");
      code = child.wait_for_exit(0, 15);
      expect(code == 2, "EOF at the prompt is a plain No: exit 2 (got " + std::to_string(code) + "): " + child.err());
    } else {
      // Re-sent while waiting: a signal landing before the read starts is still seen.
      code = child.wait_for_exit(SIGINT, 15);
      expect(code == 8, "SIGINT at the prompt: exit 8 (got " + std::to_string(code) + "): " + child.err());
      expect(child.err().find("error: interrupted") != std::string::npos, "interrupted, not declined");
    }
    ::close(master);
    expect(!std::filesystem::exists(child.record()) || secure_frontend_test::read_record_lines(child.record()).empty(),
           "nothing spawned: no downloader record");
    expect(!std::filesystem::exists(child.h.models_path / "index.json"), "never indexed");
  }
}
#endif

#if defined(_WIN32) && defined(SECURE_FRONTEND_TEST_HOOKS)
void dl04_interrupt_during_download_never_indexed_windows() {
  CliHarness h;
  const auto& args = secure_frontend_test::extra_arguments();
  const auto payload = fx::qwen_payload();
  std::string scenario = "probe 8.4.0 Schannel\n";
  std::vector<std::pair<std::string, std::string>> fixtures;
  for (const auto& f : payload) {
    std::string name = f.path;
    std::replace(name.begin(), name.end(), '/', '_');  // flat fixture names in the scenario directory
    fixtures.emplace_back(name, f.bytes);
    scenario += "response https://fixture.example/fx/" + f.path + "\nstatus 200 OK\nbody-file " + name + "\n" +
                (f.path == payload[0].path ? std::string{"delay-ms 20000\n"} : std::string{}) + "end\n";
  }
  const auto fake = secure_frontend_test::install_fake_curl(h.scratch, args.at(1), scenario, fixtures);
  std::string text = secure_frontend_test::read_file(h.config);
  text.replace(text.find(h.missing_downloader()), h.missing_downloader().size(), "\"" + fake.executable.generic_string() + "\"");
  text.replace(text.find("}\n}\n"), 4, ", \"proxy\": \"http://127.0.0.1:9\"}\n}\n");  // no DNS: the proxy (never contacted by the fake) resolves
  secure_frontend_test::write_file(h.config, text);
  const auto manifest = fx::manifest_text("m", "t", 1, payload);
  secure_frontend_test::write_file(h.scratch / "m.json", manifest);
  const auto record = h.scratch / "downloader-record.log";
  const std::vector<std::string> argv{args.at(0), "--test-record-file", record.string(), "--config", h.config.string(), "pull",
                                      "--manifest", (h.scratch / "m.json").string(), "--trust-manifest",
                                      "sha256:" + secure_frontend::to_hex(secure_frontend::sha256(manifest)), "--yes"};
  // Ruling I15: GenerateConsoleCtrlEvent reaches only processes on the caller's console. A
  // runner without one gets a fresh console here (a no-op when one is already attached).
  if (GetConsoleWindow() == nullptr) (void)AllocConsole();
  std::wstring command = secure_frontend_test::quote_windows_command_line(argv);
  STARTUPINFOW startup{};
  startup.cb = sizeof startup;
  PROCESS_INFORMATION info{};
  const BOOL started = CreateProcessW(std::filesystem::path(args.at(0)).wstring().c_str(), command.data(), nullptr, nullptr, FALSE,
                                      CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &startup, &info);
  expect(started != 0, "strata starts");
  if (started == 0) return;
  for (int i = 0; i < 200 && secure_frontend_test::read_record_lines(record).size() < 2; ++i) Sleep(50);  // probe + first transfer
  GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, info.dwProcessId);
  WaitForSingleObject(info.hProcess, 30000);
  DWORD code = 0;
  GetExitCodeProcess(info.hProcess, &code);
  CloseHandle(info.hThread);
  CloseHandle(info.hProcess);
  expect(code == 8, "console Ctrl-Break: the Job is terminated, exit 8");
  expect(std::get<secure_frontend::ModelIndex>(secure_frontend::read_model_index(h.models())).models.empty(), "never indexed");
}
#endif

}  // namespace acquire_cases

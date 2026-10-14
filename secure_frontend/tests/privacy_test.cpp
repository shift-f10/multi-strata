// SP4 Task 28 (spec §7.1-§7.3, §10.1, §10.3 DL-01 and PRIV-01..04, §10.5): the privacy lifecycle
// proofs and the hooks-OFF (release-only) proofs.
#include "secure_frontend/test_hooks.hpp"
#include "support/cli_harness.hpp"
#include "support/expect.hpp"
#include "support/fake_curl_support.hpp"
#include "support/process_runner.hpp"
#include "support/pull_harness.hpp"
#include "support/server_fixture.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <iphlpapi.h>
#else
#include <csignal>
#include <sys/types.h>
#endif

namespace {

namespace fx = secure_frontend_test::acquire;
using secure_frontend_test::ChildProcess;
using secure_frontend_test::contains;
using secure_frontend_test::expect;
using secure_frontend_test::ServerFixture;

std::string marker() { return std::string{"SECURE_FRONTEND_TEST_"} + "HOOKS_COMPILED_IN"; }  // built at run time

std::string file_text(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return std::string{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

// A strata config (CliHarness) whose downloader is the fake and whose proxy is a
// loopback literal, so pull never resolves a name: the fake gets --proxy and never connects.
struct StrataSetup final {
  secure_frontend_test::cli::CliHarness h;
  secure_frontend_test::FakeCurlInstall fake;
  std::filesystem::path record;
  std::string manifest_path;
  std::string digest;

  explicit StrataSetup(const std::filesystem::path& built_fake) : record(h.scratch / "downloader-record.log") {
    const auto payload = fx::qwen_payload();
    std::string scenario = "probe 8.4.0 OpenSSL/3.0.13\n";
    std::vector<std::pair<std::string, std::string>> fixtures;
    for (const auto& f : payload) {
      std::string name = f.path;
      std::replace(name.begin(), name.end(), '/', '_');
      fixtures.emplace_back(name, f.bytes);
      scenario += "response https://fixture.example/fx/" + f.path + "\nstatus 200 OK\nbody-file " + name + "\nend\n";
    }
    fake = secure_frontend_test::install_fake_curl(h.scratch, built_fake, scenario, fixtures);
    std::string text = secure_frontend_test::read_file(h.config);
    text.replace(text.find(h.missing_downloader()), h.missing_downloader().size(), "\"" + fake.executable.generic_string() + "\"");
    text.replace(text.rfind("}\n}\n"), 4, ", \"proxy\": \"http://127.0.0.1:9\"}\n}\n");
    secure_frontend_test::write_file(h.config, text);
    const auto manifest = fx::manifest_text("m", "t", 1, payload);
    secure_frontend_test::write_file(h.scratch / "m.json", manifest);
    manifest_path = (h.scratch / "m.json").string();
    digest = secure_frontend::to_hex(secure_frontend::sha256(manifest));
  }

  secure_frontend_test::ProcessResult strata(const std::filesystem::path& binary, std::vector<std::string> verb_args,
                                             std::vector<std::pair<std::string, std::string>> environment = {}) const {
    std::vector<std::string> args{"--test-record-file", record.string(), "--config", h.config.string()};
    args.insert(args.end(), verb_args.begin(), verb_args.end());
    return secure_frontend_test::run_to_completion(secure_frontend_test::ProcessSpec{binary, args, std::move(environment)});
  }
};

std::string chat_body() {
  return R"({"model":"qwen-local","messages":[{"role":"user","content":"strata pull qwen3.8-flash-next"}]})";
}

bool status_is(const std::string& response, const std::string_view status) {
  return response.rfind(std::string{"HTTP/1.1 "} + std::string{status}, 0) == 0;
}

// Ruling R10: the lifecycle waits for READY and proves a chat completes (200) before the stop.
void lifecycle(const ServerFixture& f, ChildProcess& server) {
  expect(f.wait_engine_ready(std::chrono::seconds(30)), "engine ready: " + server.stderr_text());
  expect(status_is(f.request("GET", "/health", f.bearer()), "200"), "health is 200 once ready");
  expect(status_is(f.request("GET", "/v1/models", f.bearer()), "200"), "models is 200");
  const auto chat = f.request("POST", "/v1/chat/completions", f.bearer(), chat_body());
  expect(status_is(chat, "200"), "a chat completes with 200: " + chat.substr(0, 64));
  server.terminate();
}

// ServerFixture::base_flags() already carries --expert (Task 24a): the fixture serves an inventory model.
std::vector<std::string> expert(const ServerFixture& f) { return f.base_flags(); }

#if !defined(_WIN32)
// ServerFixture::start with an extended environment (the shim): waits until the port accepts.
bool start_with(const ServerFixture& f, ChildProcess& server, const std::vector<std::string>& flags,
                const std::vector<std::pair<std::string, std::string>>& environment) {
  if (!server.start(secure_frontend_test::ProcessSpec{f.server_executable, flags, environment})) return false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  while (std::chrono::steady_clock::now() < deadline) {
    if (server.wait_for(std::chrono::milliseconds(0)).has_value()) return false;
    if (secure_frontend_test::can_connect(f.port)) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return false;
}

// The direct children of `pid` (every thread's /proc/<pid>/task/<tid>/children).
std::vector<long> children_of(const long pid) {
  std::vector<long> children;
  std::error_code error;
  for (const auto& task : std::filesystem::directory_iterator("/proc/" + std::to_string(pid) + "/task", error)) {
    std::ifstream input(task.path() / "children");
    for (long child = 0; input >> child;) children.push_back(child);
  }
  std::sort(children.begin(), children.end());
  children.erase(std::unique(children.begin(), children.end()), children.end());
  return children;
}

// The shim in the server's environment; `<audit>.loaded` proves it was mapped (the engine's
// environment is an allowlist, so only the server itself is audited).
std::vector<std::pair<std::string, std::string>> audited(const ServerFixture& f, const std::string& shim, const std::filesystem::path& audit) {
  auto environment = f.environment();
  environment.emplace_back("LD_PRELOAD", shim);
  environment.emplace_back("SF_CONNECT_AUDIT", audit.string());
  environment.emplace_back("SF_CONNECT_AUDIT_LOADED", audit.string() + ".loaded");
  return environment;
}

bool shim_was_loaded(const std::filesystem::path& audit) {
  return contains(file_text(audit.string() + ".loaded"), "loaded");
}
#endif

}  // namespace

// DL-01 tripwire (record channel): serve, health, models, chat and stop never spawn the downloader. Alone this
// is weak (the server can never create the record file): DL-01 is satisfied only by the three together —
// this tripwire, the socket audit (dl01_server_makes_no_outbound_connection[_windows]) and the link-set
// check (priv04_secure_server_does_not_link_acquisition).
void dl01_serve_and_infer_never_spawn_downloader() {
  ServerFixture f;
  const auto record = f.dir / "downloader-record.log";
  ChildProcess server;
  expect(f.start(server, expert(f)), "server starts: " + server.stderr_text());
  lifecycle(f, server);
  expect(!std::filesystem::exists(record), "no record file: the frontend created none, so it never prepared a spawn");
}

// DL-01 positive control: the same harness sees a pull's spawns.
void dl01_positive_control_pull_spawn_is_recorded() {
  const auto& args = secure_frontend_test::extra_arguments();  // [0] strata, [1] fake curl
  StrataSetup s(args.at(1));
  const auto result = s.strata(args.at(0), {"pull", "--manifest", s.manifest_path, "--trust-manifest", "sha256:" + s.digest, "--yes"});
  expect(result.exit_code == 0, "pull succeeds through the confined fake: " + result.err);
  const auto lines = secure_frontend_test::read_record_lines(s.record);
  bool transfer = false;
  for (const auto& line : lines) transfer = transfer || contains(line, "\"kind\":\"transfer\"");
  expect(transfer, "a transfer record exists");
}

#if !defined(_WIN32)
// DL-01 (socket audit, release-also): no outbound connection during a lifecycle; the shim is proven by a blocked positive control.
void dl01_server_makes_no_outbound_connection() {
  const auto& args = secure_frontend_test::extra_arguments();  // [0] server, [1] fake engine, [2] shim, [3] resolve probe
  ServerFixture f;
  const auto audit = f.dir / "connect-audit.log";
  ChildProcess server;
  expect(start_with(f, server, expert(f), audited(f, args.at(2), audit)), "server starts: " + server.stderr_text());
  lifecycle(f, server);
  expect(shim_was_loaded(audit), "the audit shim was loaded into the server");
  expect(!std::filesystem::exists(audit) || file_text(audit).empty(), "no non-loopback connect/sendto/getaddrinfo: " + file_text(audit));
  // Positive control: a process that does resolve a name is caught (and blocked, so nothing leaves the host).
  const auto control = f.dir / "control-audit.log";
  (void)secure_frontend_test::run_to_completion(secure_frontend_test::ProcessSpec{
      args.at(3), {}, {{"LD_PRELOAD", args.at(2)}, {"SF_CONNECT_AUDIT", control.string()}, {"SF_CONNECT_AUDIT_BLOCK", "1"}}});
  expect(contains(file_text(control), "getaddrinfo fixture.example"), "the shim records a name lookup (positive control)");
}

// PRIV-01: lifecycle including an engine crash and supervised restart makes no network use.
// The engine crashes from outside (SIGSEGV after READY, classified `crashed`): the fake's
// --crash-after-ready mode stops reading stdin until it crashes, so no generation of it could
// ever answer the 200 chat ruling R10 requires after the restart.
void priv01_lifecycle_and_crash_restart_make_no_network_use() {
  const auto& args = secure_frontend_test::extra_arguments();  // [0] server, [1] SP2 supervision fake engine, [2] shim
  ServerFixture f;
  const auto audit = f.dir / "connect-audit.log";
  ChildProcess server;
  expect(start_with(f, server, expert(f), audited(f, args.at(2), audit)), "server starts: " + server.stderr_text());
  expect(f.wait_engine_ready(std::chrono::seconds(30)), "first generation ready: " + server.stderr_text());
  const auto engines = children_of(server.pid());
  expect(engines.size() == 1U, "exactly one engine child, saw " + std::to_string(engines.size()));
  for (const long engine : engines) (void)::kill(static_cast<pid_t>(engine), SIGSEGV);  // the server set RLIMIT_CORE 0
  // Ruling R10: observe the restart from /health (ready, then not ready, then ready again) before auditing.
  bool left_ready = false;
  for (const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
       !left_ready && std::chrono::steady_clock::now() < deadline;) {
    left_ready = !contains(f.request("GET", "/health", f.bearer()), "\"engine\":\"ready\"");
    if (!left_ready) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  expect(left_ready, "the engine crash takes /health out of ready");
  expect(f.wait_engine_ready(std::chrono::seconds(30)), "the supervised restart is ready again: " + server.stderr_text());
  expect(contains(server.stderr_text(), "engine generation 1 ended: crashed"), "the supervisor saw a crash: " + server.stderr_text());
  lifecycle(f, server);
  expect(shim_was_loaded(audit), "the audit shim was loaded into the server");
  expect(!std::filesystem::exists(audit) || file_text(audit).empty(), "no network use across crash and restart: " + file_text(audit));
}
#else
namespace {

bool loopback_v6(const unsigned char* address) {
  static const unsigned char kLoopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  return std::equal(address, address + 16, kLoopback);
}

bool zero_v6(const unsigned char* address) { return std::all_of(address, address + 16, [](unsigned char b) { return b == 0; }); }

template <typename Fill>
std::vector<unsigned char> ip_table(Fill fill) {
  ULONG size = 0;
  (void)fill(nullptr, &size);
  std::vector<unsigned char> table(size + 4096U);
  size = static_cast<ULONG>(table.size());
  if (fill(table.data(), &size) != NO_ERROR) return {};
  return table;
}

// TCP (IPv4 and IPv6): a connection owned by `pid` whose remote end is not loopback (a listener's is 0).
// UDP (ruling R7): any local binding owned by `pid` that is not loopback.
std::vector<std::string> outbound_sockets(const DWORD pid) {
  std::vector<std::string> found;
  const auto tcp4 = ip_table([](void* t, ULONG* s) { return GetExtendedTcpTable(t, s, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0); });
  if (!tcp4.empty()) {
    const auto* rows = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(tcp4.data());
    for (DWORD i = 0; i < rows->dwNumEntries; ++i) {
      const auto& row = rows->table[i];
      const bool remote_loopback = (ntohl(row.dwRemoteAddr) >> 24U) == 127U || row.dwRemoteAddr == 0;
      if (row.dwOwningPid == pid && !remote_loopback) found.emplace_back("tcp4");
    }
  }
  const auto tcp6 = ip_table([](void* t, ULONG* s) { return GetExtendedTcpTable(t, s, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0); });
  if (!tcp6.empty()) {
    const auto* rows = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(tcp6.data());
    for (DWORD i = 0; i < rows->dwNumEntries; ++i) {
      const auto& row = rows->table[i];
      if (row.dwOwningPid == pid && !loopback_v6(row.ucRemoteAddr) && !zero_v6(row.ucRemoteAddr)) found.emplace_back("tcp6");
    }
  }
  const auto udp4 = ip_table([](void* t, ULONG* s) { return GetExtendedUdpTable(t, s, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0); });
  if (!udp4.empty()) {
    const auto* rows = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(udp4.data());
    for (DWORD i = 0; i < rows->dwNumEntries; ++i) {
      const auto& row = rows->table[i];
      if (row.dwOwningPid == pid && (ntohl(row.dwLocalAddr) >> 24U) != 127U) found.emplace_back("udp4");
    }
  }
  const auto udp6 = ip_table([](void* t, ULONG* s) { return GetExtendedUdpTable(t, s, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0); });
  if (!udp6.empty()) {
    const auto* rows = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(udp6.data());
    for (DWORD i = 0; i < rows->dwNumEntries; ++i) {
      const auto& row = rows->table[i];
      if (row.dwOwningPid == pid && !loopback_v6(row.ucLocalAddr)) found.emplace_back("udp6");
    }
  }
  return found;
}

}  // namespace

void dl01_server_makes_no_outbound_connection_windows() {
  ServerFixture f;
  ChildProcess server;
  expect(f.start(server, expert(f)), "server starts");
  const DWORD pid = static_cast<DWORD>(server.pid());
  std::vector<std::string> seen;
  for (int round = 0; round < 3; ++round) {
    if (round == 1) {
      expect(f.wait_engine_ready(std::chrono::seconds(30)), "engine ready");
      (void)f.request("GET", "/health", f.bearer());
      const auto chat = f.request("POST", "/v1/chat/completions", f.bearer(), chat_body());
      expect(status_is(chat, "200"), "a chat completes with 200: " + chat.substr(0, 64));
    }
    for (auto& kind : outbound_sockets(pid)) seen.push_back(std::move(kind));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  server.terminate();
  std::string kinds;
  for (const auto& kind : seen) kinds += kind + " ";
  expect(seen.empty(), "the server process owns no non-loopback TCP connection or UDP binding: " + kinds);
}
#endif

// PRIV-01: local verbs never spawn the downloader (ruling R9: each verb's exit code is asserted).
void priv01_local_verbs_never_spawn_downloader() {
  const auto& args = secure_frontend_test::extra_arguments();  // [0] strata, [1] fake curl
  StrataSetup s(args.at(1));
  const auto entry = secure_frontend_test::cli::install(s.h);
  const auto bundle = s.h.scratch / "bundle";
  const std::string trust = "sha256:" + entry.manifest_sha256;
  const std::vector<std::pair<std::vector<std::string>, int>> verbs{
      {{"list"}, 0}, {{"list", "--all"}, 0}, {{"show", "m:t"}, 0}, {{"show", "m:t", "--digests"}, 0},
      {{"export", "m:t", bundle.string()}, 0}, {{"verify", bundle.string(), "--trust-manifest", trust}, 0}, {{"doctor"}, 0},
      {{"run", "m:t"}, 0}, {{"update"}, 12}, {{"update", "--models"}, 0}, {{"rm", "m:t"}, 0},
      {{"import", bundle.string(), "--trust-manifest", trust, "--yes"}, 0}};
  for (const auto& [verb, expected] : verbs) {
    const auto result = s.strata(args.at(0), verb);
    std::string text;
    for (const auto& word : verb) text += word + " ";
    expect(result.exit_code == expected,
           "strata " + text + "exits " + std::to_string(expected) + ", saw " + std::to_string(result.exit_code) + ": " + result.err);
  }
  expect(!std::filesystem::exists(s.record), "list, show, export, verify, doctor, run (installed), update, rm, import: no spawn");
  // Ruling R9: update --models with an outdated catalog model (fixture-qwen:t1 at sequence 1; the hooks fixture
  // catalog has sequence 2). Its license changes (§6.1, F-21), so it needs an interactive y even with --yes:
  // answered No, it exits 2 and the probe (which runs only after a yes) is never spawned.
  (void)secure_frontend_test::cli::install(s.h, 1, "", secure_frontend::ModelOrigin::catalog, "fixture-qwen", "t1");
  const auto declined = s.strata(args.at(0), {"update", "--models", "--yes"});  // stdin is the null device: not interactive
  expect(declined.exit_code == 2, "update --models, not interactive: No, exit 2; saw " + std::to_string(declined.exit_code) + ": " +
                                      declined.err);
  expect(contains(declined.out, "The license of fixture-qwen:t1 changes"), "the license change was asked: " + declined.out);
  s.h.services.test_record_file = s.record;  // in process: the same verb, answered with an explicit "n"
  const int answered = s.h.run({"update", "--models", "--yes"}, "n\n", true);
  expect(answered == 2, "update --models answered n: exit 2; saw " + std::to_string(answered) + ": " + s.h.err);
  expect(!std::filesystem::exists(s.record), "a declined update --models spawns nothing");
}

// PRIV-01 positive control: doctor --downloader spawns exactly one probe.
void priv01_positive_control_doctor_downloader_probe_is_recorded() {
  const auto& args = secure_frontend_test::extra_arguments();  // [0] strata, [1] fake curl, [2] shim (Linux)
  StrataSetup s(args.at(1));
#if !defined(_WIN32)
  // Ruling R6: the strata process itself is audited too (the probe child gets an empty environment).
  const auto audit = s.h.scratch / "connect-audit.log";
  const auto result = s.strata(args.at(0), {"doctor", "--downloader"},
                               {{"LD_PRELOAD", args.at(2)}, {"SF_CONNECT_AUDIT", audit.string()}, {"SF_CONNECT_AUDIT_LOADED", audit.string() + ".loaded"}});
#else
  const auto result = s.strata(args.at(0), {"doctor", "--downloader"});
#endif
  expect(result.exit_code == 0, "doctor --downloader: " + result.err);
  const auto lines = secure_frontend_test::read_record_lines(s.record);
  expect(lines.size() == 1 && contains(lines[0], "\"kind\":\"probe\"") && contains(lines[0], "\"argv\":[\"-q\",\"--version\"]"),
         "exactly one probe record, argv -q --version");
#if !defined(_WIN32)
  expect(contains(file_text(audit.string() + ".loaded"), "loaded"), "the audit shim was loaded into strata");
  expect(!std::filesystem::exists(audit) || file_text(audit).empty(), "strata makes no network use of its own: " + file_text(audit));
#endif
}

// PRIV-02: a signed redirect query never reaches stdout, stderr or the log.
void priv02_pull_output_and_logs_contain_no_url_query() {
  const auto& args = secure_frontend_test::extra_arguments();
  StrataSetup s(args.at(1));
  secure_frontend_test::make_private_directory(s.h.scratch / "logs");
  std::string text = secure_frontend_test::read_file(s.h.config);
  text.replace(text.find("\"roots\": {"), 10, "\"roots\": {\"logs\": \"" + (s.h.scratch / "logs").generic_string() + "\", ");
  secure_frontend_test::write_file(s.h.config, text);
  std::string scenario = secure_frontend_test::read_file(s.fake.scenario_dir / "scenario.txt");
  const auto payload = fx::qwen_payload();
  scenario = "response https://fixture.example/fx/" + payload[0].path +
             "\nstatus 302 Found\nheader Location: https://us.cdn.fixture.example/x?sig=SENTINELQUERY\nend\n" +
             "response https://us.cdn.fixture.example/x?sig=SENTINELQUERY\nstatus 200 OK\nbody-file weights_fx-00001-of-00002.gguf\nend\n" + scenario;
  secure_frontend_test::write_file(s.fake.scenario_dir / "scenario.txt", scenario);
  const auto result = s.strata(args.at(0), {"pull", "--manifest", s.manifest_path, "--trust-manifest", "sha256:" + s.digest, "--yes"});
  expect(result.exit_code == 0, "pull with a redirect: " + result.err);
  expect(!contains(result.out, "SENTINELQUERY") && !contains(result.err, "SENTINELQUERY"), "not in stdout or stderr");
  const auto log = file_text(s.h.scratch / "logs" / "acquire.log");
  expect(!log.empty(), "the log was written");
  expect(!contains(log, "SENTINELQUERY"), "not in the log");
}

// PRIV-02: errors name neither the proxy URL nor an IP address.
void priv02_errors_contain_no_proxy_or_address() {
  const auto& args = secure_frontend_test::extra_arguments();
  StrataSetup s(args.at(1));
  std::string text = secure_frontend_test::read_file(s.h.config);
  text.replace(text.find("http://127.0.0.1:9"), 18, "http://proxy-sentinel.example:3128");
  secure_frontend_test::write_file(s.h.config, text);
  secure_frontend_test::write_file(s.fake.scenario_dir / "scenario.txt",
                                   "probe 8.4.0 OpenSSL/3.0.13\nresponse https://fixture.example/fx/weights/fx-00001-of-00002.gguf\nexit 60\nend\n");
  const auto result = s.strata(args.at(0), {"pull", "--manifest", s.manifest_path, "--trust-manifest", "sha256:" + s.digest, "--yes"});
  expect(result.exit_code == 3, "tls_untrusted on the only source: exit 3, saw " + std::to_string(result.exit_code) + ": " + result.err);
  expect(!contains(result.out + result.err, "proxy-sentinel") && !contains(result.out + result.err, "127.0.0.1") &&
             !contains(result.out + result.err, "93.184.216.34"),
         "no proxy URL, no address in any output");
}

// PRIV-03: API payloads that look like a pull trigger nothing.
void priv03_api_payloads_resembling_pull_trigger_nothing() {
  ServerFixture f;
  ChildProcess server;
  expect(f.start(server, expert(f)), "server starts");
  for (const auto* target : {"/api/pull", "/v1/pull", "/api/models/pull", "/v1/models/pull"}) {
    const auto response = f.request("POST", target, f.bearer(), R"({"name":"qwen3.8-flash-next:iq2_xs","stream":false})");
    expect(status_is(response, "404"), std::string{"no such route: "} + target);
  }
  (void)f.request("POST", "/v1/chat/completions", f.bearer(), chat_body());
  server.terminate();
  expect(!std::filesystem::exists(f.dir / "downloader-record.log") && !std::filesystem::exists(f.models / ".staging"),
         "nothing was staged or spawned");
}

// PRIV-04 supplement (§7.1): strata-secure-server does not link acquisition.
void priv04_secure_server_does_not_link_acquisition() {
  const auto links = file_text(secure_frontend_test::extra_arguments().at(0));
  expect(contains(links, "strata-secure-server"), "the link set was generated");
  for (const auto* forbidden : {"secure_frontend_acquire\n", "secure_frontend_acquire_core\n", "secure_frontend_downloader\n",
                                "secure_frontend_strata_cli\n"}) {
    expect(!contains(links, forbidden), std::string{"strata-secure-server does not link "} + forbidden);
  }
}

// §3.8: doctor's proxy check is presence-only.
void doctor_proxy_hint_is_presence_only() {
  const auto& args = secure_frontend_test::extra_arguments();
  secure_frontend_test::cli::CliHarness h;
  const auto result = secure_frontend_test::run_to_completion(secure_frontend_test::ProcessSpec{
      args.at(0), {"--config", h.config.string(), "doctor"}, {{"HTTPS_PROXY", "http://SENTINEL-PROXY-VALUE:1"}}});
  expect(result.exit_code == 0 && contains(result.out, "hint: a proxy variable is set"), "the hint is printed: " + result.err);
  expect(!contains(result.out + result.err, "SENTINEL-PROXY-VALUE"), "the value is never printed");
}

void release_binary_lacks_hook_marker() {
  expect(!secure_frontend::kTestHooksEnabled, "runs only hooks-OFF");
  for (const auto& binary : secure_frontend_test::extra_arguments()) {  // strata and strata-secure-server
    const auto bytes = file_text(binary);
    expect(!bytes.empty(), "the binary was read: " + std::filesystem::path(binary).filename().string());
    expect(!contains(bytes, marker()), "a shipped binary has no hook marker: " + std::filesystem::path(binary).filename().string());
  }
}

void hooks_build_announces_marker() {
  for (const auto& binary : secure_frontend_test::extra_arguments()) {
    expect(contains(file_text(binary), marker()), "positive control, hooks builds carry the marker: " +
                                                     std::filesystem::path(binary).filename().string());
  }
}

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"dl01_serve_and_infer_never_spawn_downloader", dl01_serve_and_infer_never_spawn_downloader},
      {"dl01_positive_control_pull_spawn_is_recorded", dl01_positive_control_pull_spawn_is_recorded},
#if !defined(_WIN32)
      {"dl01_server_makes_no_outbound_connection", dl01_server_makes_no_outbound_connection},
      {"priv01_lifecycle_and_crash_restart_make_no_network_use", priv01_lifecycle_and_crash_restart_make_no_network_use},
#else
      {"dl01_server_makes_no_outbound_connection_windows", dl01_server_makes_no_outbound_connection_windows},
#endif
      {"priv01_local_verbs_never_spawn_downloader", priv01_local_verbs_never_spawn_downloader},
      {"priv01_positive_control_doctor_downloader_probe_is_recorded", priv01_positive_control_doctor_downloader_probe_is_recorded},
      {"priv02_pull_output_and_logs_contain_no_url_query", priv02_pull_output_and_logs_contain_no_url_query},
      {"priv02_errors_contain_no_proxy_or_address", priv02_errors_contain_no_proxy_or_address},
      {"priv03_api_payloads_resembling_pull_trigger_nothing", priv03_api_payloads_resembling_pull_trigger_nothing},
      {"priv04_secure_server_does_not_link_acquisition", priv04_secure_server_does_not_link_acquisition},
      {"doctor_proxy_hint_is_presence_only", doctor_proxy_hint_is_presence_only},
      {"release_binary_lacks_hook_marker", release_binary_lacks_hook_marker},
      {"hooks_build_announces_marker", hooks_build_announces_marker},
  }, secure_frontend_test::failures);
}

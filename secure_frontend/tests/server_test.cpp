#include "secure_frontend/cgroup_scope.hpp"

#include "support/fake_engine_dump.hpp"
#include "support/server_harness.hpp"
#include "support/test_paths.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#include <aclapi.h>
#else
#include <sys/stat.h>
#endif

namespace {

using namespace std::chrono_literals;
using test_support::ServerProcess;

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

std::string describe(const std::optional<test_support::HttpResult>& result) {
  return result ? std::to_string(result->status) + " " + result->body : std::string("no response");
}

void harness_server_lifecycle_selftest() {
  expect(test_support::kHarnessToken.size() == 43U, "the harness token is 43 base64url characters (SP1: at least 32 bytes)");
  auto server = ServerProcess::start({});
  expect(server != nullptr, "the harness must start strata-secure-server");
  if (!server) return;
  expect(server->wait_until_listening(10s), "the listener must answer");
#if defined(_WIN32)
  expect(!test_support::process_token_elevated(server->pid()), "the harness runs the server with a non-elevated token");
#endif
  const auto models = server->get("/v1/models");
  expect(models && models->status == 200 && models->body.find("\"fake-model\"") != std::string::npos,
         "the fixture model is listed: " + describe(models));
  const auto health = server->get("/health");
  expect(health && (health->status == 200 || health->status == 503), "/health answers: " + describe(health));
  server->stop(ServerProcess::Stop::kill);
  expect(server->wait_exit(5s).has_value(), "a killed server is reaped");
}

void proc01_server_passes_literal_argv() {
  const auto dir = test_support::make_temp_dir("a2");
  const auto dump_file = dir / "dump.txt";
  const std::string weird = "--weird=a b;$(touch x)|&`\"q\"'\\ \xE2\x9C\x93";
  test_support::ServerOptions options;
  options.engine_args = {"--dump-file=" + test_support::utf8_path(dump_file), weird, "--max-context", "8192"};
  options.extra_args = {"--gpu", "0,1"};  // spec §3.9: the typed list becomes the engine's own --gpu
  auto server = ServerProcess::start(options);
  expect(server != nullptr && server->wait_until_listening(10s), "the server must listen");
  if (!server) return;
  const auto dump = test_support::read_dump_file(dump_file, 10s);
  expect(dump.has_value(), "the engine reported its argv");
  if (dump) {
    auto model = server->root() / "models" / "fake-model.gguf";
    model.make_preferred();
    const std::vector<std::string> expected{test_support::utf8_path(server->engine_path()), "--serve",
                                            "--dump-file=" + test_support::utf8_path(dump_file), weird, "--max-context", "8192",
                                            "--gpu", "0,1", "--native", test_support::utf8_path(model)};
    expect(dump->argv == expected, "every value arrives literally as one argv entry, in order, with no shell");
  }
#if !defined(_WIN32)
  expect(test_support::children_of(server->pid()).size() == 1U, "exactly one child process: no shell in between");
#endif
}

void proc04_ready_is_eager_and_health_starting_is_503() {
  test_support::ServerOptions options;
  options.engine_args = {"--split-ready", "--ready-delay-ms=1500"};
  auto server = ServerProcess::start(options);
  expect(server != nullptr && server->wait_until_listening(10s), "the server must listen");
  if (!server) return;
  const auto starting = server->get("/health");
  expect(starting && starting->status == 503 && starting->body == test_support::kHealthStarting,
         "while the model loads /health is 503 with engine=starting, saw: " + describe(starting));
  expect(server->wait_for_health(test_support::kHealthReady, 10s), "READY is consumed with no request: /health becomes 200 ready");
  const auto ready = server->get("/health");
  expect(ready && ready->status == 200, "ready is 200: " + describe(ready));
}

void proc04_chat_during_restart_is_generic_503() {
  test_support::ServerOptions options;
  options.engine_args = {"--hang-before-ready"};
  auto server = ServerProcess::start(options);
  expect(server != nullptr && server->wait_until_listening(10s), "the server must listen");
  if (!server) return;
  const auto started = std::chrono::steady_clock::now();
  const auto chat = server->post_chat(test_support::kChatBody, 5s);
  const auto elapsed = std::chrono::steady_clock::now() - started;
  expect(chat && chat->status == 503 && chat->body == test_support::kGeneric503, "a chat while starting is a generic 503: " + describe(chat));
  expect(elapsed < 1s, "it is answered at once, never after a READY wait");
}

// V8 (spec "Fix: —"): moved here from Task 10 because it needs the wired supervisor.
void proc04_abort_in_generation_is_generic_503() {
  test_support::ServerOptions options;
  options.engine_args = {"--abort-in-gen"};
  auto server = ServerProcess::start(options);
  expect(server != nullptr && server->wait_until_listening(10s) && server->wait_for_health(test_support::kHealthReady, 10s), "ready");
  if (!server) return;
  const auto chat = server->post_chat(test_support::kChatBody, 10s);
  expect(chat && chat->status == 503 && chat->body == test_support::kGeneric503,
         "an engine abort mid-generation is a generic 503 with no exit code: " + describe(chat));
  expect(server->wait_for_health(test_support::kHealthReady, 15s), "the supervisor recovers with a new generation");
  expect(server->stderr_text().find("engine generation 1 ended: abort") != std::string::npos, "only the frontend's own log names the abort");
}

// V4 at server level (spec §4 V4, ruling PF11 deferred it to 6b): an engine
// that dies between requests is noticed with no request; /health leaves
// ready within 1 s. POSIX: SIGKILL; Windows: TerminateProcess.
void proc04_health_leaves_ready_after_idle_engine_death() {
  auto server = ServerProcess::start({});
  expect(server != nullptr && server->wait_until_listening(10s) && server->wait_for_health(test_support::kHealthReady, 10s), "ready");
  if (!server) return;
  const auto engines = server->descendants();
  expect(engines.size() == 1U, "exactly one engine process");
  if (engines.size() != 1U) return;
  test_support::kill_process(engines.front());
  const auto killed = std::chrono::steady_clock::now();
  std::optional<test_support::HttpResult> health;
  while (std::chrono::steady_clock::now() - killed < 3s) {
    health = server->get("/health", 1s);
    if (health && health->body != test_support::kHealthReady) break;
    std::this_thread::sleep_for(10ms);
  }
  const auto noticed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - killed);
  expect(health && health->status == 503 && health->body != test_support::kHealthReady,
         "/health leaves ready with no chat request: " + describe(health));
  expect(noticed <= 1000ms, "within 1 s of the engine's death; took " + std::to_string(noticed.count()) + " ms");
}

// Review Focus 1: --state-dir (roots.state) must be an existing owner-only
// directory, checked before anything is spawned (the POSIX variants are
// compiled out on Windows).
void state_dir_must_be_owner_only() {
  const auto base = test_support::make_temp_dir("rf1");
  std::vector<std::pair<std::string, std::filesystem::path>> variants{{"missing", base / "missing"}};
#if !defined(_WIN32)
  const auto open_dir = base / "world-writable";
  std::filesystem::create_directory(open_dir);
  (void)chmod(open_dir.c_str(), 0777);
  const auto good = base / "good";
  std::filesystem::create_directory(good);
  (void)chmod(good.c_str(), 0700);
  const auto link = base / "link";
  std::filesystem::create_directory_symlink(good, link);
  variants.emplace_back("world-writable", open_dir);
  variants.emplace_back("symlink", link);
#endif
  for (const auto& [name, state] : variants) {
    const auto record = base / (name + ".record");
    test_support::ServerOptions options;
    options.state_dir = state;
    options.engine_args = {"--record-file=" + test_support::utf8_path(record)};
    auto server = ServerProcess::start(options);
    expect(server != nullptr, name + ": launched");
    if (!server) continue;
    expect(server->wait_exit(10s) == 1, name + ": the server refuses to start");
    expect(server->stderr_text().find("--state-dir must be an existing owner-only directory.") != std::string::npos, name + ": fixed error");
    expect(!std::filesystem::exists(record), name + ": no engine was spawned");
  }
}

// Startup clears <state>/engine-tmp/*: a generation directory a previous
// frontend left behind (here generation 7, with a file in it) is gone.
void state_dir_stale_engine_tmp_is_cleared() {
  const auto state = test_support::make_temp_dir("stale") / "state";
  secure_frontend_test::make_owner_private_directory(state);
  secure_frontend_test::make_private_directory(state / "engine-tmp");
  secure_frontend_test::make_private_directory(state / "engine-tmp" / "7");
  secure_frontend_test::write_file(state / "engine-tmp" / "7" / "left-behind", "x");
  test_support::ServerOptions options;
  options.state_dir = state;
  auto server = ServerProcess::start(options);
  expect(server != nullptr, "launched");
  if (!server) return;
  expect(server->wait_until_listening(10s), "the server starts: " + server->stderr_text());
  expect(!std::filesystem::exists(state / "engine-tmp" / "7"), "the stale generation directory was removed at startup");
  expect(std::filesystem::is_directory(state / "engine") && std::filesystem::is_directory(state / "cache" / "cuda"),
         "the state layout was created");
  server->stop(ServerProcess::Stop::kill);
  (void)server->wait_exit(5s);
}

#if defined(_WIN32)
// Adds an explicit BUILTIN\Users read ACE to `path`'s DACL.
bool grant_users_read(const std::filesystem::path& path) {
  PACL old_dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &old_dacl, nullptr,
                            &descriptor) != ERROR_SUCCESS) {
    return false;
  }
  DWORD sid_size = SECURITY_MAX_SID_SIZE;
  std::vector<unsigned char> users(SECURITY_MAX_SID_SIZE);
  const bool have_sid = CreateWellKnownSid(WinBuiltinUsersSid, nullptr, users.data(), &sid_size) != 0;
  EXPLICIT_ACCESS_W access{};
  access.grfAccessPermissions = FILE_GENERIC_READ;
  access.grfAccessMode = GRANT_ACCESS;
  access.grfInheritance = NO_INHERITANCE;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(users.data());
  PACL updated = nullptr;
  const bool ok = have_sid && SetEntriesInAclW(1, &access, old_dacl, &updated) == ERROR_SUCCESS &&
                  SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                        updated, nullptr) == ERROR_SUCCESS;
  if (updated != nullptr) LocalFree(updated);
  LocalFree(descriptor);
  return ok;
}

// Review Focus 1, Windows: owner-only means SP1's protected private DACL, not
// just "not writable by others"; a junction root is refused, not followed.
void state_dir_must_be_owner_only_windows() {
  const auto base = test_support::make_temp_dir("rf1w");
  const auto good = base / "good";
  secure_frontend_test::make_owner_private_directory(good);
  const auto shared = base / "users-read";
  secure_frontend_test::make_owner_private_directory(shared);  // the added Users ACE is its only defect
  expect(grant_users_read(shared), "test setup: add a Users read ACE");
  const auto junction = base / "junction";
  expect(secure_frontend_test::create_junction(junction, good), "test setup: a junction to a private directory");
  for (const auto& [name, state] : std::vector<std::pair<std::string, std::filesystem::path>>{{"users-read", shared}, {"junction", junction}}) {
    const auto record = base / (name + ".record");
    test_support::ServerOptions options;
    options.state_dir = state;
    options.engine_args = {"--record-file=" + test_support::utf8_path(record)};
    auto server = ServerProcess::start(options);
    expect(server != nullptr, name + ": launched");
    if (!server) continue;
    expect(server->wait_exit(10s) == 1, name + ": the server refuses to start");
    expect(server->stderr_text().find("--state-dir must be an existing owner-only directory.") != std::string::npos, name + ": fixed error");
    expect(!std::filesystem::exists(record), name + ": no engine was spawned");
  }
  // Control: the same layout with a private directory serves.
  test_support::ServerOptions options;
  options.state_dir = good;
  auto server = ServerProcess::start(options);
  expect(server != nullptr && server->wait_until_listening(10s), "a private state directory is accepted");
  if (server) server->stop(ServerProcess::Stop::kill);
}
#endif

#if !defined(_WIN32)
void proc05_frontend_sigkill_kills_engine() {
  const auto dir = test_support::make_temp_dir("c3");
  const auto pidfile = dir / "grandchild.pid";
  test_support::ServerOptions options;
  // --stall-stdin keeps the engine alive after stdin EOF, so only PDEATHSIG can end it.
  options.engine_args = {"--spawn-grandchild", "--grandchild-pidfile=" + test_support::utf8_path(pidfile), "--stall-stdin"};
  auto server = ServerProcess::start(options);
  expect(server != nullptr && server->wait_until_listening(10s), "the server listens");
  if (!server) return;
  const long frontend_pid = server->pid();
  // The fake writes the grandchild's pidfile after READY: the engine is up
  // whether or not the supervisor has consumed READY yet.
  const auto grandchild = test_support::read_pidfile(pidfile, 10s);
  expect(grandchild.has_value(), "the engine is past READY");
  const auto children = test_support::children_of(server->pid());
  expect(children.size() == 1U, "one engine");
  if (children.size() != 1U) return;
  server->stop(ServerProcess::Stop::kill);
  (void)server->wait_exit(5s);
  expect(test_support::wait_until_gone(children.front(), 2s), "the engine leader dies with a SIGKILLed frontend (PR_SET_PDEATHSIG)");
  if (grandchild) {
    if (const auto cgroups = secure_frontend::EngineCgroups::detect()) {
      // Nothing writes cgroup.kill once the frontend is SIGKILLed: the
      // grandchild stays inside the generation's cgroup (ruling on Task 16).
      const auto generation = cgroups->generation_directory(1U, frontend_pid);
      expect(test_support::cgroup_directory_of(*grandchild) == generation, "with a delegated cgroup the grandchild is in the generation's cgroup");
      std::cout << "grandchild remains until the scope's cgroup.kill (frontend SIGKILL residual, delegated)\n";
      (void)secure_frontend::kill_cgroup(generation);
      (void)test_support::wait_until_gone(*grandchild, 2s);
      (void)secure_frontend::remove_cgroup(generation, 2s);
    } else {
      // Spec §3.7 residual risk: without a delegated cgroup the engine's own
      // descendants survive a frontend SIGKILL. Logged, not asserted.
      std::cout << "residual risk (spec 3.7): grandchild " << (test_support::wait_until_gone(*grandchild, 1s) ? "gone" : "survived")
                << " after a frontend SIGKILL without a delegated cgroup\n";
    }
    test_support::kill_process(*grandchild);
  }
}

// C4 (spec §3.7): SIGTERM / SIGINT run the orderly shutdown: EOF, SIGTERM,
// SIGKILL to the engine group, sweep, listener shutdown, exit 0 within 5 s.
void stops_all_descendants_on(const ServerProcess::Stop how, const std::string& name) {
  const auto dir = test_support::make_temp_dir("c4");
  const auto pidfile = dir / "grandchild.pid";
  test_support::ServerOptions options;
  options.engine_args = {"--spawn-grandchild", "--grandchild-pidfile=" + test_support::utf8_path(pidfile)};
  auto server = ServerProcess::start(options);
  expect(server != nullptr && server->wait_until_listening(10s) && server->wait_for_health(test_support::kHealthReady, 10s), name + ": ready");
  if (!server) return;
  const auto grandchild = test_support::read_pidfile(pidfile, 5s);
  const std::vector<long> before = server->descendants();
  expect(before.size() == 2U, name + ": engine and grandchild running, saw " + std::to_string(before.size()));
  const auto started = std::chrono::steady_clock::now();
  server->stop(how);
  const auto code = server->wait_exit(6s);
  expect(code == 0, name + ": the frontend exits 0, saw " + (code ? std::to_string(*code) : std::string("still running")));
  expect(std::chrono::steady_clock::now() - started <= 5s, name + ": within the 5 s bound");
  for (const long pid : before) expect(test_support::wait_until_gone(pid, 1s), name + ": descendant " + std::to_string(pid) + " is gone");
  expect(server->port_refuses(), name + ": the port refuses connections");
  expect(server->stderr_text().find("engine generation 1 ended: killed_by_supervisor(shutdown)") != std::string::npos,
         name + ": the frontend logs the shutdown end of generation 1");
  if (grandchild) test_support::kill_process(*grandchild);
}

void proc05_frontend_sigterm_stops_all_descendants() { stops_all_descendants_on(ServerProcess::Stop::term, "SIGTERM"); }
void proc05_frontend_sigint_stops_all_descendants() { stops_all_descendants_on(ServerProcess::Stop::interrupt, "SIGINT"); }

// C7 (spec "Fix: —"): the production binary's only child is the engine,
// executed directly. The harness runs a private copy (server->engine_path()).
void proc05_frontend_has_only_engine_children() {
  auto server = ServerProcess::start({});
  expect(server != nullptr && server->wait_until_listening(10s) && server->wait_for_health(test_support::kHealthReady, 10s), "ready");
  if (!server) return;
  const auto children = test_support::children_of(server->pid());
  expect(children.size() == 1U, "the frontend has exactly one child, saw " + std::to_string(children.size()));
  if (children.size() != 1U) return;
  const std::string proc = "/proc/" + std::to_string(children.front());
  std::error_code error;
  const auto exe = std::filesystem::read_symlink(proc + "/exe", error);
  std::error_code canonical_error;
  const auto engine = std::filesystem::canonical(server->engine_path(), canonical_error);
  expect(!error && !canonical_error && exe == engine, "and it is the engine binary (no shell, no helper): " + exe.string());
  std::ifstream cmdline(proc + "/cmdline", std::ios::binary);
  const std::string arguments((std::istreambuf_iterator<char>(cmdline)), std::istreambuf_iterator<char>());
  const std::string argv0 = arguments.substr(0, arguments.find('\0'));
  expect(argv0 == test_support::utf8_path(server->engine_path()), "started directly: argv[0] is the engine path, saw " + argv0);
}

// Review Focus 3: a chat in flight when SIGTERM arrives gets a generic 503 or a
// closed connection, never a result, and the frontend still exits 0.
void proc05_sigterm_during_generation_exits_cleanly() {
  test_support::ServerOptions options;
  options.engine_args = {"--hang-in-gen"};
  auto server = ServerProcess::start(options);
  expect(server != nullptr && server->wait_until_listening(10s) && server->wait_for_health(test_support::kHealthReady, 10s), "ready");
  if (!server) return;
  const auto engine = test_support::children_of(server->pid());
  std::optional<test_support::HttpResult> chat;
  std::thread client([&server, &chat] { chat = server->post_chat(test_support::kChatBody, 10s); });
  std::this_thread::sleep_for(300ms);  // the GEN is in flight and the engine never answers
  server->stop(ServerProcess::Stop::term);
  const auto code = server->wait_exit(6s);
  client.join();
  expect(code == 0, "exit 0 with a request in flight, saw " + (code ? std::to_string(*code) : std::string("still running")));
  expect(!chat || (chat->status == 503 && chat->body == test_support::kGeneric503),
         "the in-flight client gets a generic 503 or a closed connection, never a result: " + describe(chat));
  for (const long pid : engine) expect(test_support::wait_until_gone(pid, 1s), "no engine is left");
}

// Review Focus 5: a second SIGTERM during the orderly shutdown changes nothing.
void proc05_double_sigterm_is_idempotent() {
  auto server = ServerProcess::start({});
  expect(server != nullptr && server->wait_until_listening(10s) && server->wait_for_health(test_support::kHealthReady, 10s), "ready");
  if (!server) return;
  const auto engine = test_support::children_of(server->pid());
  server->stop(ServerProcess::Stop::term);
  std::this_thread::sleep_for(50ms);
  server->stop(ServerProcess::Stop::term);
  const auto code = server->wait_exit(6s);
  expect(code == 0, "a second SIGTERM does not break the orderly shutdown, saw " + (code ? std::to_string(*code) : std::string("still running")));
  for (const long pid : engine) expect(test_support::wait_until_gone(pid, 1s), "no engine is left");
}
#endif

#if defined(_WIN32)
// C6 (moved here from Task 17): CTRL_BREAK to the server's console group runs
// the console handler's orderly shutdown; the engine (CREATE_NEW_PROCESS_GROUP,
// CREATE_NO_WINDOW) does not receive it, and the frontend stops it in order.
void proc05_windows_ctrl_break_stops_all_descendants() {
  const auto dir = test_support::make_temp_dir("c6");
  test_support::ServerOptions options;
  options.engine_args = {"--spawn-grandchild", "--grandchild-pidfile=" + test_support::utf8_path(dir / "grandchild.pid")};
  auto server = ServerProcess::start(options);
  expect(server != nullptr && server->wait_until_listening(10s) && server->wait_for_health(test_support::kHealthReady, 10s), "ready");
  if (!server) return;
  expect(test_support::read_pidfile(dir / "grandchild.pid", 5s).has_value(), "grandchild started");
  expect(server->active_processes() == 3U, "server, engine and grandchild are in the harness Job");
  server->stop(ServerProcess::Stop::ctrl_break);  // to the server's console group only
  const auto code = server->wait_exit(6s);
  expect(code == 0, "CTRL_BREAK runs the orderly shutdown and the frontend exits 0");
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (server->active_processes() != 0U && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(10ms);
  expect(server->active_processes() == 0U, "no descendant is left (Job ActiveProcesses 0)");
}

// C6: TerminateProcess runs no handler; the engine Job (kill-on-close) still
// takes every descendant down when the frontend's handle to it closes.
void proc05_windows_terminate_frontend_kills_job() {
  auto server = ServerProcess::start({.engine_args = {"--spawn-grandchild"}, .extra_args = {}, .extra_env = {}, .engine = {}});
  expect(server != nullptr && server->wait_until_listening(10s) && server->wait_for_health(test_support::kHealthReady, 10s), "ready");
  if (!server) return;
  const auto before = server->descendants();
  expect(before.size() == 2U, "engine and grandchild running, saw " + std::to_string(before.size()));
  server->stop(ServerProcess::Stop::kill);  // TerminateProcess: no handler runs
  (void)server->wait_exit(5s);
  for (const long pid : before) expect(test_support::wait_until_gone(pid, 2s), "the engine Job (kill-on-close) takes every descendant down");
}
#endif

}  // namespace

int main(int argc, char* argv[]) {
  return secure_frontend_test::run_cases(argc, argv,
                                         {
                                             {"harness_server_lifecycle_selftest", harness_server_lifecycle_selftest},
                                             {"proc01_server_passes_literal_argv", proc01_server_passes_literal_argv},
                                             {"proc04_ready_is_eager_and_health_starting_is_503", proc04_ready_is_eager_and_health_starting_is_503},
                                             {"proc04_chat_during_restart_is_generic_503", proc04_chat_during_restart_is_generic_503},
                                             {"proc04_abort_in_generation_is_generic_503", proc04_abort_in_generation_is_generic_503},
                                             {"proc04_health_leaves_ready_after_idle_engine_death", proc04_health_leaves_ready_after_idle_engine_death},
                                             {"state_dir_must_be_owner_only", state_dir_must_be_owner_only},
                                             {"state_dir_stale_engine_tmp_is_cleared", state_dir_stale_engine_tmp_is_cleared},
#if !defined(_WIN32)
                                             {"proc05_frontend_sigkill_kills_engine", proc05_frontend_sigkill_kills_engine},
                                             {"proc05_frontend_sigterm_stops_all_descendants", proc05_frontend_sigterm_stops_all_descendants},
                                             {"proc05_frontend_sigint_stops_all_descendants", proc05_frontend_sigint_stops_all_descendants},
                                             {"proc05_frontend_has_only_engine_children", proc05_frontend_has_only_engine_children},
                                             {"proc05_sigterm_during_generation_exits_cleanly", proc05_sigterm_during_generation_exits_cleanly},
                                             {"proc05_double_sigterm_is_idempotent", proc05_double_sigterm_is_idempotent},
#endif
#if defined(_WIN32)
                                             {"proc05_windows_ctrl_break_stops_all_descendants", proc05_windows_ctrl_break_stops_all_descendants},
                                             {"proc05_windows_terminate_frontend_kills_job", proc05_windows_terminate_frontend_kills_job},
                                             {"state_dir_must_be_owner_only_windows", state_dir_must_be_owner_only_windows},
#endif
                                         },
                                         failures);
}

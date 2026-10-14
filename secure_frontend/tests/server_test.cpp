#include "support/fake_engine_dump.hpp"
#include "support/server_harness.hpp"
#include "support/test_paths.hpp"

#include <chrono>
#include <iostream>
#include <string>
#include <vector>

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
  auto server = ServerProcess::start(options);
  expect(server != nullptr && server->wait_until_listening(10s), "the server must listen");
  if (!server) return;
  const auto dump = test_support::read_dump_file(dump_file, 10s);
  expect(dump.has_value(), "the engine reported its argv");
  if (dump) {
    auto model = server->root() / "models" / "fake-model.gguf";
    model.make_preferred();
    const std::vector<std::string> expected{test_support::utf8_path(test_support::fake_engine_path()), "--serve",
                                            "--dump-file=" + test_support::utf8_path(dump_file), weird, "--max-context", "8192",
                                            "--native", test_support::utf8_path(model)};
    expect(dump->argv == expected, "every value arrives literally as one argv entry, in order, with no shell");
  }
#if !defined(_WIN32)
  expect(test_support::children_of(server->pid()).size() == 1U, "exactly one child process: no shell in between");
#endif
}

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
  // The fake writes the grandchild's pidfile after READY: the engine is up
  // whether or not the server has consumed READY yet (SP0 waits lazily).
  const auto grandchild = test_support::read_pidfile(pidfile, 10s);
  expect(grandchild.has_value(), "the engine is past READY");
  const auto children = test_support::children_of(server->pid());
  expect(children.size() == 1U, "one engine");
  if (children.size() != 1U) return;
  server->stop(ServerProcess::Stop::kill);
  (void)server->wait_exit(5s);
  expect(test_support::wait_until_gone(children.front(), 2s), "the engine leader dies with a SIGKILLed frontend (PR_SET_PDEATHSIG)");
  if (grandchild) {
    // Spec §3.7 residual risk: without a delegated cgroup the engine's own
    // descendants survive a frontend SIGKILL. Logged, not asserted.
    std::cout << "residual risk (spec 3.7): grandchild " << (test_support::wait_until_gone(*grandchild, 1s) ? "gone" : "survived")
              << " after a frontend SIGKILL without a delegated cgroup\n";
    test_support::kill_process(*grandchild);
  }
}
#endif

}  // namespace

int main(int argc, char* argv[]) {
  return secure_frontend_test::run_cases(argc, argv,
                                         {
                                             {"harness_server_lifecycle_selftest", harness_server_lifecycle_selftest},
                                             {"proc01_server_passes_literal_argv", proc01_server_passes_literal_argv},
#if !defined(_WIN32)
                                             {"proc05_frontend_sigkill_kills_engine", proc05_frontend_sigkill_kills_engine},
#endif
                                         },
                                         failures);
}

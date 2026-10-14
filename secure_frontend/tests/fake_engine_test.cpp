#include "secure_frontend/engine_process.hpp"
#include "secure_frontend/engine_stdio_process.hpp"

#include "support/test_paths.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

namespace {

using namespace std::chrono_literals;
using secure_frontend::EngineReadKind;

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

// Exit code of a fake that is not given a stdio protocol (EngineProcess keeps the parent's stdio).
std::optional<int> exit_code_of(const std::vector<std::string>& arguments) {
  secure_frontend::EngineProcess process;
  if (process.start({.executable = test_support::fake_engine_path(), .arguments = arguments, .environment = {}}).has_value()) {
    return std::nullopt;
  }
  return process.wait_for(10s);
}

struct Child final {
  secure_frontend::EngineStdioProcess transport;
  explicit Child(const std::vector<std::string>& arguments) {
    expect(!transport.start({.executable = test_support::fake_engine_path(), .arguments = arguments, .environment = {}}).has_value(),
           "fake engine must start");
  }
  ~Child() { (void)transport.terminate(std::chrono::milliseconds(250)); }
  std::string line(const std::chrono::milliseconds timeout = 5s) {
    const auto result = transport.read_line(timeout);
    return result.kind == EngineReadKind::line ? result.line : std::string("<kind ") + std::to_string(static_cast<int>(result.kind)) + ">";
  }
  EngineReadKind kind(const std::chrono::milliseconds timeout) { return transport.read_line(timeout).kind; }
  void send(const std::string& text) {
    std::string error;
    expect(transport.write_line(text, error), "write must succeed: " + text);
  }
};

std::string unhex(const std::string& hex) {
  std::string out;
  for (std::size_t index = 0; index + 1 < hex.size(); index += 2) {
    out.push_back(static_cast<char>(std::stoi(hex.substr(index, 2), nullptr, 16)));
  }
  return out;
}

void fake_engine_modes_selftest() {
  // Exit paths (raw exit codes as EngineProcess normalizes them: POSIX 128 + signal).
  expect(exit_code_of({"--exit-before-ready=3"}) == 3, "--exit-before-ready=3 exits 3");
  expect(exit_code_of({"--crash-after-ready=9"}) == 9, "--crash-after-ready=<code> exits with that code");
  const auto start = std::chrono::steady_clock::now();
  expect(exit_code_of({"--crash-after-ready=7", "--crash-delay-ms=200"}) == 7, "--crash-delay-ms delays the crash");
  expect(std::chrono::steady_clock::now() - start >= 200ms, "the crash waited --crash-delay-ms");
  const auto aborted = exit_code_of({"--crash-after-ready=ABRT"});
#if defined(_WIN32)
  expect(aborted && (*aborted == 3 || static_cast<unsigned>(*aborted) == 0xC0000409U), "ABRT is exit 3 or 0xC0000409 on Windows");
  const auto segv = exit_code_of({"--crash-after-ready=SEGV"});
  expect(segv && static_cast<unsigned>(*segv) == 0xC0000005U, "SEGV is an access violation on Windows");
#else
  expect(aborted == 128 + 6, "ABRT dies by SIGABRT");
  expect(exit_code_of({"--crash-after-ready=KILL"}) == 128 + 9, "KILL dies by SIGKILL");
  expect(exit_code_of({"--crash-after-ready=SEGV"}) == 128 + 11, "SEGV dies by SIGSEGV");
  expect(exit_code_of({"--crash-after-ready=TERM"}) == 128 + 15, "TERM dies by SIGTERM");
#endif

  {  // READY variants
    Child child({"--split-ready", "--ready-delay-ms=300"});
    expect(child.kind(100ms) == EngineReadKind::timeout, "--ready-delay-ms holds READY back");
    expect(child.line() == "READY 4096 stop", "split READY arrives whole");
  }
  {
    Child child({"--ready-context=65536"});
    expect(child.line() == "READY 65536 stop", "--ready-context sets the advertised context");
  }
  {
    Child child({"--hang-before-ready"});
    expect(child.kind(300ms) == EngineReadKind::timeout, "--hang-before-ready never prints READY");
  }
  {
    Child child({"--echo-cmdline"});
    const std::string cmdline = child.line();
    expect(cmdline.rfind("CMDLINE ", 0) == 0 && unhex(cmdline.substr(8)).find("--echo-cmdline") != std::string::npos,
           "--echo-cmdline reports the command line before READY: " + cmdline);
    expect(child.line() == "READY 4096 stop", "READY follows CMDLINE");
  }

  {  // Generation behaviors
    Child child({"--hang-in-gen"});
    expect(child.line() == "READY 4096 stop", "READY");
    child.send("GEN 1 1");
    expect(child.kind(300ms) == EngineReadKind::timeout, "--hang-in-gen prints nothing for GEN");
    child.send("STOP");
    expect(child.kind(300ms) == EngineReadKind::timeout, "--hang-in-gen never answers STOP");
  }
  {
    Child child({"--abort-in-gen"});
    expect(child.line() == "READY 4096 stop", "READY");
    child.send("GEN 1 1");
    expect(child.line() == "T 7", "--abort-in-gen prints one token");
    expect(child.kind(5s) == EngineReadKind::closed, "then the engine is gone");
  }
  const std::vector<std::string> prefixes{"ERR verify: timed out at layer ", "ERR verify batch: timed out at layer ",
                                          "ERR verify: an earlier window never finished",
                                          "ERR verify batch: an earlier window never finished"};
  for (std::size_t index = 0; index < prefixes.size(); ++index) {
    Child child({"--fatal-line=" + std::to_string(index)});
    expect(child.line() == "READY 4096 stop", "READY");
    child.send("GEN 1 1");
    expect(child.line() == "T 7", "fatal mode prints a token first");
    expect(child.line().rfind(prefixes[index], 0) == 0, "fatal mode prints prefix " + std::to_string(index));
    expect(child.line() == "DONE stop", "then a trailing DONE the frontend must not accept");
    child.send("GEN 1 1");
    expect(child.line() == "T 7", "the engine lives on after the fatal line");
  }
  {
    Child child({"--stall-stdin"});
    expect(child.line() == "READY 4096 stop", "READY");
    child.send("GEN 1 1");
    expect(child.kind(300ms) == EngineReadKind::timeout, "--stall-stdin never reads the GEN");
  }

  {  // Restart helpers and recording
    const auto dir = test_support::make_temp_dir("fake-modes");
    const std::string counter = "--counter-file=" + test_support::utf8_path(dir / "count");
    {
      Child first({"--fail-first=1", counter});
      expect(first.kind(5s) == EngineReadKind::closed, "the first start fails before READY");
    }
    {
      Child second({"--fail-first=1", counter});
      expect(second.line() == "READY 4096 stop", "the second start is healthy");
    }
    const auto record = dir / "record.txt";
    {
      Child child({"--record-file=" + test_support::utf8_path(record)});
      expect(child.line() == "READY 4096 stop", "READY");
      child.send("GEN 1 1");
      expect(child.line() == "T 7" && child.line() == "DONE stop", "a normal generation");
      child.send("QUIT");
      expect(child.kind(5s) == EngineReadKind::closed, "QUIT ends the engine");
    }
    std::ifstream recorded(record);
    const std::string content((std::istreambuf_iterator<char>(recorded)), std::istreambuf_iterator<char>());
    expect(content == "GEN 1 1\nQUIT\n", "--record-file holds every stdin line, saw: " + content);

    const auto pidfile = dir / "grandchild.pid";
    {
      Child child({"--spawn-grandchild", "--grandchild-pidfile=" + test_support::utf8_path(pidfile)});
      expect(child.line() == "READY 4096 stop", "READY");
      const auto grandchild = test_support::read_pidfile(pidfile, 5s);
      expect(grandchild.has_value() && test_support::process_alive(*grandchild), "the grandchild is running");
      if (grandchild) test_support::kill_process(*grandchild);
    }
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  return secure_frontend_test::run_cases(argc, argv, {{"fake_engine_modes_selftest", fake_engine_modes_selftest}}, failures);
}

#include "secure_frontend/engine_protocol_client.hpp"
#include "secure_frontend/engine_stdio_process.hpp"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

int g_argc = 0;
char** g_argv = nullptr;

void expect(const bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

// Lists this process's open descriptors, dropping the directory iterator's own
// handle (its /proc/self/fd/<n> link points into /proc/<pid>/fd).
std::string open_descriptors() {
  std::string fds;
  for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd")) {
    std::error_code ignored;
    const auto target = std::filesystem::read_symlink(entry.path(), ignored).string();
    if (target.rfind("/proc/", 0) == 0) continue;
    if (!fds.empty()) fds += ',';
    fds += entry.path().filename().string();
  }
  return fds;
}

int fake_engine() {
  for (int index = 1; index < g_argc; ++index) {
    if (std::string(g_argv[index]) == "--ignore-term") (void)std::signal(SIGTERM, SIG_IGN);
  }
  // A real engine may emit human diagnostics on stderr before protocol READY.
  // Those bytes must never enter the strict stdout protocol stream.
  std::cerr << "diagnostic: private engine startup\n" << std::flush;
  std::cout << "READY 4096 stop\n" << std::flush;
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.rfind("GEN ", 0) == 0) {
      std::cout << "T 7\nDONE stop\n" << std::flush;
    } else if (line == "QUIT") {
      return 0;
    } else if (line == "DUMP") {
      // Protocol extension reused by SP2's PROC-* tests:
      //   FDS <comma-separated open fds>
      //   ARGV<0x1F argv[0]><0x1F argv[1]>...
      std::cout << "FDS " << open_descriptors() << '\n';
      std::cout << "ARGV";
      for (int i = 0; i < g_argc; ++i) std::cout << '\x1f' << g_argv[i];
      std::cout << '\n' << std::flush;
    }
  }
  return 0;
}

void test_round_trip(const std::filesystem::path& self) {
  secure_frontend::EngineStdioProcess transport;
  secure_frontend::EngineCommand command{.executable = self,
                                         .arguments = {"--fake-engine"},
                                         .environment = {}};
  const auto start_error = transport.start(command);
  expect(!start_error.has_value(), "fake engine must start");
  secure_frontend::EngineProtocolClient client(transport);
  secure_frontend::EngineReady ready{};
  expect(!client.await_ready(std::chrono::seconds(2), ready).has_value(), "READY must parse");
  expect(ready.max_context_tokens == 4096 && ready.supports_stop, "READY capabilities must survive transport");
  // E4: the GEN line for a full context is far beyond 8 KiB; the write cap must allow it.
  // Raw write while the client is idle, then consume the fake's two reply lines so
  // the protocol client continues from a clean stream.
  std::string big(100000U, '1'); std::string werr;
  const bool big_written = transport.write_line("GEN 1 " + big, werr);
  expect(big_written, "a 100 KB GEN line must be writable: " + werr);
  const auto reply_token = transport.read_line(std::chrono::seconds(2));
  const auto reply_done = transport.read_line(std::chrono::seconds(2));
  expect(reply_token.kind == secure_frontend::EngineReadKind::line && reply_token.line == "T 7" &&
             reply_done.kind == secure_frontend::EngineReadKind::line && reply_done.line == "DONE stop",
         "the fake engine must answer the 100 KB GEN line");
  expect(!client.begin_generation(2, {1, 2, 3}).has_value(), "GEN must write through transport");
  secure_frontend::EngineGeneration generation{};
  expect(!client.read_generation(std::chrono::seconds(2), generation).has_value(), "generation must read through transport");
  expect(generation.token_ids == std::vector<std::uint32_t>{7}, "token must survive transport");
  expect(!client.quit().has_value(), "QUIT must write through transport");
  expect(transport.terminate(std::chrono::milliseconds(250)), "child cleanup must succeed");
}

void test_invalid_record() {
  secure_frontend::EngineStdioProcess transport;
  std::string error;
  expect(!transport.write_line("bad\nline", error), "multiline writes must be rejected");
}

void child_inherits_only_stdio_descriptors(const std::filesystem::path& self) {
  // Open two extra descriptors in the parent without CLOEXEC; a correct launcher must not leak them.
  const int leak_a = open("/dev/null", O_RDONLY);
  const int leak_b = open("/dev/null", O_RDONLY);
  secure_frontend::EngineStdioProcess transport;
  expect(!transport.start({.executable = self, .arguments = {"--fake-engine"}, .environment = {}}).has_value(),
         "fake engine must start");
  std::string err;
  (void)transport.read_line(std::chrono::seconds(2));  // READY
  expect(transport.write_line("DUMP", err), "DUMP must write");
  const auto fds = transport.read_line(std::chrono::seconds(2));
  (void)transport.read_line(std::chrono::seconds(2));  // ARGV
  close(leak_a);
  close(leak_b);
  expect(fds.kind == secure_frontend::EngineReadKind::line && fds.line == "FDS 0,1,2",
         "child must see only stdio, saw: " + fds.line);
  (void)transport.terminate(std::chrono::milliseconds(250));
}

void child_receives_exact_argv_and_env(const std::filesystem::path& self) {
  secure_frontend::EngineStdioProcess transport;
  const std::string weird = "literal; $(echo x) \"quoted\" \xE2\x9C\x93 \n-less";
  expect(!transport.start({.executable = self, .arguments = {"--fake-engine", weird}, .environment = {{"STRATA_T", "1"}}})
              .has_value(),
         "fake engine must start");
  std::string err;
  (void)transport.read_line(std::chrono::seconds(2));  // READY
  expect(transport.write_line("DUMP", err), "DUMP must write");
  (void)transport.read_line(std::chrono::seconds(2));  // FDS
  const std::string expected = std::string("ARGV\x1f") + self.string() + "\x1f--serve\x1f--fake-engine\x1f" + weird;
  // The argument's embedded newline splits the ARGV record into protocol lines; rejoin them.
  auto argv = transport.read_line(std::chrono::seconds(2));
  std::string got = argv.line;
  while (argv.kind == secure_frontend::EngineReadKind::line && got.size() < expected.size()) {
    argv = transport.read_line(std::chrono::seconds(2));
    if (argv.kind == secure_frontend::EngineReadKind::line) got += '\n' + argv.line;
  }
  expect(got == expected, "argv must arrive literally, no shell: " + got);
  (void)transport.terminate(std::chrono::milliseconds(250));
}

void terminate_reaps_killed_child(const std::filesystem::path& self) {
  secure_frontend::EngineStdioProcess transport;
  expect(!transport.start({.executable = self, .arguments = {"--fake-engine", "--ignore-term"}, .environment = {}})
              .has_value(),
         "fake engine must start");
  (void)transport.read_line(std::chrono::seconds(2));  // READY: SIGTERM is now ignored
  const pid_t pid = transport.pid_for_tests();
  expect(transport.terminate(std::chrono::milliseconds(200)), "terminate must succeed even when SIGTERM is ignored");
  // SIGKILL delivery is asynchronous: give an unreaped child time to become a zombie
  // so the check below cannot pass merely because the kill has not landed yet.
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
  const std::string content((std::istreambuf_iterator<char>(stat)), std::istreambuf_iterator<char>());
  expect(content.empty() || content.find(") Z ") == std::string::npos,
         "no zombie may remain after terminate, saw: " + content.substr(0, 64));
}

}  // namespace

int main(const int argc, char* argv[]) {
  g_argc = argc;
  g_argv = argv;
  for (int index = 1; index < argc; ++index) {
    if (std::string(argv[index]) == "--fake-engine") return fake_engine();
  }
  try {
    test_round_trip("/proc/self/exe");
    test_invalid_record();
    child_inherits_only_stdio_descriptors("/proc/self/exe");
    child_receives_exact_argv_and_env("/proc/self/exe");
    terminate_reaps_killed_child("/proc/self/exe");
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

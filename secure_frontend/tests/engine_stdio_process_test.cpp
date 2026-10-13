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
#include <vector>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

int g_argc = 0;
char** g_argv = nullptr;

void expect(const bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

std::filesystem::path current_executable() {
#if defined(_WIN32)
  std::vector<wchar_t> buffer(32768);
  const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  return std::filesystem::path(std::wstring(buffer.data(), length));
#else
  std::vector<char> buffer(4096);
  const auto length = readlink("/proc/self/exe", buffer.data(), buffer.size());
  return std::filesystem::path(std::string(buffer.data(), static_cast<std::size_t>(length)));
#endif
}

#if !defined(_WIN32)
// Lists this process's open descriptors, dropping exactly the directory
// iterator's own handle (its link target is /proc/<pid>/fd).
std::string open_descriptors() {
  const std::string iterator_target = "/proc/" + std::to_string(getpid()) + "/fd";
  std::string fds;
  for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd")) {
    std::error_code ignored;
    const auto target = std::filesystem::read_symlink(entry.path(), ignored).string();
    if (target == iterator_target) continue;
    if (!fds.empty()) fds += ',';
    fds += entry.path().filename().string();
  }
  return fds;
}
#endif

#if defined(_WIN32)
// --spawn-grandchild: launch this executable again as a 30 s sleeper.  The
// fake engine runs inside the frontend's kill-on-close Job, so the grandchild
// joins the Job too and must die when the Job is terminated (P4).
DWORD spawn_sleeper_grandchild() {
  const std::wstring self = current_executable().wstring();
  std::wstring line = L"\"" + self + L"\" --fake-sleeper";
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  if (!CreateProcessW(self.c_str(), line.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &info)) return 0;
  CloseHandle(info.hThread);
  CloseHandle(info.hProcess);
  return info.dwProcessId;
}
#endif

int fake_engine() {
  bool spew = false;
  bool split_ready = false;
  bool spawn_grandchild = false;
  for (int index = 1; index < g_argc; ++index) {
    if (std::string(g_argv[index]) == "--ignore-term") (void)std::signal(SIGTERM, SIG_IGN);
    if (std::string(g_argv[index]) == "--spew") spew = true;
    if (std::string(g_argv[index]) == "--split-ready") split_ready = true;
    if (std::string(g_argv[index]) == "--spawn-grandchild") spawn_grandchild = true;
  }
  // A real engine may emit human diagnostics on stderr before protocol READY.
  // Those bytes must never enter the strict stdout protocol stream.
  std::cerr << "diagnostic: private engine startup\n" << std::flush;
  if (split_ready) {
    // --split-ready: one READY record split across two writes 100 ms apart.
    std::cout << "REA" << std::flush;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::cout << "DY 4096 stop\n" << std::flush;
  } else {
    std::cout << "READY 4096 stop\n" << std::flush;
  }
  std::string line;
#if defined(_WIN32)
  if (spawn_grandchild) {
    std::cout << "GRANDCHILD " << spawn_sleeper_grandchild() << '\n' << std::flush;
    while (std::getline(std::cin, line)) {}
    return 0;
  }
#else
  (void)spawn_grandchild;
#endif
  if (spew) {
    // --spew: one record larger than kMaxReadLineBytes with no newline, then
    // stay alive (blocked on stdin) so the reader sees size, not end-of-stream.
    std::cout << std::string(9000, 'x') << std::flush;
    while (std::getline(std::cin, line)) {}
    return 0;
  }
  while (std::getline(std::cin, line)) {
    if (line.rfind("GEN ", 0) == 0) {
      std::cout << "T 7\nDONE stop\n" << std::flush;
    } else if (line == "QUIT") {
      return 0;
#if !defined(_WIN32)
    } else if (line == "DUMP") {
      // Protocol extension reused by SP2's PROC-* tests:
      //   FDS <comma-separated open fds>
      //   ARGV<0x1F argv[0]><0x1F argv[1]>...
      std::cout << "FDS " << open_descriptors() << '\n';
      std::cout << "ARGV";
      for (int i = 0; i < g_argc; ++i) std::cout << '\x1f' << g_argv[i];
      std::cout << '\n' << std::flush;
#endif
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

void read_line_rejects_oversize_on_all_platforms(const std::filesystem::path& self) {
  secure_frontend::EngineStdioProcess transport;
  expect(!transport.start({.executable = self, .arguments = {"--fake-engine", "--spew"}, .environment = {}}).has_value(), "fake engine must start");
  // --spew: after READY the fake writes 9000 'x' bytes with no newline.
  (void)transport.read_line(std::chrono::seconds(2));  // READY
  const auto result = transport.read_line(std::chrono::seconds(2));
  expect(result.kind == secure_frontend::EngineReadKind::failure, "an oversized engine line must be a failure on every platform");
  (void)transport.terminate(std::chrono::milliseconds(250));
}

void read_line_waits_for_a_record_split_across_writes(const std::filesystem::path& self) {
  secure_frontend::EngineStdioProcess transport;
  expect(!transport.start({.executable = self, .arguments = {"--fake-engine", "--split-ready"}, .environment = {}}).has_value(),
         "fake engine must start");
  const auto ready = transport.read_line(std::chrono::seconds(2));
  expect(ready.kind == secure_frontend::EngineReadKind::line && ready.line == "READY 4096 stop",
         "a record split across writes must be read whole within the budget, not time out early");
  (void)transport.terminate(std::chrono::milliseconds(250));
}

#if defined(_WIN32)
void job_object_terminates_grandchild(const std::filesystem::path& self) {
  secure_frontend::EngineStdioProcess transport;
  expect(!transport.start({.executable = self, .arguments = {"--fake-engine", "--spawn-grandchild"}, .environment = {}})
              .has_value(),
         "fake engine must start");
  const auto ready = transport.read_line(std::chrono::seconds(5));
  expect(ready.kind == secure_frontend::EngineReadKind::line && ready.line == "READY 4096 stop", "READY must arrive");
  const auto report = transport.read_line(std::chrono::seconds(5));
  expect(report.kind == secure_frontend::EngineReadKind::line && report.line.rfind("GRANDCHILD ", 0) == 0,
         "the fake must report its grandchild");
  const unsigned long pid = std::stoul(report.line.substr(11));
  expect(pid != 0, "the grandchild must have started");
  // Open the grandchild while it is certainly alive (it sleeps 30 s): the
  // handle pins this process object, so no PID reuse can confuse the check,
  // and nothing here ever acts on a bare PID.
  HANDLE grandchild = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
  expect(grandchild != nullptr, "the live grandchild must be openable before terminate");
  (void)transport.terminate(std::chrono::milliseconds(250));
  const bool gone = WaitForSingleObject(grandchild, 2000) == WAIT_OBJECT_0;
  CloseHandle(grandchild);
  expect(gone, "the grandchild must die with the Job (P4)");
}
#endif

#if !defined(_WIN32)
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
  expect(pid > 0, "the fake engine must have a pid");
  expect(transport.terminate(std::chrono::milliseconds(200)), "terminate must succeed even when SIGTERM is ignored");
  // The gate: terminate itself must have reaped the child -- no sleep, no race.
  expect(transport.pid_for_tests() == -1, "terminate must clear the child pid once it is reaped");
  errno = 0;
  const pid_t waited = waitpid(pid, nullptr, WNOHANG);
  expect(waited == -1 && errno == ECHILD, "the killed child must already be reaped by terminate");
  std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
  const std::string content((std::istreambuf_iterator<char>(stat)), std::istreambuf_iterator<char>());
  expect(content.empty() || content.find(") Z ") == std::string::npos,
         "no zombie may remain after terminate, saw: " + content.substr(0, 64));
}
#endif

}  // namespace

int main(const int argc, char* argv[]) {
  g_argc = argc;
  g_argv = argv;
  for (int index = 1; index < argc; ++index) {
    if (std::string(argv[index]) == "--fake-engine") return fake_engine();
    if (std::string(argv[index]) == "--fake-sleeper") {
      std::this_thread::sleep_for(std::chrono::seconds(30));
      return 0;
    }
  }
  try {
    const auto self = current_executable();
    test_round_trip(self);
    test_invalid_record();
    read_line_rejects_oversize_on_all_platforms(self);
    read_line_waits_for_a_record_split_across_writes(self);
#if defined(_WIN32)
    job_object_terminates_grandchild(self);
#endif
#if !defined(_WIN32)
    child_inherits_only_stdio_descriptors(self);
    child_receives_exact_argv_and_env(self);
    terminate_reaps_killed_child(self);
#endif
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

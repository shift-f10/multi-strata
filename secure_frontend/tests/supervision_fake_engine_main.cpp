// strata-supervision-fake-engine: a test-only stand-in for `strata --serve` (SP2 F1).
// Never installed. (SP1's tests/fake_engine_main.cpp is a different, simpler fake.) It speaks the solo serve protocol the frontend uses
// (READY, GEN -> T/DONE, STOP, QUIT) and adds the failure modes the
// supervision tests need; see the mode list in the SP2 plan header.
// Unknown arguments (--serve, --native PATH, --pack DIR, --gpu LIST, ...) are
// accepted and ignored, as the real engine accepts them.
#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#include <sddl.h>
#include <shellapi.h>
#else
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

extern char** environ;
#endif

namespace {

// The engine's fatal verification lines (upstream/serve/server.py FATAL_PREFIXES).
constexpr std::string_view kFatalPrefixes[] = {
    "ERR verify: timed out at layer ",
    "ERR verify batch: timed out at layer ",
    "ERR verify: an earlier window never finished",
    "ERR verify batch: an earlier window never finished",
};

struct Options final {
  bool ignore_term{false};
  bool spew{false};
  bool split_ready{false};
  int ready_delay_ms{0};
  unsigned long ready_context{4096};
  std::optional<int> exit_before_ready;
  bool hang_before_ready{false};
  std::optional<std::string> crash_after_ready;
  int crash_delay_ms{0};
  bool hang_in_gen{false};
  bool abort_in_gen{false};
  std::optional<int> fatal_line;
  bool stall_stdin{false};
  int fail_first{0};
  std::string counter_file;
  std::string record_file;
  bool spawn_grandchild{false};
  bool grandchild_setsid{false};
  bool grandchild_ignore_term{false};
  std::string grandchild_pidfile;
  bool echo_cmdline{false};
  std::string dump_file;
};

#if !defined(_WIN32)
// POSIX only: Windows reports GetCommandLineW() instead (clang's
// -Wunused-but-set-global rejects them there).
int g_argc = 0;
char** g_argv = nullptr;
#endif

bool value_of(const std::string_view argument, const std::string_view name, std::string& value) {
  if (argument.size() <= name.size() || argument.substr(0, name.size()) != name || argument[name.size()] != '=') return false;
  value = std::string(argument.substr(name.size() + 1));
  return true;
}

Options parse_options(const int argc, char** argv) {
  Options options;
  std::string value;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument{argv[index]};
    if (argument == "--ignore-term") options.ignore_term = true;
    else if (argument == "--spew") options.spew = true;
    else if (argument == "--split-ready") options.split_ready = true;
    else if (argument == "--hang-before-ready") options.hang_before_ready = true;
    else if (argument == "--hang-in-gen") options.hang_in_gen = true;
    else if (argument == "--abort-in-gen") options.abort_in_gen = true;
    else if (argument == "--stall-stdin") options.stall_stdin = true;
    else if (argument == "--spawn-grandchild") options.spawn_grandchild = true;
    else if (argument == "--grandchild-setsid") options.grandchild_setsid = true;
    else if (argument == "--grandchild-ignore-term") options.grandchild_ignore_term = true;
    else if (argument == "--echo-cmdline") options.echo_cmdline = true;
    else if (value_of(argument, "--ready-delay-ms", value)) options.ready_delay_ms = std::stoi(value);
    else if (value_of(argument, "--ready-context", value)) options.ready_context = std::stoul(value);
    else if (value_of(argument, "--exit-before-ready", value)) options.exit_before_ready = std::stoi(value);
    else if (value_of(argument, "--crash-after-ready", value)) options.crash_after_ready = value;
    else if (value_of(argument, "--crash-delay-ms", value)) options.crash_delay_ms = std::stoi(value);
    else if (value_of(argument, "--fatal-line", value)) options.fatal_line = std::clamp(std::stoi(value), 0, 3);
    else if (value_of(argument, "--fail-first", value)) options.fail_first = std::stoi(value);
    else if (value_of(argument, "--counter-file", value)) options.counter_file = value;
    else if (value_of(argument, "--record-file", value)) options.record_file = value;
    else if (value_of(argument, "--grandchild-pidfile", value)) options.grandchild_pidfile = value;
    else if (value_of(argument, "--dump-file", value)) options.dump_file = value;
  }
  return options;
}

void sleep_ms(const int milliseconds) { std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds)); }

[[noreturn]] void sleep_forever() {
  for (;;) std::this_thread::sleep_for(std::chrono::hours(1));
}

std::string hex(const std::string_view bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2U);
  for (const unsigned char byte : bytes) {
    out.push_back(kDigits[byte >> 4U]);
    out.push_back(kDigits[byte & 0x0fU]);
  }
  return out;
}

#if defined(_WIN32)
std::string utf8(const std::wstring_view text) {
  if (text.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<std::size_t>(std::max(size, 0)), '\0');
  if (size > 0) (void)WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size, nullptr, nullptr);
  return out;
}
#endif

// Written to <path>.tmp and renamed, so a reader never sees a partial number.
void write_pidfile(const std::string& path, const long pid) {
  const std::string temporary = path + ".tmp";
  {
    std::ofstream out(temporary, std::ios::trunc);
    out << pid << '\n';
  }
  std::error_code ignored;
  std::filesystem::rename(temporary, path, ignored);
}

[[noreturn]] void crash(const std::string& how) {
  std::cout.flush();
#if !defined(_WIN32)
  const rlimit no_core{0, 0};
  (void)setrlimit(RLIMIT_CORE, &no_core);  // a test crash must not leave core files in the build tree
#endif
  if (how == "ABRT") std::abort();
#if defined(_WIN32)
  if (how == "SEGV") RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, nullptr);
  if (how == "KILL") (void)TerminateProcess(GetCurrentProcess(), 137);
  if (how == "TERM") (void)TerminateProcess(GetCurrentProcess(), 143);
#else
  if (how == "SEGV" || how == "KILL" || how == "TERM") {
    const int signal_number = how == "SEGV" ? SIGSEGV : how == "KILL" ? SIGKILL : SIGTERM;
    (void)std::signal(signal_number, SIG_DFL);
    (void)std::raise(signal_number);
  }
#endif
  std::_Exit(std::stoi(how));
}

#if defined(_WIN32)
long spawn_grandchild(const Options&) {
  std::vector<wchar_t> buffer(32768);
  const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size()) return 0;
  const std::wstring self(buffer.data(), length);
  std::wstring line = L"\"" + self + L"\" --fake-sleeper";
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  if (!CreateProcessW(self.c_str(), line.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &info)) return 0;
  CloseHandle(info.hThread);
  CloseHandle(info.hProcess);
  return static_cast<long>(info.dwProcessId);
}
#else
long spawn_grandchild(const Options& options) {
  const pid_t child = fork();
  if (child != 0) return child < 0 ? 0 : static_cast<long>(child);
  if (options.grandchild_setsid) (void)setsid();
  if (options.grandchild_ignore_term) (void)std::signal(SIGTERM, SIG_IGN);
  const int null_fd = open("/dev/null", O_RDWR);  // never hold the protocol pipes open
  if (null_fd >= 0) {
    (void)dup2(null_fd, STDIN_FILENO);
    (void)dup2(null_fd, STDOUT_FILENO);
    (void)close(null_fd);
  }
  // POSIX: the grandchild writes its own pidfile after setsid/SIG_IGN, so a
  // test that reads the pid never races the grandchild's setup.
  if (!options.grandchild_pidfile.empty()) write_pidfile(options.grandchild_pidfile, static_cast<long>(getpid()));
  sleep_ms(60000);
  std::_Exit(0);
}
#endif

#if !defined(_WIN32)
// This process's open descriptors, dropping the directory iterator's own one
// (its link target is /proc/<pid>/fd).
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

std::string join_hex(const std::vector<std::string>& items) {
  std::string out;
  for (const auto& item : items) {
    if (!out.empty()) out += ',';
    out += hex(item);
  }
  return out;
}

#if !defined(_WIN32)
std::string status_field(const std::string_view name) {
  std::ifstream status("/proc/self/status");
  std::string line;
  while (std::getline(status, line)) {
    if (line.size() > name.size() && line.compare(0, name.size(), name) == 0 && line[name.size()] == ':') {
      const auto first = line.find_first_not_of(" \t", name.size() + 1U);
      return first == std::string::npos ? std::string{} : line.substr(first);
    }
  }
  return {};
}
#else
std::string token_report() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return "sid=? elevated=? integrity=?";
  std::string sid_text = "?";
  DWORD size = 0;
  (void)GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<unsigned char> user(size);
  if (size != 0 && GetTokenInformation(token, TokenUser, user.data(), size, &size)) {
    LPWSTR sid = nullptr;
    if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid)) {
      sid_text = utf8(sid);
      LocalFree(sid);
    }
  }
  TOKEN_ELEVATION elevation{};
  DWORD elevation_size = sizeof(elevation);
  const bool elevated = GetTokenInformation(token, TokenElevation, &elevation, elevation_size, &elevation_size) && elevation.TokenIsElevated != 0;
  DWORD rid = 0;
  size = 0;
  (void)GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
  std::vector<unsigned char> label(size);
  if (size != 0 && GetTokenInformation(token, TokenIntegrityLevel, label.data(), size, &size)) {
    PSID sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(label.data())->Label.Sid;
    rid = *GetSidSubAuthority(sid, static_cast<DWORD>(*GetSidSubAuthorityCount(sid) - 1U));
  }
  CloseHandle(token);
  return "sid=" + sid_text + " elevated=" + (elevated ? "1" : "0") + " integrity=" + std::to_string(rid);
}
#endif

// The DUMP report (SP2 plan, Task 2). Every list is hex so one record stays one line.
std::vector<std::string> dump_lines() {
  std::vector<std::string> lines;
  std::vector<std::string> arguments;
  std::vector<std::string> environment;
  std::string cwd;
#if defined(_WIN32)
  lines.push_back("HANDLES " + std::to_string(GetCurrentProcessId()));
  int count = 0;
  LPWSTR* wide = CommandLineToArgvW(GetCommandLineW(), &count);
  for (int index = 0; wide != nullptr && index < count; ++index) arguments.push_back(utf8(wide[index]));
  if (wide != nullptr) LocalFree(wide);
  LPWCH block = GetEnvironmentStringsW();
  for (const wchar_t* entry = block; entry != nullptr && *entry != L'\0'; entry += std::wcslen(entry) + 1U) environment.push_back(utf8(entry));
  if (block != nullptr) FreeEnvironmentStringsW(block);
  std::vector<wchar_t> directory(32768);
  const DWORD length = GetCurrentDirectoryW(static_cast<DWORD>(directory.size()), directory.data());
  cwd = utf8(std::wstring_view(directory.data(), length));
  lines.push_back("SIG none");
#else
  lines.push_back("FDS " + open_descriptors());
  for (int index = 0; index < g_argc; ++index) arguments.emplace_back(g_argv[index]);
  for (char** entry = environ; entry != nullptr && *entry != nullptr; ++entry) environment.emplace_back(*entry);
  std::error_code ignored;
  cwd = std::filesystem::current_path(ignored).string();
  lines.push_back("SIG blk=" + status_field("SigBlk") + " ign=" + status_field("SigIgn"));
#endif
  std::sort(environment.begin(), environment.end());
  lines.push_back("ARGV " + join_hex(arguments));
  lines.push_back("ENV " + join_hex(environment));
  lines.push_back("CWD " + hex(cwd));
#if defined(_WIN32)
  lines.push_back("IDS " + token_report());
#else
  lines.push_back("IDS uid=" + std::to_string(getuid()) + " gid=" + std::to_string(getgid()) + " euid=" + std::to_string(geteuid()) +
                  " egid=" + std::to_string(getegid()) + " nnp=" + status_field("NoNewPrivs") + " capeff=" + status_field("CapEff"));
#endif
  lines.emplace_back("END");
  return lines;
}

void dump() {
  for (const auto& line : dump_lines()) std::cout << line << '\n';
  std::cout << std::flush;
}

// Written to <path>.tmp and renamed, so a reader never sees a partial report.
// The report is built before the file is opened, so FDS never lists it.
void write_dump_file(const std::string& path) {
  const auto lines = dump_lines();
  const std::string temporary = path + ".tmp";
  {
    std::ofstream out(temporary, std::ios::trunc | std::ios::binary);
    for (const auto& line : lines) out << line << '\n';
  }
  std::error_code ignored;
  std::filesystem::rename(temporary, path, ignored);
}

void echo_cmdline() {
#if defined(_WIN32)
  std::cout << "CMDLINE " << hex(utf8(GetCommandLineW())) << '\n' << std::flush;
#else
  std::string joined;
  for (int index = 0; index < g_argc; ++index) {
    if (index != 0) joined += ' ';
    joined += g_argv[index];
  }
  std::cout << "CMDLINE " << hex(joined) << '\n' << std::flush;
#endif
}

int serve(const Options& options) {
#if !defined(_WIN32)
  if (options.ignore_term) (void)std::signal(SIGTERM, SIG_IGN);
#endif
  if (!options.record_file.empty()) std::ofstream(options.record_file, std::ios::trunc).flush();
  if (options.fail_first > 0 && !options.counter_file.empty()) {
    int started = 0;
    {
      std::ifstream in(options.counter_file);
      in >> started;
    }
    {
      std::ofstream out(options.counter_file, std::ios::trunc);
      out << (started + 1) << '\n';
    }
    if (started < options.fail_first) return 1;
  }
  // A real engine may emit human diagnostics on stderr before READY; they must
  // never reach the strict stdout protocol stream.
  std::cerr << "diagnostic: private engine startup\n" << std::flush;
  if (!options.dump_file.empty()) write_dump_file(options.dump_file);
  if (options.exit_before_ready) return *options.exit_before_ready;
  if (options.hang_before_ready) sleep_forever();
  if (options.echo_cmdline) echo_cmdline();
  if (options.ready_delay_ms > 0) sleep_ms(options.ready_delay_ms);
  const std::string ready = "READY " + std::to_string(options.ready_context) + " stop\n";
  if (options.split_ready) {
    std::cout << ready.substr(0, 3) << std::flush;
    sleep_ms(100);
    std::cout << ready.substr(3) << std::flush;
  } else {
    std::cout << ready << std::flush;
  }
  if (options.spawn_grandchild) {
    const long grandchild = spawn_grandchild(options);
#if defined(_WIN32)
    if (!options.grandchild_pidfile.empty()) write_pidfile(options.grandchild_pidfile, grandchild);
#endif
    if (options.grandchild_pidfile.empty()) std::cout << "GRANDCHILD " << grandchild << '\n' << std::flush;
  }
  if (options.crash_after_ready) {
    if (options.crash_delay_ms > 0) sleep_ms(options.crash_delay_ms);
    crash(*options.crash_after_ready);
  }
  if (options.stall_stdin) sleep_forever();
  std::string line;
  if (options.spew) {
    // One record larger than kMaxReadLineBytes with no newline, then stay alive.
    std::cout << std::string(9000, 'x') << std::flush;
    while (std::getline(std::cin, line)) {
    }
    return 0;
  }
  while (std::getline(std::cin, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (!options.record_file.empty()) {
      std::ofstream out(options.record_file, std::ios::app);
      out << line << '\n';
    }
    if (line.rfind("GEN ", 0) == 0) {
      if (options.hang_in_gen) sleep_forever();  // stops reading stdin: STOP is never seen
      if (options.abort_in_gen) {
        std::cout << "T 7\n" << std::flush;
        crash("ABRT");
      }
      if (options.fatal_line) {
        const auto index = static_cast<std::size_t>(*options.fatal_line);
        std::cout << "T 7\n" << kFatalPrefixes[index] << (index < 2U ? "12" : "") << "\nDONE stop\n" << std::flush;
        continue;
      }
      std::cout << "T 7\nDONE stop\n" << std::flush;
    } else if (line == "QUIT") {
      return 0;
    } else if (line == "DUMP") {
      dump();
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
#if defined(_WIN32)
  // The crash modes (ABRT, SEGV, --abort-in-gen) must end the process at once.
  // Without this a crash can wait on a Windows Error Reporting / critical-error
  // dialog on the MSYS2 runner and the test hangs until its CTest timeout. The
  // error mode is inherited by --fake-sleeper grandchildren.
  (void)SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#endif
#if !defined(_WIN32)
  g_argc = argc;
  g_argv = argv;
#endif
  for (int index = 1; index < argc; ++index) {
    if (std::string_view(argv[index]) == "--fake-sleeper") {
      sleep_ms(60000);
      return 0;
    }
  }
  return serve(parse_options(argc, argv));
}

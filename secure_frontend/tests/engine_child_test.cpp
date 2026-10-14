#include "secure_frontend/engine_process.hpp"
#include "secure_frontend/engine_stdio_process.hpp"
#include "secure_frontend/exit_status.hpp"

#include "support/fake_engine_dump.hpp"
#include "support/test_paths.hpp"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"

#include <aclapi.h>
#else
#include <csignal>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace {

using namespace std::chrono_literals;
using secure_frontend::ExitKind;
using secure_frontend::ExitPlatform;
using secure_frontend::ExitStatus;
using secure_frontend::KillReason;

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

std::optional<ExitStatus> wait_reaped(secure_frontend::EngineStdioProcess& child, const std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    if (auto status = child.try_reap()) return status;
    if (std::chrono::steady_clock::now() >= deadline) return std::nullopt;
    std::this_thread::sleep_for(10ms);
  }
}

void proc04_exit_status_is_classified() {
  struct Row {
    ExitStatus status;
    KillReason sent;
    ExitPlatform platform;
    ExitKind kind;
    KillReason reason;
    const char* name;
  };
  const std::vector<Row> table{
      {{false, 0U}, KillReason::none, ExitPlatform::posix, ExitKind::clean_exit, KillReason::none, "posix exit 0"},
      {{false, 1U}, KillReason::none, ExitPlatform::posix, ExitKind::error_exit, KillReason::none, "posix exit 1 (ERR path or CUDA fault)"},
      {{false, 127U}, KillReason::none, ExitPlatform::posix, ExitKind::error_exit, KillReason::none, "posix exit 127 after a successful exec"},
      {{true, 6U}, KillReason::none, ExitPlatform::posix, ExitKind::abort, KillReason::none, "posix SIGABRT (watchdog)"},
      {{true, 9U}, KillReason::none, ExitPlatform::posix, ExitKind::killed_external, KillReason::none, "posix SIGKILL not ours (OOM)"},
      {{true, 11U}, KillReason::none, ExitPlatform::posix, ExitKind::crashed, KillReason::none, "posix SIGSEGV"},
      {{true, 9U}, KillReason::fatal_line, ExitPlatform::posix, ExitKind::killed_by_supervisor, KillReason::fatal_line, "posix our SIGKILL"},
      {{true, 15U}, KillReason::shutdown, ExitPlatform::posix, ExitKind::killed_by_supervisor, KillReason::shutdown, "posix our SIGTERM"},
      {{true, 6U}, KillReason::protocol_failed, ExitPlatform::posix, ExitKind::abort, KillReason::none, "aborted before our kill landed"},
      {{false, 0U}, KillReason::none, ExitPlatform::windows, ExitKind::clean_exit, KillReason::none, "windows exit 0"},
      {{false, 1U}, KillReason::none, ExitPlatform::windows, ExitKind::error_exit, KillReason::none, "windows exit 1"},
      {{false, 3U}, KillReason::none, ExitPlatform::windows, ExitKind::abort, KillReason::none, "windows abort() exit 3"},
      {{false, 0xC0000409U}, KillReason::none, ExitPlatform::windows, ExitKind::abort, KillReason::none, "windows fast-fail abort"},
      {{false, 0xC0000005U}, KillReason::none, ExitPlatform::windows, ExitKind::crashed, KillReason::none, "windows access violation"},
      {{false, 0x20000001U}, KillReason::ready_timeout, ExitPlatform::windows, ExitKind::killed_by_supervisor, KillReason::ready_timeout,
       "windows our TerminateJobObject code"},
  };
  for (const auto& row : table) {
    const auto got = secure_frontend::classify_exit(row.status, row.sent, row.platform);
    expect(got.kind == row.kind && got.reason == row.reason, std::string("classification: ") + row.name);
  }
  expect(secure_frontend::describe_exit({ExitKind::killed_by_supervisor, KillReason::fatal_line}) == "killed_by_supervisor(fatal_line)",
         "describe a supervisor kill");
  expect(secure_frontend::describe_exit({ExitKind::abort, KillReason::none}) == "abort", "describe an abort");

  // Real children: the raw status is captured by try_reap() and classified natively.
  struct Live {
    std::string argument;
    ExitKind kind;
  };
  std::vector<Live> live{{"--exit-before-ready=1", ExitKind::error_exit}, {"--crash-after-ready=ABRT", ExitKind::abort},
                         {"--crash-after-ready=SEGV", ExitKind::crashed}};
#if !defined(_WIN32)
  live.push_back({"--crash-after-ready=KILL", ExitKind::killed_external});
#endif
  for (const auto& run : live) {
    secure_frontend::EngineStdioProcess child;
    expect(!child.start({.executable = test_support::fake_engine_path(), .arguments = {run.argument}, .environment = {}}).has_value(),
           "start " + run.argument);
    const auto status = wait_reaped(child, 10s);
    expect(status.has_value(), "the child must end: " + run.argument);
    if (status) {
      expect(secure_frontend::classify_exit(*status, KillReason::none).kind == run.kind, "live classification: " + run.argument);
      expect(child.exit_status() == status, "exit_status() keeps the reaped status");
    }
  }
  // Our own kill is ours, never confused with the engine's `return 1`.
  secure_frontend::EngineStdioProcess killed;
  expect(!killed.start({.executable = test_support::fake_engine_path(), .arguments = {"--hang-before-ready"}, .environment = {}}).has_value(),
         "start hang");
  expect(killed.terminate(100ms), "terminate");
  const auto status = killed.exit_status();
  expect(status && secure_frontend::classify_exit(*status, KillReason::shutdown).kind == ExitKind::killed_by_supervisor,
         "a supervisor kill classifies as ours");
}

#if !defined(_WIN32)
void proc05_group_killed_after_leader_reaped() {
  const auto dir = test_support::make_temp_dir("c1");
  const auto pidfile = dir / "grandchild.pid";
  secure_frontend::EngineStdioProcess engine;
  expect(!engine.start({.executable = test_support::fake_engine_path(),
                        .arguments = {"--spawn-grandchild", "--grandchild-ignore-term", "--grandchild-pidfile=" + test_support::utf8_path(pidfile)},
                        .environment = {}})
              .has_value(),
         "start");
  expect(engine.read_line(5s).line == "READY 4096 stop", "READY");
  const auto grandchild = test_support::read_pidfile(pidfile, 5s);
  expect(grandchild.has_value(), "the grandchild started");
  if (!grandchild) return;
  (void)kill(static_cast<pid_t>(engine.pid()), SIGKILL);  // only the leader
  expect(wait_reaped(engine, 5s).has_value(), "the leader is reaped first");
  expect(test_support::process_alive(*grandchild), "precondition: the grandchild outlived its leader");
  expect(engine.terminate(200ms), "terminate succeeds");
  expect(test_support::wait_until_gone(*grandchild, 2s), "a group member dies although the leader was already reaped");
  test_support::kill_process(*grandchild);
}
#endif

#if !defined(_WIN32)
void proc02_child_signal_state_is_default() {
  struct sigaction ignore {};
  ignore.sa_handler = SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  struct sigaction previous {};
  (void)sigaction(SIGPIPE, &ignore, &previous);  // what install_process_defaults() does in the frontend
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, SIGUSR1);
  sigset_t old_mask;
  (void)pthread_sigmask(SIG_BLOCK, &block, &old_mask);
  secure_frontend::EngineStdioProcess child;
  const bool started = !child.start({.executable = test_support::fake_engine_path(), .arguments = {}, .environment = {}}).has_value();
  (void)pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
  (void)sigaction(SIGPIPE, &previous, nullptr);
  expect(started, "start");
  expect(child.read_line(5s).line == "READY 4096 stop", "READY");
  const auto dump = test_support::request_dump(child, 5s);
  expect(dump && dump->sig_blocked == "0000000000000000", "the engine starts with an empty signal mask, saw " + (dump ? dump->sig_blocked : ""));
  expect(dump && dump->sig_ignored == "0000000000000000", "and nothing ignored (default SIGPIPE), saw " + (dump ? dump->sig_ignored : ""));
  (void)child.terminate(250ms);
}
#endif

#if !defined(_WIN32)
void proc02_canary_descriptors_absent() {
  // What a careless launcher would leak: a non-CLOEXEC fd, a listening socket, an open token file.
  const auto dir = test_support::make_temp_dir("n5");
  const auto token = dir / "token";
  secure_frontend_test::write_file(token, "secret-token", 0600);
  const int token_fd = open(token.c_str(), O_RDONLY);
  const int null_fd = open("/dev/null", O_RDONLY);
  const int listener = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  const bool listening = listener >= 0 && bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0 && listen(listener, 1) == 0;
  expect(token_fd >= 0 && null_fd >= 0 && listening, "canaries opened");
  for (const int fd : {token_fd, null_fd, listener}) expect(fcntl(fd, F_GETFD) == 0, "precondition: canary " + std::to_string(fd) + " is inheritable");
  secure_frontend::EngineStdioProcess child;
  expect(!child.start({.executable = test_support::fake_engine_path(), .arguments = {}, .environment = {}}).has_value(), "start");
  expect(child.read_line(5s).line == "READY 4096 stop", "READY");
  const auto dump = test_support::request_dump(child, 5s);
  expect(dump && dump->fds == std::vector<int>{0, 1, 2}, "the engine sees only stdio: no canary descriptor");
  (void)child.terminate(250ms);
  for (const int fd : {token_fd, null_fd, listener}) (void)close(fd);
}
#endif

#if !defined(_WIN32)
std::optional<int> run_command(const std::string& executable, const std::vector<std::string>& arguments) {
  secure_frontend::EngineProcess process;
  if (process.start({.executable = executable, .arguments = arguments, .environment = {}}).has_value()) return std::nullopt;
  return process.wait_for(10s);
}

std::optional<int> run_as_nobody(const std::vector<std::string>& command) {
  std::vector<std::string> arguments{"-n", "-u", "nobody"};
  arguments.insert(arguments.end(), command.begin(), command.end());
  return run_command("/usr/bin/sudo", arguments);
}

// Exit 0: opened /proc/<pid>/fd/0 for writing. 3: /proc/<pid> not visible
// (engine gone, or hidepid). 4: the open itself was refused. The open runs in a
// subshell because a failed `exec` redirection exits a POSIX shell outright.
constexpr const char* kReopenProbe = R"([ -d "/proc/$1" ] || exit 3; ( exec 3>"$0" ) 2>/dev/null || exit 4; exit 0)";
constexpr int kProbeOpened = 0;
constexpr int kProbeOpenDenied = 4;

void proc03_other_uid_cannot_open_engine_fd() {
  const char* enabled = std::getenv("STRATA_TEST_SECOND_UID_SUDO");
  if (enabled == nullptr || std::string(enabled) != "1") {
    test_support::skip("needs a second uid: CI sets STRATA_TEST_SECOND_UID_SUDO=1 where `sudo -n -u nobody` is allowed");
  }
  // The variable is CI's demand that R2 be proven: a runner that cannot sudo fails, never skips.
  if (run_as_nobody({"/bin/true"}) != 0) {
    expect(false, "STRATA_TEST_SECOND_UID_SUDO=1 but `sudo -n -u nobody` failed");
    return;
  }
  secure_frontend::EngineStdioProcess child;
  expect(!child.start({.executable = test_support::fake_engine_path(), .arguments = {}, .environment = {}}).has_value(), "start");
  expect(child.read_line(5s).line == "READY 4096 stop", "READY");
  const std::string pid = std::to_string(child.pid());
  const std::string target = "/proc/" + pid + "/fd/0";
  // Positive control: the identical probe as our own uid reaches and opens the path.
  const auto same_uid = run_command("/bin/sh", {"-c", kReopenProbe, target, pid});
  expect(same_uid == kProbeOpened, "positive control: the same uid opens " + target + ", probe exit " +
                                       (same_uid ? std::to_string(*same_uid) : std::string("none")));
  const auto other_uid = run_as_nobody({"/bin/sh", "-c", kReopenProbe, target, pid});
  expect(other_uid == kProbeOpenDenied, "another uid sees the engine but cannot open its stdin through /proc, probe exit " +
                                            (other_uid ? std::to_string(*other_uid) : std::string("none")));
  // The engine was alive throughout: it still answers on the frontend's own stdin.
  std::string error;
  expect(child.write_line("DUMP", error), "DUMP through the frontend's stdin: " + error);
  const auto reply = child.read_line(5s);
  expect(reply.kind == secure_frontend::EngineReadKind::line && reply.line.rfind("FDS ", 0) == 0, "the engine is alive after the probes");
  (void)child.terminate(250ms);
}

void proc03_same_uid_reopen_is_accepted_risk() {
  secure_frontend::EngineStdioProcess child;
  expect(!child.start({.executable = test_support::fake_engine_path(), .arguments = {}, .environment = {}}).has_value(), "start");
  expect(child.read_line(5s).line == "READY 4096 stop", "READY");
  const std::string target = "/proc/" + std::to_string(child.pid()) + "/fd/0";
  const int injected = open(target.c_str(), O_WRONLY | O_CLOEXEC);
  // Spec §3.13: the same uid CAN reopen the engine's stdin through /proc and
  // inject protocol lines. Recorded accepted risk (threat model, release
  // record): the upstream engine cannot be made non-dumpable and its protocol
  // has no nonce without engine changes. If this starts failing, a mitigation
  // landed: update the threat model and flip this test.
  const int open_error = errno;
  expect(injected >= 0, "same-uid reopen of the engine's stdin still works (accepted risk, spec 3.13); open failed: " +
                            std::string(std::strerror(open_error)));
  if (injected >= 0) {
    const std::string line = "DUMP\n";
    expect(write(injected, line.data(), line.size()) == static_cast<ssize_t>(line.size()), "an injected line is accepted by the pipe");
    (void)close(injected);
    const auto reply = child.read_line(5s);
    expect(reply.kind == secure_frontend::EngineReadKind::line && reply.line.rfind("FDS ", 0) == 0, "the engine acts on the injected line");
  }
  (void)child.terminate(250ms);
}
#endif

#if defined(_WIN32)
template <typename Function>
Function resolve(const wchar_t* module, const char* name) {
  const HMODULE handle = GetModuleHandleW(module);
  if (handle == nullptr) return nullptr;
  return reinterpret_cast<Function>(reinterpret_cast<void (*)()>(GetProcAddress(handle, name)));
}

struct HandleEntry {
  HANDLE HandleValue;
  ULONG_PTR HandleCount;
  ULONG_PTR PointerCount;
  ULONG GrantedAccess;
  ULONG ObjectTypeIndex;
  ULONG HandleAttributes;
  ULONG Reserved;
};
struct HandleSnapshot {
  ULONG_PTR NumberOfHandles;
  ULONG_PTR Reserved;
  HandleEntry Handles[1];
};

void proc02_canary_handles_absent() {
  SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
  const auto dir = test_support::make_temp_dir("n5w");
  HANDLE file = CreateFileW((dir / "token").wstring().c_str(), GENERIC_WRITE, 0, &inherit, CREATE_ALWAYS, 0, nullptr);
  HANDLE event = CreateEventW(&inherit, TRUE, FALSE, nullptr);
  WSADATA data{};
  (void)WSAStartup(MAKEWORD(2, 2), &data);
  const SOCKET socket_handle = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
  (void)SetHandleInformation(reinterpret_cast<HANDLE>(socket_handle), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
  const std::vector<HANDLE> canaries{file, event, reinterpret_cast<HANDLE>(socket_handle)};
  for (HANDLE canary : canaries) {
    DWORD flags = 0;
    expect(canary != nullptr && canary != INVALID_HANDLE_VALUE && GetHandleInformation(canary, &flags) && (flags & HANDLE_FLAG_INHERIT) != 0U,
           "precondition: the canary is inheritable");
  }
  secure_frontend::EngineStdioProcess child;
  expect(!child.start({.executable = test_support::fake_engine_path(), .arguments = {}, .environment = {}}).has_value(), "start");
  expect(child.read_line(5s).line == "READY 4096 stop", "READY");
  // Parent-side inspection (spec §3.11): snapshot the child's handle table,
  // duplicate each entry and compare objects; assert canary absence, not a count.
  using QueryFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
  using CompareFn = BOOL(WINAPI*)(HANDLE, HANDLE);
  const auto query = resolve<QueryFn>(L"ntdll.dll", "NtQueryInformationProcess");
  const auto compare = resolve<CompareFn>(L"kernelbase.dll", "CompareObjectHandles");
  HANDLE process = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(child.pid()));
  expect(process != nullptr && query != nullptr && compare != nullptr, "inspection APIs are available (Windows 10 1607+)");
  if (process != nullptr && query != nullptr && compare != nullptr) {
    // True when some entry of a fresh snapshot of the engine's handle table is
    // the same kernel object as `target`. The snapshot itself is checked so a
    // failed or garbled inspection cannot pass as "absent".
    const auto engine_holds = [&](HANDLE target) -> bool {
      constexpr LONG info_length_mismatch = static_cast<LONG>(0xC0000004UL);  // STATUS_INFO_LENGTH_MISMATCH
      std::vector<unsigned char> buffer(1U << 16U);
      ULONG needed = 0;
      LONG status = query(process, 51 /* ProcessHandleInformation */, buffer.data(), static_cast<ULONG>(buffer.size()), &needed);
      for (int attempt = 0; status == info_length_mismatch && attempt < 4; ++attempt) {
        buffer.resize(std::max<std::size_t>(needed, buffer.size() * 2U) + 4096U);
        status = query(process, 51, buffer.data(), static_cast<ULONG>(buffer.size()), &needed);
      }
      if (status != 0) {
        std::ostringstream hex;
        hex << std::hex << static_cast<unsigned long>(static_cast<ULONG>(status));
        expect(false, "handle snapshot of the engine, NTSTATUS 0x" + hex.str());
        return false;
      }
      const auto* snapshot = reinterpret_cast<const HandleSnapshot*>(buffer.data());
      const std::size_t capacity = (buffer.size() - offsetof(HandleSnapshot, Handles)) / sizeof(HandleEntry);
      expect(snapshot->NumberOfHandles >= 3U && snapshot->NumberOfHandles <= capacity,
             "the snapshot lists a plausible handle count (at least stdio), saw " + std::to_string(snapshot->NumberOfHandles));
      const std::size_t count = std::min<std::size_t>(snapshot->NumberOfHandles, capacity);
      const HandleEntry* entries = snapshot->Handles;
      bool duplicated_any = false;
      bool found = false;
      for (std::size_t index = 0; index < count; ++index) {
        HANDLE duplicate = nullptr;
        if (!DuplicateHandle(process, entries[index].HandleValue, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) continue;
        duplicated_any = true;
        if (compare(duplicate, target)) found = true;
        CloseHandle(duplicate);
      }
      expect(duplicated_any, "at least one engine handle could be duplicated for comparison");
      return found;
    };
    for (HANDLE canary : canaries) expect(!engine_holds(canary), "a parent canary handle reached the engine");
    // Positive control: plant the event in the engine; the same inspection must now find it.
    HANDLE injected = nullptr;
    const bool planted = DuplicateHandle(GetCurrentProcess(), event, process, &injected, 0, FALSE, DUPLICATE_SAME_ACCESS) != 0;
    expect(planted, "positive control: the event is planted in the engine");
    if (planted) {
      expect(engine_holds(event), "positive control: the inspection finds a handle the engine does hold");
      (void)DuplicateHandle(process, injected, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    }
  }
  if (process != nullptr) CloseHandle(process);
  (void)child.terminate(250ms);
  CloseHandle(file);
  CloseHandle(event);
  (void)closesocket(socket_handle);
}
std::vector<unsigned char> current_token_user() {
  HANDLE token = nullptr;
  (void)OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
  DWORD size = 0;
  (void)GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<unsigned char> buffer(size);
  (void)GetTokenInformation(token, TokenUser, buffer.data(), size, &size);
  CloseHandle(token);
  return buffer;  // a TOKEN_USER
}

void proc02_stdin_pipe_dacl_is_owner_only() {
  secure_frontend::EngineStdioProcess child;
  expect(!child.start({.executable = test_support::fake_engine_path(), .arguments = {}, .environment = {}}).has_value(), "start");
  expect(child.read_line(5s).line == "READY 4096 stop", "READY");
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const DWORD status = GetSecurityInfo(static_cast<HANDLE>(child.stdin_handle_for_tests()), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, &dacl, nullptr, &descriptor);
  expect(status == ERROR_SUCCESS && dacl != nullptr, "the pipe has an explicit DACL");
  if (status == ERROR_SUCCESS && dacl != nullptr) {
    ACL_SIZE_INFORMATION size{};
    expect(GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation) && size.AceCount == 1U, "exactly one ACE");
    void* ace = nullptr;
    if (GetAce(dacl, 0, &ace)) {
      const auto* allowed = static_cast<ACCESS_ALLOWED_ACE*>(ace);
      const auto user = current_token_user();
      expect(allowed->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "an allow ACE");
      expect(EqualSid(const_cast<DWORD*>(&allowed->SidStart), reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid) != FALSE,
             "for the current user only");
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    expect(GetSecurityDescriptorControl(descriptor, &control, &revision) && (control & SE_DACL_PROTECTED) != 0, "protected: nothing inherited");
  }
  if (descriptor != nullptr) LocalFree(descriptor);
  const std::wstring& name = child.stdin_pipe_name_for_tests();
  expect(name.size() > 33U && name.find_last_of(L'-') == name.size() - 33U, "the name ends with a 128-bit random suffix");
  (void)child.terminate(250ms);
}

void proc03_windows_pipe_second_open_fails() {
  secure_frontend::EngineStdioProcess child;
  expect(!child.start({.executable = test_support::fake_engine_path(), .arguments = {}, .environment = {}}).has_value(), "start");
  expect(child.read_line(5s).line == "READY 4096 stop", "READY");
  // A squatter opens the read end, as the engine does: the single instance is
  // taken by our own client, so the pipe must be busy (not merely the wrong mode).
  HANDLE second = CreateFileW(child.stdin_pipe_name_for_tests().c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
  const DWORD error = second == INVALID_HANDLE_VALUE ? GetLastError() : 0U;
  if (second != INVALID_HANDLE_VALUE) CloseHandle(second);
  expect(second == INVALID_HANDLE_VALUE && error == ERROR_PIPE_BUSY,
         "a second client open of the engine stdin pipe is busy, error " + std::to_string(error));
  // Nor can a second server instance be created on the name (first-instance / one-instance guard).
  HANDLE rival = CreateNamedPipeW(child.stdin_pipe_name_for_tests().c_str(), PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_WAIT,
                                  PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nullptr);
  const DWORD rival_error = rival == INVALID_HANDLE_VALUE ? GetLastError() : 0U;
  if (rival != INVALID_HANDLE_VALUE) CloseHandle(rival);
  expect(rival == INVALID_HANDLE_VALUE && (rival_error == ERROR_ACCESS_DENIED || rival_error == ERROR_PIPE_BUSY),
         "a second server instance on the name is refused, error " + std::to_string(rival_error));
  (void)child.terminate(250ms);
}
void proc01_windows_argv_round_trip() {
  const std::vector<std::string> tricky{"a \"quoted\" word", "C:\\path with space\\", "trailing\\", "back\\\\slashes\\\"",
                                        "%PATH%",           "^&|<>()",               "line\nbreak", "\xE2\x9C\x93 \xF0\x9F\x98\x80",
                                        "",                 "-flag=value"};
  std::vector<std::string> arguments{"--echo-cmdline"};
  arguments.insert(arguments.end(), tricky.begin(), tricky.end());
  secure_frontend::EngineStdioProcess child;
  expect(!child.start({.executable = test_support::fake_engine_path(), .arguments = arguments, .environment = {}}).has_value(), "start");
  expect(child.read_line(5s).line.rfind("CMDLINE ", 0) == 0, "the raw command line is reported first");
  expect(child.read_line(5s).line == "READY 4096 stop", "READY");
  const auto dump = test_support::request_dump(child, 5s);
  std::vector<std::string> expected{test_support::utf8_path(test_support::fake_engine_path()), "--serve"};
  expected.insert(expected.end(), arguments.begin(), arguments.end());
  expect(dump && dump->argv == expected, "CommandLineToArgvW in the child yields exactly the argv the frontend was given");
  (void)child.terminate(250ms);
}
#endif

}  // namespace

int main(int argc, char* argv[]) {
  return secure_frontend_test::run_cases(argc, argv,
                                         {
                                             {"proc04_exit_status_is_classified", proc04_exit_status_is_classified},
#if !defined(_WIN32)
                                             {"proc05_group_killed_after_leader_reaped", proc05_group_killed_after_leader_reaped},
                                             {"proc02_child_signal_state_is_default", proc02_child_signal_state_is_default},
                                             {"proc02_canary_descriptors_absent", proc02_canary_descriptors_absent},
                                             {"proc03_other_uid_cannot_open_engine_fd", proc03_other_uid_cannot_open_engine_fd},
                                             {"proc03_same_uid_reopen_is_accepted_risk", proc03_same_uid_reopen_is_accepted_risk},
#endif
#if defined(_WIN32)
                                             {"proc02_canary_handles_absent", proc02_canary_handles_absent},
                                             {"proc02_stdin_pipe_dacl_is_owner_only", proc02_stdin_pipe_dacl_is_owner_only},
                                             {"proc03_windows_pipe_second_open_fails", proc03_windows_pipe_second_open_fails},
                                             {"proc01_windows_argv_round_trip", proc01_windows_argv_round_trip},
#endif
                                         },
                                         failures);
}

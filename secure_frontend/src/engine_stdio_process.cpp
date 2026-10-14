#include "secure_frontend/engine_stdio_process.hpp"

#include "secure_frontend/deadline.hpp"
#include "secure_frontend/supervision_defaults.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"

#include <bcrypt.h>
#include <sddl.h>
#else
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "posix_child_launch.hpp"
#endif

namespace secure_frontend {
namespace {

bool contains_nul(const std::string_view value) { return value.find('\0') != std::string_view::npos; }
// Checks the native form: path::string() narrows through the ANSI code page on
// Windows and can throw or mangle a non-ASCII path.
bool path_contains_nul(const std::filesystem::path& value) {
  return value.native().find(std::filesystem::path::value_type{}) != std::filesystem::path::string_type::npos;
}

std::optional<ProcessError> validate(const EngineCommand& command) {
  if (command.executable.empty() || path_contains_nul(command.executable)) {
    return ProcessError{ProcessErrorCode::invalid_command, "engine executable is invalid"};
  }
  for (const auto& arg : command.arguments) {
    if (arg == "--serve" || contains_nul(arg)) {
      return ProcessError{ProcessErrorCode::invalid_command, "engine arguments contain an invalid entry"};
    }
  }
  for (const auto& [name, value] : command.environment) {
    if (name.empty() || name.find('=') != std::string::npos || contains_nul(name) || contains_nul(value)) {
      return ProcessError{ProcessErrorCode::invalid_command, "engine environment contains an invalid entry"};
    }
  }
  return std::nullopt;
}

#if !defined(_WIN32)
void close_fd(int& fd) noexcept { if (fd >= 0) { (void)close(fd); fd = -1; } }

// A pidfd becomes readable when the child exits, so the supervisor can wait on
// the child itself (kernel 5.3+). -1 means "poll instead".
int open_pidfd(const pid_t pid) noexcept {
#if defined(__linux__) && defined(SYS_pidfd_open)
  return static_cast<int>(syscall(SYS_pidfd_open, pid, 0U));
#else
  (void)pid;
  return -1;
#endif
}

bool write_without_sigpipe(const int fd, const char* data, const std::size_t count, ssize_t& written) {
  sigset_t block{};
  sigemptyset(&block);
  sigaddset(&block, SIGPIPE);
  sigset_t prior{};
  if (pthread_sigmask(SIG_BLOCK, &block, &prior) != 0) return false;
  written = write(fd, data, count);
  const int saved_errno = errno;
  if (written < 0 && saved_errno == EPIPE && sigismember(&prior, SIGPIPE) == 0) {
    timespec zero{};
    (void)sigtimedwait(&block, nullptr, &zero);
  }
  (void)pthread_sigmask(SIG_SETMASK, &prior, nullptr);
  errno = saved_errno;
  return true;
}
#else
std::optional<std::wstring> to_wide(const std::string& text) {
  const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
  if (length <= 0 && !text.empty()) return std::nullopt;
  std::wstring result(static_cast<std::size_t>(length), L'\0');
  if (length != 0 && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), length) != length) return std::nullopt;
  return result;
}
std::wstring quote(const std::wstring_view arg) {
  std::wstring result{L"\""}; std::size_t slashes = 0;
  for (const wchar_t ch : arg) { if (ch == L'\\') ++slashes; else if (ch == L'\"') { result.append(slashes * 2 + 1, L'\\'); result += ch; slashes = 0; } else { result.append(slashes, L'\\'); result += ch; slashes = 0; } }
  result.append(slashes * 2, L'\\'); result += L'\"'; return result;
}
// Fixed text plus the numeric Win32 error code: no paths, names or secrets.
std::string with_last_error(const char* what) { return std::string(what) + " (Win32 error " + std::to_string(GetLastError()) + ")"; }
void close_handle(void*& handle) noexcept { if (handle != nullptr) { CloseHandle(static_cast<HANDLE>(handle)); handle = nullptr; } }

// 128 random bits for the pipe name (spec §3.11). Task 29 switches this to SP1's fill_random().
std::optional<std::wstring> random_pipe_suffix() {
  std::array<unsigned char, 16> bytes{};
  if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return std::nullopt;
  static constexpr wchar_t kDigits[] = L"0123456789abcdef";
  std::wstring text;
  for (const unsigned char byte : bytes) {
    text.push_back(kDigits[byte >> 4U]);
    text.push_back(kDigits[byte & 0x0fU]);
  }
  return text;
}

// D:P(A;;GA;;;<current user SID>): protected, one ACE, current user only.
// The caller LocalFree()s the result.
PSECURITY_DESCRIPTOR owner_only_descriptor() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return nullptr;
  DWORD size = 0;
  (void)GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<std::byte> buffer(size);
  const bool have_user = size != 0 && GetTokenInformation(token, TokenUser, buffer.data(), size, &size);
  CloseHandle(token);
  if (!have_user) return nullptr;
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid)) return nullptr;
  const std::wstring sddl = std::wstring(L"D:P(A;;GA;;;") + sid + L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return nullptr;
  return descriptor;
}
#endif

}  // namespace

EngineStdioProcess::~EngineStdioProcess() { cleanup(); }

std::optional<ProcessError> EngineStdioProcess::start(const EngineCommand& command) {
  if (running()) return ProcessError{ProcessErrorCode::already_running, "an engine process is already running"};
  if (const auto error = validate(command); error.has_value()) return error;
  cleanup(); pending_stdout_.clear(); exit_status_.reset();
#if defined(_WIN32)
  const std::wstring executable = command.executable.wstring();
  std::wstring line = quote(executable);
  line += L" --serve";
  for (const auto& arg : command.arguments) { auto wide = to_wide(arg); if (!wide) return ProcessError{ProcessErrorCode::invalid_command, "engine argument is not valid UTF-8"}; line += L' ' + quote(*wide); }
  std::wstring environment;
  for (const auto& [name, value] : command.environment) { auto n = to_wide(name); auto v = to_wide(value); if (!n || !v) return ProcessError{ProcessErrorCode::invalid_command, "engine environment is not valid UTF-8"}; environment += *n + L"=" + *v; environment.push_back(L'\0'); }
  environment.push_back(L'\0');
  SECURITY_ATTRIBUTES attrs{sizeof(attrs), nullptr, TRUE}; HANDLE child_stdin = nullptr, child_stdout = nullptr, child_stderr = nullptr, parent_stdin = nullptr, parent_stdout = nullptr;
  // Spec §3.11: an owner-only (protected DACL, current user), single-instance
  // pipe with a 128-bit random name that rejects remote clients. The frontend
  // end is overlapped so writes have a deadline (§3.10). After our own client
  // open the pipe's client pid must be ours, which closes the window in which
  // another process could connect first. The parent end is not inheritable;
  // only the child's read end (opened with `attrs`) is.
  const auto suffix = random_pipe_suffix();
  PSECURITY_DESCRIPTOR descriptor = owner_only_descriptor();
  if (!suffix || descriptor == nullptr) {
    if (descriptor != nullptr) LocalFree(descriptor);
    return ProcessError{ProcessErrorCode::platform_failure, "stdio pipe setup failed"};
  }
  SECURITY_ATTRIBUTES pipe_attrs{sizeof(pipe_attrs), descriptor, FALSE};
  const std::wstring pipe_name = L"\\\\.\\pipe\\secure_frontend-" + std::to_wstring(GetCurrentProcessId()) + L"-" + *suffix;
  parent_stdin = CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                                  PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
                                  static_cast<DWORD>(supervision_defaults::kStdinWriteChunk), 0, 0, &pipe_attrs);
  LocalFree(descriptor);
  if (parent_stdin == INVALID_HANDLE_VALUE) parent_stdin = nullptr;
  if (parent_stdin != nullptr) {
    child_stdin = CreateFileW(pipe_name.c_str(), GENERIC_READ, 0, &attrs, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (child_stdin == INVALID_HANDLE_VALUE) child_stdin = nullptr;
  }
  ULONG client_pid = 0;
  if (child_stdin != nullptr) {
    const bool queried = GetNamedPipeClientProcessId(parent_stdin, &client_pid) != FALSE;
    if (!queried || client_pid != GetCurrentProcessId()) {
      // A foreign client: report it as access denied rather than a stale error code.
      if (queried) SetLastError(ERROR_ACCESS_DENIED);
      const DWORD reason = GetLastError();
      CloseHandle(child_stdin);
      child_stdin = nullptr;
      SetLastError(reason);
    }
  }
  if (parent_stdin == nullptr || child_stdin == nullptr || !CreatePipe(&parent_stdout, &child_stdout, &attrs, 0) || !SetHandleInformation(parent_stdout, HANDLE_FLAG_INHERIT, 0)) { if (child_stdin) CloseHandle(child_stdin); if (parent_stdin) CloseHandle(parent_stdin); if (child_stdout) CloseHandle(child_stdout); if (parent_stdout) CloseHandle(parent_stdout); return ProcessError{ProcessErrorCode::platform_failure, with_last_error("stdio pipe setup failed")}; }
  child_stderr = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &attrs, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (child_stderr == INVALID_HANDLE_VALUE) { CloseHandle(child_stdin); CloseHandle(parent_stdin); CloseHandle(child_stdout); CloseHandle(parent_stdout); return ProcessError{ProcessErrorCode::platform_failure, with_last_error("stderr sink setup failed")}; }
  HANDLE job = CreateJobObjectW(nullptr, nullptr); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  // Spec §3.7: an unhandled exception in any Job process ends it at once
  // (no WER wait), and closing the Job kills every member.
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
  if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) { CloseHandle(child_stdin); CloseHandle(parent_stdin); CloseHandle(child_stdout); CloseHandle(parent_stdout); CloseHandle(child_stderr); if (job) CloseHandle(job); return ProcessError{ProcessErrorCode::platform_failure, with_last_error("CreateJobObjectW failed")}; }
  SIZE_T attribute_list_size = 0;
  (void)InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_list_size);
  std::vector<std::byte> attribute_list_storage(attribute_list_size);
  auto* attribute_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_list_storage.data());
  HANDLE inherited_handles[]{child_stdin, child_stdout, child_stderr};
  if (!InitializeProcThreadAttributeList(attribute_list, 1, 0, &attribute_list_size) ||
      !UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 inherited_handles, sizeof(inherited_handles), nullptr, nullptr)) {
    CloseHandle(child_stdin); CloseHandle(parent_stdin); CloseHandle(child_stdout); CloseHandle(parent_stdout); CloseHandle(child_stderr);
    CloseHandle(job);
    return ProcessError{ProcessErrorCode::platform_failure, with_last_error("process handle-list setup failed")};
  }
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = child_stdin;
  startup.StartupInfo.hStdOutput = child_stdout;
  startup.StartupInfo.hStdError = child_stderr;
  startup.lpAttributeList = attribute_list;
  PROCESS_INFORMATION info{};
  // Spec §3.7: a crashing engine must never wait on a Windows Error Reporting
  // dialog; the error mode is inherited by the child. Set once per process.
  static const UINT previous_error_mode = SetErrorMode(GetErrorMode() | SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
  (void)previous_error_mode;
  // Start suspended so the child is inside the Job before it runs a single
  // instruction: no early descendant can escape the kill-on-close Job (PROC-05).
  // CREATE_NEW_PROCESS_GROUP: Ctrl-C is disabled in the engine's group;
  // group-targeted Ctrl-Break reaches only the frontend; a console-wide
  // Ctrl-Break still reaches the engine (open item for SP2 Task 15:
  // CREATE_NO_WINDOW or accept the race). A console handler (SP2 Task 15)
  // will run the orderly shutdown.
  const BOOL created = CreateProcessW(executable.c_str(), line.data(), nullptr, nullptr, TRUE,
                                      CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED |
                                          CREATE_NEW_PROCESS_GROUP,
                                      environment.data(), nullptr, &startup.StartupInfo, &info);
  DeleteProcThreadAttributeList(attribute_list);
  CloseHandle(child_stdin); CloseHandle(child_stdout); CloseHandle(child_stderr);
  if (!created) { CloseHandle(parent_stdin); CloseHandle(parent_stdout); CloseHandle(job); return ProcessError{ProcessErrorCode::spawn_failed, with_last_error("CreateProcessW failed")}; }
  if (!AssignProcessToJobObject(job, info.hProcess)) { TerminateProcess(info.hProcess, 1); /* still suspended: it never ran */ CloseHandle(info.hThread); CloseHandle(info.hProcess); CloseHandle(parent_stdin); CloseHandle(parent_stdout); CloseHandle(job); return ProcessError{ProcessErrorCode::platform_failure, with_last_error("AssignProcessToJobObject failed")}; }
  if (ResumeThread(info.hThread) == static_cast<DWORD>(-1)) { TerminateJobObject(job, kSupervisorKillExitCode); CloseHandle(info.hThread); CloseHandle(info.hProcess); CloseHandle(parent_stdin); CloseHandle(parent_stdout); CloseHandle(job); return ProcessError{ProcessErrorCode::platform_failure, with_last_error("ResumeThread failed")}; }
  CloseHandle(info.hThread);
  process_handle_ = info.hProcess; job_handle_ = job; stdin_write_ = parent_stdin; stdout_read_ = parent_stdout; stdin_pipe_name_ = pipe_name; return std::nullopt;
#else
  // Everything the child needs is built before fork(); the child body is async-signal-safe.
  posix_launch::PreparedExec prepared;
  posix_launch::prepare(prepared, command, /*insert_serve=*/true);
  // O_CLOEXEC on every pipe end: nothing created here can leak into this or any
  // other child.  The child's ends reach fds 0/1 through dup2, which clears it.
  int input[2]{-1, -1}; int output[2]{-1, -1}; int errors[2]{-1, -1};
  if (pipe2(input, O_CLOEXEC) != 0 || pipe2(output, O_CLOEXEC) != 0 || pipe2(errors, O_CLOEXEC) != 0) { for (int* pipe_fd : {input, output, errors}) { close_fd(pipe_fd[0]); close_fd(pipe_fd[1]); } return ProcessError{ProcessErrorCode::platform_failure, "pipe setup failed"}; }
  pid_t child = -1;
  {
    posix_launch::BlockAllSignals blocked;
    child = fork();
    if (child == 0) posix_launch::exec_child(prepared, input[0], output[1], /*null_stderr=*/true, errors[1]);
  }
  if (child < 0) { for (int* pipe_fd : {input, output, errors}) { close_fd(pipe_fd[0]); close_fd(pipe_fd[1]); } return ProcessError{ProcessErrorCode::spawn_failed, "fork failed"}; }
  close_fd(input[0]); close_fd(output[1]); close_fd(errors[1]); int child_errno = 0; const ssize_t count = read(errors[0], &child_errno, sizeof(child_errno)); close_fd(errors[0]);
  if (count > 0) { close_fd(input[1]); close_fd(output[0]); int ignored = 0; (void)waitpid(child, &ignored, 0); return ProcessError{ProcessErrorCode::spawn_failed, std::string("execve failed: ") + std::strerror(child_errno)}; }
  process_id_ = child; process_group_ = child; pidfd_ = open_pidfd(child); stdin_write_ = input[1]; stdout_read_ = output[0]; return std::nullopt;
#endif
}

std::optional<ExitStatus> EngineStdioProcess::try_reap() {
  if (exit_status_) return exit_status_;
#if defined(_WIN32)
  if (process_handle_ == nullptr || WaitForSingleObject(static_cast<HANDLE>(process_handle_), 0) != WAIT_OBJECT_0) return std::nullopt;
  DWORD code = 0;
  if (!GetExitCodeProcess(static_cast<HANDLE>(process_handle_), &code)) code = 0xFFFFFFFFU;
  exit_status_ = ExitStatus{false, static_cast<std::uint32_t>(code)};
  return exit_status_;
#else
  if (process_id_ < 0) return std::nullopt;
  int status = 0;
  const pid_t value = waitpid(process_id_, &status, WNOHANG);
  if (value == process_id_) {
    exit_status_ = WIFSIGNALED(status) ? ExitStatus{true, static_cast<std::uint32_t>(WTERMSIG(status))}
                                       : ExitStatus{false, static_cast<std::uint32_t>(WIFEXITED(status) ? WEXITSTATUS(status) : 255)};
  } else if (value < 0 && errno == ECHILD) {
    // Reaped by someone else: the status is unknown. Cannot happen while only the supervisor reaps.
    exit_status_ = ExitStatus{false, 255U};
  } else {
    return std::nullopt;
  }
  process_id_ = -1;
  close_fd(pidfd_);
  return exit_status_;
#endif
}

bool EngineStdioProcess::running() {
#if defined(_WIN32)
  return process_handle_ != nullptr && !try_reap().has_value();
#else
  return process_id_ >= 0 && !try_reap().has_value();
#endif
}

bool EngineStdioProcess::write_line(const std::string_view line, std::string& error) {
  if (line.empty() || line.size() > kMaxWriteLineBytes || line.find('\n') != std::string_view::npos || line.find('\r') != std::string_view::npos || contains_nul(line)) { error = "protocol line is invalid"; return false; }
  std::string record(line); record.push_back('\n');
#if defined(_WIN32)
  if (!stdin_write_) { error = "engine stdin is closed"; return false; }
  // Spec §3.10: overlapped writes in chunks; a chunk that makes no progress
  // within kStdinWriteDeadline is cancelled and the write fails, so a hung
  // engine can never hang the serving thread (the supervisor then kills it).
  HANDLE pipe = static_cast<HANDLE>(stdin_write_);
  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (event == nullptr) { error = "engine stdin write failed"; return false; }
  bool ok = true;
  std::size_t offset = 0;
  while (ok && offset < record.size()) {
    const auto chunk = static_cast<DWORD>(std::min<std::size_t>(record.size() - offset, supervision_defaults::kStdinWriteChunk));
    OVERLAPPED overlapped{};
    overlapped.hEvent = event;
    (void)ResetEvent(event);
    DWORD written = 0;
    if (!WriteFile(pipe, record.data() + offset, chunk, nullptr, &overlapped) && GetLastError() != ERROR_IO_PENDING) {
      error = "engine stdin write failed";
      ok = false;
      break;
    }
    if (WaitForSingleObject(event, static_cast<DWORD>(supervision_defaults::kStdinWriteDeadline.count())) != WAIT_OBJECT_0) {
      (void)CancelIoEx(pipe, &overlapped);
      (void)GetOverlappedResult(pipe, &overlapped, &written, TRUE);  // the cancelled I/O must finish before `overlapped` goes away
      error = "engine stdin is not writable";
      ok = false;
      break;
    }
    if (!GetOverlappedResult(pipe, &overlapped, &written, FALSE) || written == 0) {
      error = "engine stdin write failed";
      ok = false;
      break;
    }
    offset += written;
  }
  CloseHandle(event);
  return ok;
#else
  if (stdin_write_ < 0) { error = "engine stdin is closed"; return false; } std::size_t offset = 0; while (offset < record.size()) { pollfd pollfd{stdin_write_, POLLOUT, 0}; if (poll(&pollfd, 1, 1000) <= 0) { error = "engine stdin is not writable"; return false; } ssize_t count = -1; if (!write_without_sigpipe(stdin_write_, record.data() + offset, record.size() - offset, count) || count <= 0) { error = "engine stdin write failed"; return false; } offset += static_cast<std::size_t>(count); } return true;
#endif
}

std::optional<EngineReadResult> EngineStdioProcess::take_pending_line() {
  const auto newline = pending_stdout_.find('\n');
  if (newline == std::string::npos) return std::nullopt;
  std::string line = pending_stdout_.substr(0, newline);
  pending_stdout_.erase(0, newline + 1);
  if (!line.empty() && line.back() == '\r') line.pop_back();
  if (line.size() > kMaxReadLineBytes || line.find('\0') != std::string::npos) return EngineReadResult{EngineReadKind::failure, {}, "engine emitted an invalid line"};
  return EngineReadResult{EngineReadKind::line, std::move(line), {}};
}

EngineReadResult EngineStdioProcess::read_line(const std::chrono::milliseconds timeout) {
  // K1: a zero budget is already expired on every path, even with a buffered line.
  if (timeout.count() <= 0) return {EngineReadKind::timeout, {}, {}};
  if (auto pending = take_pending_line(); pending.has_value()) return std::move(*pending);
#if defined(_WIN32)
  // Iterative and bounded exactly like POSIX: an oversized line is a failure,
  // the deadline is a timeout, and a dead child with an empty pipe is closed.
  if (!stdout_read_) return {EngineReadKind::closed, {}, {}};
  const auto deadline = deadline_after(timeout);
  std::array<char, 1024> bytes{};
  bool child_exit_seen = false;
  for (;;) {
    DWORD available = 0;
    if (!PeekNamedPipe(static_cast<HANDLE>(stdout_read_), nullptr, 0, nullptr, &available, nullptr)) return {EngineReadKind::closed, {}, {}};
    if (available != 0) {
      DWORD read = 0;
      const DWORD wanted = std::min<DWORD>(available, static_cast<DWORD>(bytes.size()));
      if (!ReadFile(static_cast<HANDLE>(stdout_read_), bytes.data(), wanted, &read, nullptr) || read == 0) return {EngineReadKind::closed, {}, {}};
      pending_stdout_.append(bytes.data(), read);
      if (pending_stdout_.size() > kMaxReadLineBytes && pending_stdout_.find('\n') == std::string::npos) return {EngineReadKind::failure, {}, "engine emitted an oversized line"};
      if (auto pending = take_pending_line(); pending.has_value()) return std::move(*pending);
      continue;
    }
    if (remaining_until(deadline).count() == 0) return {EngineReadKind::timeout, {}, {}};
    // A 1 ms pause that returns at once when the child has exited.  Output the
    // child wrote before exiting is already in the pipe, so one more empty peek
    // after the exit was observed means nothing further can arrive.
    const DWORD waited = WaitForSingleObject(static_cast<HANDLE>(process_handle_), 1);
    if (waited == WAIT_FAILED) return {EngineReadKind::failure, {}, "engine process wait failed"};
    if (waited == WAIT_OBJECT_0) {
      if (child_exit_seen) return {EngineReadKind::closed, {}, {}};
      child_exit_seen = true;
    }
  }
#else
  if (stdout_read_ < 0) {
    return {EngineReadKind::closed, {}, {}};
  }
  // One deadline for the whole call: every poll waits only for the remaining
  // budget, so a record split across several writes is still read whole as
  // long as its last byte arrives before the deadline.
  const auto deadline = deadline_after(timeout);
  std::array<char, 1024> bytes{};
  for (;;) {
    const auto remaining = remaining_until(deadline);
    const auto bounded = std::clamp<std::int64_t>(remaining.count(), 0, 0x7fffffff);
    pollfd pollfd{stdout_read_, POLLIN | POLLHUP, 0};
    const int status = poll(&pollfd, 1, static_cast<int>(bounded));
    if (status < 0 && errno == EINTR) continue;
    if (status == 0) {
      return {EngineReadKind::timeout, {}, {}};
    }
    if (status < 0) {
      return {EngineReadKind::failure, {}, "engine stdout poll failed"};
    }
    const ssize_t count = read(stdout_read_, bytes.data(), bytes.size());
    if (count == 0) {
      return {EngineReadKind::closed, {}, {}};
    }
    if (count < 0) {
      return {EngineReadKind::failure, {}, "engine stdout read failed"};
    }
    pending_stdout_.append(bytes.data(), static_cast<std::size_t>(count));
    if (pending_stdout_.size() > kMaxReadLineBytes && pending_stdout_.find('\n') == std::string::npos) {
      return {EngineReadKind::failure, {}, "engine emitted an oversized line"};
    }
    if (auto pending = take_pending_line(); pending.has_value()) return std::move(*pending);
  }
#endif
}

bool EngineStdioProcess::terminate(const std::chrono::milliseconds grace) {
#if defined(_WIN32)
  if (!process_handle_) return true;
  if (!TerminateJobObject(static_cast<HANDLE>(job_handle_), kSupervisorKillExitCode)) return false;
  if (WaitForSingleObject(static_cast<HANDLE>(process_handle_), static_cast<DWORD>(std::max<std::int64_t>(0, grace.count()))) !=
      WAIT_OBJECT_0) {
    return false;
  }
  // Keep the status of our own kill, so exit_status() is set and classify_exit()
  // credits it to the supervisor ("a supervisor kill classifies as ours").
  (void)try_reap();
  return true;
#else
  if (process_group_ < 0) return true;  // never started, or already fully cleaned up
  if (process_id_ >= 0) {
    if (kill(-process_group_, SIGTERM) != 0 && errno != ESRCH) return false;
    const auto end = std::chrono::steady_clock::now() + grace;
    while (std::chrono::steady_clock::now() < end && !try_reap()) usleep(10000);
  }
  // Spec §3.7(a): always SIGKILL the group, even when the leader was already
  // reaped: members that ignored SIGTERM or outlived the leader keep the group
  // id valid and must die too.
  (void)kill(-process_group_, SIGKILL);
  for (int step = 0; step < 50 && process_id_ >= 0; ++step) {
    if (try_reap()) break;
    usleep(10000);
  }
  if (process_id_ >= 0) return false;  // abandoned: still unreaped after the bound (header contract)
  close_fd(stdin_write_);
  close_fd(stdout_read_);
  process_group_ = -1;
  return true;
#endif
}

std::intptr_t EngineStdioProcess::monitor_handle() const noexcept {
#if defined(_WIN32)
  return process_handle_ != nullptr ? reinterpret_cast<std::intptr_t>(process_handle_) : kNoMonitorHandle;
#else
  return pidfd_ >= 0 ? static_cast<std::intptr_t>(pidfd_) : kNoMonitorHandle;
#endif
}

void EngineStdioProcess::close_stdin() noexcept {
#if defined(_WIN32)
  close_handle(stdin_write_);
#else
  close_fd(stdin_write_);
#endif
}

void EngineStdioProcess::signal_group_terminate() noexcept {
#if !defined(_WIN32)
  if (process_group_ > 0) (void)kill(-process_group_, SIGTERM);
#endif
}

void EngineStdioProcess::kill_group() noexcept {
#if defined(_WIN32)
  if (job_handle_ != nullptr) (void)TerminateJobObject(static_cast<HANDLE>(job_handle_), kSupervisorKillExitCode);
#else
  // Spec §3.7a: the process-group id stays valid while any member lives, so
  // this reaches grandchildren even after the leader was reaped.
  if (process_group_ > 0) (void)kill(-process_group_, SIGKILL);
#endif
}

void EngineStdioProcess::release_resources(const std::chrono::milliseconds bound) noexcept {
  (void)bound;
#if !defined(_WIN32)
  process_group_ = -1;  // never signal a group id the kernel may hand out again
#endif
}

long EngineStdioProcess::pid() const noexcept {
#if defined(_WIN32)
  return process_handle_ != nullptr ? static_cast<long>(GetProcessId(static_cast<HANDLE>(process_handle_))) : -1;
#else
  return process_group_;
#endif
}

void EngineStdioProcess::cleanup() noexcept { (void)terminate(std::chrono::milliseconds(250));
#if defined(_WIN32)
  close_handle(stdin_write_); close_handle(stdout_read_); close_handle(process_handle_); close_handle(job_handle_);
#else
  close_fd(stdin_write_); close_fd(stdout_read_); close_fd(pidfd_);
#endif
}

}  // namespace secure_frontend

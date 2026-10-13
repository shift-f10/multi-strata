#include "secure_frontend/engine_stdio_process.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#else
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace secure_frontend {
namespace {

bool contains_nul(const std::string_view value) { return value.find('\0') != std::string_view::npos; }

std::optional<ProcessError> validate(const EngineCommand& command) {
  if (command.executable.empty() || contains_nul(command.executable.string())) {
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

bool set_cloexec(const int fd) { return fcntl(fd, F_SETFD, FD_CLOEXEC) == 0; }

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
void close_handle(void*& handle) noexcept { if (handle != nullptr) { CloseHandle(static_cast<HANDLE>(handle)); handle = nullptr; } }
#endif

}  // namespace

EngineStdioProcess::~EngineStdioProcess() { cleanup(); }

std::optional<ProcessError> EngineStdioProcess::start(const EngineCommand& command) {
  if (running()) return ProcessError{ProcessErrorCode::already_running, "an engine process is already running"};
  if (const auto error = validate(command); error.has_value()) return error;
  cleanup(); pending_stdout_.clear();
#if defined(_WIN32)
  const std::wstring executable = command.executable.wstring();
  std::wstring line = quote(executable);
  line += L" --serve";
  for (const auto& arg : command.arguments) { auto wide = to_wide(arg); if (!wide) return ProcessError{ProcessErrorCode::invalid_command, "engine argument is not valid UTF-8"}; line += L' ' + quote(*wide); }
  std::wstring environment;
  for (const auto& [name, value] : command.environment) { auto n = to_wide(name); auto v = to_wide(value); if (!n || !v) return ProcessError{ProcessErrorCode::invalid_command, "engine environment is not valid UTF-8"}; environment += *n + L"=" + *v; environment.push_back(L'\0'); }
  environment.push_back(L'\0');
  SECURITY_ATTRIBUTES attrs{sizeof(attrs), nullptr, TRUE}; HANDLE child_stdin = nullptr, child_stdout = nullptr, child_stderr = nullptr, parent_stdin = nullptr, parent_stdout = nullptr;
  if (!CreatePipe(&child_stdin, &parent_stdin, &attrs, 0) || !SetHandleInformation(parent_stdin, HANDLE_FLAG_INHERIT, 0) || !CreatePipe(&parent_stdout, &child_stdout, &attrs, 0) || !SetHandleInformation(parent_stdout, HANDLE_FLAG_INHERIT, 0)) { if (child_stdin) CloseHandle(child_stdin); if (parent_stdin) CloseHandle(parent_stdin); if (child_stdout) CloseHandle(child_stdout); if (parent_stdout) CloseHandle(parent_stdout); return ProcessError{ProcessErrorCode::platform_failure, "stdio pipe setup failed"}; }
  child_stderr = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &attrs, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (child_stderr == INVALID_HANDLE_VALUE) { CloseHandle(child_stdin); CloseHandle(parent_stdin); CloseHandle(child_stdout); CloseHandle(parent_stdout); return ProcessError{ProcessErrorCode::platform_failure, "stderr sink setup failed"}; }
  HANDLE job = CreateJobObjectW(nullptr, nullptr); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{}; limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) { CloseHandle(child_stdin); CloseHandle(parent_stdin); CloseHandle(child_stdout); CloseHandle(parent_stdout); CloseHandle(child_stderr); if (job) CloseHandle(job); return ProcessError{ProcessErrorCode::platform_failure, "CreateJobObjectW failed"}; }
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
    return ProcessError{ProcessErrorCode::platform_failure, "process handle-list setup failed"};
  }
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = child_stdin;
  startup.StartupInfo.hStdOutput = child_stdout;
  startup.StartupInfo.hStdError = child_stderr;
  startup.lpAttributeList = attribute_list;
  PROCESS_INFORMATION info{};
  const BOOL created = CreateProcessW(executable.c_str(), line.data(), nullptr, nullptr, TRUE,
                                      CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                                      environment.data(), nullptr, &startup.StartupInfo, &info);
  DeleteProcThreadAttributeList(attribute_list);
  CloseHandle(child_stdin); CloseHandle(child_stdout); CloseHandle(child_stderr);
  if (!created) { CloseHandle(parent_stdin); CloseHandle(parent_stdout); CloseHandle(job); return ProcessError{ProcessErrorCode::spawn_failed, "CreateProcessW failed"}; }
  CloseHandle(info.hThread); if (!AssignProcessToJobObject(job, info.hProcess)) { TerminateProcess(info.hProcess, 1); CloseHandle(info.hProcess); CloseHandle(parent_stdin); CloseHandle(parent_stdout); CloseHandle(job); return ProcessError{ProcessErrorCode::platform_failure, "AssignProcessToJobObject failed"}; }
  process_handle_ = info.hProcess; job_handle_ = job; stdin_write_ = parent_stdin; stdout_read_ = parent_stdout; return std::nullopt;
#else
  int input[2]{-1, -1}; int output[2]{-1, -1}; int errors[2]{-1, -1};
  if (pipe(input) != 0 || pipe(output) != 0 || pipe(errors) != 0 || !set_cloexec(errors[1])) { for (int* pipe_fd : {input, output, errors}) { close_fd(pipe_fd[0]); close_fd(pipe_fd[1]); } return ProcessError{ProcessErrorCode::platform_failure, "pipe setup failed"}; }
  const pid_t child = fork();
  if (child < 0) { for (int* pipe_fd : {input, output, errors}) { close_fd(pipe_fd[0]); close_fd(pipe_fd[1]); } return ProcessError{ProcessErrorCode::spawn_failed, "fork failed"}; }
  if (child == 0) {
    close_fd(input[1]); close_fd(output[0]); close_fd(errors[0]);
    int null_stderr = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (setpgid(0, 0) != 0 || null_stderr < 0 || dup2(input[0], STDIN_FILENO) < 0 || dup2(output[1], STDOUT_FILENO) < 0 || dup2(null_stderr, STDERR_FILENO) < 0) { const int e = errno; (void)!write(errors[1], &e, sizeof(e)); _exit(127); }
    close_fd(null_stderr);
    close_fd(input[0]); close_fd(output[1]);
    std::vector<std::string> args; args.reserve(command.arguments.size() + 2); args.emplace_back(command.executable.string()); args.emplace_back("--serve"); args.insert(args.end(), command.arguments.begin(), command.arguments.end());
    std::vector<char*> argv; argv.reserve(args.size() + 1); for (auto& arg : args) argv.push_back(arg.data()); argv.push_back(nullptr);
    std::vector<std::string> env; env.reserve(command.environment.size()); for (const auto& [key, value] : command.environment) env.push_back(key + "=" + value);
    std::vector<char*> envp; envp.reserve(env.size() + 1); for (auto& entry : env) envp.push_back(entry.data()); envp.push_back(nullptr);
    execve(command.executable.c_str(), argv.data(), envp.data()); const int e = errno; (void)!write(errors[1], &e, sizeof(e)); _exit(127);
  }
  close_fd(input[0]); close_fd(output[1]); close_fd(errors[1]); int child_errno = 0; const ssize_t count = read(errors[0], &child_errno, sizeof(child_errno)); close_fd(errors[0]);
  if (count > 0) { close_fd(input[1]); close_fd(output[0]); int ignored = 0; (void)waitpid(child, &ignored, 0); return ProcessError{ProcessErrorCode::spawn_failed, std::string("execve failed: ") + std::strerror(child_errno)}; }
  process_id_ = child; stdin_write_ = input[1]; stdout_read_ = output[0]; return std::nullopt;
#endif
}

bool EngineStdioProcess::running() {
#if defined(_WIN32)
  return process_handle_ != nullptr && WaitForSingleObject(static_cast<HANDLE>(process_handle_), 0) == WAIT_TIMEOUT;
#else
  if (process_id_ < 0) {
    return false;
  }
  int status = 0;
  const pid_t value = waitpid(process_id_, &status, WNOHANG);
  if (value == process_id_ || (value < 0 && errno == ECHILD)) {
    process_id_ = -1;
    return false;
  }
  return true;
#endif
}

bool EngineStdioProcess::write_line(const std::string_view line, std::string& error) {
  if (line.empty() || line.size() > kMaxWriteLineBytes || line.find('\n') != std::string_view::npos || line.find('\r') != std::string_view::npos || contains_nul(line)) { error = "protocol line is invalid"; return false; }
  std::string record(line); record.push_back('\n');
#if defined(_WIN32)
  if (!stdin_write_) { error = "engine stdin is closed"; return false; } DWORD written = 0; if (!WriteFile(static_cast<HANDLE>(stdin_write_), record.data(), static_cast<DWORD>(record.size()), &written, nullptr) || written != record.size()) { error = "engine stdin write failed"; return false; } return true;
#else
  if (stdin_write_ < 0) { error = "engine stdin is closed"; return false; } std::size_t offset = 0; while (offset < record.size()) { pollfd pollfd{stdin_write_, POLLOUT, 0}; if (poll(&pollfd, 1, 1000) <= 0) { error = "engine stdin is not writable"; return false; } ssize_t count = -1; if (!write_without_sigpipe(stdin_write_, record.data() + offset, record.size() - offset, count) || count <= 0) { error = "engine stdin write failed"; return false; } offset += static_cast<std::size_t>(count); } return true;
#endif
}

EngineReadResult EngineStdioProcess::read_line(const std::chrono::milliseconds timeout) {
  const auto newline = pending_stdout_.find('\n'); if (newline != std::string::npos) { std::string line = pending_stdout_.substr(0, newline); pending_stdout_.erase(0, newline + 1); if (!line.empty() && line.back() == '\r') line.pop_back(); if (line.size() > kMaxReadLineBytes || line.find('\0') != std::string::npos) return {EngineReadKind::failure, {}, "engine emitted an invalid line"}; return {EngineReadKind::line, std::move(line), {}}; }
#if defined(_WIN32)
  if (!stdout_read_) return {EngineReadKind::closed, {}, {}}; const DWORD deadline = timeout.count() <= 0 ? 0U : static_cast<DWORD>(std::min<std::int64_t>(timeout.count(), 0x7fffffff)); const ULONGLONG end = GetTickCount64() + deadline; std::array<char, 1024> bytes{}; for (;;) { DWORD available = 0; if (!PeekNamedPipe(static_cast<HANDLE>(stdout_read_), nullptr, 0, nullptr, &available, nullptr)) return {EngineReadKind::closed, {}, {}}; if (available != 0) { DWORD read = 0; if (!ReadFile(static_cast<HANDLE>(stdout_read_), bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) || read == 0) return {EngineReadKind::closed, {}, {}}; pending_stdout_.append(bytes.data(), read); return read_line(std::chrono::milliseconds(0)); } if (GetTickCount64() >= end) return {EngineReadKind::timeout, {}, {}}; Sleep(1); }
#else
  if (stdout_read_ < 0) {
    return {EngineReadKind::closed, {}, {}};
  }
  pollfd pollfd{stdout_read_, POLLIN | POLLHUP, 0};
  const auto bounded = std::clamp<std::int64_t>(timeout.count(), 0, 0x7fffffff);
  const int status = poll(&pollfd, 1, static_cast<int>(bounded));
  if (status == 0) {
    return {EngineReadKind::timeout, {}, {}};
  }
  if (status < 0) {
    return {EngineReadKind::failure, {}, "engine stdout poll failed"};
  }
  std::array<char, 1024> bytes{};
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
  return read_line(std::chrono::milliseconds(0));
#endif
}

bool EngineStdioProcess::terminate(const std::chrono::milliseconds grace) {
#if defined(_WIN32)
  if (!process_handle_) return true; if (!TerminateJobObject(static_cast<HANDLE>(job_handle_), 1)) return false; return WaitForSingleObject(static_cast<HANDLE>(process_handle_), static_cast<DWORD>(std::max<std::int64_t>(0, grace.count()))) == WAIT_OBJECT_0;
#else
  if (process_id_ < 0) {
    return true;
  }
  if (kill(-process_id_, SIGTERM) != 0 && errno != ESRCH) {
    return false;
  }
  const auto end = std::chrono::steady_clock::now() + grace;
  while (std::chrono::steady_clock::now() < end) {
    if (!running()) {
      return true;
    }
    usleep(10000);
  }
  if (kill(-process_id_, SIGKILL) != 0 && errno != ESRCH) {
    return false;
  }
  return true;
#endif
}

void EngineStdioProcess::cleanup() noexcept { (void)terminate(std::chrono::milliseconds(250));
#if defined(_WIN32)
  close_handle(stdin_write_); close_handle(stdout_read_); close_handle(process_handle_); close_handle(job_handle_);
#else
  close_fd(stdin_write_); close_fd(stdout_read_);
#endif
}

}  // namespace secure_frontend

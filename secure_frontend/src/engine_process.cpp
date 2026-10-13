#include "secure_frontend/engine_process.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#else
#include <csignal>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace secure_frontend {
namespace {

constexpr auto kPollInterval = std::chrono::milliseconds(10);

bool invalid_environment_name(const std::string& name) {
  return name.empty() || name.find('=') != std::string::npos || name.find('\0') != std::string::npos;
}

bool contains_nul(const std::string& value) {
  return value.find('\0') != std::string::npos;
}

std::optional<ProcessError> validate_command(const EngineCommand& command) {
  if (command.executable.empty()) {
    return ProcessError{ProcessErrorCode::invalid_command, "engine executable must not be empty"};
  }
  if (contains_nul(command.executable.string())) {
    return ProcessError{ProcessErrorCode::invalid_command, "engine executable path must not contain NUL bytes"};
  }
  for (const auto& argument : command.arguments) {
    if (contains_nul(argument)) {
      return ProcessError{ProcessErrorCode::invalid_command, "engine arguments must not contain NUL bytes"};
    }
  }
  for (const auto& [name, value] : command.environment) {
    if (invalid_environment_name(name) || contains_nul(value)) {
      return ProcessError{ProcessErrorCode::invalid_command, "engine environment contains an invalid entry"};
    }
  }
  return std::nullopt;
}

int normalized_exit_code(const int status) {
#if defined(_WIN32)
  return status;
#else
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
#endif
}

#if defined(_WIN32)
std::optional<std::wstring> utf8_to_wide(const std::string& text) {
  if (text.empty()) return std::wstring{};
  const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                         static_cast<int>(text.size()), nullptr, 0);
  if (length <= 0) return std::nullopt;
  std::wstring result(static_cast<std::size_t>(length), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                          result.data(), length) != length) {
    return std::nullopt;
  }
  return result;
}

std::wstring quote_windows_argument(const std::wstring_view argument) {
  std::wstring quoted{L"\""};
  std::size_t slashes = 0;
  for (const wchar_t character : argument) {
    if (character == L'\\') {
      ++slashes;
    } else if (character == L'\"') {
      quoted.append(slashes * 2 + 1, L'\\');
      quoted += character;
      slashes = 0;
    } else {
      quoted.append(slashes, L'\\');
      quoted += character;
      slashes = 0;
    }
  }
  quoted.append(slashes * 2, L'\\');
  quoted += L'\"';
  return quoted;
}
#endif

}  // namespace

EngineProcess::~EngineProcess() { cleanup(); }

EngineProcess::EngineProcess(EngineProcess&& other) noexcept
#if defined(_WIN32)
    : process_handle_(other.process_handle_), job_handle_(other.job_handle_), exit_code_(other.exit_code_) {
  other.process_handle_ = nullptr;
  other.job_handle_ = nullptr;
#else
    : process_id_(other.process_id_), exit_code_(other.exit_code_) {
  other.process_id_ = -1;
#endif
}

EngineProcess& EngineProcess::operator=(EngineProcess&& other) noexcept {
  if (this != &other) {
    cleanup();
#if defined(_WIN32)
    process_handle_ = other.process_handle_;
    job_handle_ = other.job_handle_;
    other.process_handle_ = nullptr;
    other.job_handle_ = nullptr;
#else
    process_id_ = other.process_id_;
    other.process_id_ = -1;
#endif
    exit_code_ = other.exit_code_;
  }
  return *this;
}

std::optional<ProcessError> EngineProcess::start(const EngineCommand& command) {
  if (running()) {
    return ProcessError{ProcessErrorCode::already_running, "an engine process is already running"};
  }
  if (const auto validation = validate_command(command); validation.has_value()) {
    return validation;
  }
  exit_code_.reset();

#if defined(_WIN32)
  std::wstring command_line = quote_windows_argument(command.executable.wstring());
  for (const auto& argument : command.arguments) {
    const auto wide = utf8_to_wide(argument);
    if (!wide.has_value()) {
      return ProcessError{ProcessErrorCode::invalid_command, "engine argument is not valid UTF-8"};
    }
    command_line += L' ';
    command_line += quote_windows_argument(*wide);
  }
  std::wstring environment;
  for (const auto& [name, value] : command.environment) {
    const auto wide_name = utf8_to_wide(name);
    const auto wide_value = utf8_to_wide(value);
    if (!wide_name.has_value() || !wide_value.has_value()) {
      return ProcessError{ProcessErrorCode::invalid_command, "engine environment is not valid UTF-8"};
    }
    environment += *wide_name;
    environment += L'=';
    environment += *wide_value;
    environment += L'\0';
  }
  environment += L'\0';
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (job == nullptr) return ProcessError{ProcessErrorCode::platform_failure, "CreateJobObjectW failed"};
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
    CloseHandle(job);
    return ProcessError{ProcessErrorCode::platform_failure, "SetInformationJobObject failed"};
  }
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  if (!CreateProcessW(command.executable.c_str(), command_line.data(), nullptr, nullptr, FALSE,
                      CREATE_UNICODE_ENVIRONMENT, environment.data(), nullptr, &startup, &info)) {
    CloseHandle(job);
    return ProcessError{ProcessErrorCode::spawn_failed, "CreateProcessW failed"};
  }
  CloseHandle(info.hThread);
  if (!AssignProcessToJobObject(job, info.hProcess)) {
    TerminateProcess(info.hProcess, 1);
    CloseHandle(info.hProcess);
    CloseHandle(job);
    return ProcessError{ProcessErrorCode::platform_failure, "AssignProcessToJobObject failed"};
  }
  process_handle_ = info.hProcess;
  job_handle_ = job;
  return std::nullopt;
#else
  int error_pipe[2];
  if (pipe(error_pipe) != 0) return ProcessError{ProcessErrorCode::platform_failure, "pipe failed"};
  if (fcntl(error_pipe[1], F_SETFD, FD_CLOEXEC) != 0) {
    close(error_pipe[0]);
    close(error_pipe[1]);
    return ProcessError{ProcessErrorCode::platform_failure, "fcntl failed"};
  }
  const pid_t child = fork();
  if (child < 0) {
    close(error_pipe[0]); close(error_pipe[1]);
    return ProcessError{ProcessErrorCode::spawn_failed, "fork failed"};
  }
  if (child == 0) {
    close(error_pipe[0]);
    if (setpgid(0, 0) != 0) {
      const int saved_errno = errno;
      (void)!write(error_pipe[1], &saved_errno, sizeof(saved_errno));
      _exit(127);
    }
    std::vector<std::string> owned_arguments;
    owned_arguments.reserve(command.arguments.size() + 1);
    owned_arguments.push_back(command.executable.string());
    owned_arguments.insert(owned_arguments.end(), command.arguments.begin(), command.arguments.end());
    std::vector<char*> argv;
    argv.reserve(owned_arguments.size() + 1);
    for (auto& argument : owned_arguments) argv.push_back(argument.data());
    argv.push_back(nullptr);
    std::vector<std::string> owned_environment;
    owned_environment.reserve(command.environment.size());
    for (const auto& [name, value] : command.environment) owned_environment.push_back(name + "=" + value);
    std::vector<char*> envp;
    envp.reserve(owned_environment.size() + 1);
    for (auto& entry : owned_environment) envp.push_back(entry.data());
    envp.push_back(nullptr);
    execve(command.executable.c_str(), argv.data(), envp.data());
    const int saved_errno = errno;
    (void)!write(error_pipe[1], &saved_errno, sizeof(saved_errno));
    _exit(127);
  }
  close(error_pipe[1]);
  int child_errno = 0;
  const auto bytes_read = read(error_pipe[0], &child_errno, sizeof(child_errno));
  close(error_pipe[0]);
  if (bytes_read > 0) {
    int status = 0;
    (void)waitpid(child, &status, 0);
    return ProcessError{ProcessErrorCode::spawn_failed, std::string("execve failed: ") + std::strerror(child_errno)};
  }
  process_id_ = child;
  return std::nullopt;
#endif
}

bool EngineProcess::running() {
  if (exit_code_.has_value()) return false;
#if defined(_WIN32)
  if (process_handle_ == nullptr) return false;
#else
  if (process_id_ < 0) return false;
#endif
  return !wait_for(std::chrono::milliseconds(0)).has_value();
}

std::optional<int> EngineProcess::wait_for(const std::chrono::milliseconds timeout) {
  if (exit_code_.has_value()) return exit_code_;
#if defined(_WIN32)
  if (process_handle_ == nullptr) return std::nullopt;
  const auto wait = WaitForSingleObject(static_cast<HANDLE>(process_handle_),
      timeout.count() <= 0 ? 0U : static_cast<DWORD>(std::min<std::int64_t>(timeout.count(), 0xFFFFFFFE)));
  if (wait != WAIT_OBJECT_0) return std::nullopt;
  DWORD code = 1;
  if (!GetExitCodeProcess(static_cast<HANDLE>(process_handle_), &code)) return std::nullopt;
  exit_code_ = static_cast<int>(code);
  return exit_code_;
#else
  if (process_id_ < 0) return std::nullopt;
  const auto deadline = std::chrono::steady_clock::now() + std::max(timeout, std::chrono::milliseconds(0));
  do {
    int status = 0;
    const pid_t result = waitpid(process_id_, &status, WNOHANG);
    if (result == process_id_) {
      process_id_ = -1;
      exit_code_ = normalized_exit_code(status);
      return exit_code_;
    }
    if (result < 0 && errno == ECHILD) {
      process_id_ = -1;
      exit_code_ = 1;
      return exit_code_;
    }
    if (std::chrono::steady_clock::now() >= deadline) return std::nullopt;
    std::this_thread::sleep_for(kPollInterval);
  } while (true);
#endif
}

bool EngineProcess::terminate(const std::chrono::milliseconds grace) {
  if (exit_code_.has_value()) return true;
#if defined(_WIN32)
  if (process_handle_ == nullptr) return true;
  if (TerminateJobObject(static_cast<HANDLE>(job_handle_), 1) == 0) return false;
  return wait_for(grace).has_value();
#else
  if (process_id_ < 0) return true;
  if (kill(-process_id_, SIGTERM) != 0 && errno != ESRCH) return false;
  if (wait_for(grace).has_value()) return true;
  if (kill(-process_id_, SIGKILL) != 0 && errno != ESRCH) return false;
  return wait_for(std::chrono::seconds(1)).has_value();
#endif
}

void EngineProcess::cleanup() noexcept {
  (void)terminate(std::chrono::milliseconds(250));
#if defined(_WIN32)
  if (process_handle_ != nullptr) { CloseHandle(static_cast<HANDLE>(process_handle_)); process_handle_ = nullptr; }
  if (job_handle_ != nullptr) { CloseHandle(static_cast<HANDLE>(job_handle_)); job_handle_ = nullptr; }
#endif
}

}  // namespace secure_frontend

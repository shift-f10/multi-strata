// SP7 M1 Task 1 (spec D-5/D-4): the hardened systemd user unit text and the
// `current`-target resolution seam. Pure functions; the verbs that consume
// them (Task 2) live beside them.
#include "service_ops.hpp"

#include "secure_frontend/win32_prelude.hpp"

#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <system_error>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace secure_frontend {
namespace service {
namespace {

bool has_whitespace(const std::string& text) {
  return text.find_first_of(" \t\n\r") != std::string::npos;
}

// Fixed messages (the finding, never a configured path): systemd splits
// ExecStart on spaces and the ReadWritePaths list on spaces, so a path that
// contains one cannot be named unquoted, and we refuse to guess at quoting.
std::optional<ServiceError> check_unit(const ServiceUnit& unit) {
  const std::string exec = unit.exec_start.string();
  if (exec.empty()) return ServiceError{"service: ExecStart names no program"};
  if (has_whitespace(exec)) {
    return ServiceError{"service: the program path contains whitespace; systemd splits ExecStart on spaces and "
                        "the service refuses to guess at quoting — install strata below a path without spaces"};
  }
  if (!unit.exec_start.is_absolute()) return ServiceError{"service: the program path must be absolute"};
  if (unit.config_file.empty()) return ServiceError{"service: no config file was given to the service"};
  if (has_whitespace(unit.config_file) || !std::filesystem::path{unit.config_file}.is_absolute()) {
    return ServiceError{"service: the config file path must be absolute and free of whitespace"};
  }
  if (unit.read_write_paths.empty()) {
    return ServiceError{"service: the served process always writes its state root; the unit needs at least one "
                        "ReadWritePaths entry"};
  }
  for (const auto& path : unit.read_write_paths) {
    if (path.empty() || has_whitespace(path) || !std::filesystem::path{path}.is_absolute()) {
      return ServiceError{"service: every ReadWritePaths entry must be absolute and free of whitespace"};
    }
  }
  return std::nullopt;
}

}  // namespace

std::variant<std::string, ServiceError> render_systemd_unit(const ServiceUnit& unit) {
  if (auto failure = check_unit(unit)) return *failure;
  std::string read_write;
  for (const auto& path : unit.read_write_paths) {
    if (!read_write.empty()) read_write += ' ';
    read_write += path;
  }
  std::string unit_text = "[Unit]\n"
                          "Description=Strata local model server\n"
                          "\n"
                          "[Service]\n"
                          "ExecStart=";
  unit_text += unit.exec_start.string();
  unit_text += " --config ";
  unit_text += unit.config_file;
  unit_text += " serve\n"
               "Restart=on-failure\n"
               "RestartSec=5\n"
               "NoNewPrivileges=yes\n"
               "ProtectSystem=strict\n"
               "ProtectHome=read-only\n"
               "ReadWritePaths=";
  unit_text += read_write;
  unit_text += "\n"
               "PrivateTmp=yes\n"
               "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
               "\n"
               "[Install]\n"
               "WantedBy=default.target\n";
  return unit_text;
}

std::variant<std::filesystem::path, ServiceError> resolve_current_target(const std::filesystem::path& self_executable) {
  std::error_code ec;
  const auto self = std::filesystem::canonical(self_executable, ec);
  if (ec || !std::filesystem::is_regular_file(self)) {
    return ServiceError{"service: the running strata program could not be located on disk"};
  }
  // A versioned install (D-4) looks like <root>/<version>/bin/strata with a
  // `current` pointer at <root>; anything else is a plain single-directory
  // install, whose own canonical path is the target (M2's `update` is the verb
  // that refuses a plain install, not the service verbs).
  const auto version_dir = self.parent_path().parent_path();
  const auto install_root = version_dir.parent_path();
  if (install_root.empty()) return self;
#if defined(_WIN32)
  std::ifstream pointer{install_root / "current.txt"};
  std::string name;
  if (pointer >> name) {
    std::error_code ignored;
    if (!name.empty() && name.back() == '\r') name.pop_back();
    if (name == version_dir.filename().string()) return self;  // this version is current
  }
#else
  std::error_code link_error;
  const auto target = std::filesystem::read_symlink(install_root / "current", link_error);
  if (!link_error) {
    std::error_code ignored;
    if (std::filesystem::canonical(install_root / target, ignored) == version_dir) return self;  // this version is current
  }
#endif
  // Not through the pointer (plain install, or a version the pointer left):
  // the concrete path this program was started from is the honest ExecStart.
  return self;
}

CmdResult run_argv(const std::vector<std::string>& argv) {
  CmdResult result;
  if (argv.empty()) return result;
#if defined(_WIN32)
  // Compile-proven here; runtime behaviour is the owner-box's (windows-runtime gates).
  // CreateProcessW searches PATH for the bare application name, like execvp.
  std::wstring command;
  for (const auto& part : argv) {
    if (!command.empty()) command += L' ';
    const std::wstring wide(part.begin(), part.end());  // argv here is ASCII system commands
    if (wide.find(L' ') != std::wstring::npos) { command += L'"'; command += wide; command += L'"'; }
    else command += wide;
  }
  SECURITY_ATTRIBUTES inherit{static_cast<DWORD>(sizeof(SECURITY_ATTRIBUTES)), nullptr, TRUE};
  HANDLE out_read = nullptr; HANDLE out_write = nullptr; HANDLE err_read = nullptr; HANDLE err_write = nullptr;
  if (CreatePipe(&out_read, &out_write, &inherit, 0) == 0) return result;
  if (CreatePipe(&err_read, &err_write, &inherit, 0) == 0) {
    CloseHandle(out_read); CloseHandle(out_write);
    return result;
  }
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = out_write;
  startup.hStdError = err_write;
  PROCESS_INFORMATION info{};
  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(L'\0');
  const BOOL started = CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info);
  CloseHandle(out_write);
  CloseHandle(err_write);
  if (started == 0) {
    CloseHandle(out_read); CloseHandle(err_read);
    return result;  // exit_code stays negative: the program could not be started
  }
  const auto drain = [](HANDLE pipe, std::string& into) {
    char buffer[4096];
    DWORD got = 0;
    while (ReadFile(pipe, buffer, sizeof buffer, &got, nullptr) != 0 && got != 0) into.append(buffer, got);
  };
  drain(out_read, result.out);
  drain(err_read, result.err);
  CloseHandle(out_read);
  CloseHandle(err_read);
  WaitForSingleObject(info.hProcess, INFINITE);
  DWORD code = 0;
  if (GetExitCodeProcess(info.hProcess, &code) != 0) result.exit_code = static_cast<int>(code);
  CloseHandle(info.hThread);
  CloseHandle(info.hProcess);
#else
  int out_pipe[2] = {-1, -1};
  int err_pipe[2] = {-1, -1};
  if (pipe(out_pipe) != 0) return result;
  if (pipe(err_pipe) != 0) {
    close(out_pipe[0]); close(out_pipe[1]);
    return result;
  }
  const pid_t pid = fork();
  if (pid < 0) {
    close(out_pipe[0]); close(out_pipe[1]); close(err_pipe[0]); close(err_pipe[1]);
    return result;
  }
  if (pid == 0) {
    dup2(out_pipe[1], STDOUT_FILENO);
    dup2(err_pipe[1], STDERR_FILENO);
    close(out_pipe[0]); close(out_pipe[1]); close(err_pipe[0]); close(err_pipe[1]);
    std::vector<char*> cargv;
    for (const auto& part : argv) cargv.push_back(const_cast<char*>(part.c_str()));
    cargv.push_back(nullptr);
    execvp(cargv[0], cargv.data());
    _exit(127);  // the exec failed; a distinguishable non-zero like any missing binary
  }
  close(out_pipe[1]);
  close(err_pipe[1]);
  // Read both pipes until EOF (systemctl output is tiny, but never trust that: read
  // alternately so a full stderr buffer can never deadlock the pump).
  bool out_open = true;
  bool err_open = true;
  while (out_open || err_open) {
    bool progressed = false;
    if (out_open) {
      char buffer[4096];
      const ssize_t got = read(out_pipe[0], buffer, sizeof buffer);
      if (got > 0) { result.out.append(buffer, static_cast<std::size_t>(got)); progressed = true; }
      else if (got == 0) out_open = false;
      else if (errno != EINTR) out_open = false;
      else progressed = true;
    }
    if (err_open) {
      char buffer[4096];
      const ssize_t got = read(err_pipe[0], buffer, sizeof buffer);
      if (got > 0) { result.err.append(buffer, static_cast<std::size_t>(got)); progressed = true; }
      else if (got == 0) err_open = false;
      else if (errno != EINTR) err_open = false;
      else progressed = true;
    }
    if (!progressed && (out_open || err_open)) break;  // both at EOF or an error closed them
  }
  close(out_pipe[0]);
  close(err_pipe[0]);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  if (WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
#endif
  return result;
}

namespace {

// R-T2-c: only a bus-connect failure (systemd's fixed text) or an unstartable
// systemctl means "no user manager". A fresh install answers non-zero about the
// UNIT and proceeds.
bool manager_unreachable(const CmdResult& probe) {
  return probe.exit_code < 0 ||
         (probe.exit_code != 0 && probe.err.find("Failed to connect to bus") != std::string::npos);
}

std::string first_token(const std::string& text) {
  std::string token;
  for (const char c : text) {
    if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
      if (!token.empty()) break;
      continue;
    }
    token.push_back(c);
  }
  return token;
}

}  // namespace

ServiceOutcome plan_enable(const ServiceEnv& env, CommandRunner& runner) {
#if defined(_WIN32)
  (void)env;
  (void)runner;
  // The Task Scheduler branch is Task 6's (golden text + windows-runtime e2e);
  // the cross gate compiles it there, never claims its runtime.
  return ServiceOutcome{false, "service: the Windows task branch is not wired yet (SP7 M1 Task 6)"};
#else
  const auto rendered = render_systemd_unit(env.unit);
  const auto* unit_text = std::get_if<std::string>(&rendered);
  if (unit_text == nullptr) return ServiceOutcome{false, std::get<ServiceError>(rendered).message};
  const auto probe = runner({"systemctl", "--user", "is-enabled", std::string{kServiceName}});
  if (manager_unreachable(probe)) {
    return ServiceOutcome{
        false,
        "service: the systemd user manager is not reachable; strata never falls back to the system scope and "
        "never runs loginctl for you. Start a real login session (its systemd user instance), and for "
        "boot-time start without a login run loginctl enable-linger yourself"};
  }
  std::error_code ec;
  std::filesystem::create_directories(env.user_unit_dir, ec);
  if (ec) return ServiceOutcome{false, "service: the user unit directory could not be created: " + env.user_unit_dir.string()};
  const std::filesystem::path tmp = env.unit_path.string() + ".tmp";
  {
    std::ofstream out{tmp, std::ios::binary | std::ios::trunc};
    if (!out) return ServiceOutcome{false, "service: the unit file could not be written: " + env.unit_path.string()};
    out << *unit_text;
    if (!out) return ServiceOutcome{false, "service: the unit file could not be written: " + env.unit_path.string()};
  }
  if (chmod(tmp.c_str(), 0644) != 0) {
    std::filesystem::remove(tmp, ec);
    return ServiceOutcome{false, "service: the unit file could not be set to mode 0644: " + env.unit_path.string()};
  }
  std::filesystem::rename(tmp, env.unit_path, ec);
  if (ec) {
    std::filesystem::remove(tmp, ec);
    return ServiceOutcome{false, "service: the unit file could not be put in place: " + env.unit_path.string()};
  }
  const auto enable = runner({"systemctl", "--user", "enable", "--now", std::string{kServiceName}});
  if (enable.exit_code != 0) {
    return ServiceOutcome{false, "service: systemctl --user enable --now strata failed (exit " +
                                     std::to_string(enable.exit_code) + "); the unit stays at " + env.unit_path.string()};
  }
  return ServiceOutcome{true,
                        "service: strata.service enabled and started at " + env.unit_path.string() +
                            " (systemctl --user enable --now). Boot-time start without a login session needs "
                            "loginctl enable-linger, which strata explains and never runs."};
#endif
}

ServiceOutcome plan_disable(const ServiceEnv& env, CommandRunner& runner) {
  const auto ours = env.user_unit_dir / std::string{kUnitFileName};
  if (env.unit_path != ours) {
    return ServiceOutcome{false,
                          "service: only " + ours.string() + " is strata's unit; a unit in any other location "
                                                             "(a system-scope unit, a renamed file) is never touched"};
  }
  const auto disable = runner({"systemctl", "--user", "disable", "--now", std::string{kServiceName}});
  if (disable.exit_code != 0) {
    return ServiceOutcome{false, "service: systemctl --user disable --now strata failed (exit " +
                                     std::to_string(disable.exit_code) + "); nothing was removed"};
  }
  std::error_code ec;
  const auto presence = std::filesystem::symlink_status(env.unit_path, ec);
  if (ec) return ServiceOutcome{false, "service: the unit file could not be inspected: " + env.unit_path.string()};
  if (presence.type() == std::filesystem::file_type::not_found) {
    return ServiceOutcome{true, "service: no strata.service unit was installed — nothing to remove"};
  }
  std::filesystem::remove(env.unit_path, ec);  // exactly the checked path, never a tree
  if (ec) return ServiceOutcome{false, "service: the unit file could not be removed: " + env.unit_path.string()};
  return ServiceOutcome{true, "service: strata.service disabled and its unit removed (" + env.unit_path.string() + ")"};
}

ServiceStatus plan_status(const ServiceEnv& env, CommandRunner& runner) {
  (void)env;
  const auto enabled = runner({"systemctl", "--user", "is-enabled", std::string{kServiceName}});
  const auto active = runner({"systemctl", "--user", "is-active", std::string{kServiceName}});
  if (manager_unreachable(enabled) || manager_unreachable(active)) {
    return ServiceStatus{
        "service: enabled: the systemd user manager is not reachable (nothing is assumed)",
        "service: active: the systemd user manager is not reachable (nothing is assumed)"};
  }
  const auto enabled_state = first_token(enabled.out);
  const auto active_state = first_token(active.out);
  return ServiceStatus{"service: enabled: " + (enabled_state.empty() ? std::string{"not installed"} : enabled_state),
                       "service: active: " + (active_state.empty() ? std::string{"inactive"} : active_state)};
}

bool user_manager_reachable(CommandRunner& runner) {
  const auto probe = runner({"systemctl", "--user", "is-enabled", std::string{kServiceName}});
  return !manager_unreachable(probe);
}

}  // namespace service
}  // namespace secure_frontend

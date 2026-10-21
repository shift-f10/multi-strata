// SP7 M1 Task 1: exact-text golden rendering of the hardened systemd user
// unit (spec D-5 / PX §6) and the `current`-target resolution seam (D-4).
#include "service_ops.hpp"
#include "support/process_runner.hpp"
#include "support/test_support.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

namespace {
int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}
using secure_frontend_test::contains;
using secure_frontend::service::render_systemd_unit;
using secure_frontend::service::resolve_current_target;
using secure_frontend::service::ServiceUnit;

ServiceUnit sample_unit() {
  return ServiceUnit{
      "/opt/strata/0.2.1.3/bin/strata",
      "/home/user/.config/strata/config.json",
      {"/home/user/.local/state/strata", "/home/user/.local/state/strata/logs", "/home/user/.cache/strata"},
  };
}

void render_systemd_unit_exact_golden() {
  const auto rendered = render_systemd_unit(sample_unit());
  const auto* text = std::get_if<std::string>(&rendered);
  if (text == nullptr) {
    expect(false, "the well-formed unit renders: " + std::get<secure_frontend::service::ServiceError>(rendered).message);
    return;
  }
  const std::string expected =
      "[Unit]\n"
      "Description=Strata local model server\n"
      "\n"
      "[Service]\n"
      "ExecStart=/opt/strata/0.2.1.3/bin/strata --config /home/user/.config/strata/config.json serve\n"
      "Restart=on-failure\n"
      "RestartSec=5\n"
      "NoNewPrivileges=yes\n"
      "ProtectSystem=strict\n"
      "ProtectHome=read-only\n"
      "ReadWritePaths=/home/user/.local/state/strata /home/user/.local/state/strata/logs /home/user/.cache/strata\n"
      "PrivateTmp=yes\n"
      "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
      "\n"
      "[Install]\n"
      "WantedBy=default.target\n";
  expect(*text == expected, "the unit text is the hardened D-5 set verbatim, got:\n" + *text);
}

void render_systemd_unit_rejects_whitespace_paths() {
  for (const std::string& needle : {std::string{"a b"}, std::string{"a\tb"}, std::string{"a\nb"}, std::string{"a\rb"}}) {
    {
      auto unit = sample_unit();
      unit.exec_start = "/opt/strata/" + needle + "/bin/strata";
      const auto rendered = render_systemd_unit(unit);
      const auto* error = std::get_if<secure_frontend::service::ServiceError>(&rendered);
      expect(error != nullptr, "an ExecStart path with \"" + needle + "\" is rejected");
      if (error != nullptr) expect(contains(error->message, "whitespace"), "the rejection names whitespace: " + error->message);
    }
    {
      auto unit = sample_unit();
      unit.config_file = "/home/user/" + needle + "/config.json";
      const auto rendered = render_systemd_unit(unit);
      expect(std::holds_alternative<secure_frontend::service::ServiceError>(rendered), "a config path with \"" + needle + "\" is rejected");
    }
    {
      auto unit = sample_unit();
      unit.read_write_paths.back() = "/home/user/" + needle;
      const auto rendered = render_systemd_unit(unit);
      expect(std::holds_alternative<secure_frontend::service::ServiceError>(rendered), "a ReadWritePaths entry with \"" + needle + "\" is rejected");
    }
  }
}

void render_systemd_unit_rejects_relative_or_empty() {
  {
    auto unit = sample_unit();
    unit.exec_start = "bin/strata";  // systemd ExecStart must be absolute
    expect(std::holds_alternative<secure_frontend::service::ServiceError>(render_systemd_unit(unit)), "a relative ExecStart is rejected");
  }
  {
    auto unit = sample_unit();
    unit.read_write_paths.clear();
    expect(std::holds_alternative<secure_frontend::service::ServiceError>(render_systemd_unit(unit)),
           "an empty ReadWritePaths list is rejected (serve always writes roots.state)");
  }
}

#if !defined(_WIN32)
void resolve_current_target_follows_current_pointer() {
  const auto root = secure_frontend_test::make_scratch_directory();
  const auto version_dir = root / "0.2.1.3";
  std::filesystem::create_directories(version_dir / "bin");
  const auto exe = version_dir / "bin" / "strata";
  secure_frontend_test::write_file(exe, "binary");
  std::filesystem::create_symlink(root / "0.2.1.3", root / "current");
  // Launched through the pointer: the unit must name the resolved version directory, not `current`.
  const auto through_pointer = resolve_current_target(root / "current" / "bin" / "strata");
  const auto* path = std::get_if<std::filesystem::path>(&through_pointer);
  if (path == nullptr) {
    expect(false, "a versioned install resolves: " + std::get<secure_frontend::service::ServiceError>(through_pointer).message);
    return;
  }
  expect(*path == std::filesystem::canonical(exe), "the resolved target is the current version directory's executable, got " + path->string());
  // Launched directly from the version directory while `current` names it: same answer.
  const auto direct = resolve_current_target(exe);
  const auto* direct_path = std::get_if<std::filesystem::path>(&direct);
  expect(direct_path != nullptr && *direct_path == std::filesystem::canonical(exe), "a direct launch resolves to the same target");
  // `current` moved elsewhere: the version directory that is not current is refused.
  std::filesystem::create_directories(root / "0.2.2.0" / "bin");
  secure_frontend_test::write_file(root / "0.2.2.0" / "bin" / "strata", "binary");
  std::filesystem::remove(root / "current");
  std::filesystem::create_symlink(root / "0.2.2.0", root / "current");
  const auto stale = resolve_current_target(exe);
  const auto* stale_path = std::get_if<std::filesystem::path>(&stale);
  // D-5: ExecStart always points at the resolved current target; a version
  // directory the pointer left behind is a plain (unversioned) path instead.
  expect(stale_path != nullptr && *stale_path == std::filesystem::canonical(exe),
         "a version the pointer left stays its own canonical path");
}

void resolve_current_target_plain_install_uses_self() {
  const auto root = secure_frontend_test::make_scratch_directory();
  std::filesystem::create_directories(root / "bin");
  const auto exe = root / "bin" / "strata";
  secure_frontend_test::write_file(exe, "binary");
  const auto resolved = resolve_current_target(exe);
  const auto* path = std::get_if<std::filesystem::path>(&resolved);
  expect(path != nullptr && *path == std::filesystem::canonical(exe),
         "a plain install resolves to its own canonical path (M2's update gives the versioned error, not the service verbs)");
}
#endif
}  // namespace

#if !defined(_WIN32)
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>
#include <map>
namespace {
const std::vector<std::string> kProbeIsEnabled{"systemctl", "--user", "is-enabled", "strata"};
const std::vector<std::string> kEnableNow{"systemctl", "--user", "enable", "--now", "strata"};
const std::vector<std::string> kDisableNow{"systemctl", "--user", "disable", "--now", "strata"};
const std::vector<std::string> kProbeIsActive{"systemctl", "--user", "is-active", "strata"};

// A CommandRunner that records every argv and answers exact commands (default: exit 0).
class FakeRunner final {
 public:
  std::vector<std::vector<std::string>> calls;
  std::map<std::vector<std::string>, secure_frontend::service::CmdResult> answers{};
  secure_frontend::service::CmdResult operator()(const std::vector<std::string>& argv) {
    calls.push_back(argv);
    const auto it = answers.find(argv);
    if (it != answers.end()) return it->second;
    return secure_frontend::service::CmdResult{0, "", ""};
  }
};

secure_frontend::service::ServiceEnv scratch_env(const std::filesystem::path& dir) {
  secure_frontend::service::ServiceEnv env;
  env.user_unit_dir = dir / "systemd-user";
  env.unit_path = env.user_unit_dir / "strata.service";
  env.unit = sample_unit();
  return env;
}

std::string golden_unit_text() {
  const auto rendered = render_systemd_unit(sample_unit());
  return std::get<std::string>(rendered);
}

bool file_mode(const std::filesystem::path& path, unsigned& mode) {
  struct stat st {};
  if (stat(path.c_str(), &st) != 0) return false;
  mode = st.st_mode & 0777U;
  return true;
}

void service_enable_writes_unit_then_enables() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  auto env = scratch_env(dir);
  FakeRunner fake;
  // The real fresh-install answer: exit 1, and the error is about the UNIT, not the bus (R-T2-c).
  fake.answers[kProbeIsEnabled] = secure_frontend::service::CmdResult{
      1, "", "Failed to get unit file state for strata.service: No such file or directory"};
  secure_frontend::service::CommandRunner runner{std::ref(fake)};
  const auto outcome = secure_frontend::service::plan_enable(env, runner);
  expect(outcome.ok, "enable succeeds against a reachable manager: " + outcome.message);
  expect(secure_frontend_test::read_file(env.unit_path) == golden_unit_text(), "the unit on disk is the rendered golden text");
  unsigned mode = 0;
  expect(file_mode(env.unit_path, mode) && mode == 0644U, "the unit file is 0644");
  expect(fake.calls == std::vector<std::vector<std::string>>{kProbeIsEnabled, kEnableNow}, "exactly probe then enable --now");
}

void service_enable_missing_user_manager_writes_nothing() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  auto env = scratch_env(dir);
  FakeRunner fake;
  fake.answers[kProbeIsEnabled] = secure_frontend::service::CmdResult{
      1, "", "Failed to connect to bus: No such file or directory"};
  secure_frontend::service::CommandRunner runner{std::ref(fake)};
  const auto outcome = secure_frontend::service::plan_enable(env, runner);
  expect(!outcome.ok, "no user manager means a non-zero verb");
  expect(contains(outcome.message, "loginctl enable-linger"), "the explanation names the linger fix: " + outcome.message);
  expect(!std::filesystem::exists(env.unit_path), "the unit was NOT written");
  expect(fake.calls == std::vector<std::vector<std::string>>{kProbeIsEnabled}, "only the probe ran");
  for (const auto& call : fake.calls) expect(call.at(0) == "systemctl", "never any loginctl: " + call.at(0));
  expect(!std::filesystem::exists(dir / "systemd-user"), "and no unit directory was created");
}

void service_enable_reports_failed_enable() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  auto env = scratch_env(dir);
  FakeRunner fake;
  fake.answers[kEnableNow] = secure_frontend::service::CmdResult{1, "", "Job for strata.service failed"};
  secure_frontend::service::CommandRunner runner{std::ref(fake)};
  const auto outcome = secure_frontend::service::plan_enable(env, runner);
  expect(!outcome.ok, "a failed enable --now is a non-zero verb");
  expect(std::filesystem::exists(env.unit_path), "the unit stays where it was written (the user fixes and retries)");
}

void service_disable_removes_only_our_unit() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  auto env = scratch_env(dir);
  secure_frontend_test::make_private_directory(env.user_unit_dir);
  secure_frontend_test::write_file(env.unit_path, golden_unit_text(), 0644);
  FakeRunner fake;
  secure_frontend::service::CommandRunner runner{std::ref(fake)};
  const auto outcome = secure_frontend::service::plan_disable(env, runner);
  expect(outcome.ok, "disable succeeds: " + outcome.message);
  expect(fake.calls == std::vector<std::vector<std::string>>{kDisableNow}, "exactly disable --now");
  expect(!std::filesystem::exists(env.unit_path), "our unit file is removed");
}

void service_disable_refuses_foreign_unit() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  auto env = scratch_env(dir);
  {
    // A system-scope path: never removed, never even probed.
    env.unit_path = dir / "foreign" / "strata.service";
    secure_frontend_test::make_private_directory(dir / "foreign");
    secure_frontend_test::write_file(env.unit_path, golden_unit_text(), 0644);
    FakeRunner fake;
    secure_frontend::service::CommandRunner runner{std::ref(fake)};
    const auto outcome = secure_frontend::service::plan_disable(env, runner);
    expect(!outcome.ok, "a unit outside the user unit directory is refused");
    expect(fake.calls.empty(), "nothing ran for a refused unit");
    expect(std::filesystem::exists(env.unit_path), "the foreign unit stays");
  }
  {
    // Under the user directory but not our file name.
    env.unit_path = env.user_unit_dir / "other.service";
    secure_frontend_test::make_private_directory(env.user_unit_dir);
    secure_frontend_test::write_file(env.unit_path, "x", 0644);
    FakeRunner fake;
    secure_frontend::service::CommandRunner runner{std::ref(fake)};
    const auto outcome = secure_frontend::service::plan_disable(env, runner);
    expect(!outcome.ok && fake.calls.empty(), "a differently named unit under the user directory is refused too");
    expect(std::filesystem::exists(env.unit_path), "and it stays");
  }
}

void service_status_one_line_each() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  auto env = scratch_env(dir);
  FakeRunner fake;
  fake.answers[kProbeIsEnabled] = secure_frontend::service::CmdResult{0, "enabled\n", ""};
  fake.answers[kProbeIsActive] = secure_frontend::service::CmdResult{3, "inactive\n", ""};
  secure_frontend::service::CommandRunner runner{std::ref(fake)};
  const auto status = secure_frontend::service::plan_status(env, runner);
  expect(fake.calls == std::vector<std::vector<std::string>>{kProbeIsEnabled, kProbeIsActive}, "exactly the two probes");
  expect(contains(status.enabled_line, "enabled") && contains(status.active_line, "inactive"),
         "one human line each: " + status.enabled_line + " / " + status.active_line);
  expect(status.enabled_line.find('\n') == std::string::npos && status.active_line.find('\n') == std::string::npos,
         "each line is one line");
}

void service_status_without_user_manager() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  auto env = scratch_env(dir);
  FakeRunner fake;
  secure_frontend::service::CmdResult no_bus{1, "", "Failed to connect to bus: No such file or directory"};
  fake.answers[kProbeIsEnabled] = no_bus;
  fake.answers[kProbeIsActive] = no_bus;
  secure_frontend::service::CommandRunner runner{std::ref(fake)};
  const auto status = secure_frontend::service::plan_status(env, runner);
  expect(contains(status.enabled_line, "user manager") || contains(status.active_line, "user manager"),
         "status explains the unreachable manager instead of guessing: " + status.enabled_line + " / " + status.active_line);
}

void service_enable_e2e_path_shim() {
  const auto dir = secure_frontend_test::make_scratch_directory();
  // A PATH that contains ONLY our shim, so no real systemctl can ever be reached.
  const auto bin = dir / "bin";
  secure_frontend_test::make_private_directory(bin);
  const auto log = dir / "systemctl.log";
  secure_frontend_test::write_file(bin / "systemctl",
                                   "#!/bin/sh\n"
                                   "printf '%s\\n' \"$*\" >> " + log.string() + "\n"
                                   "if [ \"$1 $2 $3 $4\" = \"--user is-enabled strata\" ]; then\n"
                                   "  echo 'Failed to get unit file state for strata.service: No such file or directory' >&2\n"
                                   "  exit 1\n"
                                   "fi\n"
                                   "exit 0\n",
                                   0755);
  const char* saved_path = std::getenv("PATH");
  const std::string saved{saved_path != nullptr ? saved_path : ""};
  setenv("PATH", bin.string().c_str(), 1);
  auto env = scratch_env(dir);
  secure_frontend::service::CommandRunner runner{secure_frontend::service::run_argv};
  const auto outcome = secure_frontend::service::plan_enable(env, runner);
  setenv("PATH", saved.c_str(), 1);
  expect(outcome.ok, "enable runs through the PATH shim: " + outcome.message);
  expect(secure_frontend_test::read_file(env.unit_path) == golden_unit_text(), "the shim-enabled unit is the golden text");
  const std::string log_text = secure_frontend_test::read_file(log);
  expect(log_text == "--user is-enabled strata\n--user enable --now strata\n", "exactly probe then enable --now, got: " + log_text);
}
}  // namespace
#endif

int main(int argc, char** argv) {
#if defined(_WIN32)
  return secure_frontend_test::run_cases(argc, argv, {
      {"render_systemd_unit_exact_golden", render_systemd_unit_exact_golden},
      {"render_systemd_unit_rejects_whitespace_paths", render_systemd_unit_rejects_whitespace_paths},
      {"render_systemd_unit_rejects_relative_or_empty", render_systemd_unit_rejects_relative_or_empty},
  }, failures);
#else
  return secure_frontend_test::run_cases(argc, argv, {
      {"render_systemd_unit_exact_golden", render_systemd_unit_exact_golden},
      {"render_systemd_unit_rejects_whitespace_paths", render_systemd_unit_rejects_whitespace_paths},
      {"render_systemd_unit_rejects_relative_or_empty", render_systemd_unit_rejects_relative_or_empty},
      {"resolve_current_target_follows_current_pointer", resolve_current_target_follows_current_pointer},
      {"resolve_current_target_plain_install_uses_self", resolve_current_target_plain_install_uses_self},
      {"service_enable_writes_unit_then_enables", service_enable_writes_unit_then_enables},
      {"service_enable_missing_user_manager_writes_nothing", service_enable_missing_user_manager_writes_nothing},
      {"service_enable_reports_failed_enable", service_enable_reports_failed_enable},
      {"service_disable_removes_only_our_unit", service_disable_removes_only_our_unit},
      {"service_disable_refuses_foreign_unit", service_disable_refuses_foreign_unit},
      {"service_status_one_line_each", service_status_one_line_each},
      {"service_status_without_user_manager", service_status_without_user_manager},
      {"service_enable_e2e_path_shim", service_enable_e2e_path_shim},
  }, failures);
#endif
}

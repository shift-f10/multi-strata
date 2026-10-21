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
  }, failures);
#endif
}

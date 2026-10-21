// SP7 M1 Task 1 (spec D-5/D-4): the hardened systemd user unit text and the
// `current`-target resolution seam. Pure functions; the verbs that consume
// them (Task 2) live beside them.
#include "service_ops.hpp"

#include <fstream>
#include <optional>
#include <system_error>

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

}  // namespace service
}  // namespace secure_frontend

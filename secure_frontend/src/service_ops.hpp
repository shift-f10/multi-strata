#pragma once
// SP7 M1 (spec D-5): the per-user service unit. Rendering is pure text; the
// verbs that write it (plan_enable/plan_disable/plan_status, Task 2) live in
// the same library. Internal header (src/, like strata_cli_internal.hpp): the
// only consumers are our own verbs and tests.
#include <filesystem>
#include <string>
#include <variant>
#include <vector>

namespace secure_frontend {
namespace service {

// One hardened service definition, all paths in portable generic (slash) form.
// exec_start is the resolved current-target executable (resolve_current_target);
// config_file is the verb's --config path; read_write_paths are the roots the
// served process may write (the server never writes anywhere else).
struct ServiceUnit final {
  std::filesystem::path exec_start;
  std::string config_file;
  std::vector<std::string> read_write_paths;
};

// Fixed human text. It never echoes a path (the whitespace rule is the finding;
// a configured path may name nothing the user did not already type).
struct ServiceError final {
  std::string message;
};

// The exact hardened systemd user unit (D-5, verbatim directives:
// NoNewPrivileges=yes, ProtectSystem=strict, ProtectHome=read-only,
// ReadWritePaths of the roots, PrivateTmp=yes,
// RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6, Restart=on-failure,
// RestartSec=5, ExecStart=<resolved target> --config <file> serve).
// Rejects any path that is empty, not absolute, or contains a space, tab or
// newline (systemd splits ExecStart and the ReadWritePaths list on spaces;
// quoting is not ours to get subtly right).
[[nodiscard]] std::variant<std::string, ServiceError> render_systemd_unit(const ServiceUnit& unit);

// The ExecStart target (D-4): if self_executable sits under a `current`
// pointer (Linux symlink, Windows current.txt), the path is reported through
// its resolved version directory; a plain single-directory install reports its
// own canonical path. This is the seam SP7 M2's `update` will write through.
[[nodiscard]] std::variant<std::filesystem::path, ServiceError> resolve_current_target(const std::filesystem::path& self_executable);

}  // namespace service
}  // namespace secure_frontend

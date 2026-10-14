#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <utility>

namespace secure_frontend {

// Linux cgroup v2 (spec §3.7d): used only when this process already runs in a
// delegated cgroup it can write to (systemd `Delegate=yes`, `systemd-run --user
// --scope`); never created with privileges. Off everywhere else.
class EngineCgroups final {
 public:
  // nullopt unless /proc/self/cgroup names a v2 cgroup whose cgroup.procs this
  // process can write and below which it can create a child with cgroup.kill (5.14+).
  [[nodiscard]] static std::optional<EngineCgroups> detect();
  // Creates <root>/strata-engine-<generation> (0700) and returns its cgroup.procs.
  [[nodiscard]] std::optional<std::filesystem::path> prepare_generation(std::uint64_t generation) const;
  [[nodiscard]] const std::filesystem::path& root() const noexcept { return root_; }

 private:
  explicit EngineCgroups(std::filesystem::path root) : root_(std::move(root)) {}
  std::filesystem::path root_;
};

// Writes "1" to <directory>/cgroup.kill: every member dies, escapes included.
bool kill_cgroup(const std::filesystem::path& directory) noexcept;
// Waits up to `bound` for "populated 0" in cgroup.events, then removes the directory.
bool remove_cgroup(const std::filesystem::path& directory, std::chrono::milliseconds bound) noexcept;

}  // namespace secure_frontend

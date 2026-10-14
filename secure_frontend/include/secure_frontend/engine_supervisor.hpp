#pragma once

#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/config_defaults.hpp"
#include "secure_frontend/engine_process.hpp"
#include "secure_frontend/engine_protocol_client.hpp"
#include "secure_frontend/exit_status.hpp"
#include "secure_frontend/restart_policy.hpp"
#include "secure_frontend/supervised_process.hpp"
#include "secure_frontend/supervisor_clock.hpp"
#include "secure_frontend/supervisor_wake.hpp"
#include "secure_frontend/tokenizer_pack.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <vector>

namespace secure_frontend {

// Spec §3.8; the transition table is in the SP2 plan header.
enum class SupervisorState { starting, ready, generating, stopping, backoff, circuit_open, shutting_down, stopped };

// The /health view of one state. `engine` and `recovery` are fixed literals;
// `recovery` ("restarting" | "exhausted") is empty unless engine == "failed".
struct HealthSnapshot final {
  SupervisorState state;
  bool healthy;
  std::string_view engine;
  std::string_view recovery;
};

[[nodiscard]] HealthSnapshot health_for(SupervisorState state) noexcept;

// One engine generation: fresh process, protocol client and chat service per
// spawn (spec §3.2), kept alive by a shared_ptr until the last Lease ends.
struct EngineInstance final {
  std::uint64_t number{0};
  std::unique_ptr<SupervisedProcess> process;
  std::unique_ptr<EngineProtocolClient> protocol;
  std::unique_ptr<ChatExecutionService> chat;
};

class EngineSupervisor;

// The serving thread's borrow of the current generation, taken in `ready`.
// Releasing it returns the supervisor from `generating` to `ready`.
class Lease final {
 public:
  Lease(Lease&& other) noexcept;
  Lease& operator=(Lease&&) = delete;
  Lease(const Lease&) = delete;
  Lease& operator=(const Lease&) = delete;
  ~Lease();

  [[nodiscard]] ChatExecutionService& chat() const noexcept;
  [[nodiscard]] EngineProtocolClient& protocol() const noexcept;
  [[nodiscard]] SupervisedProcess& process() const noexcept;
  [[nodiscard]] std::uint64_t generation() const noexcept;

 private:
  friend class EngineSupervisor;
  Lease(EngineSupervisor& owner, std::shared_ptr<EngineInstance> instance) noexcept;
  EngineSupervisor* owner_;
  std::shared_ptr<EngineInstance> instance_;
};

struct SupervisorConfig final {
  RestartPolicy policy{};
  ChatExecutionLimits chat_limits{};
  NativeChatProfile profile{NativeChatProfile::qwen};
  EngineProtocolFlavor flavor{EngineProtocolFlavor::strata_0143};
  std::chrono::milliseconds ready_poll_slice{config_defaults::kReadyPollSlice};
  std::chrono::milliseconds monitor_poll{config_defaults::kMonitorFallbackPoll};
  std::chrono::milliseconds shutdown_stdin_wait{config_defaults::kShutdownStdinWait};
  std::chrono::milliseconds shutdown_term_wait{config_defaults::kShutdownTermWait};
  // Linux: become the child subreaper and sweep orphaned descendants after every generation (spec §3.7b).
  bool sweep_orphans{true};
  // Linux: log the /dev/nvidia-uvm hint when a generation ends before READY under PR_SET_NO_NEW_PRIVS.
  bool no_new_privileges_hint{false};
};

// Receives fixed-literal lines such as "engine generation 2 ended: abort".
using SupervisorLog = std::function<void(std::string_view line)>;

// Owns every engine generation for the frontend's lifetime (spec §3.1): one
// supervisor thread spawns, consumes READY, watches, kills and reaps; it is
// the only reaper. The serving thread borrows the current generation through
// acquire() and reports an unusable one with report_fatal().
class EngineSupervisor final {
 public:
  EngineSupervisor(SupervisorConfig config, ProcessFactory factory,
                   std::shared_ptr<SupervisorClock> clock = std::make_shared<SteadySupervisorClock>(), SupervisorLog log = {});
  ~EngineSupervisor();
  EngineSupervisor(const EngineSupervisor&) = delete;
  EngineSupervisor& operator=(const EngineSupervisor&) = delete;

  // Starts the supervisor thread, which spawns generation 1. Call once.
  // false = refused (no wake to reach the thread, or no thread): nothing runs.
  [[nodiscard]] bool start();
  // Only in `ready`; anywhere else nullopt (the caller answers a generic 503 at once).
  [[nodiscard]] std::optional<Lease> acquire();
  // The leased generation is unusable (fatal line, drain failure, write timeout,
  // failed protocol): kill it, count a failure, restart per policy.
  void report_fatal(const Lease& lease, KillReason reason);
  // One sample per /health request (SP0's sample-once rule).
  [[nodiscard]] HealthSnapshot snapshot() const;
  // Requests the orderly shutdown and waits for it; past `bound` the process exits 1.
  void shutdown(std::chrono::milliseconds bound);
  [[nodiscard]] bool stop_requested() const noexcept;

  // Test seams.
  [[nodiscard]] bool wait_for_state(SupervisorState state, std::chrono::milliseconds timeout) const;
  [[nodiscard]] std::uint64_t generations_started() const noexcept { return generations_started_.load(); }

 private:
  friend class Lease;
  void release(std::shared_ptr<EngineInstance> instance) noexcept;
  void run_guarded() noexcept;
  void run();
  void fail_closed() noexcept;
  std::shared_ptr<EngineInstance> spawn_generation();
  KillReason supervise(EngineInstance& instance, std::chrono::milliseconds& healthy_for);
  std::optional<KillReason> await_ready(EngineInstance& instance, EngineReady& ready);
  KillReason watch(EngineInstance& instance);
  bool end_generation(const std::shared_ptr<EngineInstance>& instance, KillReason reason);
  bool schedule_restart(std::chrono::milliseconds healthy_for, bool reaped);
  void wait_in_circuit_open();
  void shutdown_generation(const std::shared_ptr<EngineInstance>& instance);
  void retire(const std::shared_ptr<EngineInstance>& instance, bool reaped);
  void sweep_retired();
  void finish();
  void set_state(SupervisorState state);
  void set_state(SupervisorState state, std::shared_ptr<EngineInstance> current);
  void log_end(std::uint64_t generation, std::string_view kind);

  SupervisorConfig config_;
  ProcessFactory factory_;
  std::shared_ptr<SupervisorClock> clock_;
  SupervisorLog log_;
  RestartTracker tracker_;
  SupervisorWake wake_;
  mutable std::mutex mutex_;
  mutable std::condition_variable changed_;
  SupervisorState state_{SupervisorState::stopped};
  std::shared_ptr<EngineInstance> current_;
  KillReason pending_kill_{KillReason::none};
  // Ended generations still borrowed by a Lease: destroyed by sweep_retired()
  // on the supervisor thread once the Lease lets go (spec §3.1; on Windows the
  // destructor terminates the Job and waits).
  std::vector<std::shared_ptr<EngineInstance>> retired_;
  std::vector<std::shared_ptr<EngineInstance>> abandoned_;
  std::atomic<std::uint64_t> generations_started_{0};
  std::atomic<bool> shutdown_requested_{false};
  std::thread thread_;
};

// Maps the protocol's terminal failure to the §3.5 kill reason.
[[nodiscard]] KillReason kill_reason_for(const EngineProtocolClient& protocol) noexcept;

// The serving thread's one call per chat request: borrows the current
// generation, runs the request, and reports a generation left unusable.
// nullopt = no generation is ready (answer a generic 503 at once).
[[nodiscard]] std::optional<ChatExecutionOutcome> execute_with_lease(EngineSupervisor& supervisor, const ChatCompletionRequest& request,
                                                                     const TokenizerPack& tokenizer);

// What the production factory launches for every generation.
struct EngineLaunchPlan final {
  EngineCommand command;
};

// Production factory: an EngineStdioProcess started from `plan` per generation.
[[nodiscard]] ProcessFactory make_stdio_process_factory(EngineLaunchPlan plan);

}  // namespace secure_frontend

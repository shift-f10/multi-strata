#include "secure_frontend/engine_supervisor.hpp"

#include "secure_frontend/deadline.hpp"
#include "secure_frontend/engine_stdio_process.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <variant>

namespace secure_frontend {
namespace {

constexpr auto kReapPoll = std::chrono::milliseconds(10);

void log_to_stderr(const std::string_view line) {
  std::cerr << line << '\n';
  std::cerr.flush();
}

}  // namespace

HealthSnapshot health_for(const SupervisorState state) noexcept {
  switch (state) {
    case SupervisorState::starting: return {state, false, "starting", ""};
    case SupervisorState::ready: return {state, true, "ready", ""};
    case SupervisorState::generating: return {state, true, "generating", ""};
    case SupervisorState::stopping:
    case SupervisorState::backoff: return {state, false, "failed", "restarting"};
    case SupervisorState::circuit_open: return {state, false, "failed", "exhausted"};
    case SupervisorState::shutting_down:
    case SupervisorState::stopped: return {state, false, "failed", ""};
  }
  return {SupervisorState::stopped, false, "failed", ""};
}

KillReason kill_reason_for(const EngineProtocolClient& protocol) noexcept {
  const auto code = protocol.failure_code();
  if (!code) return KillReason::protocol_failed;
  switch (*code) {
    case EngineProtocolErrorCode::transport_write_failed: return KillReason::write_timeout;
    default: return KillReason::protocol_failed;
  }
}

std::optional<ChatExecutionOutcome> execute_with_lease(EngineSupervisor& supervisor, const ChatCompletionRequest& request,
                                                       const TokenizerPack& tokenizer) {
  auto lease = supervisor.acquire();
  if (!lease) return std::nullopt;
  ChatExecutionOutcome outcome = lease->chat().execute(request, tokenizer);
  // A closed or failed protocol leaves the generation unusable. Any ERR line
  // keeps SP0's per-request answer; the generation itself is replaced.
  if (lease->protocol().closed()) supervisor.report_fatal(*lease, kill_reason_for(lease->protocol()));
  return outcome;
}

ProcessFactory make_stdio_process_factory(EngineLaunchPlan plan) {
  return [plan = std::move(plan)](const std::uint64_t) -> SpawnResult {
    auto process = std::make_unique<EngineStdioProcess>();
    if (const auto error = process->start(plan.command); error.has_value()) return SpawnFailure{error->message};
    return std::unique_ptr<SupervisedProcess>(std::move(process));
  };
}

Lease::Lease(EngineSupervisor& owner, std::shared_ptr<EngineInstance> instance) noexcept
    : owner_(&owner), instance_(std::move(instance)) {}
Lease::Lease(Lease&& other) noexcept : owner_(std::exchange(other.owner_, nullptr)), instance_(std::move(other.instance_)) {}
Lease::~Lease() {
  if (owner_ != nullptr && instance_) owner_->release(std::move(instance_));
}
ChatExecutionService& Lease::chat() const noexcept { return *instance_->chat; }
EngineProtocolClient& Lease::protocol() const noexcept { return *instance_->protocol; }
SupervisedProcess& Lease::process() const noexcept { return *instance_->process; }
std::uint64_t Lease::generation() const noexcept { return instance_->number; }

EngineSupervisor::EngineSupervisor(SupervisorConfig config, ProcessFactory factory, std::shared_ptr<SupervisorClock> clock,
                                   SupervisorLog log)
    : config_(std::move(config)),
      factory_(std::move(factory)),
      clock_(std::move(clock)),
      log_(log ? std::move(log) : SupervisorLog(log_to_stderr)),
      tracker_(config_.policy) {}

EngineSupervisor::~EngineSupervisor() {
  if (thread_.joinable()) shutdown(supervision_defaults::kShutdownBound);
}

void EngineSupervisor::start() {
  {
    std::lock_guard lock(mutex_);
    if (thread_.joinable()) return;
    state_ = SupervisorState::starting;
    changed_.notify_all();
  }
  thread_ = std::thread([this] { run(); });
}

std::optional<Lease> EngineSupervisor::acquire() {
  std::lock_guard lock(mutex_);
  if (state_ != SupervisorState::ready || !current_) return std::nullopt;
  state_ = SupervisorState::generating;
  changed_.notify_all();
  return Lease(*this, current_);
}

// The Lease's reference is dropped under the lock: current_ or retired_ still
// holds the instance, so its destructor never runs on the serving thread. A
// retired one wakes the supervisor thread so it is swept promptly.
void EngineSupervisor::release(std::shared_ptr<EngineInstance> instance) noexcept {
  bool retired = false;
  {
    std::lock_guard lock(mutex_);
    if (state_ == SupervisorState::generating && current_ == instance) {
      state_ = SupervisorState::ready;
      changed_.notify_all();
    }
    retired = current_ != instance;
    instance.reset();
  }
  if (retired) wake_.notify();
}

void EngineSupervisor::report_fatal(const Lease& lease, const KillReason reason) {
  {
    std::lock_guard lock(mutex_);
    if (current_ != lease.instance_ || (state_ != SupervisorState::ready && state_ != SupervisorState::generating)) return;
    pending_kill_ = reason == KillReason::none ? KillReason::protocol_failed : reason;
    state_ = SupervisorState::stopping;
    changed_.notify_all();
  }
  wake_.notify();
}

HealthSnapshot EngineSupervisor::snapshot() const {
  std::lock_guard lock(mutex_);
  return health_for(state_);
}

bool EngineSupervisor::stop_requested() const noexcept { return shutdown_requested_.load(); }

bool EngineSupervisor::wait_for_state(const SupervisorState state, const std::chrono::milliseconds timeout) const {
  std::unique_lock lock(mutex_);
  return changed_.wait_for(lock, timeout, [this, state] { return state_ == state; });
}

void EngineSupervisor::shutdown(const std::chrono::milliseconds bound) {
  shutdown_requested_.store(true);
  wake_.notify();
  if (!thread_.joinable()) return;
  {
    std::unique_lock lock(mutex_);
    if (!changed_.wait_for(lock, bound, [this] { return state_ == SupervisorState::stopped; })) {
      // Spec §3.7: an orderly shutdown that cannot finish within the bound exits 1.
      std::_Exit(EXIT_FAILURE);
    }
  }
  thread_.join();
}

void EngineSupervisor::run() {
  for (;;) {
    sweep_retired();
    if (stop_requested()) break;
    std::chrono::milliseconds healthy_for{0};
    bool reaped = true;
    // Scoped to the generation: once retired, only retired_ and Leases hold it,
    // so the backoff and circuit_open sweeps can destroy it.
    if (auto instance = spawn_generation()) {
      const KillReason reason = supervise(*instance, healthy_for);
      if (reason == KillReason::shutdown) {
        shutdown_generation(instance);
        break;
      }
      reaped = end_generation(instance, reason);
    }
    if (stop_requested()) break;
    if (!schedule_restart(healthy_for, reaped)) {
      wait_in_circuit_open();
      break;
    }
  }
  finish();
}

std::shared_ptr<EngineInstance> EngineSupervisor::spawn_generation() {
  const std::uint64_t number = generations_started_.fetch_add(1U) + 1U;
  set_state(SupervisorState::starting, nullptr);
  SpawnResult spawned = factory_(number);
  if (std::holds_alternative<SpawnFailure>(spawned)) {
    log_end(number, exit_kind_literal(ExitKind::spawn_failed));
    return nullptr;
  }
  auto instance = std::make_shared<EngineInstance>();
  instance->number = number;
  instance->process = std::move(std::get<std::unique_ptr<SupervisedProcess>>(spawned));
  instance->protocol = std::make_unique<EngineProtocolClient>(instance->process->transport(), EngineProtocolLimits{}, config_.flavor);
  set_state(SupervisorState::starting, instance);
  return instance;
}

KillReason EngineSupervisor::supervise(EngineInstance& instance, std::chrono::milliseconds& healthy_for) {
  EngineReady ready{};
  if (const auto reason = await_ready(instance, ready); reason.has_value()) return *reason;
  instance.chat = std::make_unique<ChatExecutionService>(*instance.protocol, config_.chat_limits, config_.profile);
  instance.chat->adopt_ready(ready);
  const auto ready_at = clock_->now();
  set_state(SupervisorState::ready);
  const KillReason reason = watch(instance);
  healthy_for = std::chrono::duration_cast<std::chrono::milliseconds>(clock_->now() - ready_at);
  return reason;
}

// Eager READY (spec §3.4): consumed on this thread right after spawn, in short
// slices so shutdown and an early exit are seen promptly.
std::optional<KillReason> EngineSupervisor::await_ready(EngineInstance& instance, EngineReady& ready) {
  for (;;) {
    if (stop_requested()) return KillReason::shutdown;
    const auto error = instance.protocol->await_ready(config_.ready_poll_slice, ready);
    if (!error) return std::nullopt;
    if (error->code == EngineProtocolErrorCode::closed) return KillReason::none;  // it ended; its exit status says why
    if (error->code != EngineProtocolErrorCode::timeout) return KillReason::protocol_failed;
    if (instance.process->try_reap()) return KillReason::none;
  }
}

KillReason EngineSupervisor::watch(EngineInstance& instance) {
  for (;;) {
    {
      std::lock_guard lock(mutex_);
      if (pending_kill_ != KillReason::none) return std::exchange(pending_kill_, KillReason::none);
    }
    if (stop_requested()) return KillReason::shutdown;
    if (instance.process->try_reap()) return KillReason::none;
    sweep_retired();
    // Spec V4: wait on the child itself, so a death between requests is seen
    // at once; without a pidfd, poll every monitor_poll.
    const std::intptr_t handle = instance.process->monitor_handle();
    (void)wake_.wait(handle, handle == kNoMonitorHandle ? config_.monitor_poll : std::chrono::milliseconds(-1));
  }
}

// `stopping` (spec §3.8): kill the whole group/Job, reap within reap_timeout,
// classify and log. Returns false when the child could not be reaped.
bool EngineSupervisor::end_generation(const std::shared_ptr<EngineInstance>& instance, const KillReason reason) {
  set_state(SupervisorState::stopping);
  SupervisedProcess& process = *instance->process;
  const bool ended_on_its_own = process.try_reap().has_value();
  process.kill_group();  // spec §3.7a: always, even after the leader has ended
  const auto deadline = deadline_after(config_.policy.reap_timeout);
  std::optional<ExitStatus> status = process.try_reap();
  while (!status && remaining_until(deadline).count() > 0) {
    std::this_thread::sleep_for(kReapPoll);
    status = process.try_reap();
  }
  retire(instance, status.has_value());
  if (!status) {
    log_end(instance->number, "unreaped");
    return false;
  }
  process.release_resources(std::chrono::milliseconds(1000));
  const KillReason sent = ended_on_its_own ? KillReason::none : (reason == KillReason::none ? KillReason::protocol_failed : reason);
  log_end(instance->number, describe_exit(classify_exit(*status, sent)));
  return true;
}

bool EngineSupervisor::schedule_restart(const std::chrono::milliseconds healthy_for, const bool reaped) {
  (void)reaped;
  const RestartDecision decision = tracker_.record_failure(healthy_for);
  if (decision.circuit_open) {
    set_state(SupervisorState::circuit_open, nullptr);
    return false;
  }
  set_state(SupervisorState::backoff, nullptr);
  // Spec §3.3: only shutdown cuts the delay short. Any other wake (a released
  // Lease, a stale report_fatal notify) sweeps and sleeps out the remainder.
  const auto restart_at = clock_->now() + decision.delay;
  for (auto remaining = decision.delay; remaining.count() > 0 && !stop_requested();
       remaining = std::chrono::ceil<std::chrono::milliseconds>(restart_at - clock_->now())) {
    if (clock_->sleep_backoff(remaining, wake_)) break;
    sweep_retired();
  }
  return true;
}

void EngineSupervisor::wait_in_circuit_open() {
  while (!stop_requested()) {
    sweep_retired();
    (void)wake_.wait(kNoMonitorHandle, std::chrono::milliseconds(-1));
  }
}

void EngineSupervisor::shutdown_generation(const std::shared_ptr<EngineInstance>& instance) {
  set_state(SupervisorState::shutting_down);
  instance->process->kill_group();
  const auto deadline = deadline_after(config_.shutdown_term_wait);
  while (!instance->process->try_reap() && remaining_until(deadline).count() > 0) std::this_thread::sleep_for(kReapPoll);
  const bool reaped = instance->process->try_reap().has_value();
  if (reaped) instance->process->release_resources(std::chrono::milliseconds(0));
  retire(instance, reaped);
}

// Takes the ended generation out of service. A reaped one waits in retired_
// for its Lease; an unreaped one is kept alive in abandoned_, since destroying
// it would wait for the child again.
void EngineSupervisor::retire(const std::shared_ptr<EngineInstance>& instance, const bool reaped) {
  std::lock_guard lock(mutex_);
  current_.reset();
  pending_kill_ = KillReason::none;
  (reaped ? retired_ : abandoned_).push_back(instance);
}

// Supervisor thread only: destroys retired generations no Lease still holds.
void EngineSupervisor::sweep_retired() {
  std::vector<std::shared_ptr<EngineInstance>> released;
  {
    std::lock_guard lock(mutex_);
    const auto still_leased = std::partition(retired_.begin(), retired_.end(),
                                             [](const std::shared_ptr<EngineInstance>& instance) { return instance.use_count() > 1; });
    released.assign(std::make_move_iterator(still_leased), std::make_move_iterator(retired_.end()));
    retired_.erase(still_leased, retired_.end());
  }
}

void EngineSupervisor::finish() {
  sweep_retired();
  set_state(SupervisorState::stopped, nullptr);
}

void EngineSupervisor::set_state(const SupervisorState state) {
  std::lock_guard lock(mutex_);
  state_ = state;
  changed_.notify_all();
}

void EngineSupervisor::set_state(const SupervisorState state, std::shared_ptr<EngineInstance> current) {
  std::lock_guard lock(mutex_);
  state_ = state;
  current_ = std::move(current);
  changed_.notify_all();
}

void EngineSupervisor::log_end(const std::uint64_t generation, const std::string_view kind) {
  log_("engine generation " + std::to_string(generation) + " ended: " + std::string(kind));
}

}  // namespace secure_frontend

// SP5 M1 Task 11 (D-9, Ruling T11-w): the supervised strata-vision role.
// The READY gate mirrors the pin (serve/server.py:2599-2612): the first stdout
// line must start with "READY"; any other line, an oversize line (the shared
// 8192-byte bound, engine_stdio_process.hpp), a closed stdout or the 300 s
// timeout ends the generation. An ended generation is killed (kVisionKillExitCode
// on Windows, Ruling T11-x), reaped, and counted by the shared RestartTracker;
// the policy (default: restart ONCE, then circuit) decides the next move.
#include "secure_frontend/vision_supervisor.hpp"

#include "secure_frontend/deadline.hpp"  // MonotonicClock

#include <algorithm>
#include <thread>
#include <utility>

namespace secure_frontend {

std::vector<std::string> compose_vision_arguments(const VisionChildSpec& spec) {
  // The pin's reader_args order (serve/server.py:2556-2568); --gpu is not typed
  // in M1; --no-flash-attn is the added spec §5.1 family flag, last.
  std::vector<std::string> args{"--mmproj", spec.mmproj, "--model", spec.model};
  if (spec.threads > 0) {
    args.emplace_back("--threads");
    args.emplace_back(std::to_string(spec.threads));
  }
  if (spec.max_tokens.has_value()) {
    args.emplace_back("--max-tokens");
    args.emplace_back(std::to_string(*spec.max_tokens));
  }
  if (spec.min_tokens.has_value()) {
    args.emplace_back("--min-tokens");
    args.emplace_back(std::to_string(*spec.min_tokens));
  }
  if (spec.no_flash_attn) args.emplace_back("--no-flash-attn");
  return args;
}

VisionSupervisor::VisionSupervisor(ProcessFactory factory, VisionLimits limits)
    : factory_(std::move(factory)), limits_(std::move(limits)), tracker_(limits_.policy) {}

VisionSupervisor::~VisionSupervisor() { stop(); }

void VisionSupervisor::start() {
  if (state_ == VisionState::up || state_ == VisionState::circuit_open) return;
  state_ = VisionState::starting;
  while (state_ == VisionState::starting) {
    ++generation_;
    auto spawned = factory_(generation_);
    if (const auto* failure = std::get_if<SpawnFailure>(&spawned)) {
      (void)failure;  // a spawn that produced no child is a generation failure (SP2 §3.3 family)
    } else {
      process_ = std::get<std::unique_ptr<SupervisedProcess>>(std::move(spawned));
      if (await_ready()) {
        state_ = VisionState::up;
        return;
      }
      if (!end_generation()) {
        state_ = VisionState::circuit_open;  // V10 family: never respawn onto an unreaped child
        return;
      }
    }
    // never became ready: healthy_for 0, so the healthy window cannot reset it
    const auto decision = tracker_.record_failure(std::chrono::milliseconds{0});
    if (decision.circuit_open) {
      state_ = VisionState::circuit_open;
      return;
    }
    std::this_thread::sleep_for(decision.delay);  // backoff on the owner thread (boot-time, single)
  }
}

bool VisionSupervisor::await_ready() {
  // Ruling T11-gg: vision.ready_timeout_s 0 means "wait for ever" — the pin's own rule
  // for STRATA_VISION_READY_S (serve/server.py:291), so the loop ends only on a line
  // or the child's end.
  const bool forever = limits_.policy.ready_timeout.count() == 0;
  const auto deadline = MonotonicClock::now() + limits_.policy.ready_timeout;
  while (forever || MonotonicClock::now() < deadline) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonotonicClock::now());
    const auto slice = forever ? std::chrono::milliseconds{250} : std::min(left, std::chrono::milliseconds{250});
    const auto read = process_->transport().read_line(slice);
    if (read.kind == EngineReadKind::line) return read.line.rfind("READY", 0) == 0;  // the FIRST line decides
    if (read.kind == EngineReadKind::timeout) {
      if (process_->try_reap().has_value()) return false;  // died while we waited
      continue;
    }
    return false;  // closed stdout, or a failed read (oversize line included)
  }
  return false;  // the READY gate (VISION_READY_S) timed out
}

bool VisionSupervisor::end_generation() {
  process_->kill_group();
  const auto deadline = MonotonicClock::now() + limits_.policy.reap_timeout;
  while (!process_->try_reap().has_value()) {
    if (MonotonicClock::now() >= deadline) return false;
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  process_->release_resources(std::chrono::milliseconds{0});
  process_.reset();
  return true;
}

void VisionSupervisor::stop() {
  if (process_ != nullptr) {
    // The pin's stop: QUIT, then the drain-else-kill shape (serve/server.py:2792).
    std::string error;
    (void)process_->transport().write_line("QUIT", MonotonicClock::now() + std::chrono::milliseconds{500}, error);
    const auto drain = MonotonicClock::now() + std::chrono::seconds{2};
    while (!process_->try_reap().has_value()) {
      if (MonotonicClock::now() >= drain) {
        process_->kill_group();
        const auto kill_deadline = MonotonicClock::now() + limits_.policy.reap_timeout;
        while (!process_->try_reap().has_value() && MonotonicClock::now() < kill_deadline) {
          std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    process_->release_resources(std::chrono::milliseconds{0});
    process_.reset();
  }
  state_ = VisionState::stopped;
}

}  // namespace secure_frontend

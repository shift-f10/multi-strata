#pragma once

#include "secure_frontend/config_defaults.hpp"
#include "secure_frontend/restart_policy.hpp"
#include "secure_frontend/supervised_process.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace secure_frontend {

// SP5 M1 Task 11 (D-9 vision split, Ruling T11-w): the supervised `strata-vision`
// encoder child. A separate role, not a second EngineSupervisor: the engine role
// is chat-protocol shaped (READY <ctx> <mode>, GEN/T/DONE, leases), while the
// pin's vision child speaks its own lifecycle — the first stdout line must start
// with "READY" (serve/server.py:2599-2612), "ENC <img> <out>" requests and
// "QUIT" to stop (:2755-2792; the request path is Task 12). The SP2 machinery
// it reuses: ProcessFactory/SupervisedProcess, RestartTracker, kill plumbing.
//
// Thread contract: one owner thread drives start()/stop()/state() (boot and
// shutdown); Task 12 adds the serving-thread request path with its own guard.

// The child's argv tail (the pin's reader_args, serve/server.py:2556-2568):
// --mmproj and --model first, then the optional --threads / --max-tokens /
// --min-tokens. --gpu is not typed for the vision child in M1 (the GPU stays
// with the owner's box, cf. Rulings T7-c/T11-ee). no_flash_attn is an added
// flag from the spec §5.1 family (not read by this pin; the kit proves it).
struct VisionChildSpec final {
  std::string mmproj;                       // the manifest's encoder artifact (absolute UTF-8)
  std::string model;                        // the weights the encoder reads (its --native)
  std::int64_t threads{0};                  // vision.threads (0: the pin's truthy skip, :2562)
  std::optional<std::int64_t> max_tokens;   // engine.max_tokens, when set (:2564-2565)
  std::optional<std::int64_t> min_tokens;   // engine.min_tokens, when set (:2566-2567)
  bool no_flash_attn{false};                // vision.no_flash_attn (added; spec §5.1)
};

[[nodiscard]] std::vector<std::string> compose_vision_arguments(const VisionChildSpec& spec);

enum class VisionState { stopped, starting, up, circuit_open };

// The SP2 restart policy on this role (plan): restart once, then circuit
// (max_consecutive_failures 2 by default), and the pin's 300 s READY gate
// (VISION_READY_S default, serve/server.py:327 — not an env knob in M1).
struct VisionLimits final {
  RestartPolicy policy{RestartPolicy{.ready_timeout = std::chrono::milliseconds{std::chrono::seconds(
                                            config_defaults::kVisionReadyTimeoutS)}}};
  VisionLimits() { policy.max_consecutive_failures = 2U; }  // the plan: restart ONCE, then circuit
};

class VisionSupervisor final {
 public:
  VisionSupervisor(ProcessFactory factory, VisionLimits limits = {});
  ~VisionSupervisor();
  VisionSupervisor(const VisionSupervisor&) = delete;
  VisionSupervisor& operator=(const VisionSupervisor&) = delete;

  // Starts generations until the READY gate opens the role, or the policy is
  // exhausted (circuit_open: the boot caller decides what that means, Ruling
  // T11-z). Blocks on the owner thread; backoff sleeps between attempts.
  void start();

  // QUITs the child (pin :2792), reaps it within the policy's bound, and kills
  // the group if it lingers. Always leaves the role stopped.
  void stop();

  [[nodiscard]] VisionState state() const noexcept { return state_; }
  [[nodiscard]] bool up() const noexcept { return state_ == VisionState::up; }
  // Spawns attempted by start(); diagnostics and test evidence.
  [[nodiscard]] std::uint64_t generations_started() const noexcept { return generation_; }

 private:
  // One attempt at the pin's READY gate; consumes lines until the first one.
  [[nodiscard]] bool await_ready();
  // Kills and bounded-reaps the ended generation; false when it stayed unreaped.
  [[nodiscard]] bool end_generation();

  ProcessFactory factory_;
  VisionLimits limits_;
  std::unique_ptr<SupervisedProcess> process_;
  RestartTracker tracker_;
  VisionState state_{VisionState::stopped};
  std::uint64_t generation_{0};
};

}  // namespace secure_frontend

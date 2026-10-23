#pragma once

// The model launcher (plan docs/superpowers/plans/2026-10-23-model-launcher.md Task 3; spec §5):
// with models.cards set, the server starts no fixed model. It holds the cards, starts the one
// models.start names (or none, D5), and lets the page start, switch and stop them (Task 4's
// routes). One model runs at a time; each start composes its own ModelRuntime (tokenizer,
// supervisor, port, gate, chat route) from the main config + the card + the option values, so a
// request validated against one model never runs on another's engine.
//
// A start (§5.2): the request is validated at once (card, option values, the card's config) and
// answered; the launcher's own thread then composes the model (the tokenizer loads) BEFORE it
// touches the running one, so a bad card never takes the running model down. Then the switch:
// new chat requests get 503 model_switching; queued ones are refused; the generation in flight
// may finish for up to 60 s (D3), then it is cut like a shutdown; the old engine is shut down;
// the state directory is prepared; the new engine starts and the launcher waits for READY. A
// start that fails stays stopped with a fixed reason (D4). Starts and stops are logged.

#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/api_router.hpp"
#include "secure_frontend/engine_supervisor.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/generation_gate.hpp"
#include "secure_frontend/json.hpp"
#include "secure_frontend/model_cards.hpp"
#include "secure_frontend/model_options.hpp"
#include "secure_frontend/model_runtime.hpp"
#include "secure_frontend/request_router.hpp"
#include "secure_frontend/serve_monitor.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace secure_frontend {

// The cards one launcher holds: the listed ones (kMaxModelCards) and the cards prepared
// downloads add (model downloads, plan 2026-10-23-model-downloads Task 4).
inline constexpr std::size_t kMaxLauncherCards = 64;

enum class CardState { stopped, starting, running, failed };
[[nodiscard]] std::string_view card_state_name(CardState state) noexcept;

struct LauncherSettings final {
  FrontendConfigDraft main;                         // the main config (main_config_card_issues is empty)
  std::vector<ModelCard> cards;                     // the loaded cards (load_model_cards)
  std::optional<std::filesystem::path> memory_file; // D7: the remembered options (nullopt: none kept)
  GateLimits gate;                                  // each runtime's generation gate
  ServeMonitor* monitor{nullptr};                   // listener.monitor; told about each generation
  std::chrono::milliseconds drain_wait{std::chrono::seconds(60)};  // D3: the generation in flight may finish
  std::chrono::milliseconds cut_wait{std::chrono::seconds(15)};    // ... then it is cut and given this long
  std::chrono::milliseconds stop_bound{config_defaults::kShutdownBound};  // one supervisor's orderly shutdown
  // How a start's engine processes are made (production: make_stdio_process_factory).
  std::function<ProcessFactory(EngineLaunchPlan)> factory{};
  // One fixed line per start, stop and outcome (default: stderr).
  std::function<void(std::string_view)> log{};
};

class ModelLauncher final {
 public:
  explicit ModelLauncher(LauncherSettings settings);
  ~ModelLauncher();
  ModelLauncher(const ModelLauncher&) = delete;
  ModelLauncher& operator=(const ModelLauncher&) = delete;

  // A refusal of start/stop: the API error row and, for invalid_option, the option's name.
  struct Refusal final {
    ApiError error;
    std::string param{};
  };
  // Validates and accepts a start of card `name` with `options` (the body's "options" object;
  // nullptr = the remembered values, else the card's defaults). nullopt: accepted (202).
  [[nodiscard]] std::optional<Refusal> start(std::string_view name, const JsonValue* options, bool remote_client);
  // Stops the running model (or the one starting, once its start is done). nullopt: accepted.
  [[nodiscard]] std::optional<Refusal> stop(bool remote_client);
  // A card made while the server runs (a prepared download's): listed at once, stopped. false:
  // a card of that name is already held, or kMaxLauncherCards are.
  [[nodiscard]] bool add_card(ModelCard card);

  // GET /v1/strata/models (the plan's JSON shape).
  [[nodiscard]] std::string list_json() const;
  // /v1/models: the running model's id and aliases (none while nothing runs or a switch is on).
  [[nodiscard]] ServedModels served() const;
  // POST /v1/chat/completions in launcher mode.
  [[nodiscard]] RouteResult chat(std::string_view body, const RequestContext& context);
  // GET /health: the running model's engine, "starting" while a start or switch runs, "none"
  // when nothing runs.
  [[nodiscard]] HealthView health() const;
  // GET /metrics: the Monitor's JSON for the running model.
  [[nodiscard]] std::string metrics_json() const;

  // The pool's shutdown hook: no more starts; every runtime's generation ends like a shutdown.
  void begin_shutdown() noexcept;
  // Joins the launcher's thread and shuts the running model's supervisor down.
  void shutdown();
  // After shutdown(): a supervisor left an engine it could not reap (spec C4: exit 1).
  [[nodiscard]] bool engine_left_unreaped() const noexcept;

  // Test seams: wait until no start or stop is running; the card's state.
  [[nodiscard]] bool wait_until_settled(std::chrono::milliseconds timeout) const;
  [[nodiscard]] CardState state_of(std::string_view name) const;

 private:
  struct CardStatus final {
    CardState state{CardState::stopped};
    std::string_view error{};  // a fixed reason; empty unless failed
  };
  struct Job final {
    enum class Kind { start, stop } kind{Kind::start};
    std::size_t card{0};
    ModelOptionValues values{};
    std::shared_ptr<const FrontendConfig> config{};
  };
  void run_jobs();
  void run_start(const Job& job);
  void retire_running(std::unique_lock<std::mutex>& lock);
  void remember(std::size_t card, const ModelOptionValues& values);
  // Under mutex_: add_card appends to settings_.cards (reserved to kMaxLauncherCards, so a held
  // card reference stays valid), and every lookup or walk of the list holds the lock.
  [[nodiscard]] std::optional<std::size_t> find_card(std::string_view name) const;
  [[nodiscard]] std::shared_ptr<ModelRuntime> running_runtime() const;
  void log(std::string_view line) const;

  LauncherSettings settings_;
  RememberedOptions remembered_;
  mutable std::mutex mutex_;
  mutable std::condition_variable changed_;
  std::vector<CardStatus> status_;
  std::shared_ptr<ModelRuntime> running_;     // the started (or starting) model's runtime
  std::optional<std::size_t> running_card_;   // which card it is
  std::optional<std::size_t> starting_card_;  // the card an accepted start is bringing up
  bool busy_{false};                          // a start or stop is accepted and not finished
  bool switching_{false};                     // chat is refused: the old model is being retired or the new one loads
  bool shutting_down_{false};
  bool unreaped_{false};
  std::optional<Job> pending_;
  std::thread worker_;
};

}  // namespace secure_frontend

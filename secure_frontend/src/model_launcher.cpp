#include "secure_frontend/model_launcher.hpp"

#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/config_file.hpp"
#include "secure_frontend/engine_stdio_process.hpp"
#include "secure_frontend/launch_composition.hpp"
#include "secure_frontend/token_store.hpp"

#include <algorithm>
#include <charconv>
#include <iostream>
#include <utility>
#include <variant>

namespace secure_frontend {
namespace {

// The fixed reasons a card's state may carry (the page shows them; the log has the detail).
constexpr std::string_view kStateDirFailed = "the state directory could not be prepared";
constexpr std::string_view kSupervisorFailed = "the engine supervisor could not start";
constexpr std::string_view kEndedBeforeReady = "the engine ended before it was ready (see the server log)";
constexpr std::string_view kExhausted = "the engine stopped after repeated failures (see the server log)";

// A chat body already passed the chat route's own reader; this one only finds its "model".
constexpr JsonLimits kModelFieldLimits{.max_bytes = 16U * 1024U * 1024U, .max_depth = 64U, .max_container_entries = 1U << 20U,
                                       .max_string_bytes = 16U * 1024U * 1024U, .allow_fractions = true};

std::string value_text(const ModelOptionValue& value) {
  if (const auto* b = std::get_if<bool>(&value)) return *b ? "true" : "false";
  if (const auto* i = std::get_if<std::int64_t>(&value)) return std::to_string(*i);
  if (const auto* d = std::get_if<double>(&value)) {
    char buffer[32];
    const auto [end, error] = std::to_chars(buffer, buffer + sizeof(buffer), *d);
    return error == std::errc{} ? std::string{buffer, end} : std::string{"?"};
  }
  return std::get<std::string>(value);
}

std::string json_string(const std::string_view text) {
  std::string out;
  append_json_string(&out, text);
  return out;
}

// The option an issue names ("options.kv" -> "kv"), when it is an option name.
std::string option_of(const ConfigErrors& errors) {
  constexpr std::string_view kPrefix = "options.";
  for (const auto& issue : errors) {
    if (issue.key_path.rfind(kPrefix, 0) != 0) continue;
    std::string name = issue.key_path.substr(kPrefix.size());
    if (const auto dot = name.find('.'); dot != std::string::npos) name.resize(dot);
    if (is_model_option_name(name)) return name;
  }
  return {};
}

}  // namespace

std::string_view card_state_name(const CardState state) noexcept {
  switch (state) {
    case CardState::stopped: return "stopped";
    case CardState::starting: return "starting";
    case CardState::running: return "running";
    case CardState::failed: return "failed";
  }
  return "stopped";  // unreachable: every value is a case above
}

ModelLauncher::ModelLauncher(LauncherSettings settings) : settings_(std::move(settings)) {
  // add_card never reallocates: a start holds its card by reference outside the lock.
  if (settings_.cards.size() > kMaxLauncherCards) settings_.cards.resize(kMaxLauncherCards);
  settings_.cards.reserve(kMaxLauncherCards);
  status_.resize(settings_.cards.size());
  status_.reserve(kMaxLauncherCards);
  if (!settings_.factory) {
    settings_.factory = [](EngineLaunchPlan plan) { return make_stdio_process_factory(std::move(plan)); };
  }
  if (settings_.memory_file.has_value()) {
    auto text = read_trusted_config_text(*settings_.memory_file);
    if (const auto* read = std::get_if<TrustedConfigText>(&text)) remembered_ = parse_remembered_options(read->text);
  }
  worker_ = std::thread([this] { run_jobs(); });
}

ModelLauncher::~ModelLauncher() { shutdown(); }

bool ModelLauncher::add_card(ModelCard card) {
  std::string name = card.name;
  {
    std::lock_guard lock(mutex_);
    if (shutting_down_ || find_card(card.name).has_value() || settings_.cards.size() >= kMaxLauncherCards) return false;
    settings_.cards.push_back(std::move(card));
    status_.emplace_back();
  }
  log("[strata] models: added " + name);
  return true;
}

void ModelLauncher::log(const std::string_view line) const {
  if (settings_.log) {
    settings_.log(line);
    return;
  }
  std::cerr << line << '\n' << std::flush;
}

std::optional<std::size_t> ModelLauncher::find_card(const std::string_view name) const {
  for (std::size_t i = 0; i < settings_.cards.size(); ++i) {
    if (settings_.cards[i].name == name) return i;
  }
  return std::nullopt;
}

std::optional<ModelLauncher::Refusal> ModelLauncher::start(const std::string_view name, const JsonValue* options,
                                                           const bool remote_client) {
  std::optional<std::size_t> card;
  const ModelCard* chosen_card = nullptr;
  {
    std::lock_guard lock(mutex_);
    card = find_card(name);
    if (shutting_down_) return Refusal{ApiError::server_shutting_down};
    if (busy_ || pending_.has_value()) return Refusal{ApiError::switch_in_progress};
    if (!card.has_value()) return Refusal{ApiError::model_not_found};
    busy_ = true;  // reserved: one start or stop at a time
    chosen_card = &settings_.cards[*card];
  }
  const auto release = [this] {
    std::lock_guard lock(mutex_);
    busy_ = false;
    changed_.notify_all();
  };
  const ModelCard& chosen = *chosen_card;
  ModelOptionValues remembered;
  {
    std::lock_guard lock(mutex_);
    if (const auto found = remembered_.find(chosen.name); found != remembered_.end()) remembered = found->second;
  }
  auto values = resolve_option_values(chosen.options, options, remembered);
  if (const auto* issues = std::get_if<ConfigErrors>(&values)) {
    release();
    return Refusal{ApiError::invalid_option, option_of(*issues)};
  }
  auto validated = card_config(settings_.main, chosen, std::get<ModelOptionValues>(values));
  if (const auto* issues = std::get_if<ConfigErrors>(&validated)) {
    for (const auto& issue : *issues) log("[strata] models: " + chosen.name + ": " + format_issue(issue));
    release();
    return Refusal{ApiError::invalid_request};
  }
  auto config = std::get<ValidatedConfig>(validated).shared();
  if (const auto issues = launch_config_issues(*config, true); !issues.empty()) {
    for (const auto& issue : issues) log("[strata] models: " + chosen.name + ": " + issue);
    release();
    return Refusal{ApiError::invalid_request};
  }
  std::string line = "[strata] models: start " + chosen.name;
  for (const auto& [option, value] : std::get<ModelOptionValues>(values)) line += " " + option + "=" + value_text(value);
  line += remote_client ? " (remote client)" : " (loopback client)";
  log(line);
  {
    std::lock_guard lock(mutex_);
    status_[*card] = CardStatus{CardState::starting, {}};
    starting_card_ = *card;
    pending_ = Job{Job::Kind::start, *card, std::move(std::get<ModelOptionValues>(values)), std::move(config)};
  }
  changed_.notify_all();
  return std::nullopt;
}

std::optional<ModelLauncher::Refusal> ModelLauncher::stop(const bool remote_client) {
  {
    std::lock_guard lock(mutex_);
    if (shutting_down_) return Refusal{ApiError::server_shutting_down};
    if (busy_ || pending_.has_value()) return Refusal{ApiError::switch_in_progress};
    if (running_ == nullptr) return std::nullopt;  // nothing runs: already stopped
    busy_ = true;
    switching_ = true;
    pending_ = Job{Job::Kind::stop, running_card_.value_or(0U), {}, {}};
  }
  log(std::string{"[strata] models: stop"} + (remote_client ? " (remote client)" : " (loopback client)"));
  changed_.notify_all();
  return std::nullopt;
}

void ModelLauncher::run_jobs() {
  for (;;) {
    Job job;
    {
      std::unique_lock lock(mutex_);
      changed_.wait(lock, [this] { return pending_.has_value() || shutting_down_; });
      if (shutting_down_) return;
      job = std::move(*pending_);
      pending_.reset();
    }
    if (job.kind == Job::Kind::start) {
      run_start(job);
    } else {
      std::unique_lock lock(mutex_);
      retire_running(lock);
    }
    std::lock_guard lock(mutex_);
    busy_ = false;
    switching_ = false;
    starting_card_.reset();
    changed_.notify_all();
  }
}

// D3: queued requests are refused, the generation in flight may finish for drain_wait, then
// it is cut (its stop flag ends it like a shutdown) and given cut_wait; then the supervisor
// shuts the engine down. Requests still holding the runtime keep it alive until they end.
void ModelLauncher::retire_running(std::unique_lock<std::mutex>& lock) {
  if (running_ == nullptr) return;
  std::shared_ptr<ModelRuntime> old = running_;
  const std::size_t card = running_card_.value_or(0U);
  lock.unlock();
  old->mark_retiring();
  old->gate().shutdown();
  const auto wait_idle = [&old](const std::chrono::milliseconds bound) {
    const auto until = std::chrono::steady_clock::now() + bound;
    while (old->in_flight() > 0U && std::chrono::steady_clock::now() < until) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return old->in_flight() == 0U;
  };
  if (!wait_idle(settings_.drain_wait)) {
    log("[strata] models: the generation in flight is cut for the switch");
    old->raise_stop();
    (void)wait_idle(settings_.cut_wait);
  }
  old->supervisor().shutdown(settings_.stop_bound);
  const bool unreaped = old->supervisor().engine_left_unreaped();
  lock.lock();
  if (unreaped) unreaped_ = true;
  running_.reset();
  running_card_.reset();
  status_[card] = CardStatus{CardState::stopped, {}};
  const std::string name = settings_.cards[card].name;
  lock.unlock();
  log("[strata] models: stopped " + name);
  lock.lock();
}

void ModelLauncher::run_start(const Job& job) {
  const ModelCard& card = [this, &job]() -> const ModelCard& {
    std::lock_guard lock(mutex_);
    return settings_.cards[job.card];
  }();
  const auto fail = [this, &job, &card](const std::string_view reason) {
    {
      std::lock_guard lock(mutex_);
      status_[job.card] = CardStatus{CardState::failed, reason};
    }
    log("[strata] models: " + card.name + " failed: " + std::string{reason});
  };
  // §5.2 step 2: compose (the tokenizer loads) before the running model is touched.
  auto composed = compose_model(*job.config, true);
  if (auto* failure = std::get_if<ComposeFailure>(&composed)) {
    for (const auto& message : failure->messages) log("[strata] models: " + card.name + ": " + message);
    fail(failure->reason);
    return;
  }
  auto& model = std::get<ComposedModel>(composed);
  {
    // §5.2 step 3: from here chat is refused until the new model is ready (or failed).
    std::unique_lock lock(mutex_);
    switching_ = true;
    retire_running(lock);
    if (shutting_down_) {
      status_[job.card] = CardStatus{};
      return;
    }
    // A restart of the running card: retiring it marked it stopped; it is starting again.
    status_[job.card] = CardStatus{CardState::starting, {}};
  }
  if (!prepare_state_dir(*job.config->roots.state, *model.plan.environment)) {
    fail(kStateDirFailed);
    return;
  }
  EngineLaunchPlan plan = std::move(model.plan);
  // The Monitor's engine readings belong to the engine that ran before.
  if (settings_.monitor != nullptr) settings_.monitor->engine_changed();
  auto runtime = std::make_shared<ModelRuntime>(std::move(model), settings_.factory(std::move(plan)), settings_.gate, settings_.monitor);
  if (!runtime->supervisor().start()) {
    fail(kSupervisorFailed);
    return;
  }
  {
    std::lock_guard lock(mutex_);
    running_ = runtime;
    running_card_ = job.card;
  }
  // READY, or the first end before it (D4: no retry loop for a start that cannot load).
  bool ready = false;
  for (;;) {
    {
      std::lock_guard lock(mutex_);
      if (shutting_down_) break;
    }
    const auto snapshot = runtime->supervisor().snapshot();
    if (snapshot.state == SupervisorState::ready || snapshot.state == SupervisorState::generating) {
      ready = true;
      break;
    }
    if (snapshot.state != SupervisorState::starting || runtime->supervisor().generations_started() > 1U) break;
    (void)runtime->supervisor().wait_for_change(SupervisorState::starting, std::chrono::milliseconds(200));
  }
  if (!ready) {
    runtime->supervisor().shutdown(settings_.stop_bound);
    std::lock_guard lock(mutex_);
    if (runtime->supervisor().engine_left_unreaped()) unreaped_ = true;
    running_.reset();
    running_card_.reset();
    if (shutting_down_) {
      status_[job.card] = CardStatus{};
      return;
    }
  }
  if (!ready) {
    fail(kEndedBeforeReady);
    return;
  }
  {
    std::lock_guard lock(mutex_);
    status_[job.card] = CardStatus{CardState::running, {}};
  }
  log("[strata] models: " + card.name + " is running");
  remember(job.card, job.values);
}

void ModelLauncher::remember(const std::size_t card, const ModelOptionValues& values) {
  std::string text;
  {
    std::lock_guard lock(mutex_);
    remembered_[settings_.cards[card].name] = values;
    text = render_remembered_options(remembered_);
  }
  if (!settings_.memory_file.has_value()) return;
  const auto& file = *settings_.memory_file;
  auto root = open_root(file.parent_path());
  const auto name = parse_relative_path(path_to_utf8(file.filename()));
  if (!std::holds_alternative<CanonicalRoot>(root) || !std::holds_alternative<RelativePath>(name) ||
      write_private_file(std::get<CanonicalRoot>(root), std::get<RelativePath>(name), text, TokenStoreMode::replace).has_value()) {
    log("[strata] models: the page's options could not be remembered (the state directory refused the file)");
  }
}

std::shared_ptr<ModelRuntime> ModelLauncher::running_runtime() const {
  std::lock_guard lock(mutex_);
  return switching_ ? nullptr : running_;
}

std::string ModelLauncher::list_json() const {
  std::lock_guard lock(mutex_);
  const auto state_of_card = [this](const std::size_t i) -> CardStatus {
    CardStatus status = status_[i];
    // A running model whose engine kept failing: the supervisor's circuit is open.
    if (status.state == CardState::running && running_card_ == i && running_ != nullptr &&
        running_->supervisor().snapshot().state == SupervisorState::circuit_open) {
      status = CardStatus{CardState::failed, kExhausted};
    }
    return status;
  };
  std::string out = "{\"object\":\"list\",\"running\":";
  const bool runs = running_card_.has_value() && !switching_;
  out += runs ? json_string(settings_.cards[*running_card_].name) : std::string{"null"};
  std::string_view top = switching_ || busy_ ? "starting" : "stopped";
  std::string_view top_error;
  if (runs) {
    const CardStatus status = state_of_card(*running_card_);
    top = card_state_name(status.state);
    top_error = status.error;
  }
  out += ",\"state\":" + json_string(top) + ",\"error\":" + (top_error.empty() ? std::string{"null"} : json_string(top_error));
  out += ",\"data\":[";
  for (std::size_t i = 0; i < settings_.cards.size(); ++i) {
    const ModelCard& card = settings_.cards[i];
    const CardStatus status = state_of_card(i);
    ModelOptionValues values;
    if (const auto found = remembered_.find(card.name); found != remembered_.end()) values = found->second;
    if (i != 0U) out += ',';
    out += "{\"name\":" + json_string(card.name) + ",\"profile\":" + json_string(profile_name(card.profile)) +
           ",\"state\":" + json_string(card_state_name(status.state)) +
           ",\"error\":" + (status.error.empty() ? std::string{"null"} : json_string(status.error)) +
           ",\"options\":" + describe_options_json(card.options, values) + "}";
  }
  out += "]}\n";
  return out;
}

ServedModels ModelLauncher::served() const {
  std::lock_guard lock(mutex_);
  ServedModels served;
  std::string extension = "[";
  for (std::size_t i = 0; i < settings_.cards.size(); ++i) {
    if (i != 0U) extension += ',';
    extension += "{\"id\":" + json_string(settings_.cards[i].name) +
                 ",\"state\":" + json_string(card_state_name(status_[i].state)) + "}";
  }
  served.extension = extension + "]";
  if (running_ != nullptr && !switching_ && running_card_.has_value() && status_[*running_card_].state == CardState::running) {
    served.id = running_->model_id();
    served.aliases = running_->aliases();
  }
  return served;
}

RouteResult ModelLauncher::chat(const std::string_view body, const RequestContext& context) {
  std::shared_ptr<ModelRuntime> runtime;
  {
    std::lock_guard lock(mutex_);
    if (shutting_down_) return make_error_response(ApiError::server_shutting_down);
    // A start with nothing running yet counts as a switch: the model is on its way.
    if (switching_ || (running_ == nullptr && busy_)) return make_error_response(ApiError::model_switching);
    if (running_ == nullptr) return make_error_response(ApiError::no_model_running);
    runtime = running_;
  }
  // The request holds the runtime until its response or stream ends; the switch waits on it.
  struct InFlight final {
    std::shared_ptr<ModelRuntime> runtime;
    explicit InFlight(std::shared_ptr<ModelRuntime> held) : runtime(std::move(held)) { runtime->enter(); }
    ~InFlight() { runtime->leave(); }
    InFlight(const InFlight&) = delete;
    InFlight& operator=(const InFlight&) = delete;
  };
  auto held = std::make_shared<InFlight>(runtime);
  const RequestContext inner{.client_gone = context.client_gone, .shutting_down = runtime->stop_flag(),
                             .loopback_peer = context.loopback_peer};
  RouteResult result = runtime->chat().handle(body, inner);
  if (auto* stream = std::get_if<StreamHandler>(&result)) {
    return StreamHandler{[handler = std::move(*stream), held](StreamSink& sink) { handler(sink); }};
  }
  auto& response = std::get<HttpResponse>(result);
  // A request the switch refused from the old model's queue, or cut (D3), was not refused by a
  // shutdown: it is told the server is switching models.
  if (response.log_code == "server_shutting_down" && runtime->retiring()) {
    std::lock_guard lock(mutex_);
    if (!shutting_down_) return make_error_response(ApiError::model_switching);
  }
  // D6: a request naming another card is told that card is not running.
  if (response.log_code == "model_not_found") {
    const auto parsed = parse_json(body, kModelFieldLimits);
    if (const auto* root = std::get_if<JsonValue>(&parsed); root != nullptr && root->if_object() != nullptr) {
      for (const auto& member : *root->if_object()) {
        if (member.key != "model" || member.value.if_string() == nullptr) continue;
        std::lock_guard lock(mutex_);
        const auto named = find_card(*member.value.if_string());
        if (!named.has_value()) continue;
        // The card an accepted start is bringing up is on its way, not stopped.
        if (starting_card_ == named) return make_error_response(ApiError::model_switching);
        return make_error_response(ApiError::model_not_running);
      }
    }
  }
  return result;
}

HealthView ModelLauncher::health() const {
  std::shared_ptr<ModelRuntime> runtime;
  {
    std::lock_guard lock(mutex_);
    if (switching_ || (running_ == nullptr && busy_)) return HealthView{false, "starting", ""};
    if (running_ == nullptr) return HealthView{true, "none", ""};
    runtime = running_;
  }
  const auto snapshot = runtime->port().snapshot();
  return HealthView{snapshot.healthy, snapshot.engine, snapshot.recovery};
}

std::string ModelLauncher::metrics_json() const {
  if (settings_.monitor == nullptr) return "{}\n";
  const auto runtime = running_runtime();
  if (runtime == nullptr) {
    std::lock_guard lock(mutex_);
    return settings_.monitor->render_json({.model = "", .engine = switching_ || busy_ ? "starting" : "none", .queued = 0U});
  }
  return settings_.monitor->render_json(
      {.model = runtime->model_id(), .engine = runtime->port().snapshot().engine, .queued = runtime->gate().waiting()});
}

void ModelLauncher::begin_shutdown() noexcept {
  {
    std::lock_guard lock(mutex_);
    shutting_down_ = true;
    if (running_ != nullptr) {
      running_->raise_stop();
      running_->gate().shutdown();
    }
  }
  changed_.notify_all();
}

void ModelLauncher::shutdown() {
  begin_shutdown();
  if (worker_.joinable()) worker_.join();
  std::shared_ptr<ModelRuntime> runtime;
  {
    std::lock_guard lock(mutex_);
    runtime = std::move(running_);
    running_card_.reset();
  }
  if (runtime == nullptr) return;
  runtime->supervisor().shutdown(settings_.stop_bound);
  if (runtime->supervisor().engine_left_unreaped()) {
    std::lock_guard lock(mutex_);
    unreaped_ = true;
  }
}

bool ModelLauncher::engine_left_unreaped() const noexcept {
  std::lock_guard lock(mutex_);
  return unreaped_;
}

bool ModelLauncher::wait_until_settled(const std::chrono::milliseconds timeout) const {
  std::unique_lock lock(mutex_);
  return changed_.wait_for(lock, timeout, [this] { return !busy_ && !pending_.has_value(); });
}

CardState ModelLauncher::state_of(const std::string_view name) const {
  std::lock_guard lock(mutex_);
  const auto card = find_card(name);
  return card.has_value() ? status_[*card].state : CardState::stopped;
}

}  // namespace secure_frontend

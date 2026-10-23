// SP5 M1 Task 13 (Ruling T13-b): the supervised serve path moved VERBATIM out of
// secure_server_main.cpp — the same code strata-secure-server runs and the code
// `strata serve` runs. This file parses no command line and installs no daemon:
// foreground boot, pinned order, SP3 I1 shutdown (see server_bootstrap.hpp).

#include "secure_frontend/server_bootstrap.hpp"
#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/api_router.hpp"
#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_route.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/connection_pool.hpp"
#include "secure_frontend/crt_environment.hpp"
#include "secure_frontend/download_catalog.hpp"
#include "secure_frontend/download_manager.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/engine_environment.hpp"
#include "secure_frontend/engine_stdio_process.hpp"
#include "secure_frontend/engine_supervisor.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/generation_gate.hpp"
#include "secure_frontend/host_readings.hpp"
#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/image_payload.hpp"
#include "secure_frontend/launch_composition.hpp"
#include "secure_frontend/model_cards.hpp"
#include "secure_frontend/model_launcher.hpp"
#include "secure_frontend/model_runtime.hpp"
#include "secure_frontend/privilege_check.hpp"
#include "secure_frontend/process_defaults.hpp"
#include "secure_frontend/request_log.hpp"
#include "secure_frontend/serve_monitor.hpp"
#include "secure_frontend/shutdown_signal.hpp"
#include "secure_frontend/subsystem_limits.hpp"
#include "secure_frontend/test_hooks.hpp"
#include "secure_frontend/token_store.hpp"
#include "secure_frontend/token_reader.hpp"
#include "secure_frontend/token_verifier.hpp"
#include "secure_frontend/tokenizer_pack.hpp"
#include "secure_frontend/vision_supervisor.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace {


using secure_frontend::EngineProfile;
using secure_frontend::FrontendConfig;

std::string host_header(const secure_frontend::Config& config) {
  const bool ipv6 = config.host.find(':') != std::string::npos;
  return (ipv6 ? "[" + config.host + "]" : config.host) + ":" + std::to_string(config.port);
}

secure_frontend::TokenReadResult read_configured_token(const FrontendConfig& config) {
  if (config.roots.secret.has_value()) return secure_frontend::read_token(config.token, *config.roots.secret);
  return secure_frontend::read_token(config.token, std::filesystem::path{"."});
}

int server_check_impl(const FrontendConfig& config, const std::vector<std::string>& overridden, const bool expert) {
  std::cout << secure_frontend::describe(config);
  for (const auto& key : overridden) std::cout << key << ": the command line overrides the config file\n";
  std::cout.flush();
  // SP4 §4.9 c/d (F-8): the launch-related config errors serve would refuse, for
  // the same mode (managed, or --expert). Pure: roots.models is not read.
  if (const auto issues = secure_frontend::launch_config_issues(config, expert); !issues.empty()) {
    for (const auto& issue : issues) std::cerr << "Configuration error: " << issue << '\n';
    return EXIT_FAILURE;
  }
  if (config.listener.loopback_without_key) {
    std::cout << "token: not used (listener.loopback_without_key: loopback only)\nConfiguration is valid.\n";
    return EXIT_SUCCESS;
  }
  // The verdict follows the token read: a configuration whose token cannot be
  // read is not reported valid first.
  const auto token = read_configured_token(config);
  if (const auto* error = std::get_if<secure_frontend::TokenReadError>(&token)) {
    std::cerr << "token: unavailable: " << error->message << '\n'
              << "Configuration is not usable: the API token cannot be read.\n";
    return EXIT_FAILURE;
  }
  std::cout << "token: available (value not shown)\nConfiguration is valid.\n";
  return EXIT_SUCCESS;
}

// roots.state (--state-dir) holds the engine's cwd, temp and CUDA cache (spec
// §3.9, §3.12). validate() only checked that it is absolute (--check stays
// side-effect free); serve refuses, before anything is created, bound or
// spawned, unless it is an existing owner-only directory.
bool state_dir_is_usable(const FrontendConfig& config) {
  if (!config.roots.state) {
    std::cerr << "roots.state (--state-dir) is required to serve.\n";
    return false;
  }
  // POSIX: lstat -- a real directory, not a symlink, owned by the effective
  // uid, no group/other bits. Windows: opened without following a junction or
  // symlink (refused), owner the current user, protected DACL with allow-ACEs
  // only for the user, SYSTEM and Administrators (is_private_state_root).
  const bool owner_only = secure_frontend::is_private_state_root(*config.roots.state);
  if (!owner_only) {
    std::cerr << "--state-dir must be an existing owner-only directory.\n";
    return false;
  }
  return true;
}

// listener.monitor (session log step 16): this machine's readings once a second; the GPU's
// through the system's nvidia-smi, its own child (no shell, ProgramFiles alone, the Job),
// started after bind like every child and stopped (before the supervisor) on every way out.
struct HostSampler final {
  secure_frontend::ServeMonitor* monitor{nullptr};
  secure_frontend::GpuSampler gpu;
  std::atomic<bool> stopping{false};
  std::thread thread;
  void start(secure_frontend::ServeMonitor& target) {
    monitor = &target;
    gpu.start({.executable = secure_frontend::nvidia_smi_path(), .arguments = secure_frontend::nvidia_smi_arguments(),
               .environment = secure_frontend::nvidia_smi_environment(), .no_new_privileges = true, .insert_serve = false});
    thread = std::thread([this] {
      secure_frontend::CpuMeter cpu;
      while (!stopping.load()) {
        secure_frontend::HostSample sample;
        sample.cpu_percent = cpu.sample();
        sample.memory = secure_frontend::read_memory();
        sample.gpu = gpu.latest();
        if (!sample.gpu.has_value()) sample.gpu_note = gpu.note();
        monitor->add_host_sample(sample);
        for (int slice = 0; slice < 10 && !stopping.load(); ++slice) std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    });
  }
  ~HostSampler() {
    stopping = true;
    if (thread.joinable()) thread.join();
    gpu.stop();
  }
};

int server_run_impl(const FrontendConfig& config, const bool expert) {
  // Ruling T13-c: server-grade process defaults, also when serve arrives
  // through the strata CLI (install_process_defaults is idempotent).
  secure_frontend::install_process_defaults();
  if (!state_dir_is_usable(config)) return EXIT_FAILURE;
  // roots.logs / roots.cache: validate() only checked them, so --check stays
  // side-effect free; serve creates a missing one here, before bind or spawn.
  if (const auto issues = secure_frontend::create_runtime_roots(config); !issues.empty()) {
    for (const auto& issue : issues) std::cerr << "Configuration error: " << secure_frontend::format_issue(issue) << '\n';
    return EXIT_FAILURE;
  }
  // Every reason below is fixed text (plus, for the inventory, an entry name
  // below roots.models, spec §6.1): never a token or a configured value.
  // listener.loopback_without_key (owner decision 2026-10-21): no key is read at all; load
  // refused a token.source next to it, and bind re-checks that the listener is loopback.
  const bool keyless = config.listener.loopback_without_key;
  secure_frontend::BearerTokenValidator validator;
  if (!keyless) {
    auto token_result = read_configured_token(config);
    auto* token = std::get_if<secure_frontend::SecretBytes>(&token_result);
    if (token == nullptr) {
      std::cerr << "Unable to read API token: " << std::get<secure_frontend::TokenReadError>(token_result).message << '\n';
      return EXIT_FAILURE;
    }
    validator = secure_frontend::make_bearer_validator(std::make_shared<const secure_frontend::TokenVerifier>(std::move(*token)));
  }

  const secure_frontend::Config listener = secure_frontend::listener_config(config);
  // Model launcher plan 2026-10-23 Task 3: the per-model half of the boot (compose, the
  // tokenizer pack, the served name and aliases, the effort tail, the supervisor config, the
  // closed environment and the launch plan, the chat route's settings) is compose_model() in
  // model_runtime.cpp, which the launcher shares. Its comments moved with it.
  auto composed_result = secure_frontend::compose_model(config, expert);
  if (auto* failure = std::get_if<secure_frontend::ComposeFailure>(&composed_result)) {
    for (const auto& message : failure->messages) std::cerr << message << '\n';
    return failure->exit_code;
  }
  auto& model = std::get<secure_frontend::ComposedModel>(composed_result);
  const auto& launch = model.launch;
  const std::string& model_id = model.model_id;
  const secure_frontend::SupervisorConfig& supervisor_config = model.supervisor;
  const std::filesystem::path& state_dir = *config.roots.state;
  if (!secure_frontend::prepare_state_dir(state_dir, *model.plan.environment)) {
    std::cerr << "Unable to prepare the state or cache directory.\n";
    return EXIT_FAILURE;
  }
  // The supervisor thread spawns, watches and restarts the engine (spec §3.1).
  // Declared before the listener and the router, so it outlives both; a Lease
  // lives only inside one ChatRoute::handle call.
  secure_frontend::EngineSupervisor supervisor(supervisor_config, secure_frontend::make_stdio_process_factory(std::move(model.plan)));

  const std::string authority = host_header(listener);  // the startup line only
  // SP3 Task 16 (spec §2.2, §2.5): SupervisorPort serializes the frontend's
  // snapshot/acquire/report_fatal into SP2 (D-1); GenerationGate holds the
  // single generation slot with a FIFO queue; ChatRoute validates (P4) before a
  // queue place is taken and runs the generation through the lease (P6).
  // Declaration order here — supervisor, port, gate, chat route, then router,
  // server, pool — keeps every object a pool worker touches alive until the
  // pool is joined.
  secure_frontend::SupervisorPort port(supervisor);
  secure_frontend::GenerationGate gate({.max_queued = config.limits.concurrency.max_queued_generations,
                                        .queue_timeout = config.limits.concurrency.queue_timeout});
  // SP5 M1 Task 11 (D-9 vision split; Rulings T11-y/T11-ee/T11-z) and Task 12 (C-9):
  // the supervised maya-vision child and the route's encoder service. Construction
  // spawns nothing — the resident start below runs only after bind, so a listener that
  // cannot bind still never leaves an encoder child behind (CFG-01 family). The exe is
  // OUR distribution's — maya-vision beside the engine executable (the pin's
  // vision-exe-from-config stays kRejected, spec §4); the mmproj artifact and the
  // weights come from compose (the manifest's launch.mmproj).
  std::optional<secure_frontend::VisionSupervisor> vision;
  std::optional<secure_frontend::VisionService> vision_service;
  if (config.vision.enabled) {
    if (!launch.vision_mmproj.has_value() || !launch.vision_model.has_value()) {  // compose guards; fail closed twice
      std::cerr << "vision: this model declares no mmproj artifact.\n";
      return EXIT_FAILURE;
    }
    // Ruling T12-j: ENC/QUIT names ride protocol lines space-separated, and the GENI
    // line names the combined file by absolute path — the pin's own #480 shows names
    // with spaces corrupt that split. A state path holding whitespace can never host
    // the scratch dir: boot fails closed instead of corrupting the protocol.
    if (state_dir.string().find_first_of(" \t") != std::string::npos) {
      std::cerr << "vision: the state directory path must not contain spaces.\n";
      return EXIT_FAILURE;
    }
    // Ruling T12-c: image scratch is <state>/vision, owner-only, and IS the child's
    // cwd — every ENC/QUIT name is relative to it, as at the pin (#480 again).
    const std::filesystem::path vision_scratch = state_dir / "vision";
    if (!secure_frontend::create_owner_only_directory(vision_scratch)) {
      std::cerr << "vision: unable to prepare the image scratch directory.\n";
      return EXIT_FAILURE;
    }
    // SP5-P2 Task 6 (issue 27): the engine distribution's vision encoder is named
    // `maya-vision` at 451f9cb6 (maya.py:86 VEXE); the kit places it beside the engine
    // executable, where the supervisor looks.
    std::filesystem::path vision_exe = config.engine.executable.path().parent_path() / "maya-vision";
#if defined(_WIN32)
    vision_exe += L".exe";
#endif
    if (std::error_code ec; !std::filesystem::exists(vision_exe, ec) || ec) {
      std::cerr << "vision: no maya-vision beside the engine executable.\n";
      return EXIT_FAILURE;
    }
    const auto argv = secure_frontend::compose_vision_arguments(secure_frontend::VisionChildSpec{
        .mmproj = *launch.vision_mmproj, .model = *launch.vision_model, .threads = config.vision.threads,
        .max_tokens = config.engine.max_tokens,
        .no_flash_attn = config.vision.no_flash_attn});
    // The engine's confinement family minus the per-generation cgroup delegation
    // (recorded M1 gap, AGENT_HANDOFF); the environment stays an empty allowlist and
    // the cwd is the scratch dir (T11-ee, image half landed with Task 12).
    const std::filesystem::path exe = std::move(vision_exe);
    const std::filesystem::path vision_cwd = vision_scratch;
    const bool nnp = secure_frontend::config_defaults::kNoNewPrivilegesDefault && !config.engine.allow_new_privileges;
    secure_frontend::ProcessFactory vision_factory = [exe, argv, vision_cwd, nnp](std::uint64_t) -> secure_frontend::SpawnResult {
      auto child = std::make_unique<secure_frontend::EngineStdioProcess>();
      secure_frontend::EngineCommand command{.executable = exe,
                                             .arguments = argv,
                                             .environment = {},
                                             .working_directory = vision_cwd,
                                             .no_new_privileges = nnp,
                                             .kill_exit_code = secure_frontend::kVisionKillExitCode,
                                             .insert_serve = false};  // the pin's reader_args carry no --serve (T11-ff)
      if (const auto error = child->start(command)) return secure_frontend::SpawnFailure{error->message};
      return child;
    };
    secure_frontend::VisionLimits vision_limits;
    // The STRATA_VISION_READY_S counterpart, typed (vision.ready_timeout_s; 0 = wait
    // for ever, the pin's :291 rule) — and the STRATA_VISION_ENCODE_S row
    // (vision.encode_timeout_s, :328; 0 = for ever) for one ENC round trip.
    vision_limits.policy.ready_timeout = std::chrono::milliseconds{std::chrono::seconds{config.vision.ready_timeout_s}};
    vision_limits.encode_timeout = std::chrono::milliseconds{std::chrono::seconds{config.vision.encode_timeout_s}};
    vision.emplace(std::move(vision_factory), std::move(vision_limits));
    secure_frontend::VisionService::Limits service_limits;
    service_limits.payload.max_side = config.vision.max_side;  // vision.max_side, the pre-decode probe (T12-c)
    service_limits.scratch_dir = vision_scratch;
    vision_service.emplace(*vision, std::move(service_limits));
  }
  // listener.monitor (session log step 16): the Monitor's meter. The chat route tells it about
  // each generation, the host sampler below adds a reading a second, GET /metrics renders it.
  std::optional<secure_frontend::ServeMonitor> monitor;
  if (config.listener.monitor) monitor.emplace();
  secure_frontend::ChatRouteConfig chat_config = model.chat;
  chat_config.vision = vision_service.has_value() ? &*vision_service : nullptr;
  chat_config.monitor = monitor.has_value() ? &*monitor : nullptr;
  secure_frontend::ChatRoute chat_route(std::move(chat_config), port, gate, model.tokenizer);
  // Spec §4.1: every request goes through the header-first router (Host,
  // Origin, preflight, bearer token, route table, Content-Type, body limit)
  // before a body byte is read. Spec §3.6 (E9, re-anchor 4 / P26): /v1/models
  // lists only the served model, launch.model_id, owned by "local".
  secure_frontend::ApiRouter router(secure_frontend::ApiRouterConfig{
      .policy = secure_frontend::make_http_policy(config.listener.host, config.listener.port, config.listener.host_aliases,
                                                  config.listener.cors_origins),
      .validator = validator,
      .model_id = model_id,
      .owned_by = "local",
      .aliases = model.aliases,
      .chat_body_limit = config.limits.chat.max_body_bytes,
      .health = [&port] {
        const auto s = port.snapshot();
        return secure_frontend::HealthView{s.healthy, s.engine, s.recovery};
      },
      // ChatRoute: P4 validation, then the gate, then P6 through the lease
      // (spec §2.2). The route answers its own refusals.
      .chat = [&chat_route](const std::string_view body, const secure_frontend::RequestContext& context) -> secure_frontend::RouteResult {
        return chat_route.handle(body, context);
      },
      .web_ui = config.listener.web_ui,
      .require_key = !keyless,
      .metrics = monitor.has_value() ? secure_frontend::MetricsProvider{[&monitor, &port, &gate, &model_id] {
        return monitor->render_json({.model = model_id, .engine = port.snapshot().engine, .queued = gate.waiting()});
      }}
                                     : secure_frontend::MetricsProvider{}});
  const secure_frontend::ConnectionLimits connection_bounds = secure_frontend::connection_limits(config);
  std::string bind_error;
  auto server = secure_frontend::HttpSocketServer::bind(listener, static_cast<int>(config.listener.backlog), &bind_error);
  if (!server) { std::cerr << "Unable to bind secure listener.\n"; return EXIT_FAILURE; }
  // Bound first, spawned second: a listener that cannot bind never leaves an
  // engine child behind (CFG-01). The token was read above, before any spawn.
  // Spec §3.7: once every engine is gone the supervisor shuts the listener,
  // which wakes the accept() below. Signals route to the supervisor's wake.
  supervisor.set_on_stopped([&server] { server->shutdown_listener(); });
  secure_frontend::install_shutdown_signals(supervisor.wake());
  // Spec §8: the operator-facing startup summary — the process's own settings
  // only (stderr, once; like --check prints them). Never any secret or path.
  std::cerr << "strata: listening " << authority << ", workers " << config.limits.concurrency.max_concurrent_requests
            << ", queued generations " << config.limits.concurrency.max_queued_generations << '\n' << std::flush;
  if (!supervisor.start()) { std::cerr << "Unable to start the engine supervisor.\n"; return EXIT_FAILURE; }
  // Every way out of this scope, an exception included, stops the supervisor
  // while the listener its on-stopped hook uses still exists.
  struct StopSupervisor final {
    secure_frontend::EngineSupervisor& supervisor;
    ~StopSupervisor() { supervisor.shutdown(secure_frontend::config_defaults::kShutdownBound); }
  } stop_supervisor{supervisor};
  HostSampler host_sampler;
  if (monitor.has_value()) host_sampler.start(*monitor);
  // SP5 M1 Task 11 (Ruling T11-z): resident (the pin's eager default, serve/server.py:
  // 2511) starts the encoder now — no READY within the policy, and boot fails, because
  // vision.enabled is a promise of images. resident=false stays stopped until the FIRST
  // image wakes it: the pin's _vision_up laziness (:2646) lives in VisionSupervisor::
  // encode. The objects were built before the ChatRoute; the spawn happens here, after
  // bind, so a listener that cannot bind still never leaves an encoder child behind.
  if (config.vision.enabled && config.vision.resident) {
    vision->start();
    if (!vision->up()) {
      std::cerr << "vision: the encoder did not reach READY; refusing to serve without it.\n";
      return EXIT_FAILURE;
    }
    std::cerr << "[strata] vision: the encoder is resident\n";
  }
  if (keyless) {
    std::cerr << "strata: warning: listener.loopback_without_key is true: the API and the page answer without a key on "
              << authority << " (loopback only; Host and Origin are still checked)\n";
  }
  std::cout << "Secure server listening on http://" << authority
            << (keyless ? " (no API key: loopback only; Ctrl-C to stop)\n" : " (authenticated; Ctrl-C to stop)\n");
  std::cout.flush();
  // Task 12: the server is concurrent (spec §2.1). The accept loop runs on this
  // thread; the workers exist for the life of the pool, which is constructed
  // after supervisor.start() and destroyed (already joined) before the
  // supervisor shutdown below.
  secure_frontend::RequestLogger request_log(config.logging.requests, secure_frontend::stderr_sink());
  secure_frontend::ConnectionPool pool(
      *server,
      secure_frontend::PoolLimits{.workers = config.limits.concurrency.max_concurrent_requests,
                                  .per_remote_cap = config.limits.concurrency.max_connections_per_remote_address,
                                  .connection = connection_bounds},
      router,
      // Spec §8: one fixed-field line per finished connection when logging.requests is on.
      [&request_log](const secure_frontend::FinishedConnection& finished) { request_log.record(secure_frontend::log_record_for(finished)); });
  // Pre-flight P33 (kept per ruling T16-pool: shutdown_signalled() alone would
  // miss the recovery-exhausted exit): the supervisor's stop request ends the
  // accept loop; the on-stopped hook closing the listener is the second exit
  // path. T12b: a dead listener ends the loop with PoolExit::listener_failed,
  // handled exactly as SP2's loop handled it: orderly supervisor shutdown, exit
  // non-zero. The on-shutdown hook (Task 16) wakes gate waiters as
  // shutting_down before the workers are joined.
  const auto pool_exit = pool.run_until([&supervisor] { return supervisor.stop_requested(); }, [&gate] { gate.shutdown(); });
  if (pool_exit == secure_frontend::PoolExit::listener_failed) {
    std::cerr << "listener stopped\n";
  if (vision) vision->stop();  // the encoder role first: spawned last, stopped first
    supervisor.shutdown(secure_frontend::config_defaults::kShutdownBound);
    return EXIT_FAILURE;
  }
  if (vision) vision->stop();  // the encoder role first: spawned last, stopped first
  supervisor.shutdown(secure_frontend::config_defaults::kShutdownBound);
  // Spec C4: exit 0 means no engine is left; an unreaped one was logged.
  return supervisor.engine_left_unreaped() ? EXIT_FAILURE : EXIT_SUCCESS;
}

// Model launcher (plan 2026-10-23 Task 3): the cards that load and validate together with the
// main config at their own defaults (D9: a bad card is refused by name, the others load). The
// server's own settings are the main config's, read through the first usable card.
struct UsableCards final {
  std::vector<secure_frontend::ModelCard> cards;
  std::shared_ptr<const FrontendConfig> server;
};

// One card with the main config at its defaults; null (each issue logged by the card's name)
// when it does not validate or launch.
std::shared_ptr<const FrontendConfig> usable_card_config(const secure_frontend::FrontendConfigDraft& main,
                                                         const secure_frontend::ModelCard& card) {
  auto validated = secure_frontend::card_config(main, card, secure_frontend::default_option_values(card));
  if (const auto* issues = std::get_if<secure_frontend::ConfigErrors>(&validated)) {
    for (const auto& issue : *issues) std::cerr << "model card " << card.name << " refused: " << secure_frontend::format_issue(issue) << '\n';
    return nullptr;
  }
  auto config = std::get<secure_frontend::ValidatedConfig>(validated).shared();
  if (const auto issues = secure_frontend::launch_config_issues(*config, true); !issues.empty()) {
    for (const auto& issue : issues) std::cerr << "model card " << card.name << " refused: " << issue << '\n';
    return nullptr;
  }
  return config;
}

std::optional<UsableCards> usable_cards(const secure_frontend::FrontendConfigDraft& main) {
  if (const auto issues = secure_frontend::main_config_card_issues(main); !issues.empty()) {
    for (const auto& issue : issues) std::cerr << "Configuration error: " << secure_frontend::format_issue(issue) << '\n';
    return std::nullopt;
  }
  const auto entry = main.entries.find("models.cards");
  const auto* listed = entry == main.entries.end() ? nullptr : std::get_if<std::vector<std::string>>(&entry->second.value);
  if (listed == nullptr) {
    std::cerr << "Configuration error: models.cards: must be an array of strings\n";
    return std::nullopt;
  }
  std::vector<std::filesystem::path> files;
  for (const auto& text : *listed) files.push_back(secure_frontend::path_from_utf8(text));
  auto loaded = secure_frontend::load_model_cards(files);
  for (const auto& refusal : loaded.refused) {
    for (const auto& issue : refusal.issues) {
      std::cerr << "model card " << refusal.position << (refusal.name.empty() ? std::string{} : " (" + refusal.name + ")")
                << " refused: " << secure_frontend::format_issue(issue) << '\n';
    }
  }
  UsableCards usable;
  for (auto& card : loaded.cards) {
    auto config = usable_card_config(main, card);
    if (config == nullptr) continue;
    if (usable.server == nullptr) usable.server = config;
    usable.cards.push_back(std::move(card));
  }
  if (usable.cards.empty()) {
    std::cerr << "models.cards: no model card is usable; refusing to serve.\n";
    return std::nullopt;
  }
  return usable;
}

int launcher_check_impl(const secure_frontend::FrontendConfigDraft& main, const std::vector<std::string>& overridden) {
  const auto usable = usable_cards(main);
  if (!usable) return EXIT_FAILURE;
  const FrontendConfig& config = *usable->server;
  std::cout << secure_frontend::describe(config);
  for (const auto& key : overridden) std::cout << key << ": the command line overrides the config file\n";
  for (const auto& card : usable->cards) {
    std::cout << "model card " << card.name << ": usable (" << secure_frontend::profile_name(card.profile) << ", "
              << card.options.size() << " page options)\n";
  }
  std::cout.flush();
  if (config.listener.loopback_without_key) {
    std::cout << "token: not used (listener.loopback_without_key: loopback only)\nConfiguration is valid.\n";
    return EXIT_SUCCESS;
  }
  const auto token = read_configured_token(config);
  if (const auto* error = std::get_if<secure_frontend::TokenReadError>(&token)) {
    std::cerr << "token: unavailable: " << error->message << '\n'
              << "Configuration is not usable: the API token cannot be read.\n";
    return EXIT_FAILURE;
  }
  std::cout << "token: available (value not shown)\nConfiguration is valid.\n";
  return EXIT_SUCCESS;
}

secure_frontend::HttpResponse json_answer(const int status, std::string body) {
  return {.status = status, .headers = {{"Content-Type", "application/json; charset=utf-8"}}, .body = std::move(body)};
}

secure_frontend::HttpResponse refusal_answer(const secure_frontend::ModelLauncher::Refusal& refusal) {
  return secure_frontend::make_error_response(refusal.error, {.param = refusal.param});
}

// POST /v1/strata/models/start: {"name": "<card>", "options": {...}} (options optional).
secure_frontend::HttpResponse start_answer(secure_frontend::ModelLauncher& launcher, const std::string_view body, const bool remote) {
  constexpr secure_frontend::JsonLimits kStartLimits{.max_bytes = secure_frontend::kModelControlBodyLimit, .max_depth = 3U,
                                                     .max_container_entries = 64U, .max_string_bytes = 256U, .allow_fractions = true};
  const auto parsed = secure_frontend::parse_json(body, kStartLimits);
  const auto* root = std::get_if<secure_frontend::JsonValue>(&parsed);
  if (root == nullptr) return secure_frontend::make_error_response(secure_frontend::ApiError::invalid_json);
  const auto* members = root->if_object();
  if (members == nullptr) return secure_frontend::make_error_response(secure_frontend::ApiError::invalid_request);
  const std::string* name = nullptr;
  const secure_frontend::JsonValue* options = nullptr;
  for (const auto& member : *members) {
    if (member.key == "name" && member.value.if_string() != nullptr) name = member.value.if_string();
    else if (member.key == "options" && member.value.if_object() != nullptr) options = &member.value;
    else return secure_frontend::make_error_response(secure_frontend::ApiError::invalid_request);
  }
  if (name == nullptr) return secure_frontend::make_error_response(secure_frontend::ApiError::invalid_request);
  if (const auto refused = launcher.start(*name, options, remote)) return refusal_answer(*refused);
  std::string text = "{\"state\":\"starting\",\"name\":";
  secure_frontend::append_json_string(&text, *name);
  return json_answer(202, text + "}\n");
}

// Model downloads (plan 2026-10-23-model-downloads Task 4): the cards prepared downloads wrote
// (<roots.state>/cards/*.json, by file name), each read and validated like a listed card; one
// whose name is already held is refused by name.
void load_download_cards(const secure_frontend::FrontendConfigDraft& main, const std::filesystem::path& directory,
                         std::vector<secure_frontend::ModelCard>& cards) {
  std::vector<std::filesystem::path> files;
  std::error_code ec;
  for (std::filesystem::directory_iterator it(directory, ec), end; !ec && it != end; it.increment(ec)) {
    if (it->is_regular_file(ec) && it->path().extension() == ".json") files.push_back(it->path());
  }
  std::sort(files.begin(), files.end());
  for (const auto& file : files) {
    const std::string shown = secure_frontend::path_to_utf8(file.filename());
    if (cards.size() >= secure_frontend::kMaxLauncherCards) {
      std::cerr << "download card " << shown << " refused: the launcher holds " << secure_frontend::kMaxLauncherCards << " cards\n";
      break;
    }
    auto read = secure_frontend::read_model_card(file);
    if (const auto* issues = std::get_if<secure_frontend::ConfigErrors>(&read)) {
      for (const auto& issue : *issues) std::cerr << "download card " << shown << " refused: " << secure_frontend::format_issue(issue) << '\n';
      continue;
    }
    auto& card = std::get<secure_frontend::ModelCard>(read);
    if (std::any_of(cards.begin(), cards.end(), [&card](const secure_frontend::ModelCard& held) { return held.name == card.name; })) {
      std::cerr << "download card " << shown << " (" << card.name << ") refused: a card of that name is already loaded\n";
      continue;
    }
    if (usable_card_config(main, card) == nullptr) continue;
    cards.push_back(std::move(card));
  }
}

// What a prepared Qwen download's card takes from models.download_engine_card: its engine.
std::optional<secure_frontend::DownloadCardTemplate> download_card_template(const FrontendConfig& config,
                                                                            const std::vector<secure_frontend::ModelCard>& cards) {
  if (!config.models.download_engine_card.has_value()) return std::nullopt;
  for (const auto& card : cards) {
    if (card.name != *config.models.download_engine_card) continue;
    const auto& entries = card.config.entries;
    const auto text = [&entries](const std::string_view key) -> const std::string* {
      const auto found = entries.find(std::string{key});
      return found == entries.end() ? nullptr : std::get_if<std::string>(&found->second.value);
    };
    const auto* executable = text("engine.executable");
    if (card.profile != secure_frontend::EngineProfile::qwen || executable == nullptr) break;
    secure_frontend::DownloadCardTemplate made;
    made.engine_executable = *executable;
    if (const auto found = entries.find("engine.lib_dirs"); found != entries.end()) {
      if (const auto* dirs = std::get_if<std::vector<std::string>>(&found->second.value)) made.engine_lib_dirs = *dirs;
    }
    if (const auto* gpu = text("engine.gpu")) made.engine_gpu = *gpu;
    return made;
  }
  std::cerr << "[strata] downloads: models.download_engine_card names no usable qwen card; a prepared download gets no card\n";
  return std::nullopt;
}

// The downloads' children (strata, the prepare Python) get a closed environment: the system's
// own variables and a private temp folder, plus STRATA_GGUF_PY when the server has it (upstream's
// pack tools find gguf-py through it).
std::map<std::string, std::string, std::less<>> download_environment(const std::filesystem::path& temp) {
  std::map<std::string, std::string, std::less<>> environment;
  const std::string temp_text = secure_frontend::path_to_utf8(temp);
#if defined(_WIN32)
  const auto system = secure_frontend::query_windows_system_values();
  environment.emplace("SystemRoot", system.system_root);
  environment.emplace("WINDIR", system.system_root);
  environment.emplace("SystemDrive", system.system_drive);
  environment.emplace("PATH", system.system_root + "\\System32");
  environment.emplace("TEMP", temp_text);
  environment.emplace("TMP", temp_text);
#else
  environment.emplace("PATH", "/usr/bin:/bin");
  environment.emplace("TMPDIR", temp_text);
#endif
  if (const char* gguf_py = secure_frontend::crt_getenv("STRATA_GGUF_PY"); gguf_py != nullptr && *gguf_py != '\0') {
    environment.emplace("STRATA_GGUF_PY", gguf_py);
  }
  return environment;
}

int launcher_run_impl(const secure_frontend::FrontendConfigDraft& main, const std::optional<std::filesystem::path>& config_file) {
  // Ruling T13-c: server-grade process defaults (idempotent).
  secure_frontend::install_process_defaults();
  auto usable = usable_cards(main);
  if (!usable) return EXIT_FAILURE;
  const std::shared_ptr<const FrontendConfig> server_config = usable->server;
  const FrontendConfig& config = *server_config;
  if (!state_dir_is_usable(config)) return EXIT_FAILURE;
  if (const auto issues = secure_frontend::create_runtime_roots(config); !issues.empty()) {
    for (const auto& issue : issues) std::cerr << "Configuration error: " << secure_frontend::format_issue(issue) << '\n';
    return EXIT_FAILURE;
  }
  const bool keyless = config.listener.loopback_without_key;
  secure_frontend::BearerTokenValidator validator;
  if (!keyless) {
    auto token_result = read_configured_token(config);
    auto* token = std::get_if<secure_frontend::SecretBytes>(&token_result);
    if (token == nullptr) {
      std::cerr << "Unable to read API token: " << std::get<secure_frontend::TokenReadError>(token_result).message << '\n';
      return EXIT_FAILURE;
    }
    validator = secure_frontend::make_bearer_validator(std::make_shared<const secure_frontend::TokenVerifier>(std::move(*token)));
  }
  const secure_frontend::Config listener = secure_frontend::listener_config(config);
  const std::string authority = host_header(listener);  // the startup line only
  std::optional<secure_frontend::ServeMonitor> monitor;
  if (config.listener.monitor) monitor.emplace();
  // Model downloads: the store and the downloads' own folders, owner-only; the cards prepared
  // downloads wrote load beside the listed ones.
  const std::filesystem::path downloads_dir = *config.roots.state / "downloads";
  const std::filesystem::path download_cards_dir = *config.roots.state / "cards";
  if (config.models.downloads) {
    if (!config_file.has_value() || !config.models.downloads_root.has_value()) {
      std::cerr << "models.downloads: needs the config file (--config) and models.downloads_root\n";
      return EXIT_FAILURE;
    }
    for (const auto& directory : {*config.models.downloads_root, downloads_dir, downloads_dir / "tmp", download_cards_dir}) {
      if (const auto opened = secure_frontend::open_root(directory, secure_frontend::RootPolicy::create_private);
          const auto* failure = std::get_if<secure_frontend::PathError>(&opened)) {
        std::cerr << "models.downloads: " << secure_frontend::path_to_utf8(directory) << ": " << failure->message << '\n';
        return EXIT_FAILURE;
      }
    }
    load_download_cards(main, download_cards_dir, usable->cards);
  }
  const std::size_t card_count = usable->cards.size();
  std::optional<secure_frontend::DownloadCardTemplate> card_template;
  if (config.models.downloads) card_template = download_card_template(config, usable->cards);
  // D7: the page's last options per card, owner-only beside the engine's state.
  secure_frontend::ModelLauncher launcher(secure_frontend::LauncherSettings{
      .main = main,
      .cards = std::move(usable->cards),
      .memory_file = *config.roots.state / "model-options.json",
      .gate = {.max_queued = config.limits.concurrency.max_queued_generations, .queue_timeout = config.limits.concurrency.queue_timeout},
      .monitor = monitor.has_value() ? &*monitor : nullptr});
  // D2: model control for key holders on loopback; remote clients only with models.control_remote.
  const bool remote_allowed = config.models.control_remote;
  const auto allowed = [remote_allowed](const secure_frontend::RequestContext& context) {
    return context.loopback_peer || remote_allowed;
  };
  secure_frontend::ModelControl control;
  if (config.models.control) {
    control.list = [&launcher, allowed](const secure_frontend::RequestContext& context) -> secure_frontend::RouteResult {
      if (!allowed(context)) return secure_frontend::make_error_response(secure_frontend::ApiError::control_not_allowed);
      return json_answer(200, launcher.list_json());
    };
    control.start = [&launcher, allowed](const std::string_view body,
                                         const secure_frontend::RequestContext& context) -> secure_frontend::RouteResult {
      if (!allowed(context)) return secure_frontend::make_error_response(secure_frontend::ApiError::control_not_allowed);
      return start_answer(launcher, body, !context.loopback_peer);
    };
    control.stop = [&launcher, allowed](const secure_frontend::RequestContext& context) -> secure_frontend::RouteResult {
      if (!allowed(context)) return secure_frontend::make_error_response(secure_frontend::ApiError::control_not_allowed);
      if (const auto refused = launcher.stop(!context.loopback_peer)) return refusal_answer(*refused);
      return json_answer(202, "{\"state\":\"stopped\"}\n");
    };
  }
  // Model downloads (O1-O4): every transfer and link lookup a `strata` child, the prepare step
  // the embedded script under the configured Python; a prepared card joins the launcher.
  std::optional<secure_frontend::DownloadManager> downloads;
  secure_frontend::ModelDownloads download_routes;
  if (config.models.downloads) {
    secure_frontend::DownloadSettings settings;
    settings.catalog = secure_frontend::parse_download_catalog(secure_frontend::embedded_download_catalog());
    settings.strata_executable = secure_frontend::strata_beside_this_executable();
    std::error_code ec;
    settings.config_file = std::filesystem::absolute(*config_file, ec);
    settings.downloads_root = *config.models.downloads_root;
    settings.work_dir = downloads_dir;
    settings.cards_dir = download_cards_dir;
    settings.prepare_python = config.models.prepare_python;
    settings.prepare_tools = config.models.prepare_tools;
    if (config.models.prepare_python.has_value()) {
      auto root = secure_frontend::open_root(downloads_dir);
      const auto script = secure_frontend::parse_relative_path("prepare_download.py");
      if (std::holds_alternative<secure_frontend::CanonicalRoot>(root) && std::holds_alternative<secure_frontend::RelativePath>(script) &&
          !secure_frontend::write_private_file(std::get<secure_frontend::CanonicalRoot>(root), std::get<secure_frontend::RelativePath>(script),
                                               secure_frontend::embedded_prepare_script(), secure_frontend::TokenStoreMode::replace)) {
        settings.prepare_script = downloads_dir / "prepare_download.py";
      } else {
        std::cerr << "[strata] downloads: the prepare script could not be written; Qwen downloads stay files only\n";
      }
    }
    settings.card_template = card_template;
    settings.child_environment = download_environment(downloads_dir / "tmp");
    settings.on_card = [&launcher, &main](const std::string&, const std::filesystem::path& file) {
      auto read = secure_frontend::read_model_card(file);
      if (const auto* issues = std::get_if<secure_frontend::ConfigErrors>(&read)) {
        for (const auto& issue : *issues) std::cerr << "download card refused: " << secure_frontend::format_issue(issue) << '\n';
        return false;
      }
      auto& card = std::get<secure_frontend::ModelCard>(read);
      if (usable_card_config(main, card) == nullptr) return false;
      return launcher.add_card(std::move(card));
    };
    settings.log = [](const std::string_view line) { std::cerr << line << '\n' << std::flush; };
    settings.seams = secure_frontend::production_download_seams();
    downloads.emplace(std::move(settings));
    download_routes.handle = [&manager = *downloads, allowed](const secure_frontend::RouteId route, const std::string_view body,
                                                             const secure_frontend::RequestContext& context) -> secure_frontend::RouteResult {
      if (!allowed(context)) return secure_frontend::make_error_response(secure_frontend::ApiError::control_not_allowed);
      return secure_frontend::download_route_answer(manager, route, body);
    };
  }
  secure_frontend::ApiRouter router(secure_frontend::ApiRouterConfig{
      .policy = secure_frontend::make_http_policy(config.listener.host, config.listener.port, config.listener.host_aliases,
                                                  config.listener.cors_origins),
      .validator = validator,
      .model_id = {},
      .owned_by = "local",
      .aliases = {},
      .chat_body_limit = config.limits.chat.max_body_bytes,
      .health = [&launcher] { return launcher.health(); },
      .chat = [&launcher](const std::string_view body, const secure_frontend::RequestContext& context) -> secure_frontend::RouteResult {
        return launcher.chat(body, context);
      },
      .web_ui = config.listener.web_ui,
      .require_key = !keyless,
      .metrics = monitor.has_value() ? secure_frontend::MetricsProvider{[&launcher] { return launcher.metrics_json(); }}
                                     : secure_frontend::MetricsProvider{},
      .served = [&launcher] { return launcher.served(); },
      .control = std::move(control),
      .downloads = std::move(download_routes)});
  const secure_frontend::ConnectionLimits connection_bounds = secure_frontend::connection_limits(config);
  std::string bind_error;
  auto server = secure_frontend::HttpSocketServer::bind(listener, static_cast<int>(config.listener.backlog), &bind_error);
  if (!server) { std::cerr << "Unable to bind secure listener.\n"; return EXIT_FAILURE; }
  // Spec §3.7: a signal sets the process-wide flag the accept loop below polls; the wake only
  // has to exist (no supervisor runs before a card starts). Released before it is destroyed.
  secure_frontend::SupervisorWake signal_wake;
  secure_frontend::install_shutdown_signals(signal_wake);
  struct ReleaseSignals final {
    secure_frontend::SupervisorWake& wake;
    ~ReleaseSignals() { secure_frontend::release_shutdown_signals(wake); }
  } release_signals{signal_wake};
  std::cerr << "strata: listening " << authority << ", workers " << config.limits.concurrency.max_concurrent_requests
            << ", queued generations " << config.limits.concurrency.max_queued_generations << ", model cards " << card_count
            << (config.models.control ? (config.models.control_remote ? " (control: loopback and remote)" : " (control: loopback)")
                                      : " (control off)")
            << (config.models.downloads ? ", downloads on" : "") << '\n' << std::flush;
  HostSampler host_sampler;
  if (monitor.has_value()) host_sampler.start(*monitor);
  if (keyless) {
    std::cerr << "strata: warning: listener.loopback_without_key is true: the API and the page answer without a key on "
              << authority << " (loopback only; Host and Origin are still checked)\n";
  }
  // D5: models.start names the card started at boot (after bind, like every spawn).
  if (config.models.start.has_value()) {
    if (const auto refused = launcher.start(*config.models.start, nullptr, false)) {
      std::cerr << "[strata] models: models.start names no usable card (or it was refused); waiting for the page\n";
      (void)refused;
    }
  } else {
    std::cerr << "[strata] models: no model started (models.start is unset); waiting for the page\n";
  }
  std::cout << "Secure server listening on http://" << authority
            << (keyless ? " (no API key: loopback only; Ctrl-C to stop)\n" : " (authenticated; Ctrl-C to stop)\n");
  std::cout.flush();
  secure_frontend::RequestLogger request_log(config.logging.requests, secure_frontend::stderr_sink());
  secure_frontend::PoolExit pool_exit = secure_frontend::PoolExit::stopped;
  {
    secure_frontend::ConnectionPool pool(
        *server,
        secure_frontend::PoolLimits{.workers = config.limits.concurrency.max_concurrent_requests,
                                    .per_remote_cap = config.limits.concurrency.max_connections_per_remote_address,
                                    .connection = connection_bounds},
        router,
        [&request_log](const secure_frontend::FinishedConnection& finished) { request_log.record(secure_frontend::log_record_for(finished)); });
    // The pool's shutdown hook ends the running model's generation like a shutdown (the
    // runtime's stop flag) and refuses its queue, before the workers are joined.
    pool_exit = pool.run_until([] { return secure_frontend::shutdown_signalled(); }, [&launcher] { launcher.begin_shutdown(); });
  }
  if (downloads) downloads->shutdown();  // a running transfer stops; its partial files are kept
  launcher.shutdown();
  secure_frontend::notify_shutdown_complete();
  if (pool_exit == secure_frontend::PoolExit::listener_failed) {
    std::cerr << "listener stopped\n";
    return EXIT_FAILURE;
  }
  // Spec C4: exit 0 means no engine is left; an unreaped one was logged.
  return launcher.engine_left_unreaped() ? EXIT_FAILURE : EXIT_SUCCESS;
}

}  // namespace

namespace secure_frontend {

// The exported entry points (the anonymous-namespace boot helpers above are
// file-local; only these two names leave this translation unit).
int server_run(const FrontendConfig& config, const bool expert) { return server_run_impl(config, expert); }
int server_check(const FrontendConfig& config, const std::vector<std::string>& overridden, bool expert) {
  return server_check_impl(config, overridden, expert);
}
int launcher_run(const FrontendConfigDraft& main, const std::optional<std::filesystem::path>& config_file) {
  return launcher_run_impl(main, config_file);
}
int launcher_check(const FrontendConfigDraft& main, const std::vector<std::string>& overridden) {
  return launcher_check_impl(main, overridden);
}

}  // namespace secure_frontend

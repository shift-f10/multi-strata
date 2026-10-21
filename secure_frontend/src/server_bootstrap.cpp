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
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/engine_environment.hpp"
#include "secure_frontend/engine_stdio_process.hpp"
#include "secure_frontend/engine_supervisor.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/generation_gate.hpp"
#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/image_payload.hpp"
#include "secure_frontend/launch_composition.hpp"
#include "secure_frontend/privilege_check.hpp"
#include "secure_frontend/process_defaults.hpp"
#include "secure_frontend/request_log.hpp"
#include "secure_frontend/shutdown_signal.hpp"
#include "secure_frontend/subsystem_limits.hpp"
#include "secure_frontend/test_hooks.hpp"
#include "secure_frontend/token_reader.hpp"
#include "secure_frontend/token_verifier.hpp"
#include "secure_frontend/tokenizer_pack.hpp"
#include "secure_frontend/vision_supervisor.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
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

// Creates <state>/engine, the temp root and the CUDA cache owner-only and
// clears the temp root: no engine runs yet, so temp directories a previous
// frontend left behind are stale. Where the CUDA cache lives is
// engine_environment_for()'s decision: <roots.cache>/cuda (that root was
// already created 0700 by create_runtime_roots() and is left as it is) or
// <state>/cache/cuda, whose parent below the state dir is created owner-only too.
bool prepare_state_dir(const std::filesystem::path& state_dir, const secure_frontend::EngineEnvironment& environment) {
  std::vector<std::filesystem::path> directories{state_dir / "engine", environment.temp_dir};
  const auto below_state = [&state_dir](const std::filesystem::path& path) {
    const auto relative = path.lexically_relative(state_dir);
    return !relative.empty() && relative != "." && *relative.begin() != "..";
  };
  if (below_state(environment.cuda_cache_dir.parent_path())) directories.push_back(environment.cuda_cache_dir.parent_path());
  directories.push_back(environment.cuda_cache_dir);
  for (const auto& directory : directories) {
    if (!secure_frontend::create_owner_only_directory(directory)) return false;
  }
  return secure_frontend::clear_directory_contents(environment.temp_dir);
}

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
  auto token_result = read_configured_token(config);
  auto* token = std::get_if<secure_frontend::SecretBytes>(&token_result);
  if (token == nullptr) {
    std::cerr << "Unable to read API token: " << std::get<secure_frontend::TokenReadError>(token_result).message << '\n';
    return EXIT_FAILURE;
  }
  auto verifier = std::make_shared<const secure_frontend::TokenVerifier>(std::move(*token));

  const secure_frontend::Config listener = secure_frontend::listener_config(config);
  // Derived once, before bind/spawn; each subsystem keeps its own const copy.
  // (SP5 M1 Task 12: vision_capable is filled after compose — see below — so this
  // stays mutable until the ChatRoute copies it.)
  auto schema_limits = secure_frontend::chat_schema_limits(config);
  // SP4 §2.3/§4.9 (Task 24b): managed models launch from the installed manifest;
  // --expert keeps SP1's operator path (inventory, roots.tokenizer_pack).
  auto composed = secure_frontend::compose_engine_launch(config, expert);
  if (const auto* failure = std::get_if<secure_frontend::LaunchFailure>(&composed)) {
    for (const auto& message : failure->messages) std::cerr << message << '\n';
    return failure->exit == secure_frontend::ExitCode::usage ? EXIT_FAILURE : secure_frontend::exit_code_value(failure->exit);
  }
  auto& launch = std::get<secure_frontend::ComposedLaunch>(composed);
  // SP5 M1 Task 6 (parity row mtp; pin serve/server.py:2922-2925): an explicit "mtp":
  // false is applied at every start and the dropped flags are reported once, fixed text.
  if (!launch.mtp_removed.empty()) {
    std::string flags;
    for (const auto& flag : launch.mtp_removed) {
      if (!flags.empty()) flags += ' ';
      flags += flag;
    }
    std::cerr << "[strata] \"mtp\": false - starting without the draft layer (" << flags << " left out)\n";
  }
  // SP5 M1 Task 12 (C-9, Ruling T12-b): the content-array gate is a MODEL capability —
  // it opens only when vision.enabled AND the installed manifest declares launch.mmproj
  // (compose refuses that pairing for glm53, so the gate implies the qwen renderer).
  // The request itself can never open it.
  if (config.vision.enabled && launch.vision_mmproj.has_value()) schema_limits.vision_capable = true;
  const auto tokenizer_result = secure_frontend::load_local_tokenizer_pack(*launch.tokenizer_root);
  const auto* tokenizer = std::get_if<secure_frontend::TokenizerPack>(&tokenizer_result);
  if (tokenizer == nullptr) {
    std::cerr << "Unable to load local tokenizer pack (" << (launch.managed ? "the model's tokenizer" : "roots.tokenizer_pack")
              << "): " << std::get<secure_frontend::TokenizerPackError>(tokenizer_result).message << '\n';
    return EXIT_FAILURE;
  }
  const std::string& model_id = launch.model_id;
  // SP5 M1 Task 8 (model.aliases; set_aliases :3774-3777): drop an alias equal to the
  // served name, keep order, dedup — the route and /v1/models share one effective list.
  std::vector<std::string> model_aliases;
  for (const auto& alias : config.engine.aliases) {
    if (alias != model_id &&
        std::find(model_aliases.begin(), model_aliases.end(), alias) == model_aliases.end())
      model_aliases.push_back(alias);
  }
  const bool glm = launch.profile == EngineProfile::glm53;
  auto* engine_arguments = &launch.engine_args;
  // SP5 M1 Task 5 (parity row effort_position, serve/server.py:2836-2856): reasoning.effort_position
  // "end" composes the engine's --tail-role-token checkpoint flag (probe rules in the composer).
  if (config.reasoning.effort_position == secure_frontend::EffortPosition::end) {
    const auto tail = secure_frontend::compose_effort_end_arguments(config.engine.executable.path(), *tokenizer);
    std::cerr << "[strata] " << tail.notice << '\n';
    engine_arguments->insert(engine_arguments->end(), tail.arguments.begin(), tail.arguments.end());
  }

  // Profile, protocol flavor, chat limits and the READY deadline all come from
  // the validated config (limits.engine.ready_timeout_s drives the policy).
  secure_frontend::SupervisorConfig supervisor_config = secure_frontend::supervisor_config(config);
  // SP4 §4.9 c: the profile is the composed launch's (a managed model's
  // manifest sets it; engine.profile is --expert only), not the config key.
  supervisor_config.profile = glm ? secure_frontend::NativeChatProfile::glm53 : secure_frontend::NativeChatProfile::qwen;
  supervisor_config.flavor =
      glm ? secure_frontend::EngineProtocolFlavor::lighttransport_glm53 : secure_frontend::EngineProtocolFlavor::strata_0143;
  const std::filesystem::path& state_dir = *config.roots.state;
  std::vector<std::filesystem::path> lib_dirs = config.engine.lib_dirs;
  if (lib_dirs.empty()) lib_dirs.push_back(config.engine.executable.path().parent_path());
  secure_frontend::EngineLaunchPlan plan{.command = {.executable = config.engine.executable.path(),
                                                     .arguments = std::move(*engine_arguments), .environment = {}}};
  // Spec §3.9: the engine's whole environment, rendered per generation; nothing
  // is inherited from this server's environment.
  auto environment = secure_frontend::engine_environment_for(state_dir, config.roots.cache, std::move(lib_dirs));
  if (!prepare_state_dir(state_dir, environment)) {
    std::cerr << "Unable to prepare the state or cache directory.\n";
    return EXIT_FAILURE;
  }
  plan.environment = std::move(environment);
  // Spec §3.12: the engine's cwd-relative files (`pack/full`, stall dumps)
  // land in <state_dir>/engine, created by prepare_state_dir() above.
  plan.command.working_directory = state_dir / "engine";
  // Spec §3.7(d): detected, never configured; off unless this process runs in
  // a writable delegated cgroup v2.
  plan.use_delegated_cgroup = true;
  // Spec §3.12 (G2): PR_SET_NO_NEW_PRIVS on the engine unless
  // engine.allow_new_privileges (--allow-new-privileges); when it is set, an
  // engine that dies before READY gets the one-time /dev/nvidia-uvm hint.
  plan.command.no_new_privileges =
      secure_frontend::config_defaults::kNoNewPrivilegesDefault && !config.engine.allow_new_privileges;
#if defined(__linux__)
  supervisor_config.no_new_privileges_hint = plan.command.no_new_privileges;
#endif
  // The supervisor thread spawns, watches and restarts the engine (spec §3.1).
  // Declared before the listener and the router, so it outlives both; a Lease
  // lives only inside one ChatRoute::handle call.
  secure_frontend::EngineSupervisor supervisor(supervisor_config, secure_frontend::make_stdio_process_factory(std::move(plan)));

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
  // the supervised strata-vision child and the route's encoder service. Construction
  // spawns nothing — the resident start below runs only after bind, so a listener that
  // cannot bind still never leaves an encoder child behind (CFG-01 family). The exe is
  // OUR distribution's — strata-vision beside the engine executable (the pin's
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
    std::filesystem::path vision_exe = config.engine.executable.path().parent_path() / "strata-vision";
#if defined(_WIN32)
    vision_exe += L".exe";
#endif
    if (std::error_code ec; !std::filesystem::exists(vision_exe, ec) || ec) {
      std::cerr << "vision: no strata-vision beside the engine executable.\n";
      return EXIT_FAILURE;
    }
    const auto argv = secure_frontend::compose_vision_arguments(secure_frontend::VisionChildSpec{
        .mmproj = *launch.vision_mmproj, .model = *launch.vision_model, .threads = config.vision.threads,
        .max_tokens = config.engine.max_tokens, .min_tokens = config.engine.min_tokens,
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
  secure_frontend::ChatRoute chat_route(
      secure_frontend::ChatRouteConfig{.schema = schema_limits, .model_id = model_id, .profile = supervisor_config.profile,
                                       .max_prompt_tokens = config.limits.chat.max_prompt_tokens,
                                       .max_completion_tokens = config.limits.chat.max_completion_tokens,
                                       .default_max_tokens = config.limits.chat.default_max_tokens,
                                       .sampling_default = config.sampling,
                                       .fit_max_tokens = config.engine.fit_max_tokens,
                                       .minimum_output_tokens = config.engine.min_tokens.value_or(0U),
                                       .maximum_output_tokens = config.engine.max_tokens.value_or(0U),
                                       .model_aliases = model_aliases,
                                       .queue_timeout = config.limits.concurrency.queue_timeout,
                                       .write_stall = config.limits.http.write_stall,
                                       .response_write_deadline = config.limits.http.response_write_deadline,
                                       .stream_keepalive = config.limits.http.stream_keepalive,
                                       .vision = vision_service.has_value() ? &*vision_service : nullptr},
      port, gate, *tokenizer);
  // Spec §4.1: every request goes through the header-first router (Host,
  // Origin, preflight, bearer token, route table, Content-Type, body limit)
  // before a body byte is read. Spec §3.6 (E9, re-anchor 4 / P26): /v1/models
  // lists only the served model, launch.model_id, owned by "local".
  secure_frontend::ApiRouter router(secure_frontend::ApiRouterConfig{
      .policy = secure_frontend::make_http_policy(config.listener.host, config.listener.port, config.listener.host_aliases,
                                                  config.listener.cors_origins),
      .validator = secure_frontend::make_bearer_validator(verifier),
      .model_id = model_id,
      .owned_by = "local",
      .aliases = model_aliases,
      .chat_body_limit = config.limits.chat.max_body_bytes,
      .health = [&port] {
        const auto s = port.snapshot();
        return secure_frontend::HealthView{s.healthy, s.engine, s.recovery};
      },
      // ChatRoute: P4 validation, then the gate, then P6 through the lease
      // (spec §2.2). The route answers its own refusals.
      .chat = [&chat_route](const std::string_view body, const secure_frontend::RequestContext& context) -> secure_frontend::RouteResult {
        return chat_route.handle(body, context);
      }});
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
  std::cout << "Secure server listening on http://" << authority << " (authenticated; Ctrl-C to stop)\n";
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

}  // namespace

namespace secure_frontend {

// The exported entry points (the anonymous-namespace boot helpers above are
// file-local; only these two names leave this translation unit).
int server_run(const FrontendConfig& config, const bool expert) { return server_run_impl(config, expert); }
int server_check(const FrontendConfig& config, const std::vector<std::string>& overridden, bool expert) {
  return server_check_impl(config, overridden, expert);
}

}  // namespace secure_frontend

#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/api_router.hpp"
#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/engine_environment.hpp"
#include "secure_frontend/engine_supervisor.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/frontend_init.hpp"
#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/launch_composition.hpp"
#include "secure_frontend/privilege_check.hpp"
#include "secure_frontend/process_defaults.hpp"
#include "secure_frontend/server_cli.hpp"
#include "secure_frontend/shutdown_signal.hpp"
#include "secure_frontend/subsystem_limits.hpp"
#include "secure_frontend/test_hooks.hpp"
#include "secure_frontend/token_reader.hpp"
#include "secure_frontend/token_verifier.hpp"
#include "secure_frontend/tokenizer_pack.hpp"
#include "secure_frontend/utf8_argv.hpp"

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

int check(const FrontendConfig& config, const std::vector<std::string>& overridden, const bool expert) {
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

int run(const FrontendConfig& config, const bool expert) {
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
  const auto schema_limits = secure_frontend::chat_schema_limits(config);
  // SP4 §2.3/§4.9 (Task 24b): managed models launch from the installed manifest;
  // --expert keeps SP1's operator path (inventory, roots.tokenizer_pack).
  auto composed = secure_frontend::compose_engine_launch(config, expert);
  if (const auto* failure = std::get_if<secure_frontend::LaunchFailure>(&composed)) {
    for (const auto& message : failure->messages) std::cerr << message << '\n';
    return failure->exit == secure_frontend::ExitCode::usage ? EXIT_FAILURE : secure_frontend::exit_code_value(failure->exit);
  }
  auto& launch = std::get<secure_frontend::ComposedLaunch>(composed);
  const auto tokenizer_result = secure_frontend::load_local_tokenizer_pack(*launch.tokenizer_root);
  const auto* tokenizer = std::get_if<secure_frontend::TokenizerPack>(&tokenizer_result);
  if (tokenizer == nullptr) {
    std::cerr << "Unable to load local tokenizer pack (" << (launch.managed ? "the model's tokenizer" : "roots.tokenizer_pack")
              << "): " << std::get<secure_frontend::TokenizerPackError>(tokenizer_result).message << '\n';
    return EXIT_FAILURE;
  }
  const std::string& model_id = launch.model_id;
  const bool glm = launch.profile == EngineProfile::glm53;
  auto* engine_arguments = &launch.engine_args;

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
  // lives only inside one execute_with_lease() call.
  secure_frontend::EngineSupervisor supervisor(supervisor_config, secure_frontend::make_stdio_process_factory(std::move(plan)));

  const std::string authority = host_header(listener);  // the startup line only
  // Spec §3.4/§3.8: outside `ready` there is no lease and no wait; a stopping
  // server answers server_shutting_down, anything else engine_unavailable with
  // Retry-After 5 unless recovery is exhausted. Pre-flight S11/D7: the direct
  // supervisor.snapshot() here and in /health, and execute_with_lease below,
  // are transitional (serial server, one caller) until Task 16's ChatRoute and
  // SupervisorPort replace them.
  const auto engine_refusal = [&supervisor]() {
    const auto snapshot = supervisor.snapshot();
    if (snapshot.state == secure_frontend::SupervisorState::shutting_down ||
        snapshot.state == secure_frontend::SupervisorState::stopped) {
      return secure_frontend::make_error_response(secure_frontend::ApiError::server_shutting_down);
    }
    return secure_frontend::make_error_response(secure_frontend::ApiError::engine_unavailable,
                                                {.retry_after = secure_frontend::engine_retry_after(snapshot.recovery)});
  };
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
      .chat_body_limit = config.limits.chat.max_body_bytes,
      .health = [&supervisor] {
        const auto s = supervisor.snapshot();
        return secure_frontend::HealthView{s.healthy, s.engine, s.recovery};
      },
      // Serial chat through SP2's lease until Task 16 replaces it with ChatRoute.
      .chat = [&](const std::string_view body, const secure_frontend::RequestContext&) -> secure_frontend::RouteResult {
        // Parse first: a request the frontend refuses (tools, functions, MCP,
        // unknown fields) is answered with no engine or process action (EXT-01);
        // the error names only a fixed key (P28).
        const auto parsed = secure_frontend::parse_chat_request(body, schema_limits);
        if (const auto* error = std::get_if<secure_frontend::ChatRequestError>(&parsed)) {
          return secure_frontend::make_error_response(error->error, {.param = error->param});
        }
        const auto& request = std::get<secure_frontend::ChatCompletionRequest>(parsed);
        if (request.model != model_id) return secure_frontend::make_error_response(secure_frontend::ApiError::model_not_found);
        const auto outcome = secure_frontend::execute_with_lease(supervisor, request, *tokenizer);
        if (!outcome.has_value()) return engine_refusal();
        if (const auto* failure = std::get_if<secure_frontend::ChatExecutionError>(&*outcome)) {
          using Code = secure_frontend::ChatExecutionErrorCode;
          switch (failure->code) {
            case Code::context_limit_exceeded:
              return secure_frontend::make_error_response(secure_frontend::ApiError::context_length_exceeded);
            case Code::invalid_request:
            case Code::planning_failed:
              return secure_frontend::make_error_response(secure_frontend::ApiError::invalid_request);
            case Code::generation_timed_out:
              return secure_frontend::make_error_response(secure_frontend::ApiError::engine_error);
            case Code::output_decode_failed:
              return secure_frontend::make_error_response(secure_frontend::ApiError::internal_error);
            case Code::engine_protocol_failed:
              return engine_refusal();
          }
          return secure_frontend::make_error_response(secure_frontend::ApiError::internal_error);
        }
        const auto& result = std::get<secure_frontend::ChatExecutionResult>(*outcome);
        const auto rendered = secure_frontend::render_chat_completion_response(request, result.text, schema_limits);
        if (!rendered) return secure_frontend::make_error_response(secure_frontend::ApiError::internal_error);
        return secure_frontend::HttpResponse{
            .status = 200, .headers = {{"Content-Type", "application/json; charset=utf-8"}}, .body = *rendered};
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
  if (!supervisor.start()) { std::cerr << "Unable to start the engine supervisor.\n"; return EXIT_FAILURE; }
  // Every way out of this scope, an exception included, stops the supervisor
  // while the listener its on-stopped hook uses still exists.
  struct StopSupervisor final {
    secure_frontend::EngineSupervisor& supervisor;
    ~StopSupervisor() { supervisor.shutdown(secure_frontend::config_defaults::kShutdownBound); }
  } stop_supervisor{supervisor};
  std::cout << "Secure server listening on http://" << authority << " (authenticated; Ctrl-C to stop)\n";
  std::cout.flush();
  for (;;) {
    std::string error;
    const bool served = server->serve_one(router, connection_bounds, &error);
    if (supervisor.stop_requested()) break;
    // The on-stopped hook closed the listener (pre-flight P33): nothing more to accept.
    if (server->native_handle() == secure_frontend::kInvalidNativeSocket) break;
    if (!served && server->listener_failed()) {
      std::cerr << "listener stopped: " << error << '\n';
      supervisor.shutdown(secure_frontend::config_defaults::kShutdownBound);
      return EXIT_FAILURE;
    }
    // Any other failure was one client's; keep serving.
  }
  supervisor.shutdown(secure_frontend::config_defaults::kShutdownBound);
  // Spec C4: exit 0 means no engine is left; an unreaped one was logged.
  return supervisor.engine_left_unreaped() ? EXIT_FAILURE : EXIT_SUCCESS;
}

}  // namespace

int main(int argc, char* argv[]) {
  // Spec §10: Winsock is initialized once per process (bind() no longer calls WSAStartup).
  const secure_frontend::WinsockGuard winsock;
#if defined(SECURE_FRONTEND_TEST_HOOKS)
  std::cerr << "warning: test hooks compiled in (" << secure_frontend::kTestHooksMarker << "); never ship this binary\n";
#endif
  secure_frontend::install_process_defaults();
#if defined(_WIN32)
  // Spec A2: UTF-8 from the wide command line, not the ANSI code page (utf8_argv.hpp).
  const auto utf8_arguments = secure_frontend::utf8_command_line(argc, argv);
  if (!utf8_arguments) {
    std::cerr << "Error: the command line is not valid Unicode\nRun strata-secure-server --help for usage.\n";
    return EXIT_FAILURE;
  }
  std::vector<const char*> utf8_argv;
  for (const auto& argument : *utf8_arguments) utf8_argv.push_back(argument.c_str());
  utf8_argv.push_back(nullptr);
  const auto parsed = secure_frontend::parse_server_command_line(static_cast<int>(utf8_arguments->size()), utf8_argv.data());
#else
  const auto parsed = secure_frontend::parse_server_command_line(argc, argv);
#endif
  if (const auto* error = std::get_if<secure_frontend::CliError>(&parsed)) {
    std::cerr << "Error: " << error->message << "\nRun strata-secure-server --help for usage.\n";
    return EXIT_FAILURE;
  }
  const auto& invocation = std::get<secure_frontend::ServerInvocation>(parsed);
  if (invocation.command == secure_frontend::ServerCommand::help) {
    std::cout << secure_frontend::server_usage();
    return EXIT_SUCCESS;
  }
  // Spec §3.12 (G4): never as root or with an elevated Windows token, for
  // init and --check too. No flag or variable overrides this.
  if (const auto refused = secure_frontend::privileged_start_error(secure_frontend::current_process_privileges())) {
    std::cerr << *refused << '\n';
    return EXIT_FAILURE;
  }
  if (invocation.command == secure_frontend::ServerCommand::init) {
    const auto failure = secure_frontend::init_frontend(*invocation.config_file, invocation.flags, invocation.force);
    if (failure.has_value()) {
      std::cerr << "init: " << failure->message << '\n';
      for (const auto& issue : failure->issues) std::cerr << "Configuration error: " << secure_frontend::format_issue(issue) << '\n';
      return EXIT_FAILURE;
    }
    std::cout << "init: wrote the configuration file and, for a file token source, a new token (not shown).\n";
    return EXIT_SUCCESS;
  }
  std::vector<std::string> overridden;
  const auto loaded = secure_frontend::load_server_config(invocation, &overridden);
  if (const auto* issues = std::get_if<secure_frontend::ConfigErrors>(&loaded)) {
    for (const auto& issue : *issues) std::cerr << "Configuration error: " << secure_frontend::format_issue(issue) << '\n';
    return EXIT_FAILURE;
  }
  const auto config = std::get<secure_frontend::ValidatedConfig>(loaded).shared();
  if (invocation.command == secure_frontend::ServerCommand::check) return check(*config, overridden, invocation.expert);
  return run(*config, invocation.expert);
}

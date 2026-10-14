#include "secure_frontend/api_router.hpp"
#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/engine_supervisor.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/frontend_init.hpp"
#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/model_inventory.hpp"
#include "secure_frontend/process_defaults.hpp"
#include "secure_frontend/server_cli.hpp"
#include "secure_frontend/shutdown_signal.hpp"
#include "secure_frontend/subsystem_limits.hpp"
#include "secure_frontend/token_reader.hpp"
#include "secure_frontend/token_verifier.hpp"
#include "secure_frontend/tokenizer_pack.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
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

secure_frontend::HttpResponse json_error(const int status, const char* message) {
  return {.status = status,
          .headers = {{"Content-Type", "application/json; charset=utf-8"}, {"Cache-Control", "no-store"}},
          .body = std::string{"{\"error\":\""} + message + "\"}\n"};
}

secure_frontend::TokenReadResult read_configured_token(const FrontendConfig& config) {
  if (config.roots.secret.has_value()) return secure_frontend::read_token(config.token, *config.roots.secret);
  return secure_frontend::read_token(config.token, std::filesystem::path{"."});
}

int check(const FrontendConfig& config, const std::vector<std::string>& overridden) {
  std::cout << secure_frontend::describe(config);
  for (const auto& key : overridden) std::cout << key << ": the command line overrides the config file\n";
  std::cout.flush();
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

int run(const FrontendConfig& config) {
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
  const auto listener_limits = secure_frontend::http_socket_server_limits(config);
  const auto tokenizer_result = secure_frontend::load_local_tokenizer_pack(config.roots.tokenizer_pack);
  const auto* tokenizer = std::get_if<secure_frontend::TokenizerPack>(&tokenizer_result);
  if (tokenizer == nullptr) {
    std::cerr << "Unable to load local tokenizer pack (roots.tokenizer_pack): "
              << std::get<secure_frontend::TokenizerPackError>(tokenizer_result).message << '\n';
    return EXIT_FAILURE;
  }
  const auto models_result = secure_frontend::enumerate_local_models(config.roots.models);
  const auto* manifests = std::get_if<std::vector<secure_frontend::ModelManifest>>(&models_result);
  if (manifests == nullptr) {
    std::cerr << "Unable to inventory local models (roots.models): "
              << std::get<secure_frontend::ModelInventoryError>(models_result).message << '\n';
    return EXIT_FAILURE;
  }
  const std::string& model_id = config.engine.model_id.value();
  const auto selected = std::find_if(manifests->begin(), manifests->end(),
                                     [&model_id](const auto& model) { return model.id == model_id; });
  if (selected == manifests->end()) { std::cerr << "Selected model is not present in roots.models.\n"; return EXIT_FAILURE; }
  const bool glm = config.engine.profile == EngineProfile::glm53;
  const auto arguments_profile = glm ? secure_frontend::EngineArgumentsProfile::lighttransport_glm53
                                     : secure_frontend::EngineArgumentsProfile::strata_0143;
  auto engine_arguments_result =
      secure_frontend::build_engine_arguments(arguments_profile, *selected, config.roots.models, config.engine.args);
  auto* engine_arguments = std::get_if<std::vector<std::string>>(&engine_arguments_result);
  if (engine_arguments == nullptr) { std::cerr << "Engine arguments rejected.\n"; return EXIT_FAILURE; }
  std::vector<secure_frontend::ApiModel> models;
  models.reserve(manifests->size());
  for (const auto& manifest : *manifests) models.push_back({.id = manifest.id, .owned_by = manifest.owned_by});

  // Profile, protocol flavor, chat limits and the READY deadline all come from
  // the validated config (limits.engine.ready_timeout_s drives the policy).
  const secure_frontend::SupervisorConfig supervisor_config = secure_frontend::supervisor_config(config);
  secure_frontend::EngineLaunchPlan plan{.command = {.executable = config.engine.executable.path(),
                                                     .arguments = std::move(*engine_arguments), .environment = {}}};
  // The supervisor thread spawns, watches and restarts the engine (spec §3.1).
  // Declared before the listener and the router, so it outlives both; a Lease
  // lives only inside one execute_with_lease() call.
  secure_frontend::EngineSupervisor supervisor(supervisor_config, secure_frontend::make_stdio_process_factory(std::move(plan)));

  const std::string authority = host_header(listener);
  secure_frontend::HttpPolicy policy{.allowed_hosts = {authority}, .same_origin_origins = {"http://" + authority},
                                     .cors_allowed_origins = {}, .cors_enabled = false};
  // /health takes one supervisor snapshot per request: the router calls the
  // bool provider first, then the engine and recovery providers, once each
  // (api_router.hpp), and the listener is serial.
  secure_frontend::HealthSnapshot health = secure_frontend::health_for(secure_frontend::SupervisorState::stopped);
  const secure_frontend::ApiRouter router(
      [&supervisor, &health] {
        health = supervisor.snapshot();
        return health.healthy;
      },
      [models] { return models; }, [&health] { return health.engine; }, [&health] { return health.recovery; });
  auto server = secure_frontend::HttpSocketServer::bind(
      listener, std::move(policy), secure_frontend::make_bearer_validator(verifier),
      [&router, &supervisor, &tokenizer, &model_id, &schema_limits](
          const std::string_view method, const std::string_view target, const std::string_view body) {
        if (method == "GET") return router.dispatch(method, target);
        if (method != "POST" || target != "/v1/chat/completions") return json_error(404, "Not Found");
        // Parse first: a request the frontend refuses (tools, functions, MCP,
        // stream, unknown fields) is answered with no engine or process action (EXT-01).
        const auto request = secure_frontend::parse_chat_completion_request(body, schema_limits);
        if (!request || request->model != model_id) return json_error(400, "Bad Request");
        // Outside `ready` there is no lease: an immediate generic 503, never a wait (spec §3.4).
        const auto outcome = secure_frontend::execute_with_lease(supervisor, *request, *tokenizer);
        if (!outcome) return json_error(503, "Service Unavailable");
        const auto* completion = std::get_if<secure_frontend::ChatExecutionResult>(&*outcome);
        if (completion == nullptr) return json_error(503, "Service Unavailable");
        const auto response =
            secure_frontend::render_chat_completion_response(*request, completion->text, schema_limits);
        if (!response) return json_error(503, "Service Unavailable");
        return secure_frontend::HttpResponse{
            .status = 200,
            .headers = {{"Content-Type", "application/json; charset=utf-8"}, {"Cache-Control", "no-store"}},
            .body = *response};
      },
      nullptr, listener_limits);
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
    const bool served = server->serve_one(&error);
    if (supervisor.stop_requested()) break;
    if (!served && server->listener_failed()) {
      std::cerr << "listener stopped: " << error << '\n';
      supervisor.shutdown(secure_frontend::config_defaults::kShutdownBound);
      return EXIT_FAILURE;
    }
    // Any other failure was one client's; keep serving.
  }
  supervisor.shutdown(secure_frontend::config_defaults::kShutdownBound);
  return EXIT_SUCCESS;
}

}  // namespace

int main(int argc, char* argv[]) {
  secure_frontend::install_process_defaults();
  const auto parsed = secure_frontend::parse_server_command_line(argc, argv);
  if (const auto* error = std::get_if<secure_frontend::CliError>(&parsed)) {
    std::cerr << "Error: " << error->message << "\nRun strata-secure-server --help for usage.\n";
    return EXIT_FAILURE;
  }
  const auto& invocation = std::get<secure_frontend::ServerInvocation>(parsed);
  if (invocation.command == secure_frontend::ServerCommand::help) {
    std::cout << secure_frontend::server_usage();
    return EXIT_SUCCESS;
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
  if (invocation.command == secure_frontend::ServerCommand::check) return check(*config, overridden);
  return run(*config);
}

#include "secure_frontend/api_router.hpp"
#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/engine_stdio_process.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/frontend_init.hpp"
#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/launch_composition.hpp"
#include "secure_frontend/process_defaults.hpp"
#include "secure_frontend/server_cli.hpp"
#include "secure_frontend/subsystem_limits.hpp"
#include "secure_frontend/test_hooks.hpp"
#include "secure_frontend/token_reader.hpp"
#include "secure_frontend/token_verifier.hpp"
#include "secure_frontend/tokenizer_pack.hpp"

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

int run(const FrontendConfig& config, const bool expert) {
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
  std::vector<secure_frontend::ApiModel> models;
  models.reserve(launch.served_models.size());
  for (const auto& id : launch.served_models) models.push_back({.id = id, .owned_by = "local"});

  secure_frontend::EngineStdioProcess engine;
  const secure_frontend::EngineCommand command{.executable = config.engine.executable.path(),
                                               .arguments = std::move(*engine_arguments), .environment = {}};
  const auto protocol_flavor = glm ? secure_frontend::EngineProtocolFlavor::lighttransport_glm53
                                   : secure_frontend::EngineProtocolFlavor::strata_0143;
  secure_frontend::EngineProtocolClient protocol(engine, {}, protocol_flavor);
  const auto chat_profile = glm ? secure_frontend::NativeChatProfile::glm53 : secure_frontend::NativeChatProfile::qwen;
  secure_frontend::ChatExecutionService chat(protocol, secure_frontend::chat_execution_limits(config), chat_profile);

  const std::string authority = host_header(listener);
  secure_frontend::HttpPolicy policy{.allowed_hosts = {authority}, .same_origin_origins = {"http://" + authority},
                                     .cors_allowed_origins = {}, .cors_enabled = false};
  const auto engine_state = [&engine, &chat]() -> std::string_view {
    if (!engine.running()) return "failed";
    switch (chat.health()) {
      case secure_frontend::EngineHealth::starting: return "starting";
      case secure_frontend::EngineHealth::ready: return "ready";
      case secure_frontend::EngineHealth::generating: return "generating";
      case secure_frontend::EngineHealth::failed: return "failed";
    }
    return "failed";
  };
  std::string_view health_snapshot{"failed"};
  const secure_frontend::ApiRouter router(
      [&engine_state, &health_snapshot] { health_snapshot = engine_state(); return health_snapshot != "failed"; },
      [models] { return models; }, [&health_snapshot] { return health_snapshot; });
  auto server = secure_frontend::HttpSocketServer::bind(
      listener, std::move(policy), secure_frontend::make_bearer_validator(verifier),
      [&router, &chat, &engine, &tokenizer, &model_id, &schema_limits](
          const std::string_view method, const std::string_view target, const std::string_view body) {
        if (method == "GET") return router.dispatch(method, target);
        if (method != "POST" || target != "/v1/chat/completions") return json_error(404, "Not Found");
        if (!engine.running()) return json_error(503, "Service Unavailable");
        const auto request = secure_frontend::parse_chat_completion_request(body, schema_limits);
        if (!request || request->model != model_id) return json_error(400, "Bad Request");
        const auto result = chat.execute(*request, *tokenizer);
        const auto* completion = std::get_if<secure_frontend::ChatExecutionResult>(&result);
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
  // engine child behind (CFG-01).
  if (engine.start(command).has_value()) { std::cerr << "Unable to start local engine.\n"; return EXIT_FAILURE; }
  std::cout << "Secure server listening on http://" << authority << " (authenticated; Ctrl-C to stop)\n";
  std::cout.flush();
  for (;;) {
    std::string error;
    if (!server->serve_one(&error) && server->listener_failed()) {
      std::cerr << "listener stopped: " << error << '\n';
      return EXIT_FAILURE;
    }
  }
}

}  // namespace

int main(int argc, char* argv[]) {
#if defined(SECURE_FRONTEND_TEST_HOOKS)
  std::cerr << "warning: test hooks compiled in (" << secure_frontend::kTestHooksMarker << "); never ship this binary\n";
#endif
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
  if (invocation.command == secure_frontend::ServerCommand::check) return check(*config, overridden, invocation.expert);
  return run(*config, invocation.expert);
}

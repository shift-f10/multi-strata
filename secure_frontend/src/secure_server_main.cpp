#include "secure_frontend/api_router.hpp"
#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/engine_stdio_process.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/model_inventory.hpp"
#include "secure_frontend/process_defaults.hpp"
#include "secure_frontend/server_cli.hpp"
#include "secure_frontend/subsystem_limits.hpp"
#include "secure_frontend/token_reader.hpp"
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

class TokenVerifier final {
 public:
  explicit TokenVerifier(std::string token) : token_(std::move(token)) {}
  ~TokenVerifier() {
    volatile char* bytes = token_.empty() ? nullptr : token_.data();
    for (std::size_t index = 0; bytes != nullptr && index < token_.size(); ++index) bytes[index] = '\0';
  }
  [[nodiscard]] bool matches(const std::string_view candidate) const {
    return secure_frontend::constant_time_token_equals(candidate, token_);
  }

 private:
  std::string token_;
};

secure_frontend::HttpResponse json_error(const int status, const char* message) {
  return {.status = status,
          .headers = {{"Content-Type", "application/json; charset=utf-8"}, {"Cache-Control", "no-store"}},
          .body = std::string{"{\"error\":\""} + message + "\"}\n"};
}

secure_frontend::TokenReadResult read_configured_token(const FrontendConfig& config) {
  return secure_frontend::read_token(config.token, config.roots.secret.has_value() ? config.roots.secret->path()
                                                                                   : std::filesystem::path{"."});
}

int check(const FrontendConfig& config, const std::vector<std::string>& overridden) {
  std::cout << "Configuration is valid.\n" << secure_frontend::describe(config);
  for (const auto& key : overridden) std::cout << key << ": the command line overrides the config file\n";
  const auto token = read_configured_token(config);
  if (const auto* error = std::get_if<secure_frontend::TokenReadError>(&token)) {
    std::cout << "token: unavailable: " << error->message << '\n';
    return EXIT_FAILURE;
  }
  std::cout << "token: available (value not shown)\n";
  return EXIT_SUCCESS;
}

int run(const FrontendConfig& config) {
  auto token_result = read_configured_token(config);
  auto* token = std::get_if<std::string>(&token_result);
  if (token == nullptr) { std::cerr << "Unable to read API token.\n"; return EXIT_FAILURE; }
  auto verifier = std::make_shared<TokenVerifier>(std::move(*token));

  const secure_frontend::Config listener = secure_frontend::listener_config(config);
  // Derived once, before bind/spawn; each subsystem keeps its own const copy.
  const auto schema_limits = secure_frontend::chat_schema_limits(config);
  const auto listener_limits = secure_frontend::http_socket_server_limits(config);
  const auto tokenizer_result = secure_frontend::load_local_tokenizer_pack(config.roots.tokenizer_pack.path());
  const auto* tokenizer = std::get_if<secure_frontend::TokenizerPack>(&tokenizer_result);
  if (tokenizer == nullptr) { std::cerr << "Unable to load local tokenizer pack.\n"; return EXIT_FAILURE; }
  const auto models_result = secure_frontend::enumerate_local_models(config.roots.models.path());
  const auto* manifests = std::get_if<std::vector<secure_frontend::ModelManifest>>(&models_result);
  if (manifests == nullptr) { std::cerr << "Unable to inventory local models.\n"; return EXIT_FAILURE; }
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
      listener, std::move(policy), [verifier](const std::string_view supplied) { return verifier->matches(supplied); },
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

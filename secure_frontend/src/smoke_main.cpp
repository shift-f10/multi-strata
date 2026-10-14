#include "secure_frontend/api_router.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/model_inventory.hpp"
#include "secure_frontend/process_defaults.hpp"
#include "secure_frontend/secret_source.hpp"
#include "secure_frontend/token_reader.hpp"
#include "secure_frontend/token_verifier.hpp"

#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace {

struct Options final { std::string key_env; std::filesystem::path models_root; std::string host{"127.0.0.1"}; std::uint32_t port{8080}; };

std::optional<Options> parse(int argc, char** argv) {
  Options options;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc) return std::nullopt;
    const std::string_view flag{argv[index]}; const std::string_view value{argv[index + 1]};
    if (flag == "--api-key-env") options.key_env = value;
    else if (flag == "--models-root") options.models_root = std::string{value};
    else if (flag == "--host") options.host = value;
    else if (flag == "--port") {
      const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), options.port);
      if (error != std::errc{} || end != value.data() + value.size()) return std::nullopt;
    } else return std::nullopt;
  }
  if (options.key_env.empty() || options.models_root.empty()) return std::nullopt;
  return options;
}

void usage() { std::cerr << "usage: secure-frontend-smoke --api-key-env NAME --models-root PATH [--host IP] [--port PORT]\n"; }

}  // namespace

int main(int argc, char** argv) {
  secure_frontend::install_process_defaults();
  const auto options = parse(argc, argv);
  if (!options.has_value()) { usage(); return EXIT_FAILURE; }
  const auto source_result = secure_frontend::make_environment_secret_source(options->key_env);
  const auto* source = std::get_if<secure_frontend::SecretSource>(&source_result);
  if (source == nullptr) { std::cerr << "invalid API-key environment variable name\n"; return EXIT_FAILURE; }
  auto token_result = secure_frontend::read_token(*source, {});
  auto* token = std::get_if<secure_frontend::SecretBytes>(&token_result);
  if (token == nullptr) { std::cerr << "API key is unavailable\n"; return EXIT_FAILURE; }
  const auto verifier = std::make_shared<const secure_frontend::TokenVerifier>(std::move(*token));
  const auto config_result = secure_frontend::validate_config({.host = options->host, .port = options->port,
      .api_key = std::string{"provided"}, .allow_remote = false, .allow_wildcard_bind = false});
  const auto* config = std::get_if<secure_frontend::Config>(&config_result);
  if (config == nullptr) { std::cerr << "invalid listener configuration\n"; return EXIT_FAILURE; }
  const std::string host_header = options->host.find(':') == std::string::npos
      ? options->host + ":" + std::to_string(options->port)
      : "[" + options->host + "]:" + std::to_string(options->port);
  const auto bind_address = secure_frontend::parse_listener_address(config->host);
  if (!bind_address.has_value()) { std::cerr << "invalid listener configuration\n"; return EXIT_FAILURE; }
  const std::filesystem::path models_root = options->models_root;
  const secure_frontend::ApiRouter router(
      [] { return true; },
      [models_root] {
        std::vector<secure_frontend::ApiModel> models;
        const auto inventory = secure_frontend::enumerate_local_models(models_root);
        if (const auto* entries = std::get_if<std::vector<secure_frontend::ModelManifest>>(&inventory)) {
          for (const auto& entry : *entries) models.push_back({.id = entry.id, .owned_by = entry.owned_by});
        }
        return models;
      });
  std::string error;
  // Same allowlist as before ({host_header}, kept as an alias), no CORS.
  auto server = secure_frontend::HttpSocketServer::bind(*config,
      secure_frontend::make_http_policy(*bind_address, config->port, {host_header}, {}),
      secure_frontend::make_bearer_validator(verifier),
      [router](std::string_view method, std::string_view target, std::string_view) {
        return router.dispatch(method, target);
      }, &error);
  if (!server.has_value()) { std::cerr << "listener setup failed: " << error << '\n'; return EXIT_FAILURE; }
  std::cout << "secure frontend smoke server listening on http://" << host_header << " (local models only)\n";
  for (;;) {
    if (!server->serve_one(&error) && server->listener_failed()) {
      std::cerr << "listener stopped: " << error << '\n';
      return EXIT_FAILURE;
    }
    // Any other failure was one client's; keep serving.
  }
}

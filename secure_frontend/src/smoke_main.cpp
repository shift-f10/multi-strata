#include "secure_frontend/api_router.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/model_inventory.hpp"
#include "secure_frontend/secret_source.hpp"
#include "secure_frontend/token_reader.hpp"

#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
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
  const auto options = parse(argc, argv);
  if (!options.has_value()) { usage(); return EXIT_FAILURE; }
  const auto source_result = secure_frontend::make_environment_secret_source(options->key_env);
  const auto* source = std::get_if<secure_frontend::SecretSource>(&source_result);
  if (source == nullptr) { std::cerr << "invalid API-key environment variable name\n"; return EXIT_FAILURE; }
  const auto token_result = secure_frontend::read_token(*source, {});
  const auto* token = std::get_if<std::string>(&token_result);
  if (token == nullptr) { std::cerr << "API key is unavailable\n"; return EXIT_FAILURE; }
  const auto config_result = secure_frontend::validate_config({.host = options->host, .port = options->port,
      .api_key = std::string{"provided"}, .allow_remote = false, .allow_wildcard_bind = false});
  const auto* config = std::get_if<secure_frontend::Config>(&config_result);
  if (config == nullptr) { std::cerr << "invalid listener configuration\n"; return EXIT_FAILURE; }
  const std::string host_header = options->host.find(':') == std::string::npos
      ? options->host + ":" + std::to_string(options->port)
      : "[" + options->host + "]:" + std::to_string(options->port);
  const std::string origin = "http://" + host_header;
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
  auto server = secure_frontend::HttpSocketServer::bind(*config, {.allowed_hosts = {host_header},
      .same_origin_origins = {origin}, .cors_allowed_origins = {}, .cors_enabled = false},
      [expected = *token](std::string_view candidate) {
        return secure_frontend::constant_time_token_equals(candidate, expected);
      }, [router](std::string_view method, std::string_view target, std::string_view) {
        return router.dispatch(method, target);
      }, &error);
  if (!server.has_value()) { std::cerr << "listener setup failed: " << error << '\n'; return EXIT_FAILURE; }
  std::cout << "secure frontend smoke server listening on http://" << host_header << " (local models only)\n";
  while (server->serve_one(&error)) {}
  std::cerr << "listener stopped: " << error << '\n';
  return EXIT_FAILURE;
}

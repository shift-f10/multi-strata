#include "secure_frontend/api_router.hpp"
#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/engine_stdio_process.hpp"
#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/model_inventory.hpp"
#include "secure_frontend/process_defaults.hpp"
#include "secure_frontend/secret_source.hpp"
#include "secure_frontend/token_reader.hpp"
#include "secure_frontend/tokenizer_pack.hpp"

#include <algorithm>
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
#include <vector>

namespace {

using secure_frontend::SecretSource;

struct Options final {
  secure_frontend::NativeChatProfile profile{secure_frontend::NativeChatProfile::qwen};
  bool profile_specified{false};
  std::optional<std::string> host;
  std::optional<std::uint32_t> port;
  std::optional<std::string> token_environment;
  std::optional<std::string> token_file;
  std::optional<std::filesystem::path> secret_root;
  std::optional<std::filesystem::path> models_root;
  std::optional<std::filesystem::path> tokenizer_pack;
  std::optional<std::filesystem::path> engine;
  std::optional<std::string> model_id;
  std::vector<std::string> engine_arguments;
  bool allow_remote{false};
  bool allow_wildcard_bind{false};
};

void usage(std::ostream& output) {
  output << "Usage: strata-secure-server --models-root PATH --tokenizer-pack PATH --engine PATH "
            "--model-id ID [--engine-arg ARG ...] "
            "(--token-env NAME | --token-file RELATIVE --secret-root PATH) [options]\n"
            "\n"
            "Options:\n"
            "  --profile qwen|glm53     Fixed local prompt profile (default: qwen)\n"
            "  --host IP                 Bind IP literal (default: 127.0.0.1)\n"
            "  --port PORT               TCP port 1-65535 (default: 8080)\n"
            "  --allow-remote            Required for every non-loopback bind\n"
            "  --allow-wildcard-bind     Also required for 0.0.0.0 or ::\n"
            "  --models-root PATH        Existing local directory of .gguf files\n"
            "  --model-id ID             Local model ID selected for this engine process\n"
            "  --tokenizer-pack PATH     Local directory with vocab.json, merges.txt, token_type.json\n"
            "  --engine PATH             Local Strata engine executable\n"
            "  --engine-arg ARG          Optional literal engine argument; repeat as needed.\n"
            "                            --native, --pack, --serve, --batch, --slots and\n"
            "                            --vision are rejected\n"
            "  --token-env NAME          Read bearer token from one environment variable\n"
            "  --token-file RELATIVE     Read token from owner-only file below --secret-root\n"
            "  --secret-root PATH        Required with --token-file\n"
            "  --help                     Print this help\n"
            "\n"
            "The server starts exactly one local --serve child with no shell and an empty "
            "environment allowlist. It serves authenticated GET /health, GET /v1/models, "
            "and non-streaming text-only POST /v1/chat/completions. Streaming, tools, "
            "downloads, remote URLs, telemetry, and MCP are disabled.\n"
            "\n"
            "The engine loads exactly the model named by --model-id: this server supplies "
            "--native <model> from the local inventory, so the model path is never passed "
            "with --engine-arg.\n"
            "\n"
            "The glm53 profile requires a separately built LightTransport-compatible "
            "strata-glm-decode engine. Supply its required positional engine arguments "
            "unchanged using repeated --engine-arg; this server adds --serve and --native <model>.\n";
}

bool next_value(const int argc, char* argv[], int* index, std::string* output, std::string* error) {
  if (*index + 1 >= argc) {
    *error = std::string{"missing value for "} + argv[*index];
    return false;
  }
  *output = argv[++*index];
  if (output->empty()) {
    *error = "empty command-line option value";
    return false;
  }
  return true;
}

bool parse_port(const std::string_view value, std::uint32_t* output) {
  std::uint32_t parsed = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
  if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) return false;
  *output = parsed;
  return true;
}

bool parse_profile(const std::string_view value, secure_frontend::NativeChatProfile* output) {
  if (value == "qwen") {
    *output = secure_frontend::NativeChatProfile::qwen;
    return true;
  }
  if (value == "glm53") {
    *output = secure_frontend::NativeChatProfile::glm53;
    return true;
  }
  return false;
}

bool parse_options(const int argc, char* argv[], Options* options, bool* help, std::string* error) {
  *help = false;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument{argv[index]};
    if (argument == "--help") {
      *help = true;
      return true;
    }
    if (argument == "--allow-remote") {
      if (options->allow_remote) { *error = "duplicate --allow-remote"; return false; }
      options->allow_remote = true;
      continue;
    }
    if (argument == "--allow-wildcard-bind") {
      if (options->allow_wildcard_bind) { *error = "duplicate --allow-wildcard-bind"; return false; }
      options->allow_wildcard_bind = true;
      continue;
    }
    std::string value;
    if (!next_value(argc, argv, &index, &value, error)) return false;
    if (argument == "--host") {
      if (options->host.has_value()) { *error = "duplicate --host"; return false; }
      options->host = std::move(value);
    } else if (argument == "--profile") {
      if (options->profile_specified || !parse_profile(value, &options->profile)) {
        *error = "--profile must be exactly qwen or glm53 and may be supplied once";
        return false;
      }
      options->profile_specified = true;
    } else if (argument == "--port") {
      std::uint32_t port = 0;
      if (options->port.has_value() || !parse_port(value, &port)) {
        *error = "--port must be an unsigned decimal integer";
        return false;
      }
      options->port = port;
    } else if (argument == "--models-root") {
      if (options->models_root.has_value()) { *error = "duplicate --models-root"; return false; }
      options->models_root = std::filesystem::path{std::move(value)};
    } else if (argument == "--tokenizer-pack") {
      if (options->tokenizer_pack.has_value()) { *error = "duplicate --tokenizer-pack"; return false; }
      options->tokenizer_pack = std::filesystem::path{std::move(value)};
    } else if (argument == "--engine") {
      if (options->engine.has_value()) { *error = "duplicate --engine"; return false; }
      options->engine = std::filesystem::path{std::move(value)};
    } else if (argument == "--model-id") {
      if (options->model_id.has_value()) { *error = "duplicate --model-id"; return false; }
      options->model_id = std::move(value);
    } else if (argument == "--engine-arg") {
      options->engine_arguments.push_back(std::move(value));
    } else if (argument == "--token-env") {
      if (options->token_environment.has_value()) { *error = "duplicate --token-env"; return false; }
      options->token_environment = std::move(value);
    } else if (argument == "--token-file") {
      if (options->token_file.has_value()) { *error = "duplicate --token-file"; return false; }
      options->token_file = std::move(value);
    } else if (argument == "--secret-root") {
      if (options->secret_root.has_value()) { *error = "duplicate --secret-root"; return false; }
      options->secret_root = std::filesystem::path{std::move(value)};
    } else {
      *error = std::string{"unknown option: "} + std::string{argument};
      return false;
    }
  }
  if (!options->models_root || !options->tokenizer_pack || !options->engine || !options->model_id) {
    *error = "--models-root, --tokenizer-pack, --engine, and --model-id are required";
    return false;
  }
  if (options->token_environment.has_value() == options->token_file.has_value()) {
    *error = "supply exactly one of --token-env or --token-file";
    return false;
  }
  if (options->token_file.has_value() != options->secret_root.has_value()) {
    *error = "--token-file and --secret-root must be supplied together";
    return false;
  }
  if (!std::holds_alternative<std::string>(secure_frontend::validate_model_id(*options->model_id))) {
    *error = "--model-id is not portable or valid";
    return false;
  }
  return true;
}

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

int run(const Options& options) {
  const auto source_result = options.token_environment ? secure_frontend::make_environment_secret_source(*options.token_environment)
                                                        : secure_frontend::make_protected_file_secret_source(*options.token_file);
  const auto* source = std::get_if<SecretSource>(&source_result);
  if (source == nullptr) { std::cerr << "Invalid token source.\n"; return EXIT_FAILURE; }
  auto token_result = secure_frontend::read_token(*source, options.secret_root.value_or(std::filesystem::path{"."}));
  auto* token = std::get_if<std::string>(&token_result);
  if (token == nullptr) { std::cerr << "Unable to read API token.\n"; return EXIT_FAILURE; }
  auto verifier = std::make_shared<TokenVerifier>(std::move(*token));

  const secure_frontend::ConfigInput input{.host = options.host, .port = options.port,
                                             .api_key = std::string{"configured"}, .allow_remote = options.allow_remote,
                                             .allow_wildcard_bind = options.allow_wildcard_bind};
  const auto config_result = secure_frontend::validate_config(input);
  const auto* config = std::get_if<secure_frontend::Config>(&config_result);
  if (config == nullptr) { std::cerr << "Invalid listener configuration.\n"; return EXIT_FAILURE; }

  const auto tokenizer_result = secure_frontend::load_local_tokenizer_pack(*options.tokenizer_pack);
  const auto* tokenizer = std::get_if<secure_frontend::TokenizerPack>(&tokenizer_result);
  if (tokenizer == nullptr) { std::cerr << "Unable to load local tokenizer pack.\n"; return EXIT_FAILURE; }
  const auto models_result = secure_frontend::enumerate_local_models(*options.models_root);
  const auto* manifests = std::get_if<std::vector<secure_frontend::ModelManifest>>(&models_result);
  if (manifests == nullptr) { std::cerr << "Unable to inventory local models.\n"; return EXIT_FAILURE; }
  const auto selected = std::find_if(manifests->begin(), manifests->end(), [&options](const auto& model) {
    return model.id == *options.model_id;
  });
  if (selected == manifests->end()) { std::cerr << "Selected model is not present in --models-root.\n"; return EXIT_FAILURE; }
  auto engine_arguments_result = secure_frontend::build_engine_arguments(*selected, *options.models_root, options.engine_arguments);
  auto* engine_arguments = std::get_if<std::vector<std::string>>(&engine_arguments_result);
  if (engine_arguments == nullptr) { std::cerr << "Engine arguments rejected.\n"; return EXIT_FAILURE; }
  std::vector<secure_frontend::ApiModel> models;
  models.reserve(manifests->size());
  for (const auto& manifest : *manifests) models.push_back({.id = manifest.id, .owned_by = manifest.owned_by});

  secure_frontend::EngineStdioProcess engine;
  const secure_frontend::EngineCommand command{.executable = *options.engine, .arguments = std::move(*engine_arguments), .environment = {}};
  if (engine.start(command).has_value()) { std::cerr << "Unable to start local engine.\n"; return EXIT_FAILURE; }
  const auto protocol_flavor = options.profile == secure_frontend::NativeChatProfile::glm53
      ? secure_frontend::EngineProtocolFlavor::lighttransport_glm53
      : secure_frontend::EngineProtocolFlavor::strata_0143;
  secure_frontend::EngineProtocolClient protocol(engine, {}, protocol_flavor);
  secure_frontend::ChatExecutionService chat(protocol, {}, options.profile);

  const std::string authority = host_header(*config);
  secure_frontend::HttpPolicy policy{.allowed_hosts = {authority}, .same_origin_origins = {"http://" + authority},
                                     .cors_allowed_origins = {}, .cors_enabled = false};
  const secure_frontend::ApiRouter router(
      [&engine, &chat] { return engine.running() && chat.health() != secure_frontend::EngineHealth::failed; },
      [models] { return models; });
  auto server = secure_frontend::HttpSocketServer::bind(
      *config, std::move(policy), [verifier](const std::string_view supplied) { return verifier->matches(supplied); },
      [&router, &chat, &engine, &tokenizer, &options](const std::string_view method, const std::string_view target,
                                                        const std::string_view body) {
        if (method == "GET") return router.dispatch(method, target);
        if (method != "POST" || target != "/v1/chat/completions") return json_error(404, "Not Found");
        if (!engine.running()) return json_error(503, "Service Unavailable");
        const auto request = secure_frontend::parse_chat_completion_request(body);
        if (!request || request->model != *options.model_id) return json_error(400, "Bad Request");
        const auto result = chat.execute(*request, *tokenizer);
        const auto* completion = std::get_if<secure_frontend::ChatExecutionResult>(&result);
        if (completion == nullptr) return json_error(503, "Service Unavailable");
        const auto response = secure_frontend::render_chat_completion_response(*request, completion->text);
        if (!response) return json_error(503, "Service Unavailable");
        return secure_frontend::HttpResponse{.status = 200,
                                              .headers = {{"Content-Type", "application/json; charset=utf-8"}, {"Cache-Control", "no-store"}},
                                              .body = *response};
      },
      nullptr);
  if (!server) { std::cerr << "Unable to bind secure listener.\n"; return EXIT_FAILURE; }
  std::cout << "Secure server listening on http://" << authority << " (authenticated; Ctrl-C to stop)\n";
  std::cout.flush();
  for (;;) {
    std::string error;
    if (!server->serve_one(&error) && server->listener_failed()) {
      std::cerr << "listener stopped: " << error << '\n';
      return EXIT_FAILURE;
    }
    // Any other failure was one client's; keep serving.
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  secure_frontend::install_process_defaults();
  Options options;
  bool help = false;
  std::string error;
  if (!parse_options(argc, argv, &options, &help, &error)) {
    std::cerr << "Error: " << error << '\n';
    usage(std::cerr);
    return EXIT_FAILURE;
  }
  if (help) { usage(std::cout); return EXIT_SUCCESS; }
  return run(options);
}

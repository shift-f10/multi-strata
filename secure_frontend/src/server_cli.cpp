#include "secure_frontend/server_cli.hpp"

#include "secure_frontend/config_file.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace secure_frontend {
namespace {

enum class FlagKind { boolean, integer, string, append, token_env, token_file };
struct FlagSpec final {
  std::string_view flag;
  std::string_view key;
  FlagKind kind;
};

constexpr std::array<FlagSpec, 16> kFlags{{
    {"--host", "listener.host", FlagKind::string},
    {"--port", "listener.port", FlagKind::integer},
    {"--allow-remote", "listener.allow_remote", FlagKind::boolean},
    {"--allow-wildcard-bind", "listener.allow_wildcard_bind", FlagKind::boolean},
    {"--profile", "engine.profile", FlagKind::string},
    {"--models-root", "roots.models", FlagKind::string},
    {"--tokenizer-pack", "roots.tokenizer_pack", FlagKind::string},
    {"--engine", "engine.executable", FlagKind::string},
    {"--model-id", "engine.model_id", FlagKind::string},
    {"--engine-arg", "engine.args", FlagKind::append},
    {"--token-env", "token.source", FlagKind::token_env},
    {"--token-file", "token.source", FlagKind::token_file},
    {"--secret-root", "roots.secret", FlagKind::string},
    {"--state-dir", "roots.state", FlagKind::string},
    {"--engine-lib-dir", "engine.lib_dirs", FlagKind::append},
    {"--gpu", "engine.gpu", FlagKind::string},
}};

const FlagSpec* find_flag(const std::string_view argument) {
  for (const auto& spec : kFlags) if (spec.flag == argument) return &spec;
  return nullptr;
}

bool all_digits(const std::string& value) {
  return !value.empty() && value.size() <= 18U &&
         value.find_first_not_of("0123456789") == std::string::npos;
}

}  // namespace

std::string safe_option_name(const std::string_view argument) {
  const std::string_view name = argument.substr(0, argument.find('='));
  std::string out;
  for (const char c : name) {
    if (out.size() == 64U) { out += "..."; break; }
    const auto byte = static_cast<unsigned char>(c);
    out.push_back(byte >= 0x21U && byte <= 0x7eU ? c : '?');
  }
  return out;
}

std::variant<ServerInvocation, CliError> parse_server_command_line(const int argc, const char* const* argv) {
  ServerInvocation invocation;
  auto& entries = invocation.flags.entries;
  int first = 1;
  if (argc > 1 && std::string_view{argv[1]} == "init") {
    invocation.command = ServerCommand::init;
    first = 2;
  }
  for (int index = first; index < argc; ++index) {
    const std::string_view argument{argv[index]};
    if (argument == "--help") { invocation.command = ServerCommand::help; return invocation; }
    if (argument == "--check") {
      if (invocation.command == ServerCommand::init) return CliError{"--check cannot be combined with init"};
      if (invocation.command == ServerCommand::check) return CliError{"duplicate --check"};
      invocation.command = ServerCommand::check;
      continue;
    }
    if (argument == "--force") {
      if (invocation.command != ServerCommand::init) return CliError{"--force is only valid with init"};
      if (invocation.force) return CliError{"duplicate --force"};
      invocation.force = true;
      continue;
    }
    if (argument == "--config") {
      if (index + 1 >= argc) return CliError{"missing value for --config"};
      if (invocation.config_file.has_value()) return CliError{"duplicate --config"};
      const std::string value{argv[++index]};
      if (value.empty()) return CliError{"empty value for --config"};
      invocation.config_file = std::filesystem::path{value};
      continue;
    }
    const FlagSpec* spec = find_flag(argument);
    if (spec == nullptr) {
      const auto equals = argument.find('=');
      if (equals != std::string_view::npos && find_flag(argument.substr(0, equals)) != nullptr) {
        return CliError{"write " + safe_option_name(argument) + " VALUE as two arguments"};
      }
      if (argument.rfind("--", 0) == 0) return CliError{"unknown option: " + safe_option_name(argument)};
      return CliError{"unexpected argument (not shown); every value must follow its option"};
    }
    const std::string key{spec->key};
    if (spec->kind == FlagKind::boolean) {
      if (entries.find(key) != entries.end()) return CliError{"duplicate " + std::string{spec->flag}};
      entries[key] = ConfigDraftEntry{true, ConfigSource::command_line};
      continue;
    }
    if (index + 1 >= argc) return CliError{"missing value for " + std::string{spec->flag}};
    const std::string value{argv[++index]};
    if (value.empty()) return CliError{"empty value for " + std::string{spec->flag}};
    switch (spec->kind) {
      case FlagKind::append: {
        auto [it, inserted] = entries.try_emplace(key, ConfigDraftEntry{std::vector<std::string>{}, ConfigSource::command_line});
        (void)inserted;
        std::get<std::vector<std::string>>(it->second.value).push_back(value);
        break;
      }
      case FlagKind::token_env:
      case FlagKind::token_file:
        if (entries.find(key) != entries.end()) return CliError{"supply at most one of --token-env or --token-file"};
        entries[key] = ConfigDraftEntry{(spec->kind == FlagKind::token_env ? "env:" : "file:") + value,
                                        ConfigSource::command_line};
        break;
      case FlagKind::integer:
        if (entries.find(key) != entries.end()) return CliError{"duplicate " + std::string{spec->flag}};
        if (all_digits(value)) entries[key] = ConfigDraftEntry{static_cast<std::int64_t>(std::stoll(value)), ConfigSource::command_line};
        else entries[key] = ConfigDraftEntry{value, ConfigSource::command_line};
        break;
      case FlagKind::string:
      case FlagKind::boolean:
        if (entries.find(key) != entries.end()) return CliError{"duplicate " + std::string{spec->flag}};
        entries[key] = ConfigDraftEntry{value, ConfigSource::command_line};
        break;
    }
  }
  if (invocation.command == ServerCommand::init && !invocation.config_file.has_value()) {
    return CliError{"init requires --config FILE"};
  }
  return invocation;
}

std::string server_usage() {
  std::string text =
      "Usage: strata-secure-server [--config FILE] [options]\n"
      "       strata-secure-server --check [--config FILE] [options]\n"
      "       strata-secure-server init --config FILE [--force] [options]\n"
      "\n"
      "Configuration comes from built-in defaults, then FILE (strict JSON; see the\n"
      "README's key table), then the options below. An option wins over the file and\n"
      "--check reports every key where that happened.\n"
      "\n"
      "  --config FILE            Read configuration keys from FILE\n"
      "  --check                  Validate everything, print the effective configuration\n"
      "                           (never the token) and exit\n"
      "  --help                   Print this help\n"
      "\n"
      "init writes FILE (owner-only, atomic) from the options given and generates a\n"
      "43-character token at token.source below roots.secret (default: FILE's\n"
      "directory). It refuses to replace either without --force. The token is never\n"
      "printed; the product's `strata key show` will display it.\n"
      "\n"
      "Options (each sets one configuration key):\n";
  for (const auto& spec : kFlags) {
    std::string row = "  " + std::string{spec.flag};
    if (spec.kind != FlagKind::boolean) row += " VALUE";
    row.resize(std::max<std::size_t>(row.size() + 1U, 27U), ' ');
    row += std::string{spec.key};
    if (spec.kind == FlagKind::token_env) row += " = env:VALUE";
    if (spec.kind == FlagKind::token_file) row += " = file:VALUE";
    if (spec.kind == FlagKind::append) row += " (repeatable)";
    text += row + "\n";
  }
  text +=
      "\n"
      "The server supervises one local --serve child at a time (it waits for READY,\n"
      "restarts a failed engine with backoff, then stops trying until it is restarted)\n"
      "with no shell and a fixed environment (PATH, the library path, temp and CUDA\n"
      "cache directories below --state-dir; on Windows also SystemRoot, WINDIR,\n"
      "SystemDrive, NUMBER_OF_PROCESSORS); nothing is inherited from this server's\n"
      "environment. It serves authenticated GET /health, GET /v1/models and\n"
      "non-streaming text-only POST /v1/chat/completions.\n"
      "Streaming, tools, downloads, remote URLs, telemetry and MCP are disabled. With\n"
      "the qwen profile the frontend supplies --native from engine.model_id; the\n"
      "operator passes --pack and other weight flags with --engine-arg. --engine-arg\n"
      "refuses the frontend-owned --native, --serve and --gpu: GPUs are chosen only\n"
      "with --gpu, passed as the engine's own --gpu argument (strata family: no GPU\n"
      "variable in the engine environment).\n";
  return text;
}

ConfigValidationResult load_server_config(const ServerInvocation& invocation, std::vector<std::string>* overridden) {
  FrontendConfigDraft draft = invocation.flags;
  if (invocation.config_file.has_value()) {
    auto file = read_config_file(*invocation.config_file);
    if (auto* errors = std::get_if<ConfigErrors>(&file)) return *errors;
    draft = merge_drafts(std::move(std::get<FrontendConfigDraft>(file)), invocation.flags);
  }
  if (overridden != nullptr) *overridden = draft.overridden_by_command_line;
  return validate(draft);
}

}  // namespace secure_frontend

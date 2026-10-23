// Model launcher (plan docs/superpowers/plans/2026-10-23-model-launcher.md Tasks 3-4; spec §5):
// the real strata-secure-server booted with model cards over the supervision fake engine. A
// card starts from the API with typed options, a switch waits for the generation in flight, a
// failed start leaves the server usable, one switch runs at a time, and the page's options are
// remembered.
#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/json.hpp"
#include "secure_frontend/model_launcher.hpp"
#include "support/config_json.hpp"
#include "support/fake_engine_dump.hpp"
#include "support/server_harness.hpp"
#include "support/test_paths.hpp"
#include "support/test_support.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace {

int failures = 0;
void expect(const bool value, const std::string_view message) {
  if (!value) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

using test_support::CardOptions;
using test_support::HttpResult;
using test_support::ServerOptions;
using test_support::ServerProcess;

constexpr auto kRequest = std::chrono::seconds(10);

std::string chat_body(const std::string& model) {
  return R"({"model":")" + model + R"(","messages":[{"role":"user","content":"Hi"}],"max_tokens":2})";
}

std::optional<HttpResult> call(const ServerProcess& server, const std::string_view method, const std::string_view target,
                               const std::string_view body = "", const std::chrono::milliseconds timeout = kRequest) {
  return test_support::http_request(server.port(), method, target, body, timeout);
}

std::string shown(const std::optional<HttpResult>& result) {
  return result ? std::to_string(result->status) + " " + result->body : std::string{"(no answer)"};
}

bool has_code(const std::optional<HttpResult>& result, const int status, const std::string_view code) {
  return result && result->status == status && result->body.find("\"code\":\"" + std::string{code} + "\"") != std::string::npos;
}

// The state of card `name` in GET /v1/strata/models ("" when the list cannot be read).
std::string card_state(const ServerProcess& server, const std::string& name, std::string* error = nullptr) {
  const auto listed = call(server, "GET", "/v1/strata/models");
  if (!listed || listed->status != 200) return {};
  const auto parsed = secure_frontend::parse_json(
      listed->body, {.max_bytes = 1U << 20U, .max_depth = 16U, .max_container_entries = 4096U, .max_string_bytes = 4096U,
                     .allow_fractions = true});
  const auto* root = std::get_if<secure_frontend::JsonValue>(&parsed);
  if (root == nullptr || root->if_object() == nullptr) return {};
  for (const auto& member : *root->if_object()) {
    if (member.key != "data" || member.value.if_array() == nullptr) continue;
    for (const auto& card : *member.value.if_array()) {
      if (card.if_object() == nullptr) continue;
      std::string card_name;
      std::string state;
      for (const auto& field : *card.if_object()) {
        if (field.key == "name" && field.value.if_string()) card_name = *field.value.if_string();
        if (field.key == "state" && field.value.if_string()) state = *field.value.if_string();
        if (field.key == "error" && field.value.if_string() && error != nullptr) *error = *field.value.if_string();
      }
      if (card_name == name) return state;
    }
  }
  return {};
}

bool wait_for_card(const ServerProcess& server, const std::string& name, const std::string& state,
                   const std::chrono::milliseconds timeout = std::chrono::seconds(30)) {
  const auto until = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < until) {
    if (card_state(server, name) == state) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  return card_state(server, name) == state;
}

std::vector<std::string> dumped_argv(const std::filesystem::path& file) {
  const auto dump = test_support::read_dump_file(file, std::chrono::seconds(5));
  return dump ? dump->argv : std::vector<std::string>{};
}

std::string joined(const std::vector<std::string>& argv) {
  std::string out;
  for (const auto& argument : argv) out += (out.empty() ? "" : " ") + argument;
  return out.empty() ? std::string{"(no dump)"} : out;
}

bool has_pair(const std::vector<std::string>& argv, const std::string& flag, const std::string& value) {
  for (std::size_t i = 0; i + 1U < argv.size(); ++i) {
    if (argv[i] == flag && argv[i + 1U] == value) return true;
  }
  return false;
}

// Two qwen cards over the fake engine: Alpha offers context, KV precision and KV streaming,
// Beta none. `alpha_args` / `beta_args` are their fixed engine arguments.
ServerOptions two_cards(std::vector<std::string> alpha_args = {}, std::vector<std::string> beta_args = {},
                        std::map<std::string, std::string> literals = {{"models.control", "true"}}) {
  ServerOptions options;
  options.model_cards = {
      CardOptions{.name = "Alpha",
                  .profile = "qwen",
                  .engine_args = std::move(alpha_args),
                  .options_json = R"({"max_context": {"default": 32768, "max": 65536},
                                      "kv": {"default": "int8", "choices": ["int8", "k8v4"]},
                                      "kv_resident": {"default": 0}})"},
      CardOptions{.name = "Beta", .profile = "qwen", .engine_args = std::move(beta_args)}};
  options.config_literals = std::move(literals);
  return options;
}

void launcher_boots_idle_and_starts_a_card() {
  // The engine may write only below its state directory: a relative dump lands in its cwd,
  // <state>/engine.
  auto server = ServerProcess::start(two_cards({"--dump-file=alpha.dump"}));
  expect(server && server->wait_until_listening(std::chrono::seconds(20)), "the launcher boots");
  if (!server) return;
  const auto dump = server->root() / "state" / "engine" / "alpha.dump";
  const auto health = call(*server, "GET", "/health");
  expect(health && health->status == 200 && health->body == "{\"status\":\"ok\",\"engine\":\"none\"}\n",
         "no engine at boot (D5): " + shown(health));
  expect(server->descendants().empty(), "nothing spawned before a start");
  expect(card_state(*server, "Alpha") == "stopped" && card_state(*server, "Beta") == "stopped", "both cards are listed, stopped");
  const auto listed = call(*server, "GET", "/v1/strata/models");
  expect(listed && listed->body.find("\"name\":\"kv_resident\"") != std::string::npos &&
             listed->body.find("\"choices\":[\"int8\",\"k8v4\"]") != std::string::npos,
         "the list describes each card's options: " + shown(listed));
  expect(has_code(call(*server, "POST", "/v1/chat/completions", chat_body("Alpha")), 503, "no_model_running"),
         "no chat before a start");
  const auto models = call(*server, "GET", "/v1/models");
  expect(models && models->body.find("\"data\":[]") != std::string::npos && models->body.find("\"strata_models\"") != std::string::npos,
         "/v1/models lists nothing running and the cards: " + shown(models));

  const auto started = call(*server, "POST", "/v1/strata/models/start",
                            R"({"name":"Alpha","options":{"max_context":65536,"kv":"k8v4","kv_resident":20480}})");
  expect(started && started->status == 202 && started->body.find("\"state\":\"starting\"") != std::string::npos,
         "a start is accepted: " + shown(started));
  expect(wait_for_card(*server, "Alpha", "running"), "Alpha runs: " + server->stderr_text());
  const auto argv = dumped_argv(dump);
  expect(has_pair(argv, "--max-context", "65536") && has_pair(argv, "--kv", "k8v4") && has_pair(argv, "--kv-resident", "20480"),
         "the page's options reach the engine's arguments: " + joined(argv));
  const auto chat = call(*server, "POST", "/v1/chat/completions", chat_body("Alpha"));
  expect(chat && chat->status == 200 && chat->body.find("\"model\":\"Alpha\"") != std::string::npos, "Alpha answers: " + shown(chat));
  expect(has_code(call(*server, "POST", "/v1/chat/completions", chat_body("Beta")), 409, "model_not_running"),
         "a request naming another card is told it is not running (D6)");
  expect(has_code(call(*server, "POST", "/v1/chat/completions", chat_body("nobody")), 404, "model_not_found"),
         "an unknown model is still not found");
  const auto running_models = call(*server, "GET", "/v1/models");
  expect(running_models && running_models->body.find("\"id\":\"Alpha\"") != std::string::npos, "/v1/models lists Alpha");
  const auto ready = call(*server, "GET", "/health");
  expect(ready && ready->status == 200 && ready->body.find("\"engine\":\"ready\"") != std::string::npos, "health follows the engine");

  const auto stopped = call(*server, "POST", "/v1/strata/models/stop", "{}");
  expect(stopped && stopped->status == 202, "a stop is accepted: " + shown(stopped));
  expect(wait_for_card(*server, "Alpha", "stopped"), "Alpha stops");
  const auto after = call(*server, "GET", "/health");
  expect(after && after->body.find("\"engine\":\"none\"") != std::string::npos, "the GPU is free again: " + shown(after));
  server->stop(ServerProcess::Stop::ctrl_break);
  const auto exit = server->wait_exit(std::chrono::seconds(20));
  expect(exit == std::optional<int>{0}, "a clean exit");
}

// D3: a switch waits for the generation in flight; meanwhile chat answers model_switching.
void switch_waits_for_the_generation_then_swaps() {
  auto server = ServerProcess::start(two_cards({"--tokens=12", "--token-interval-ms=250"}));
  expect(server && server->wait_until_listening(std::chrono::seconds(20)), "the launcher boots");
  if (!server) return;
  expect(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha"})")->status == 202, "Alpha starts");
  expect(wait_for_card(*server, "Alpha", "running"), "Alpha runs");
  std::optional<HttpResult> long_chat;
  std::thread generating([&] {
    long_chat = call(*server, "POST", "/v1/chat/completions",
                     R"({"model":"Alpha","messages":[{"role":"user","content":"Hi"}],"max_tokens":12})", std::chrono::seconds(30));
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(700));  // the generation is under way
  const auto switched = call(*server, "POST", "/v1/strata/models/start", R"({"name":"Beta"})");
  expect(switched && switched->status == 202, "a switch is accepted while Alpha generates: " + shown(switched));
  const auto during = call(*server, "POST", "/v1/chat/completions", chat_body("Alpha"));
  expect(has_code(during, 503, "model_switching"), "a new chat during the switch: " + shown(during));
  const auto for_beta = call(*server, "POST", "/v1/chat/completions", chat_body("Beta"));
  expect(has_code(for_beta, 503, "model_switching"), "a chat naming the card being started: " + shown(for_beta));
  expect(has_code(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha"})"), 409, "switch_in_progress"),
         "one switch at a time");
  expect(has_code(call(*server, "POST", "/v1/strata/models/stop", "{}"), 409, "switch_in_progress"), "no stop during a switch");
  generating.join();
  expect(long_chat && long_chat->status == 200 && long_chat->body.find("\"completion_tokens\":12") != std::string::npos,
         "the generation in flight finished whole: " + shown(long_chat));
  expect(wait_for_card(*server, "Beta", "running") && card_state(*server, "Alpha") == "stopped", "Beta replaced Alpha");
  const auto beta = call(*server, "POST", "/v1/chat/completions", chat_body("Beta"));
  expect(beta && beta->status == 200 && beta->body.find("\"model\":\"Beta\"") != std::string::npos, "Beta answers: " + shown(beta));
  server->stop(ServerProcess::Stop::ctrl_break);
  expect(server->wait_exit(std::chrono::seconds(20)) == std::optional<int>{0}, "a clean exit");
}

// D4: a start that cannot load stays failed with a fixed reason; the server stays usable.
void failed_start_keeps_the_server_usable() {
  auto server = ServerProcess::start(two_cards({}, {"--exit-before-ready=3"}));
  expect(server && server->wait_until_listening(std::chrono::seconds(20)), "the launcher boots");
  if (!server) return;
  expect(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha"})")->status == 202, "Alpha starts");
  expect(wait_for_card(*server, "Alpha", "running"), "Alpha runs");
  expect(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Beta"})")->status == 202, "the switch to Beta is accepted");
  expect(wait_for_card(*server, "Beta", "failed"), "Beta fails to load");
  std::string error;
  (void)card_state(*server, "Beta", &error);
  expect(error == "the engine ended before it was ready (see the server log)", "a fixed reason: " + error);
  expect(card_state(*server, "Alpha") == "stopped", "the old model is not restarted (D4)");
  const auto health = call(*server, "GET", "/health");
  expect(health && health->status == 200 && health->body.find("\"engine\":\"none\"") != std::string::npos, "nothing runs: " + shown(health));
  expect(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha"})")->status == 202 && wait_for_card(*server, "Alpha", "running"),
         "another card starts after the failure");
  server->stop(ServerProcess::Stop::ctrl_break);
  expect(server->wait_exit(std::chrono::seconds(20)) == std::optional<int>{0}, "a clean exit");
}

void start_refusals_name_the_problem() {
  auto server = ServerProcess::start(two_cards({"--ready-delay-ms=1500"}));
  expect(server && server->wait_until_listening(std::chrono::seconds(20)), "the launcher boots");
  if (!server) return;
  expect(has_code(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Gamma"})"), 404, "model_not_found"), "an unknown card");
  const auto too_big = call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha","options":{"max_context":131072}})");
  expect(has_code(too_big, 400, "invalid_option") && too_big->body.find("\"param\":\"max_context\"") != std::string::npos,
         "a value over the card's bound names the option: " + shown(too_big));
  expect(has_code(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha","options":{"kv":"q4_0"}})"), 400, "invalid_option"),
         "a choice the card does not offer");
  expect(has_code(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha","options":{"kv_resident":100}})"), 400, "invalid_option"),
         "KV streaming below the engine's floor");
  expect(has_code(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Beta","options":{"kv":"int8"}})"), 400, "invalid_option"),
         "an option the card does not list");
  expect(has_code(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha","engine":"x"})"), 400, "invalid_request"),
         "no other member than name and options");
  expect(has_code(call(*server, "POST", "/v1/strata/models/start", R"(["Alpha"])"), 400, "invalid_request"), "an object");
  expect(has_code(call(*server, "POST", "/v1/strata/models/start", R"({"name":)"), 400, "invalid_json"), "JSON");
  expect(server->descendants().empty(), "no refusal spawned anything");
  expect(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha"})")->status == 202, "a good start is accepted");
  const auto health = call(*server, "GET", "/health");
  expect(health && health->status == 503 && health->body.find("\"engine\":\"starting\"") != std::string::npos,
         "health says starting while the card loads: " + shown(health));
  expect(has_code(call(*server, "POST", "/v1/chat/completions", chat_body("Alpha")), 503, "model_switching"), "chat waits for the load");
  expect(wait_for_card(*server, "Alpha", "running"), "Alpha runs");
  server->stop(ServerProcess::Stop::ctrl_break);
  expect(server->wait_exit(std::chrono::seconds(20)) == std::optional<int>{0}, "a clean exit");
}

// D7: the page's last options per card, in an owner-only file under roots.state, are the next
// start's values (and the list's), also after a restart.
void options_are_remembered() {
  const auto scratch = test_support::make_temp_dir("launcher");
  const auto state = scratch / "state";
  secure_frontend_test::make_owner_private_directory(state);
  const auto dump = state / "engine" / "alpha.dump";
  auto options = two_cards({"--dump-file=alpha.dump"});
  options.state_dir = state;
  {
    auto server = ServerProcess::start(options);
    expect(server && server->wait_until_listening(std::chrono::seconds(20)), "the launcher boots");
    if (!server) return;
    expect(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha","options":{"max_context":16384}})")->status == 202,
           "Alpha starts with a smaller context");
    expect(wait_for_card(*server, "Alpha", "running"), "Alpha runs");
    server->stop(ServerProcess::Stop::ctrl_break);
    expect(server->wait_exit(std::chrono::seconds(20)) == std::optional<int>{0}, "a clean exit");
  }
  expect(std::filesystem::exists(state / "model-options.json"), "the options file is under roots.state");
  auto server = ServerProcess::start(options);
  expect(server && server->wait_until_listening(std::chrono::seconds(20)), "the launcher boots again");
  if (!server) return;
  const auto listed = call(*server, "GET", "/v1/strata/models");
  expect(listed && listed->body.find("\"default\":32768,\"min\":") != std::string::npos &&
             listed->body.find("\"value\":16384") != std::string::npos,
         "the list offers the remembered value: " + shown(listed));
  std::filesystem::remove(dump);
  expect(call(*server, "POST", "/v1/strata/models/start", R"({"name":"Alpha"})")->status == 202 && wait_for_card(*server, "Alpha", "running"),
         "a start without options");
  expect(has_pair(dumped_argv(dump), "--max-context", "16384"), "uses the remembered value");
  server->stop(ServerProcess::Stop::ctrl_break);
  expect(server->wait_exit(std::chrono::seconds(20)) == std::optional<int>{0}, "a clean exit");
}

// D5 and the control switch: models.start starts a card at boot; with models.control off the
// control routes are no routes and the model still serves.
void models_start_and_control_off() {
  auto server = ServerProcess::start(two_cards({}, {}, {{"models.start", "\"Beta\""}}));
  expect(server && server->wait_until_listening(std::chrono::seconds(20)), "the launcher boots");
  if (!server) return;
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  std::optional<HttpResult> chat;
  while (std::chrono::steady_clock::now() < until) {
    chat = call(*server, "POST", "/v1/chat/completions", chat_body("Beta"));
    if (chat && chat->status == 200) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  expect(chat && chat->status == 200, "the card models.start names serves: " + shown(chat));
  for (const auto& [method, target] : std::vector<std::pair<std::string, std::string>>{
           {"GET", "/v1/strata/models"}, {"POST", "/v1/strata/models/start"}, {"POST", "/v1/strata/models/stop"},
           {"GET", "/v1/strata/downloads"}, {"POST", "/v1/strata/downloads/start"}}) {
    const auto r = call(*server, method, target, method == "POST" ? R"({"name":"Alpha"})" : "");
    expect(r && r->status == 404, method + " " + target + " is no route with models.control and models.downloads off: " + shown(r));
  }
  server->stop(ServerProcess::Stop::ctrl_break);
  expect(server->wait_exit(std::chrono::seconds(20)) == std::optional<int>{0}, "a clean exit with a model running");
  expect(server->descendants().empty(), "no engine left behind");
}

// D9: a bad card is refused by name at boot, the others load; the main config may not set a
// card's rows.
void bad_card_refused_at_boot_and_main_rows_refused() {
  auto options = two_cards();
  options.model_cards.push_back(CardOptions{.name = "Broken", .profile = "qwen", .options_json = R"({"kv": {"default": "fp32"}})"});
  auto server = ServerProcess::start(options);
  expect(server && server->wait_until_listening(std::chrono::seconds(20)), "the launcher boots with a bad card listed");
  if (!server) return;
  expect(server->stderr_text().find("model card 3 (Broken) refused: options.kv") != std::string::npos,
         "the bad card is refused by name: " + server->stderr_text());
  expect(card_state(*server, "Alpha") == "stopped" && card_state(*server, "Broken").empty(), "the good cards load, the bad one is not listed");
  server->stop(ServerProcess::Stop::ctrl_break);
  (void)server->wait_exit(std::chrono::seconds(20));

  auto conflicting = two_cards({}, {}, {{"models.control", "true"}, {"defaults.sampling.temperature", "0.5"}});
  auto refused = ServerProcess::start(conflicting);
  expect(refused != nullptr, "the server process starts");
  if (!refused) return;
  const auto exit = refused->wait_exit(std::chrono::seconds(20));
  expect(exit.has_value() && *exit != 0 &&
             refused->stderr_text().find("defaults.sampling.temperature: is set by each model card when models.cards is set") !=
                 std::string::npos,
         "a card row in the main config refuses the boot by name: " + refused->stderr_text());
}


// Model downloads (plan 2026-10-23-model-downloads Task 4): models.downloads serves the download
// routes (the embedded catalog and the drive's free space), makes the store and <state>/downloads
// and <state>/cards owner-only, and a card a prepared download wrote there loads at boot like a
// listed one.
void downloads_serve_the_catalog_and_load_download_cards() {
  const auto scratch = secure_frontend_test::make_scratch_directory();
  secure_frontend_test::make_owner_private_directory(scratch / "state");
  auto options = two_cards({}, {}, {{"models.control", "true"}, {"models.downloads", "true"},
                                    {"models.downloads_root", secure_frontend_test::json_literal(secure_frontend::path_to_utf8(scratch / "store"))}});
  options.state_dir = scratch / "state";
  auto first = ServerProcess::start(options);
  expect(first && first->wait_until_listening(std::chrono::seconds(20)), "the launcher boots with downloads on");
  if (!first) return;
  const auto listed = call(*first, "GET", "/v1/strata/downloads");
  expect(listed && listed->status == 200 && listed->body.find("\"disk\":{\"root\":") != std::string::npos &&
             listed->body.find("\"id\":\"qwen3.8-flash-next-iq2_xs\"") != std::string::npos &&
             listed->body.find("\"source\":\"maya\"") != std::string::npos,
         "the embedded catalog and the disk: " + shown(listed).substr(0, 400) + " " + first->stderr_text());
  std::error_code ec;
  expect(std::filesystem::is_directory(scratch / "store", ec) && std::filesystem::is_directory(scratch / "state" / "downloads", ec) &&
             std::filesystem::is_directory(scratch / "state" / "cards", ec),
         "the store, <state>/downloads and <state>/cards are made");
  expect(has_code(call(*first, "POST", "/v1/strata/downloads/start", R"({"id":"nope"})"), 404, "model_not_found"),
         "a start of an unknown id is refused");
  expect(has_code(call(*first, "POST", "/v1/strata/downloads/link", R"({"url":"https://example.com/a/b/resolve/main/m.gguf"})"), 400,
                  "invalid_request"),
         "a link off Hugging Face is refused (O4)");
  // The card a prepared download wrote: Alpha's own file under another name.
  std::ifstream alpha_file(first->root() / "cards" / "1.json", std::ios::binary);
  std::string card{std::istreambuf_iterator<char>(alpha_file), std::istreambuf_iterator<char>()};
  const auto named = card.find("\"name\": \"Alpha\"");
  expect(named != std::string::npos, "the harness card names Alpha");
  if (named == std::string::npos) return;
  card.replace(named, std::string_view{"\"name\": \"Alpha\""}.size(), "\"name\": \"Gamma\"");
  secure_frontend_test::write_file(scratch / "state" / "cards" / "gamma.json", card, 0600);
  first->stop(ServerProcess::Stop::ctrl_break);
  expect(first->wait_exit(std::chrono::seconds(20)) == std::optional<int>{0}, "a clean exit");

  auto second = ServerProcess::start(options);
  expect(second && second->wait_until_listening(std::chrono::seconds(20)), "the launcher boots again");
  if (!second) return;
  expect(card_state(*second, "Gamma") == "stopped" && card_state(*second, "Alpha") == "stopped",
         "the download's card loads at boot beside the listed ones: " + second->stderr_text());
  second->stop(ServerProcess::Stop::ctrl_break);
  expect(second->wait_exit(std::chrono::seconds(20)) == std::optional<int>{0}, "a clean exit again");
}

// A prepared download becomes a card while the server runs: the launcher adds it (listed at
// once), refuses a second card of the same name, and holds at most kMaxLauncherCards.
void cards_can_be_added_while_serving() {
  secure_frontend::ModelCard alpha;
  alpha.name = "Alpha";
  secure_frontend::LauncherSettings settings;
  settings.cards = {alpha};
  settings.log = [](std::string_view) {};
  secure_frontend::ModelLauncher launcher(std::move(settings));
  secure_frontend::ModelCard gamma;
  gamma.name = "Gamma";
  expect(launcher.add_card(gamma), "a card is added");
  expect(launcher.list_json().find("\"name\":\"Gamma\"") != std::string::npos, "it is listed at once");
  expect(launcher.served().extension.find("\"id\":\"Gamma\"") != std::string::npos, "and in /v1/models' card states");
  expect(!launcher.add_card(gamma), "a second card of the same name is refused");
  std::size_t added = 2;
  for (std::size_t i = 0; i < 2U * secure_frontend::kMaxLauncherCards && launcher.add_card([i] {
         secure_frontend::ModelCard more;
         more.name = "M" + std::to_string(i);
         return more;
       }());
       ++i) {
    ++added;
  }
  expect(added == secure_frontend::kMaxLauncherCards, "at most kMaxLauncherCards cards: " + std::to_string(added));
  launcher.shutdown();
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"launcher_boots_idle_and_starts_a_card", launcher_boots_idle_and_starts_a_card},
      {"switch_waits_for_the_generation_then_swaps", switch_waits_for_the_generation_then_swaps},
      {"failed_start_keeps_the_server_usable", failed_start_keeps_the_server_usable},
      {"start_refusals_name_the_problem", start_refusals_name_the_problem},
      {"options_are_remembered", options_are_remembered},
      {"models_start_and_control_off", models_start_and_control_off},
      {"downloads_serve_the_catalog_and_load_download_cards", downloads_serve_the_catalog_and_load_download_cards},
      {"cards_can_be_added_while_serving", cards_can_be_added_while_serving},
      {"bad_card_refused_at_boot_and_main_rows_refused", bad_card_refused_at_boot_and_main_rows_refused},
  }, failures);
}

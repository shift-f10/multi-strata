#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/api_router.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/request_router.hpp"
#include "secure_frontend/secret_bytes.hpp"
#include "secure_frontend/token_verifier.hpp"
#include "secure_frontend/web_ui.hpp"
#include "support/test_support.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

constexpr std::string_view kRouterToken = "router-token-0123456789abcdefghijklmnopq";
constexpr secure_frontend::HeadLimits kRouterLimits{4096, 16384, 64, 65536};

secure_frontend::ApiRouter router_with(secure_frontend::HealthProvider health, std::string model = "fake-model",
                                       std::string owned_by = "local") {
  secure_frontend::SecretBytes secret;
  (void)secret.assign(kRouterToken);
  return secure_frontend::ApiRouter({
      .policy = secure_frontend::make_http_policy(*secure_frontend::parse_listener_address("127.0.0.1"), 8080, {}, {}),
      .validator = secure_frontend::make_bearer_validator(std::make_shared<const secure_frontend::TokenVerifier>(std::move(secret))),
      .model_id = std::move(model), .owned_by = std::move(owned_by), .chat_body_limit = 49152,
      .health = health ? std::move(health) : secure_frontend::HealthProvider{[] { return secure_frontend::HealthView{true, "ready", ""}; }},
      .chat = {}});
}
secure_frontend::RequestHead head_of(std::string method, std::string target) {
  secure_frontend::RequestHead head;
  head.method = std::move(method);
  head.target = std::move(target);
  head.fields = {{"Host", "127.0.0.1:8080"}, {"Authorization", "Bearer " + std::string{kRouterToken}}};
  return head;
}
secure_frontend::RouteDecision decision_of(secure_frontend::ApiRouter& router, std::string method, std::string target) {
  return router.authorize(head_of(std::move(method), std::move(target)));
}
secure_frontend::HttpResponse complete(secure_frontend::RouteResult result) {
  return std::get<secure_frontend::HttpResponse>(std::move(result));
}
secure_frontend::HttpResponse get(secure_frontend::ApiRouter& router, const std::string& target) {
  const auto decision = decision_of(router, "GET", target);
  if (decision.early) return *decision.early;
  return complete(router.handle(head_of("GET", target), "", decision, {}));
}

// health_samples_status_before_state_once_each: the provider is called exactly once per /health.
void health_samples_status_before_state_once_each() {
  int calls = 0;
  auto router = router_with([&calls] { ++calls; return secure_frontend::HealthView{true, "ready", ""}; });
  (void)router.handle(head_of("GET", "/health"), "", decision_of(router, "GET", "/health"), {});
  expect(calls == 1, "one snapshot per /health request");
  // SP2 (spec §3.4): READY is consumed eagerly, so `starting` is reported 503.
  auto starting = router_with([] { return secure_frontend::HealthView{false, "starting", ""}; });
  const auto r = get(starting, "/health");
  expect(r.status == 503 && r.body == "{\"status\":\"unavailable\",\"engine\":\"starting\"}\n", "a starting engine: " + r.body);
}

// Pre-flight T6b(a)/V11: recovery is reported only with an unhealthy engine.
void health_carries_recovery_only_with_failed() {
  auto restarting = router_with([] { return secure_frontend::HealthView{false, "failed", "restarting"}; });
  const auto r = get(restarting, "/health");
  expect(r.status == 503 && r.body == "{\"status\":\"unavailable\",\"engine\":\"failed\",\"recovery\":\"restarting\"}\n",
         "failed + restarting: " + r.body);
  auto exhausted = router_with([] { return secure_frontend::HealthView{false, "failed", "exhausted"}; });
  expect(get(exhausted, "/health").body == "{\"status\":\"unavailable\",\"engine\":\"failed\",\"recovery\":\"exhausted\"}\n",
         "failed + exhausted");
  auto ready = router_with([] { return secure_frontend::HealthView{true, "ready", ""}; });
  const auto healthy = get(ready, "/health");
  expect(healthy.status == 200 && healthy.body == "{\"status\":\"ok\",\"engine\":\"ready\"}\n", "ready carries no recovery field");
  const std::string fail_closed = secure_frontend::render_error_body(secure_frontend::ApiError::engine_unavailable);
  auto mixed = router_with([] { return secure_frontend::HealthView{true, "ready", "restarting"}; });
  const auto m = get(mixed, "/health");
  expect(m.status == 503 && m.body == fail_closed, "recovery with a healthy engine fails closed: " + m.body);
  auto unknown = router_with([] { return secure_frontend::HealthView{false, "failed", "/secret"}; });
  const auto u = get(unknown, "/health");
  expect(u.status == 503 && u.body == fail_closed && u.body.find("secret") == std::string::npos,
         "an unknown recovery literal is never echoed");
}
void health_includes_engine_state_when_provided() {
  auto router = router_with([] { return secure_frontend::HealthView{true, "generating", ""}; });
  const auto r = complete(router.handle(head_of("GET", "/health"), "", decision_of(router, "GET", "/health"), {}));
  expect(r.status == 200 && r.body == "{\"status\":\"ok\",\"engine\":\"generating\"}\n", "SP2 body unchanged: " + r.body);
  expect(r.header_value("Content-Type") == std::optional<std::string_view>{"application/json; charset=utf-8"}, "JSON content type");
}
void health_is_503_with_engine_state_when_unavailable() {
  auto router = router_with([] { return secure_frontend::HealthView{false, "failed", "restarting"}; });
  const auto r = complete(router.handle(head_of("GET", "/health"), "", decision_of(router, "GET", "/health"), {}));
  expect(r.status == 503 && r.body == "{\"status\":\"unavailable\",\"engine\":\"failed\",\"recovery\":\"restarting\"}\n", "503 body: " + r.body);
  auto bogus = router_with([] { return secure_frontend::HealthView{true, "/secret/path\"x", ""}; });
  const auto b = get(bogus, "/health");
  expect(b.status == 503 && b.body == secure_frontend::render_error_body(secure_frontend::ApiError::engine_unavailable),
         "an engine state outside the fixed literals is never echoed: " + b.body);
}
void dispatches_exact_health_route() {
  auto router = router_with([] { return secure_frontend::HealthView{true, "ready", ""}; });
  expect(decision_of(router, "GET", "/health").route == secure_frontend::RouteId::health && !decision_of(router, "GET", "/health").early,
         "/health is routed");
}
void dispatches_models_with_json_escaping() {
  auto router = router_with({}, "quote\"model", "own\\er");
  const auto r = complete(router.handle(head_of("GET", "/v1/models"), "", decision_of(router, "GET", "/v1/models"), {}));
  expect(r.status == 200 && r.body == "{\"object\":\"list\",\"data\":[{\"id\":\"quote\\\"model\",\"object\":\"model\",\"created\":0,\"owned_by\":\"own\\\\er\"}]}\n",
         "only the served model, escaped: " + r.body);
  const auto model = complete(router.handle(head_of("GET", "/v1/models/other"), "", decision_of(router, "GET", "/v1/models/other"), {}));
  expect(model.status == 404 && model.body == secure_frontend::render_error_body(secure_frontend::ApiError::model_not_found),
         "other model id: 404 model_not_found");
  auto plain = router_with({});
  const auto same = get(plain, "/v1/models/fake-model");
  expect(same.status == 200 && same.body == "{\"id\":\"fake-model\",\"object\":\"model\",\"created\":0,\"owned_by\":\"local\"}\n",
         "the served id answers the model object: " + same.body);
}
void rejects_non_exact_routes() {
  auto router = router_with({});
  for (const char* target : {"/health/", "//health", "/HEALTH", "/v1/models/", "/v1//models", "/v1/chat/completions/"}) {
    const auto d = decision_of(router, "GET", target);
    expect(d.early.has_value() && d.early->status == 404, std::string{"404 for "} + target);
    if (d.early) {
      expect(d.early->body == secure_frontend::render_error_body(secure_frontend::ApiError::not_found),
             std::string{"404 body is the §7.2 not_found row for "} + target);
    }
  }
}
void fails_closed_when_provider_throws_or_returns_invalid_model() {
  auto router = router_with([]() -> secure_frontend::HealthView { throw 1; });
  const auto r = complete(router.handle(head_of("GET", "/health"), "", decision_of(router, "GET", "/health"), {}));
  expect(r.status == 503 && r.body == secure_frontend::render_error_body(secure_frontend::ApiError::engine_unavailable),
         "a throwing health provider is a fixed 503");
  const std::string internal = secure_frontend::render_error_body(secure_frontend::ApiError::internal_error);
  for (const std::string& bad_id : {std::string{"bad\x01model"}, std::string{}, std::string(1025, 'a'), std::string{"bad\x7fmodel"}}) {
    auto bad = router_with({}, bad_id);
    const auto models = complete(bad.handle(head_of("GET", "/v1/models"), "", decision_of(bad, "GET", "/v1/models"), {}));
    expect(models.status == 500 && models.body == internal, "an invalid model id fails closed (size " + std::to_string(bad_id.size()) + ")");
  }
  auto bad_owner = router_with({}, "fake-model", "own\ner");
  expect(get(bad_owner, "/v1/models").status == 500, "a control byte in owned_by fails closed");
  expect(get(bad_owner, "/v1/models/fake-model").status == 500, "and on /v1/models/<id> too");
  auto longest = router_with({}, std::string(1024, 'a'));
  expect(get(longest, "/v1/models").status == 200, "1024 bytes is the inclusive bound");
}
void auth01_every_route_rejects_missing_malformed_wrong_token() {
  auto router = router_with({});
  const std::string token{kRouterToken};
  const std::pair<std::string, int> variants[] = {
      {"", 401}, {"Authorization: bearer " + token + "\r\n", 401}, {"Authorization: Bearer \r\n", 401},
      {"Authorization: Bearer\t" + token + "\r\n", 401}, {"Authorization: Basic " + token + "\r\n", 401},
      {"Authorization: Bearer " + token + "\r\nAuthorization: Bearer " + token + "\r\n", 400},
      {"Authorization: Bearer wrong-token-0123456789abcdefghijklmn\r\n", 401}};
  std::vector<std::pair<std::string, std::string>> routes;
  for (const auto& entry : secure_frontend::kRouteTable) {
    routes.emplace_back(std::string{entry.method}, entry.prefix ? std::string{entry.path} + "fake-model" : std::string{entry.path});
  }
  routes.emplace_back("GET", "/does-not-exist");
  for (const auto& [method, target] : routes) {
    for (const auto& [headers, status] : variants) {
      std::string request = method + " " + target + " HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n" + headers;
      request += method == "POST" ? "Content-Length: 2\r\nContent-Type: application/json\r\n\r\n{}" : "\r\n";
      const auto response = secure_frontend::handle_http_request(request, router, kRouterLimits);
      expect(response.status == status, method + " " + target + " must answer " + std::to_string(status));
      expect(response.body.find("fake-model") == std::string::npos && response.body.find("status") == std::string::npos,
             "no route data before authentication");
      if (status == 401) {
        expect(response.header_value("WWW-Authenticate") == std::optional<std::string_view>{"Bearer"}, "401 names the Bearer scheme");
      }
    }
  }
  const auto allowed = secure_frontend::handle_http_request(
      "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAuthorization: Bearer " + token + "\r\n\r\n", router, kRouterLimits);
  expect(allowed.status == 200 && allowed.body.find("fake-model") != std::string::npos,
         "the same route answers with the right token (the negatives are not vacuous)");
}
void models_list_keeps_utf8_model_id() {
  auto router = router_with({}, "mod\xc3\xa8le-\xc3\xbc");
  const auto r = complete(router.handle(head_of("GET", "/v1/models"), "", decision_of(router, "GET", "/v1/models"), {}));
  expect(r.status == 200 && r.body.find("mod\xc3\xa8le-\xc3\xbc") != std::string::npos && r.body.find("\\u00") == std::string::npos,
         "UTF-8 model id copied unchanged");
  // Spec §3.9: copied unchanged only after validation; invalid UTF-8 fails closed.
  const std::string internal = secure_frontend::render_error_body(secure_frontend::ApiError::internal_error);
  for (const std::string& invalid : {std::string{"mod\xc3"}, std::string{"\xff-model"}, std::string{"\xed\xa0\x80"},
                                     std::string{"\xc0\xaf"}}) {
    auto bad = router_with({}, invalid);
    const auto models = get(bad, "/v1/models");
    expect(models.status == 500 && models.body == internal, "an invalid UTF-8 model id fails closed");
    auto bad_owner = router_with({}, "fake-model", invalid);
    expect(get(bad_owner, "/v1/models").status == 500, "an invalid UTF-8 owned_by fails closed");
  }
}
// --- The built-in chat page (listener.web_ui) and the keyless loopback listener -------
// (owner decisions 2026-10-21, session log step 12)

secure_frontend::ApiRouter page_router(const bool web_ui, const bool require_key) {
  secure_frontend::SecretBytes secret;
  (void)secret.assign(kRouterToken);
  return secure_frontend::ApiRouter({
      .policy = secure_frontend::make_http_policy(*secure_frontend::parse_listener_address("127.0.0.1"), 8080, {}, {}),
      .validator = secure_frontend::make_bearer_validator(std::make_shared<const secure_frontend::TokenVerifier>(std::move(secret))),
      .model_id = "fake-model", .owned_by = "local", .chat_body_limit = 49152,
      .health = [] { return secure_frontend::HealthView{true, "ready", ""}; },
      .chat = {}, .web_ui = web_ui, .require_key = require_key});
}
// One request with no Authorization header; `fields` are extra header lines.
secure_frontend::HttpResponse bare(secure_frontend::ApiRouter& router, const std::string& method, const std::string& target,
                                   const std::string& fields = "") {
  std::string request = method + " " + target + " HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n" + fields;
  request += method == "POST" ? "Content-Length: 2\r\nContent-Type: application/json\r\n\r\n{}" : "\r\n";
  return secure_frontend::handle_http_request(request, router, kRouterLimits);
}

void web_ui_off_by_default_serves_nothing_public() {
  auto router = router_with({});
  for (const auto& asset : secure_frontend::web_ui_assets()) {
    const auto response = bare(router, "GET", std::string{asset.target});
    expect(response.status == 401 && response.content_security_policy.empty(),
           "web_ui off: " + std::string{asset.target} + " needs the key like every other target");
    expect(get(router, std::string{asset.target}).status == 404, "web_ui off: with the key it is not a route at all");
  }
}

void web_ui_serves_the_bundled_page_without_a_key() {
  auto router = page_router(true, true);
  // Session log step 14: the page, its two scripts and three stylesheets (upstream's UI kit,
  // MIT), the icon sprite and favicon, and the Outfit font (OFL) - each at one exact target.
  const std::vector<std::pair<std::string, std::string>> expected{
      {"/", "text/html; charset=utf-8"},
      {"/ui/theme.js", "text/javascript; charset=utf-8"},
      {"/ui/app.js", "text/javascript; charset=utf-8"},
      {"/ui/tokens.css", "text/css; charset=utf-8"},
      {"/ui/components.css", "text/css; charset=utf-8"},
      {"/ui/app.css", "text/css; charset=utf-8"},
      {"/ui/sprite.svg", "image/svg+xml; charset=utf-8"},
      {"/ui/favicon.svg", "image/svg+xml; charset=utf-8"},
      {"/ui/fonts/outfit-latin-wght.woff2", "font/woff2"},
      {"/ui/fonts/outfit-latin-ext-wght.woff2", "font/woff2"}};
  expect(secure_frontend::web_ui_assets().size() == expected.size(), "exactly the bundled files");
  for (const auto& [target, type] : expected) {
    const auto* asset = secure_frontend::find_web_asset(target);
    expect(asset != nullptr && asset->content_type == type, target + " is bundled as " + type + " (nosniff needs it exact)");
  }
  for (const auto& asset : secure_frontend::web_ui_assets()) {
    const std::string target{asset.target};
    const auto response = bare(router, "GET", target);
    expect(response.status == 200, target + " answers 200 without a key");
    expect(response.body == asset.body, target + " is the bundled file, byte for byte");
    expect(response.header_value("Content-Type") == std::optional<std::string_view>{asset.content_type},
           target + " has its own type: " + std::string{response.header_value("Content-Type").value_or("<none>")});
    expect(response.content_security_policy == secure_frontend::kWebUiContentSecurityPolicy,
           target + " carries the page policy (self only), not default-src 'none'");
    expect(response.header_value("Cross-Origin-Opener-Policy") == std::optional<std::string_view>{"same-origin"},
           target + " isolates its browsing context");
  }
  const auto authorized = get(router, "/");
  expect(authorized.status == 200 && authorized.body == secure_frontend::find_web_asset("/")->body,
         "a request that carries the key gets the same page");
}

void web_ui_leaves_every_api_route_authenticated() {
  auto router = page_router(true, true);
  for (const auto& entry : secure_frontend::kRouteTable) {
    const std::string target = entry.prefix ? std::string{entry.path} + "fake-model" : std::string{entry.path};
    const auto response = bare(router, std::string{entry.method}, target);
    expect(response.status == 401 && response.body.find("fake-model") == std::string::npos,
           std::string{entry.method} + " " + target + " still needs the key with web_ui on");
  }
  // Only the exact GET targets are public: no other method, suffix or neighbour (401, the
  // key is asked for), and no query at all (the parser refuses '?' in a target: 400).
  for (const auto& [method, target, status] : std::vector<std::tuple<std::string, std::string, int>>{
           {"POST", "/", 401}, {"HEAD", "/", 401}, {"GET", "/ui/", 401}, {"GET", "/ui/other.js", 401},
           {"GET", "/index.html", 401}, {"GET", "//", 401}, {"GET", "/UI/app.js", 401}, {"POST", "/ui/app.js", 401},
           {"GET", "/ui/fonts/", 401}, {"GET", "/ui/fonts/OFL.txt", 401}, {"GET", "/ui/LICENSE.strata-ui.txt", 401},
           {"GET", "/?a=1", 400}, {"GET", "/ui/app.js?v=1", 400}}) {
    const auto response = bare(router, method, target);
    expect(response.status == status && response.content_security_policy.empty() && response.body.find("<html") == std::string::npos,
           method + " " + target + " is not a page file (" + std::to_string(response.status) + ")");
  }
}

void web_ui_still_checks_host_and_origin() {
  auto router = page_router(true, true);
  expect(bare(router, "GET", "/").status == 200, "control: the page answers");
  const auto rebound = secure_frontend::handle_http_request("GET / HTTP/1.1\r\nHost: evil.example:8080\r\n\r\n", router, kRouterLimits);
  expect(rebound.status == 403 && rebound.body.find("<html") == std::string::npos, "a foreign Host (DNS rebinding) gets no page");
  const auto cross = bare(router, "GET", "/", "Origin: https://evil.example\r\n");
  expect(cross.status == 403, "a foreign Origin gets no page");
  const auto same = bare(router, "GET", "/ui/app.js", "Origin: http://127.0.0.1:8080\r\n");
  expect(same.status == 200, "the page's own origin is same-origin");
}

// The bundled files themselves (session log steps 12 and 14): every text file ASCII with LF line
// ends; nothing names another server (the SVG namespace URI is an identifier, never fetched); no
// inline script, style or handler (the CSP would refuse them anyway); the script renders text
// only, keeps the key in sessionStorage (this tab) and never in localStorage, which only the
// theme script uses, for the theme; the sprite carries no metadata blob; the fonts are WOFF2.
void web_ui_assets_are_bundled_and_inert() {
  const auto body = [](std::string_view target) { return std::string{secure_frontend::find_web_asset(target)->body}; };
  constexpr std::string_view kSvgNamespace = "http://www.w3.org/2000/svg";
  for (const auto& asset : secure_frontend::web_ui_assets()) {
    const std::string name{asset.target};
    std::string text{asset.body};
    if (asset.content_type == "font/woff2") {
      expect(text.rfind("wOF2", 0) == 0, name + " is a WOFF2 font");
      continue;
    }
    expect(!text.empty() && std::all_of(text.begin(), text.end(), [](char c) { return static_cast<unsigned char>(c) < 0x80U && c != '\r'; }),
           name + " is ASCII with LF line ends");
    for (std::size_t at = text.find(kSvgNamespace); at != std::string::npos; at = text.find(kSvgNamespace)) {
      text.erase(at, kSvgNamespace.size());
    }
    expect(text.find("http://") == std::string::npos && text.find("https://") == std::string::npos && text.find("//cdn") == std::string::npos,
           name + " names no other server");
  }
  const std::string html = body("/");
  expect(html.find("<script src=\"/ui/theme.js\"></script>") != std::string::npos &&
             html.find("<script src=\"/ui/app.js\" defer></script>") != std::string::npos,
         "the page loads exactly its two bundled scripts");
  std::size_t scripts = 0;
  for (std::size_t at = html.find("<script"); at != std::string::npos; at = html.find("<script", at + 1U)) ++scripts;
  expect(scripts == 2U, "two script elements, both bundled (no inline script)");
  for (const char* sheet : {"/ui/tokens.css", "/ui/components.css", "/ui/app.css"}) {
    expect(html.find(std::string{"<link rel=\"stylesheet\" href=\""} + sheet + "\">") != std::string::npos,
           std::string{"the page loads "} + sheet);
  }
  expect(html.find(" style=") == std::string::npos && html.find("<style") == std::string::npos, "no inline style");
  for (const char* handler : {" onclick=", " onload=", " onerror=", " onsubmit=", " oninput=", " onkeydown="}) {
    expect(html.find(handler) == std::string::npos, std::string{"no inline handler:"} + handler);
  }
  expect(html.find("id=\"key\" type=\"password\"") != std::string::npos && html.find("name=\"key\"") == std::string::npos,
         "the key field is a password input with no name, so no form can ever put it in a URL");
  const std::string js = body("/ui/app.js");
  for (const char* sink : {"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                           "localStorage", "setAttribute(\"on", "javascript:"}) {
    expect(js.find(sink) == std::string::npos, std::string{"app.js never uses "} + sink);
  }
  expect(js.find("sessionStorage") != std::string::npos && js.find("textContent") != std::string::npos &&
             js.find("credentials = \"omit\"") != std::string::npos,
         "the key lives in sessionStorage, output is text, no cookies are sent");
  const std::string theme = body("/ui/theme.js");
  expect(theme.find("strata.theme") != std::string::npos && theme.find("sessionStorage") == std::string::npos &&
             theme.find("fetch(") == std::string::npos && theme.find("Key") == std::string::npos,
         "the theme script stores the theme and nothing else");
  const std::string sprite = body("/ui/sprite.svg");
  expect(sprite.find("<metadata") == std::string::npos && sprite.find("c2pa") == std::string::npos && sprite.find("i-new-chat") != std::string::npos,
         "the icon sprite is the symbols only");
}

// Session log step 16: the page has upstream's Monitor tab (fed by GET /metrics, built from DOM
// nodes like the rest) and upstream's four thinking levels, sent as reasoning_effort.
void web_ui_has_the_monitor_and_four_thinking_levels() {
  const std::string html{secure_frontend::find_web_asset("/")->body};
  const std::string js{secure_frontend::find_web_asset("/ui/app.js")->body};
  expect(html.find("id=\"tab-btn-monitor\"") != std::string::npos && html.find("id=\"view-monitor\"") != std::string::npos &&
             html.find("id=\"monitor-off\"") != std::string::npos,
         "a Monitor tab, its view, and the note for a server with the Monitor off");
  for (const char* level : {"data-v=\"none\"", "data-v=\"low\"", "data-v=\"medium\"", "data-v=\"high\""}) {
    expect(html.find(level) != std::string::npos, std::string{"the Thinking control offers "} + level);
  }
  expect(html.find("data-v=\"on\"") == std::string::npos, "the old Off / On control is gone");
  expect(js.find("api(\"/metrics\")") != std::string::npos && js.find("response.status === 404") != std::string::npos,
         "the Monitor asks /metrics through the keyed API helper and handles the switch being off");
  expect(js.find("reasoning_effort: LEVELS[s.thinking] ? s.thinking : \"high\"") != std::string::npos,
         "the level is sent as reasoning_effort, high by default");
  // Gemma 4 plan 1 Task 12 (spec §6.6, D10): the drawer says what the levels mean for Gemma.
  expect(html.find("Gemma models think or answer directly; Low, Medium and High all mean thinking on") != std::string::npos,
         "the Thinking control notes that Gemma has no levels");
}

// Model launcher plan Task 5 (spec §6): the Models tab. It is in the page from the start but
// hidden, and shown only when GET /v1/strata/models answers; a server with model control off
// answers 404 and the tab stays hidden, so the page is exactly today's.
void web_ui_has_the_models_tab_hidden_until_the_server_offers_it() {
  const std::string html{secure_frontend::find_web_asset("/")->body};
  const std::string js{secure_frontend::find_web_asset("/ui/app.js")->body};
  expect(html.find("<button class=\"st-tab\" role=\"tab\" id=\"tab-btn-models\" aria-controls=\"view-models\" "
                   "aria-selected=\"false\" data-tab=\"models\" hidden>") != std::string::npos,
         "a Models tab beside Chat and Monitor, hidden until the server offers it");
  expect(html.find("id=\"tab-btn-models\"") > html.find("id=\"tab-btn-chat\"") &&
             html.find("id=\"tab-btn-models\"") < html.find("id=\"tab-btn-monitor\""),
         "the Models tab sits between Chat and Monitor");
  expect(html.find("<section class=\"view view--models\" id=\"view-models\" role=\"tabpanel\" aria-labelledby=\"tab-btn-models\" hidden>") !=
             std::string::npos,
         "the Models view, hidden like every other view");
  for (const char* id : {"id=\"model-list\"", "id=\"model-detail\"", "id=\"model-options\"", "id=\"model-start\"",
                         "id=\"model-stop\"", "id=\"model-progress\"", "id=\"model-start-error\"", "id=\"model-detail-error\""}) {
    expect(html.find(id) != std::string::npos, std::string{"the Models view has "} + id);
  }
  expect(js.find("api(\"/v1/strata/models\")") != std::string::npos,
         "the card list is asked through the keyed API helper");
  expect(js.find("if (response.status === 404) { setLauncherEnabled(false); return; }") != std::string::npos &&
             js.find("$(\"tab-btn-models\").hidden = !on;") != std::string::npos,
         "a 404 (model control off) hides the Models tab");
  // Owner report 2026-10-23 ("I do not see the new tab", from another machine): a 403
  // (models.control_remote off for a remote client) shows the tab with the reason and the fix,
  // instead of hiding it with no word.
  expect(js.find("if (response.status === 403) { setLauncherDenied(); return; }") != std::string::npos &&
             js.find("$(\"models-denied\").hidden = false;") != std::string::npos,
         "a 403 shows the Models tab with the reason");
  expect(html.find("id=\"models-denied\"") != std::string::npos && html.find("control_remote") != std::string::npos,
         "the reason names the switch that allows other machines");
  expect(js.find("[\"login\", \"chat\", \"models\", \"monitor\", \"about\"]") != std::string::npos &&
             js.find("$(\"tab-btn-models\").addEventListener(\"click\", function () { showView(\"models\"); });") != std::string::npos,
         "the Models tab switches views like the others");
}

// The Models view drives the control API: every call through the keyed helper (one fetch in
// the whole script), every option kind rendered from the server's description, a confirmation
// before a running model is replaced, the server's refusal shown beside Start (with the option
// it names), and a 2 s poll while a card is starting.
// Owner request 2026-10-23: the context and KV streaming as dropdowns. An integer option the server
// describes with a value list renders as a select labelled with the server's labels ("128K", "1M",
// "Off"), and an option with at_most (KV streaming) offers no value above the other option's
// (the context), following it as it changes and after Defaults.
void web_ui_listed_integers_are_dropdowns() {
  const std::string js{secure_frontend::find_web_asset("/ui/app.js")->body};
  expect(js.find("case \"integer\": return Array.isArray(option.choices) ? choiceControl(option, value) : numberControl(option, value, true, false);") !=
             std::string::npos,
         "a listed integer is a dropdown, any other integer a number box");
  expect(js.find("option.choice_labels") != std::string::npos, "the dropdown shows the server's labels");
  expect(js.find("c.option.at_most") != std::string::npos && js.find("ceiling.element.addEventListener(\"change\"") != std::string::npos,
         "KV streaming follows the context's dropdown");
  expect(js.find("launcher.limits.forEach(function (apply) { apply(); });") != std::string::npos,
         "Defaults applies the ceiling again");
}

void web_ui_models_tab_starts_stops_and_polls() {
  const std::string js{secure_frontend::find_web_asset("/ui/app.js")->body};
  // top_p's lower bound is the smallest double above 0 (an open bound): the page says
  // "above 0", never "5e-324" (box run 2026-10-23).
  expect(js.find("n > 0 && n < 1e-6") != std::string::npos && js.find("\"above 0\"") != std::string::npos,
         "a tiny positive bound reads as above 0");
  expect(js.find("fetch(") != std::string::npos && js.find("fetch(") == js.rfind("fetch("),
         "one fetch in the script: every call goes through the keyed API helper");
  expect(js.find("api(\"/v1/strata/models/start\", {") != std::string::npos &&
             js.find("JSON.stringify({ name: card.name, options: collected.values })") != std::string::npos,
         "Start posts the card's name and its typed option values");
  expect(js.find("api(\"/v1/strata/models/stop\", { method: \"POST\" })") != std::string::npos, "Stop posts to the stop route");
  for (const char* kind : {"case \"boolean\":", "case \"integer\":", "case \"decimal\":", "case \"choice\":",
                           "case \"integer_or_auto\":"}) {
    expect(js.find(kind) != std::string::npos, std::string{"the options renderer handles "} + kind);
  }
  expect(js.find("toggle.setAttribute(\"role\", \"switch\")") != std::string::npos && js.find("el(\"select\", \"st-input\")") != std::string::npos &&
             js.find("auto.type = \"checkbox\"") != std::string::npos && js.find("input.step = integral ? \"1\" : \"any\"") != std::string::npos,
         "a switch, a choice list, an auto box and number inputs with integer or decimal steps");
  expect(js.find("input.min = String(option.min)") != std::string::npos && js.find("input.max = String(option.max)") != std::string::npos,
         "number inputs carry the card's bounds");
  expect(js.find("window.confirm(") != std::string::npos && js.find("if (running && !window.confirm(") != std::string::npos,
         "Start asks before a running model is stopped");
  expect(js.find("parsed.error.param") != std::string::npos && js.find("$(\"model-start-error\").textContent") != std::string::npos,
         "a refusal is shown beside Start, naming the option");
  expect(js.find("launcher.timer = window.setTimeout(pollLauncher, 2000);") != std::string::npos &&
             js.find("function launcherStarting(") != std::string::npos,
         "the page asks again every 2 s while a card is starting");
  expect(js.find("$(\"model-progress\").textContent") != std::string::npos, "a progress line while a card loads");
}

// Model downloads plan Task 5 (spec sections 3-4, O1-O4): a Downloads section on the Models tab.
// It is in the page from the start but hidden, and shown only when GET /v1/strata/downloads
// answers: a server with models.downloads off answers 404 and the section stays hidden (the tab is
// exactly the launcher's); a 403 (a remote client without models.control_remote) shows the
// reason and the switch, like the Models tab's own note. A disk line heads the cards (O2), which
// are grouped by where they come from (O1), and a paste box takes one Hugging Face link (O3).
void web_ui_models_tab_has_a_downloads_section() {
  const std::string html{secure_frontend::find_web_asset("/")->body};
  const std::string js{secure_frontend::find_web_asset("/ui/app.js")->body};
  const auto section = html.find("<div class=\"st-card downloads\" id=\"downloads\" hidden>");
  expect(section != std::string::npos && section > html.find("id=\"view-models\"") && section < html.find("id=\"view-monitor\""),
         "a Downloads section inside the Models view, hidden until the server offers it");
  for (const char* id : {"id=\"downloads-refresh\"", "id=\"downloads-denied\"", "id=\"downloads-body\"", "id=\"downloads-disk\"",
                         "id=\"downloads-list\"", "id=\"downloads-link-form\"", "id=\"downloads-url\"", "id=\"downloads-check\"",
                         "id=\"downloads-link-error\"", "id=\"downloads-confirm\""}) {
    expect(html.find(id) != std::string::npos, std::string{"the Downloads section has "} + id);
  }
  expect(html.find("<label class=\"st-label\" for=\"downloads-url\">Hugging Face link to a .gguf file</label>") != std::string::npos &&
             html.find("id=\"downloads-check\">Check</button>") != std::string::npos,
         "a paste box for a Hugging Face .gguf link, with a Check button");
  expect(html.find("id=\"downloads-url\" type=\"text\"") != std::string::npos && html.find("name=\"url\"") == std::string::npos,
         "the link field has no name, so no form can ever put it in a URL");
  const auto denied = html.find("id=\"downloads-denied\"");
  expect(denied != std::string::npos && html.find("control_remote", denied) < html.find("</p>", denied),
         "the downloads 403 note names the switch that allows other machines");
  expect(js.find("api(\"/v1/strata/downloads\")") != std::string::npos, "the download list is asked through the keyed API helper");
  expect(js.find("if (name === \"models\") { renderModels(false); refreshLauncher(); refreshDownloads(); }") != std::string::npos,
         "opening the Models tab reads the downloads too");
  expect(js.find("if (response.status === 404) { setDownloadsShown(false); return; }") != std::string::npos &&
             js.find("$(\"downloads\").hidden = !on;") != std::string::npos,
         "a 404 (downloads off) keeps the section hidden");
  expect(js.find("if (response.status === 403) { setDownloadsDenied(); return; }") != std::string::npos &&
             js.find("$(\"downloads-denied\").hidden = false;") != std::string::npos && js.find("$(\"downloads-body\").hidden = true;") != std::string::npos,
         "a 403 shows the section with the reason instead of the cards");
  expect(js.find("\"Free space on \" + root") != std::string::npos && js.find("\" GB of \" + dgb(disk.total_bytes) + \" GB\"") != std::string::npos &&
             js.find("function dgb(bytes) { return fmt((Number(bytes) || 0) / 1e9, 1); }") != std::string::npos,
         "a disk line: the downloads drive's free space of its total, in decimal GB with one decimal");
  for (const char* group : {"[\"strata\", \"Strata models\"]", "[\"maya\", \"Project Maya models\"]", "[\"custom\", \"Your downloads\"]"}) {
    expect(js.find(group) != std::string::npos, std::string{"the cards are grouped by source: "} + group);
  }
  expect(js.find("if (card.runnable === false && card.note)") != std::string::npos, "a card that cannot run here shows its note");
}

// The Downloads cards drive the download routes, every call through the keyed helper: Download
// and Cancel post the card's id; a card that does not fit says so with both figures and cannot
// start; a refusal (507 insufficient_storage too) is the server's sentence on its card; a progress
// bar and line for the running transfer; a 2 s poll while a card is queued, downloading,
// verifying or preparing, and none otherwise; the model list read again when a card turns ready;
// a pasted link pre-checked (O4: https on huggingface.co, a .gguf file before any query) before
// the server is asked, then shown and confirmed.
// Owner: "Have a download pause and resume functionality". Pause while a card is queued or
// downloading; a paused card keeps its bar and figures, offers Resume (the start route: the server
// continues from the partial files) and Cancel (which deletes them, and says so first).
void web_ui_downloads_pause_and_resume() {
  const std::string js{secure_frontend::find_web_asset("/ui/app.js")->body};
  expect(js.find("paused: [\"st-badge--queued\", \"Paused\"]") != std::string::npos, "a paused card has its badge");
  expect(js.find("api(\"/v1/strata/downloads/pause\", jsonPost({ id: card.id }))") != std::string::npos,
         "Pause posts the card's id to the pause route");
  const auto pause_at = js.find("var pause = el(\"button\", \"st-btn st-btn--secondary st-btn--sm\", \"Pause\");");
  expect(pause_at != std::string::npos && js.rfind("if (card.state === \"queued\" || card.state === \"downloading\") {", pause_at) != std::string::npos &&
             js.find("pause.addEventListener(\"click\", function () { pauseDownload(card); });") != std::string::npos,
         "Pause is offered while a card is queued or downloading");
  expect(js.find("var resume = el(\"button\", \"st-btn st-btn--primary st-btn--sm\", \"Resume\");") != std::string::npos &&
             js.find("resume.addEventListener(\"click\", function () { startDownload(card); });") != std::string::npos &&
             js.find("resume.disabled = card.fits === false || downloads.acting;") != std::string::npos,
         "a paused card offers Resume, which is a start, and only when the rest fits");
  expect(js.find("var DL_CANCELLABLE = [\"queued\", \"downloading\", \"paused\"];") != std::string::npos &&
             js.find("if (oneOf(DL_CANCELLABLE, card.state)) {") != std::string::npos,
         "Cancel is offered while a card is queued, downloading or paused");
  expect(js.find("\"Cancel the download of \" + card.name + \"? The part downloaded so far is deleted.\"") != std::string::npos,
         "Cancel says that the partial download is deleted");
  expect(js.find("if (card.state === \"downloading\" || card.state === \"paused\") {") != std::string::npos &&
             js.find("\"Paused at \" + transferText(figures, null) + \"; Resume continues from there\"") != std::string::npos,
         "a paused card keeps its bar and says how far it got");
  expect(js.find("if (card.state === \"paused\" && card.fits === false) { box.appendChild(el(\"p\", \"msg-warn\", noRoomText(card.needed_bytes))); }") !=
             std::string::npos,
         "a paused card whose rest does not fit says so");
  expect(js.find("toast(\"info\", \"Download paused\", card.name + \": Resume continues from where it stopped\");") != std::string::npos,
         "a pause is confirmed");
  expect(js.find("(parsed.reason ? \": \" + parsed.reason : \"\")") != std::string::npos,
         "a refused link shows the server's fixed reason");
  const std::string css{secure_frontend::find_web_asset("/ui/app.css")->body};
  expect(css.find(".dl-card[data-state=\"paused\"]") != std::string::npos, "a paused card is styled");
}

void web_ui_downloads_start_cancel_poll_and_check_links() {
  const std::string js{secure_frontend::find_web_asset("/ui/app.js")->body};
  expect(js.find("function jsonPost(payload) { return { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, "
                 "body: JSON.stringify(payload) }; }") != std::string::npos,
         "the download routes take JSON bodies");
  expect(js.find("api(\"/v1/strata/downloads/start\", jsonPost({ id: card.id }))") != std::string::npos,
         "Download posts the card's id to the start route");
  expect(js.find("api(\"/v1/strata/downloads/cancel\", jsonPost({ id: card.id }))") != std::string::npos,
         "Cancel posts the card's id to the cancel route");
  expect(js.find("api(\"/v1/strata/downloads/link\", jsonPost({ url: url }))") != std::string::npos,
         "Check posts the pasted link to the link route");
  expect(js.find("api(\"/v1/strata/downloads/start\", jsonPost({ url: offer.url, confirm: true }))") != std::string::npos,
         "a confirmed link starts with confirm: true");
  expect(js.find("var noRoom = startable && card.fits === false;") != std::string::npos &&
             js.find("download.disabled = noRoom || downloads.acting;") != std::string::npos,
         "a card that does not fit cannot start");
  expect(js.find("if (noRoom) { box.appendChild(el(\"p\", \"msg-warn\", noRoomText(card.needed_bytes))); }") != std::string::npos &&
             js.find("return \"Insufficient disk space: \" + dgb(needed) + \" GB needed, \" + (free === null ? \"-\" : dgb(free)) + \" GB free\";") !=
                 std::string::npos,
         "a card that does not fit says how much it needs and how much is free");
  expect(js.find("if (card.state === \"queued\" || card.state === \"downloading\") {") != std::string::npos,
         "Cancel is offered while a card is queued or downloading");
  expect(js.find("if (answer.error) { downloads.errors[card.id] = answer.error; }") != std::string::npos &&
             js.find("var refused = downloads.errors[card.id];") != std::string::npos,
         "a refusal is shown on its card");
  expect(js.find("fill.style.width = ") != std::string::npos && js.find("\" of \" + dgb(figures.total) + \" GB (\" + pct + \"%)\"") != std::string::npos &&
             js.find("\" MB/s\"") != std::string::npos && js.find("\"ETA \" + clock(active.eta_s)") != std::string::npos,
         "the running transfer has a bar and a line: GB done of the total, the percentage, the rate and the ETA");
  expect(js.find("\"Verifying: ") != std::string::npos && js.find("\"Preparing: ") != std::string::npos,
         "verifying and preparing are said in words");
  expect(js.find("var DL_ACTIVE = [\"queued\", \"downloading\", \"verifying\", \"preparing\"];") != std::string::npos &&
             js.find("downloads.timer = window.setTimeout(pollDownloads, 2000);") != std::string::npos &&
             js.find("if (!downloadsActive(parsed)) { stopDownloadsPoll(); return; }") != std::string::npos,
         "the page asks again every 2 s while a card is active, and stops when none is");
  expect(js.find("if (card.state === \"ready\") { readyNow.push(card); }") != std::string::npos &&
             js.find("if (readyNow.length) { refreshLauncher();") != std::string::npos,
         "a card that turns ready reads the model list again, so its new model card appears");
  expect(js.find(R"(var HF_LINK = /^https:\/\/huggingface\.co\//;)") != std::string::npos &&
             js.find(R"(var GGUF_FILE = /\.gguf$/i;)") != std::string::npos &&
             js.find("if (!GGUF_FILE.test(url.split(/[?#]/)[0]))") != std::string::npos,
         "a pasted link must be https on huggingface.co and name a .gguf file (before any query)");
  const auto precheck = js.find("var problem = linkProblem(url);");
  expect(precheck != std::string::npos &&
             js.find("if (problem) { showLinkError(problem); return; }", precheck) < js.find("api(\"/v1/strata/downloads/link\"", precheck),
         "a link that fails the pre-check is refused without asking the server");
  expect(js.find("row(\"Repository\", ") != std::string::npos && js.find("row(\"Commit\", commit ? commit.slice(0, 7) : \"-\", commit);") != std::string::npos &&
             js.find("go.disabled = !fits || downloads.acting;") != std::string::npos,
         "the confirm block shows the repository and the short commit, and cannot start what does not fit");
}

// The chat follows the running model: the header names it, the composer is off with a link to
// the Models tab when none runs, /v1/models is asked again when the running card changes, and
// the launcher's chat refusals read as plain sentences.
void web_ui_chat_follows_the_running_model() {
  const std::string html{secure_frontend::find_web_asset("/")->body};
  const std::string js{secure_frontend::find_web_asset("/ui/app.js")->body};
  expect(html.find("id=\"header-model\"") != std::string::npos, "the header has a place for the running model's name");
  expect(html.find("No model is running &mdash; open the Models tab") != std::string::npos &&
             html.find("id=\"no-model-open\"") != std::string::npos,
         "the composer's notice and its button to the Models tab");
  expect(js.find("$(\"no-model-open\").addEventListener(\"click\", function () { showView(\"models\"); });") != std::string::npos,
         "the notice's button opens the Models tab");
  expect(js.find("$(\"input\").disabled = !on;") != std::string::npos && js.find("$(\"send-btn\").disabled = !on;") != std::string::npos,
         "with no model running the composer is disabled");
  expect(js.find("$(\"header-model\").textContent") != std::string::npos, "the header shows the running model's name");
  expect(js.find("refreshChatModel(") != std::string::npos && js.find("listModels()") != std::string::npos,
         "the chat's model is read again from /v1/models when the running card changes");
  for (const char* code : {"model_switching:", "no_model_running:", "model_not_running:"}) {
    expect(js.find(code) != std::string::npos, std::string{"a friendly chat error for "} + code);
  }
  expect(js.find("CHAT_ERRORS[code]") != std::string::npos, "the chat's error path uses the friendly errors");
}

void keyless_router_answers_without_a_key() {
  auto keyless = page_router(true, false);
  const auto models = bare(keyless, "GET", "/v1/models");
  expect(models.status == 200 && models.body.find("fake-model") != std::string::npos, "keyless: /v1/models without a key");
  expect(bare(keyless, "GET", "/health").status == 200, "keyless: /health without a key");
  expect(get(keyless, "/v1/models").status == 200, "keyless: a request that still sends a key is served too");
  const auto rebound =
      secure_frontend::handle_http_request("GET /v1/models HTTP/1.1\r\nHost: evil.example:8080\r\n\r\n", keyless, kRouterLimits);
  expect(rebound.status == 403, "keyless: a foreign Host is still refused (DNS rebinding)");
  expect(bare(keyless, "GET", "/v1/models", "Origin: https://evil.example\r\n").status == 403,
         "keyless: a foreign Origin is still refused (another site's page)");
  expect(bare(keyless, "POST", "/v1/chat/completions", "").status != 401, "keyless: chat needs no key");
  auto keyed = page_router(true, true);
  expect(bare(keyed, "GET", "/v1/models").status == 401, "control: the same router with require_key answers 401");
}

// --- The Monitor (listener.monitor; session log step 16) ---------------------------------
// GET /metrics is an API route: the key first, then the switch. Off (no provider) it is not
// served at all; on, it answers the provider's JSON, asked once per request.
secure_frontend::ApiRouter metrics_router(secure_frontend::MetricsProvider metrics) {
  secure_frontend::SecretBytes secret;
  (void)secret.assign(kRouterToken);
  return secure_frontend::ApiRouter({
      .policy = secure_frontend::make_http_policy(*secure_frontend::parse_listener_address("127.0.0.1"), 8080, {}, {}),
      .validator = secure_frontend::make_bearer_validator(std::make_shared<const secure_frontend::TokenVerifier>(std::move(secret))),
      .model_id = "fake-model", .owned_by = "local", .chat_body_limit = 49152,
      .health = [] { return secure_frontend::HealthView{true, "ready", ""}; },
      .chat = {}, .metrics = std::move(metrics)});
}

void metrics_route_needs_the_key_and_the_switch() {
  auto off = metrics_router({});
  expect(bare(off, "GET", "/metrics").status == 401, "the Monitor's route needs the key");
  expect(get(off, "/metrics").status == 404, "off: with the key it is not served at all");
  const std::string off_key = "Authorization: Bearer " + std::string{kRouterToken} + "\r\n";
  expect(bare(off, "POST", "/metrics", off_key).status == 404,
         "off: no method reveals the route either (EXT-01: upstream's /metrics is 404, not 405)");
  int calls = 0;
  auto on = metrics_router([&calls] {
    ++calls;
    return std::string{"{\"live\":{\"state\":\"idle\"}}\n"};
  });
  expect(bare(on, "GET", "/metrics").status == 401 && calls == 0, "on: the key is still asked first; the provider is untouched");
  const auto served = get(on, "/metrics");
  expect(served.status == 200 && served.body == "{\"live\":{\"state\":\"idle\"}}\n" && calls == 1,
         "on: the provider's JSON, asked once (" + std::to_string(served.status) + ")");
  expect(served.header_value("Content-Type") == std::optional<std::string_view>{"application/json; charset=utf-8"},
         "served as JSON");
  const std::string key = "Authorization: Bearer " + std::string{kRouterToken} + "\r\n";
  expect(bare(on, "POST", "/metrics", key).status == 405, "GET only");
  expect(get(on, "/metrics/prometheus").status == 404 && get(on, "/Metrics").status == 404, "the exact target only");
  auto throwing = metrics_router([]() -> std::string { throw std::runtime_error("monitor"); });
  expect(get(throwing, "/metrics").status == 500, "a provider that throws is an internal error, nothing else");
}
}  // namespace

// --- The model launcher's routes (plan 2026-10-23 Task 4) ---------------------------------

// A launcher-mode router: the served model comes from a provider and the control routes are
// handled by `control` (each call recorded in `calls`).
secure_frontend::ApiRouter launcher_router(std::vector<std::string>* calls, std::optional<std::string> running = "Gemma-4",
                                           secure_frontend::HealthView health = {true, "ready", ""}, bool control = true) {
  secure_frontend::SecretBytes secret;
  (void)secret.assign(kRouterToken);
  secure_frontend::ModelControl handlers;
  if (control) {
    handlers.list = [calls](const secure_frontend::RequestContext& context) -> secure_frontend::RouteResult {
      calls->push_back(std::string{"list "} + (context.loopback_peer ? "loopback" : "remote"));
      return secure_frontend::HttpResponse{.status = 200, .headers = {}, .body = "{\"object\":\"list\"}\n"};
    };
    handlers.start = [calls](std::string_view body, const secure_frontend::RequestContext&) -> secure_frontend::RouteResult {
      calls->push_back("start " + std::string{body});
      return secure_frontend::HttpResponse{.status = 202, .headers = {}, .body = "{\"state\":\"starting\"}\n"};
    };
    handlers.stop = [calls](const secure_frontend::RequestContext&) -> secure_frontend::RouteResult {
      calls->push_back("stop");
      return secure_frontend::HttpResponse{.status = 202, .headers = {}, .body = "{\"state\":\"stopped\"}\n"};
    };
  }
  return secure_frontend::ApiRouter({
      .policy = secure_frontend::make_http_policy(*secure_frontend::parse_listener_address("127.0.0.1"), 8080, {}, {}),
      .validator = secure_frontend::make_bearer_validator(std::make_shared<const secure_frontend::TokenVerifier>(std::move(secret))),
      .model_id = "", .owned_by = "local", .chat_body_limit = 49152,
      .health = [health] { return health; },
      .chat = {},
      .served = [running] {
        secure_frontend::ServedModels served;
        served.id = running;
        if (running) served.aliases = {"gemma"};
        served.extension = "[{\"id\":\"Gemma-4\",\"state\":\"running\"},{\"id\":\"Qwen\",\"state\":\"stopped\"}]";
        return served;
      },
      .control = std::move(handlers)});
}

secure_frontend::HttpResponse request(secure_frontend::ApiRouter& router, const std::string& method, const std::string& target,
                                      const std::string& body = "", bool keyed = true, bool loopback = true,
                                      const std::string& content_type = "application/json") {
  auto head = head_of(method, target);
  if (!keyed) head.fields = {{"Host", "127.0.0.1:8080"}};
  if (!body.empty() || method == "POST") {
    head.fields.emplace_back("Content-Type", content_type);
    head.content_length = body.size();
  }
  const auto decision = router.authorize(head);
  if (decision.early) return *decision.early;
  secure_frontend::RequestContext context;
  context.loopback_peer = loopback;
  return complete(router.handle(head, body, decision, context));
}

void model_control_routes_need_the_switch_and_the_key() {
  std::vector<std::string> calls;
  auto router = launcher_router(&calls);
  for (const auto& [method, target] : std::vector<std::pair<std::string, std::string>>{
           {"GET", "/v1/strata/models"}, {"POST", "/v1/strata/models/start"}, {"POST", "/v1/strata/models/stop"}}) {
    expect(request(router, method, target, method == "POST" ? "{}" : "", false).status == 401, method + " " + target + " needs the key");
  }
  expect(calls.empty(), "no handler runs before the key");
  expect(request(router, "GET", "/v1/strata/models").status == 200 && calls == std::vector<std::string>{"list loopback"},
         "the list answers with the key");
  expect(request(router, "GET", "/v1/strata/models", "", true, false).status == 200 && calls.back() == "list remote",
         "the handler learns the client's class");
  expect(request(router, "POST", "/v1/strata/models/start", "{\"name\":\"Qwen\"}").status == 202 &&
             calls.back() == "start {\"name\":\"Qwen\"}",
         "a start reaches its handler with the body");
  expect(request(router, "POST", "/v1/strata/models/stop", "{}").status == 202 && calls.back() == "stop", "a stop reaches its handler");
  expect(request(router, "POST", "/v1/strata/models").status == 405, "the list is GET only");
  expect(request(router, "GET", "/v1/strata/models/start").status == 405, "a start is POST only");
  expect(request(router, "POST", "/v1/strata/models/start", "{}", true, true, "text/plain").status == 415, "a start body is JSON");
  expect(request(router, "POST", "/v1/strata/models/start", std::string(5000, ' ')).status == 413, "a start body is small");
  expect(request(router, "GET", "/v1/strata/models/other").status == 404, "no other control route");
  std::vector<std::string> none;
  auto off = launcher_router(&none, "Gemma-4", {true, "ready", ""}, false);
  for (const auto& [method, target] : std::vector<std::pair<std::string, std::string>>{
           {"GET", "/v1/strata/models"}, {"POST", "/v1/strata/models/start"}, {"POST", "/v1/strata/models/stop"}}) {
    expect(request(off, method, target, method == "POST" ? "{}" : "").status == 404, method + " " + target + " is no route with control off");
  }
  auto single = router_with({});
  expect(get(single, "/v1/strata/models").status == 404, "a single-model server has no control routes");
}

// Model downloads (plan 2026-10-23-model-downloads Task 4): the download routes, keyed, served
// only while their handler is set (models.downloads), each POST a small JSON body.
secure_frontend::ApiRouter downloads_router(std::vector<std::string>* calls, const bool on) {
  secure_frontend::SecretBytes secret;
  (void)secret.assign(kRouterToken);
  secure_frontend::ModelDownloads downloads;
  if (on) {
    downloads.handle = [calls](const secure_frontend::RouteId route, const std::string_view body,
                               const secure_frontend::RequestContext& context) -> secure_frontend::RouteResult {
      calls->push_back(std::to_string(static_cast<int>(route)) + " " + std::string{body} + (context.loopback_peer ? "" : " remote"));
      return secure_frontend::HttpResponse{.status = 202, .headers = {}, .body = "{}\n"};
    };
  }
  return secure_frontend::ApiRouter({
      .policy = secure_frontend::make_http_policy(*secure_frontend::parse_listener_address("127.0.0.1"), 8080, {}, {}),
      .validator = secure_frontend::make_bearer_validator(std::make_shared<const secure_frontend::TokenVerifier>(std::move(secret))),
      .model_id = "", .owned_by = "local", .chat_body_limit = 49152,
      .health = [] { return secure_frontend::HealthView{true, "none", ""}; },
      .chat = {},
      .served = [] { return secure_frontend::ServedModels{}; },
      .downloads = std::move(downloads)});
}

void model_download_routes_need_the_switch_and_the_key() {
  using secure_frontend::RouteId;
  const std::vector<std::tuple<std::string, std::string, RouteId>> routes{
      {"GET", "/v1/strata/downloads", RouteId::strata_downloads},
      {"POST", "/v1/strata/downloads/start", RouteId::strata_download_start},
      {"POST", "/v1/strata/downloads/pause", RouteId::strata_download_pause},
      {"POST", "/v1/strata/downloads/cancel", RouteId::strata_download_cancel},
      {"POST", "/v1/strata/downloads/link", RouteId::strata_download_link}};
  std::vector<std::string> calls;
  auto router = downloads_router(&calls, true);
  for (const auto& [method, target, route] : routes) {
    expect(request(router, method, target, method == "POST" ? "{}" : "", false).status == 401, method + " " + target + " needs the key");
  }
  expect(calls.empty(), "no download handler runs before the key");
  for (const auto& [method, target, route] : routes) {
    const std::string body = method == "POST" ? "{\"id\":\"x\"}" : "";
    expect(request(router, method, target, body).status == 202 && !calls.empty() &&
               calls.back() == std::to_string(static_cast<int>(route)) + " " + body,
           method + " " + target + " reaches the handler with its route and body");
  }
  expect(request(router, "GET", "/v1/strata/downloads", "", true, false).status == 202 && calls.back().ends_with(" remote"),
         "the handler learns the client's class");
  expect(request(router, "POST", "/v1/strata/downloads").status == 405, "the list is GET only");
  expect(request(router, "GET", "/v1/strata/downloads/pause").status == 405, "a pause is POST only");
  expect(request(router, "POST", "/v1/strata/downloads/start", "{}", true, true, "text/plain").status == 415, "a start body is JSON");
  expect(request(router, "POST", "/v1/strata/downloads/link", std::string(5000, ' ')).status == 413, "a link body is small");
  expect(request(router, "GET", "/v1/strata/downloads/other").status == 404, "no other download route");
  std::vector<std::string> none;
  auto off = downloads_router(&none, false);
  for (const auto& [method, target, route] : routes) {
    expect(request(off, method, target, method == "POST" ? "{}" : "").status == 404, method + " " + target + " is no route with downloads off");
  }
  expect(none.empty(), "downloads off: nothing is called");
}

void served_models_follow_the_running_card() {
  std::vector<std::string> calls;
  auto router = launcher_router(&calls);
  const auto models = request(router, "GET", "/v1/models");
  expect(models.status == 200 && models.body.find("\"id\":\"Gemma-4\"") != std::string::npos &&
             models.body.find("\"id\":\"gemma\"") != std::string::npos &&
             models.body.find("\"strata_models\":[{\"id\":\"Gemma-4\",\"state\":\"running\"},{\"id\":\"Qwen\",\"state\":\"stopped\"}]") !=
                 std::string::npos,
         "/v1/models lists the running card, its aliases and the cards' states: " + models.body);
  expect(request(router, "GET", "/v1/models/gemma").status == 200, "an alias of the running card is found");
  expect(request(router, "GET", "/v1/models/Qwen").status == 404, "a stopped card is not a served model");
  auto idle = launcher_router(&calls, std::nullopt, {true, "none", ""});
  const auto empty = request(idle, "GET", "/v1/models");
  expect(empty.status == 200 && empty.body.find("\"data\":[]") != std::string::npos && empty.body.find("strata_models") != std::string::npos,
         "nothing running: an empty list and the cards: " + empty.body);
  const auto health = request(idle, "GET", "/health");
  expect(health.status == 200 && health.body == "{\"status\":\"ok\",\"engine\":\"none\"}\n", "nothing running is a healthy server: " + health.body);
  auto unhealthy_none = router_with([] { return secure_frontend::HealthView{false, "none", ""}; });
  expect(get(unhealthy_none, "/health").status == 503, "\"none\" is only ever healthy (fails closed otherwise)");
}

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"health_samples_status_before_state_once_each", health_samples_status_before_state_once_each},
      {"model_control_routes_need_the_switch_and_the_key", model_control_routes_need_the_switch_and_the_key},
      {"model_download_routes_need_the_switch_and_the_key", model_download_routes_need_the_switch_and_the_key},
      {"web_ui_listed_integers_are_dropdowns", web_ui_listed_integers_are_dropdowns},
      {"served_models_follow_the_running_card", served_models_follow_the_running_card},
      {"health_carries_recovery_only_with_failed", health_carries_recovery_only_with_failed},
      {"health_includes_engine_state_when_provided", health_includes_engine_state_when_provided},
      {"health_is_503_with_engine_state_when_unavailable", health_is_503_with_engine_state_when_unavailable},
      {"dispatches_exact_health_route", dispatches_exact_health_route},
      {"dispatches_models_with_json_escaping", dispatches_models_with_json_escaping},
      {"rejects_non_exact_routes", rejects_non_exact_routes},
      {"fails_closed_when_provider_throws_or_returns_invalid_model", fails_closed_when_provider_throws_or_returns_invalid_model},
      {"auth01_every_route_rejects_missing_malformed_wrong_token", auth01_every_route_rejects_missing_malformed_wrong_token},
      {"models_list_keeps_utf8_model_id", models_list_keeps_utf8_model_id},
      {"web_ui_off_by_default_serves_nothing_public", web_ui_off_by_default_serves_nothing_public},
      {"web_ui_serves_the_bundled_page_without_a_key", web_ui_serves_the_bundled_page_without_a_key},
      {"web_ui_leaves_every_api_route_authenticated", web_ui_leaves_every_api_route_authenticated},
      {"web_ui_still_checks_host_and_origin", web_ui_still_checks_host_and_origin},
      {"web_ui_assets_are_bundled_and_inert", web_ui_assets_are_bundled_and_inert},
      {"web_ui_has_the_monitor_and_four_thinking_levels", web_ui_has_the_monitor_and_four_thinking_levels},
      {"web_ui_has_the_models_tab_hidden_until_the_server_offers_it", web_ui_has_the_models_tab_hidden_until_the_server_offers_it},
      {"web_ui_models_tab_starts_stops_and_polls", web_ui_models_tab_starts_stops_and_polls},
      {"web_ui_chat_follows_the_running_model", web_ui_chat_follows_the_running_model},
      {"web_ui_models_tab_has_a_downloads_section", web_ui_models_tab_has_a_downloads_section},
      {"web_ui_downloads_start_cancel_poll_and_check_links", web_ui_downloads_start_cancel_poll_and_check_links},
      {"web_ui_downloads_pause_and_resume", web_ui_downloads_pause_and_resume},
      {"keyless_router_answers_without_a_key", keyless_router_answers_without_a_key},
      {"metrics_route_needs_the_key_and_the_switch", metrics_route_needs_the_key_and_the_switch},
  }, failures);
}

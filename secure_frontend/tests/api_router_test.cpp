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
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"health_samples_status_before_state_once_each", health_samples_status_before_state_once_each},
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
      {"keyless_router_answers_without_a_key", keyless_router_answers_without_a_key},
  }, failures);
}

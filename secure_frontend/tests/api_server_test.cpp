#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/request_router.hpp"
#include "secure_frontend/socket_io.hpp"
#include "support/raw_http.hpp"
#include "support/server_harness.hpp"
#include "support/test_paths.hpp"
#include "support/test_support.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

// SP3 DOS-01 / AUTH-01 / §4.6 over TCP against the real strata-secure-server
// (spec §9.3). Every case starts its own server on an ephemeral port.
namespace {
using namespace std::chrono_literals;
using secure_frontend::ApiError;
int failures = 0;
void expect(bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}

std::unique_ptr<test_support::ServerProcess> start_server(std::map<std::string, std::string> literals = {},
                                                         std::vector<std::string> engine_args = {}) {
  test_support::ServerOptions options;
  options.config_literals = std::move(literals);
  options.engine_args = std::move(engine_args);
  auto server = test_support::ServerProcess::start(options);
  const bool ready = server != nullptr && server->wait_until_listening(10s) && server->wait_for_health(test_support::kHealthReady, 15s);
  expect(ready, "server ready" + (server ? std::string{": "} + server->stderr_text() : std::string{}));
  return ready ? std::move(server) : nullptr;
}
std::string authority(const test_support::ServerProcess& s) { return "127.0.0.1:" + std::to_string(s.port()); }
std::string token() { return std::string{test_support::kHarnessToken}; }
std::string chat_body(const std::string& extra = R"("max_tokens":2)", const std::string& content = "Hi") {
  return R"({"model":"fake-model","messages":[{"role":"user","content":")" + content + R"("}])" +
         (extra.empty() ? "" : "," + extra) + "}";
}
std::string chat_request(const test_support::ServerProcess& s, const std::string& body, std::vector<std::string> extra = {}) {
  extra.insert(extra.begin(), {raw_http::bearer(token()), "Content-Type: application/json"});
  return raw_http::request("POST", "/v1/chat/completions", authority(s), extra, body);
}
std::optional<raw_http::Response> raw(const test_support::ServerProcess& s, const std::string& request,
                                      std::chrono::milliseconds timeout = 10s) {
  return raw_http::exchange("127.0.0.1", s.port(), request, timeout);
}
// record_of / count_of: shared helpers (pre-flight P35) for the later cases of Tasks 10, 12, 16, 17 and 19-22.
[[maybe_unused]] std::string record_of(const std::filesystem::path& file) {
  std::ifstream in(file, std::ios::binary);
  return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
[[maybe_unused]] std::size_t count_of(const std::string& text, std::string_view needle) {
  std::size_t n = 0;
  for (std::size_t p = text.find(needle); p != std::string::npos; p = text.find(needle, p + 1U)) ++n;
  return n;
}
// Pre-flight D2: the "retry /health on <ip> up to 100 x 100 ms" loop shared by
// web01_ipv6_bound_host_rules (Task 10) and net01_ipv6_loopback_listener_only (Task 12).
std::optional<raw_http::Response> wait_health_on(std::string_view ip, std::uint16_t port, const std::string& host) {
  std::optional<raw_http::Response> r;
  for (int i = 0; i < 100; ++i) {
    r = raw_http::exchange(ip, port, raw_http::request("GET", "/health", host, {raw_http::bearer(token())}));
    if (r && r->status == 200) break;
    std::this_thread::sleep_for(100ms);
  }
  return r;
}
bool has_no_cors_headers(const raw_http::Response& r) {
  return !r.header("Access-Control-Allow-Origin") && !r.header("Access-Control-Allow-Credentials");
}
// One authenticated request for a kRouteTable entry (prefix routes get the served id).
std::string route_request(const secure_frontend::RouteEntry& e, const std::string& host, std::vector<std::string> extra = {}) {
  extra.insert(extra.begin(), raw_http::bearer(token()));
  const std::string target = e.prefix ? std::string{e.path} + "fake-model" : std::string{e.path};
  if (e.method == "POST") {
    extra.push_back("Content-Type: application/json");
    return raw_http::request("POST", target, host, extra, chat_body());
  }
  return raw_http::request(e.method, target, host, extra);
}

void dos01_body_over_limit_is_413_before_reading() {
  auto server = start_server();
  if (!server) return;
  auto c = raw_http::Connection::open("127.0.0.1", server->port());
  const std::string head = "POST /v1/chat/completions HTTP/1.1\r\nHost: " + authority(*server) + "\r\n" + raw_http::bearer(token()) +
                           "\r\nContent-Type: application/json\r\nContent-Length: 49153\r\n\r\n";
  const auto started = std::chrono::steady_clock::now();
  expect(c && c->send(head), "header only");
  const auto r = raw_http::parse_response(c ? c->read_until_close(5s) : "");
  expect(r && r->status == 413 && r->body == secure_frontend::render_error_body(ApiError::request_too_large),
         "49153 > max_body_bytes: 413 after auth, body never read");
  expect(std::chrono::steady_clock::now() - started < 1s, "answered at once");
}

void dos01_content_length_over_request_limit_is_413_before_auth() {
  auto server = start_server();
  if (!server) return;
  auto c = raw_http::Connection::open("127.0.0.1", server->port());
  const auto started = std::chrono::steady_clock::now();
  expect(c && c->send("POST /v1/chat/completions HTTP/1.1\r\nHost: " + authority(*server) + "\r\nContent-Length: 70000\r\n\r\n"),
         "no token, no body");
  const auto r = raw_http::parse_response(c ? c->read_until_close(5s) : "");
  expect(r && r->status == 413, "413 (a global limit), not 401");
  expect(std::chrono::steady_clock::now() - started < 100ms + 400ms, "within 100 ms plus scheduling slack");
}

void dos01_unauthenticated_gets_401_before_body_is_read() {
  auto server = start_server();
  if (!server) return;
  auto c = raw_http::Connection::open("127.0.0.1", server->port());
  const auto started = std::chrono::steady_clock::now();
  expect(c && c->send("POST /v1/chat/completions HTTP/1.1\r\nHost: " + authority(*server) +
                      "\r\nAuthorization: Bearer wrong-token-0123456789abcdefghijklmnop\r\nContent-Type: application/json\r\n"
                      "Content-Length: 40000\r\n\r\n"), "wrong token, body withheld");
  const auto r = raw_http::parse_response(c ? c->read_until_close(5s) : "");
  expect(r && r->status == 401 && r->header("WWW-Authenticate") == std::optional<std::string>{"Bearer"}, "401 before any body byte");
  expect(std::chrono::steady_clock::now() - started < 500ms, "within 100 ms plus slack");
}

void dos01_expect_continue_after_auth_only() {
  auto server = start_server();
  if (!server) return;
  const std::string body = chat_body();
  auto bad = raw_http::Connection::open("127.0.0.1", server->port());
  expect(bad && bad->send("POST /v1/chat/completions HTTP/1.1\r\nHost: " + authority(*server) +
                          "\r\nAuthorization: Bearer nope-0123456789abcdefghijklmnopqrstuv\r\nContent-Type: application/json\r\n"
                          "Expect: 100-continue\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n"), "bad token");
  const std::string refused = bad ? bad->read_until_close(5s) : "";
  expect(refused.find("100 Continue") == std::string::npos && refused.rfind("HTTP/1.1 401", 0) == 0, "no 100 before auth");
  auto good = raw_http::Connection::open("127.0.0.1", server->port());
  expect(good && good->send("POST /v1/chat/completions HTTP/1.1\r\nHost: " + authority(*server) + "\r\n" + raw_http::bearer(token()) +
                            "\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: " +
                            std::to_string(body.size()) + "\r\n\r\n"), "valid token");
  expect(good && good->read_for(500ms) == "HTTP/1.1 100 Continue\r\n\r\n", "100 after auth");
  expect(good && good->send(body), "body");
  const auto r = raw_http::parse_response(good ? good->read_until_close(10s) : "");
  expect(r && r->status == 200, "the chat completes");
}

void dos01_slow_header_is_408_at_header_deadline() {
  auto server = start_server({{"limits.http.header_deadline_ms", "1000"}});
  if (!server) return;
  auto c = raw_http::Connection::open("127.0.0.1", server->port());
  const auto started = std::chrono::steady_clock::now();
  expect(c && c->send("GET /health HTTP/1.1\r\nHost: "), "partial header");
  const auto r = raw_http::parse_response(c ? c->read_until_close(5s) : "");
  const auto elapsed = std::chrono::steady_clock::now() - started;
  expect(r && r->status == 408 && r->body == secure_frontend::render_error_body(ApiError::request_timeout), "408 request_timeout");
  expect(elapsed >= 900ms && elapsed < 2s, "at the 1 s header deadline");
}

void dos01_slow_body_is_408_at_request_deadline() {
  auto server = start_server({{"limits.http.header_deadline_ms", "1000"}, {"limits.http.request_deadline_ms", "2000"}});
  if (!server) return;
  auto c = raw_http::Connection::open("127.0.0.1", server->port());
  const auto started = std::chrono::steady_clock::now();
  const std::string body = chat_body();
  expect(c && c->send("POST /v1/chat/completions HTTP/1.1\r\nHost: " + authority(*server) + "\r\n" + raw_http::bearer(token()) +
                      "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" +
                      body.substr(0, 5)), "valid token, partial body");
  const auto r = raw_http::parse_response(c ? c->read_until_close(5s) : "");
  const auto elapsed = std::chrono::steady_clock::now() - started;
  expect(r && r->status == 408, "408 for an authenticated slow body");
  expect(elapsed >= 1900ms && elapsed < 3s, "at the 2 s request deadline");
}

void dos01_incomplete_body_then_close_frees_worker() {
  auto server = start_server();
  if (!server) return;
  {
    auto c = raw_http::Connection::open("127.0.0.1", server->port());
    expect(c && c->send("POST /v1/chat/completions HTTP/1.1\r\nHost: " + authority(*server) + "\r\n" + raw_http::bearer(token()) +
                        "\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"model\""), "partial body");
  }   // closed here
  const auto started = std::chrono::steady_clock::now();
  const auto r = raw(*server, chat_request(*server, chat_body()));
  expect(r && r->status == 200 && std::chrono::steady_clock::now() - started < 2s, "the next client is served at once");
}

void err_unauthenticated_is_401_on_every_path_and_method() {
  auto server = start_server();
  if (!server) return;
  for (const char* method : {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}) {
    for (const char* target : {"/health", "/v1/models", "/v1/models/fake-model", "/v1/chat/completions", "/v1/completions", "/x"}) {
      const std::string request = std::string{method} + " " + target + " HTTP/1.1\r\nHost: " + authority(*server) +
                                  (std::string{method} == "POST" || std::string{method} == "PUT" ? "\r\nContent-Length: 0" : "") + "\r\n\r\n";
      const auto r = raw(*server, request);
      expect(r && r->status == 401 && r->body == secure_frontend::render_error_body(ApiError::invalid_api_key),
             std::string{method} + " " + target + " is 401 without a token");
    }
  }
}

void security_headers_on_every_response() {
  auto server = start_server();
  if (!server) return;
  const std::vector<std::string> requests{
      raw_http::request("GET", "/health", authority(*server), {raw_http::bearer(token())}),
      raw_http::request("GET", "/v1/models", authority(*server), {raw_http::bearer(token())}),
      raw_http::request("GET", "/nope", authority(*server), {raw_http::bearer(token())}),
      raw_http::request("GET", "/health", authority(*server), {}),
      raw_http::request("GET", "/health", "evil:1", {raw_http::bearer(token())}),
      chat_request(*server, chat_body()),
      chat_request(*server, "{"),
      "GET /health HTTP/1.0\r\nHost: " + authority(*server) + "\r\n\r\n"};
  for (const auto& request : requests) {
    const auto r = raw(*server, request);
    expect(r.has_value(), "response for " + request.substr(0, request.find('\r')));
    if (!r) continue;
    for (const auto& [name, value] : std::vector<std::pair<std::string, std::string>>{
             {"Connection", "close"}, {"Cache-Control", "no-store"}, {"X-Content-Type-Options", "nosniff"},
             {"Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"}, {"Referrer-Policy", "no-referrer"},
             {"Cross-Origin-Resource-Policy", "same-origin"}}) {
      expect(r->header(name) == std::optional<std::string>{value}, name + " on " + std::to_string(r->status));
    }
    expect(r->header("Date").has_value() && !r->header("Server") && !r->header("X-Powered-By"), "Date, no Server, no X-Powered-By");
  }
}

// SP3 WEB-01..06 / AUTH-01 / CFG-01 over TCP (spec §4.3, §4.4, §9.3).
void web01_bad_host_rejected_on_every_route() {
  auto server = start_server();
  if (!server) return;
  const std::string port = std::to_string(server->port());
  const std::vector<std::pair<std::string, int>> hosts{
      {"evil.example:" + port, 403}, {"127.0.0.2:" + port, 403}, {"127.0.0.1:1", 403}, {"127.0.0.1", 403},
      {"localhost.:" + port, 400}, {"user@127.0.0.1:" + port, 400}, {"::1:" + port, 400}};
  for (const auto& entry : secure_frontend::kRouteTable) {
    for (const auto& [host, status] : hosts) {
      const auto r = raw(*server, route_request(entry, host));
      expect(r && r->status == status && r->body.find("fake-model") == std::string::npos && r->body.find("\"status\"") == std::string::npos,
             std::string{entry.path} + " with Host " + host + " is " + std::to_string(status) + " and carries no route data");
    }
    const auto twice = raw(*server, route_request(entry, authority(*server), {"Host: " + authority(*server)}));
    expect(twice && twice->status == 400, std::string{entry.path} + " with two Host fields is 400");
  }
}

void web01_ipv6_bound_host_rules() {
  if (!test_support::ipv6_loopback_available()) test_support::skip("no IPv6 loopback on this host");
  test_support::ServerOptions options;
  options.config_literals = {{"listener.host", "\"::1\""}};
  auto server = test_support::ServerProcess::start(options);
  expect(server != nullptr, "server starts on ::1");
  if (!server) return;
  const std::string port = std::to_string(server->port());
  const auto ok = wait_health_on("::1", server->port(), "[::1]:" + port);
  expect(ok && ok->status == 200, "[::1]:port is the bound authority" + (ok ? std::string{} : ": " + server->stderr_text()));
  const auto unbracketed = raw_http::exchange("::1", server->port(), raw_http::request("GET", "/health", "::1", {raw_http::bearer(token())}));
  expect(unbracketed && unbracketed->status == 400, "::1 is malformed");
  const auto no_port = raw_http::exchange("::1", server->port(), raw_http::request("GET", "/health", "[::1]", {raw_http::bearer(token())}));
  expect(no_port && no_port->status == 403, "[::1] without the port is not allowed");
  const auto local = raw_http::exchange("::1", server->port(), raw_http::request("GET", "/health", "localhost:" + port, {raw_http::bearer(token())}));
  expect(local && local->status == 200, "localhost:port is allowed on a loopback bind (E10)");
}

void web02_bound_authority_and_localhost_alias_succeed() {
  auto server = start_server();
  if (!server) return;
  const std::string port = std::to_string(server->port());
  for (const std::string& host : std::vector<std::string>{authority(*server), "localhost:" + port, "LOCALHOST:" + port}) {
    for (const auto& entry : secure_frontend::kRouteTable) {
      const auto r = raw(*server, route_request(entry, host));
      expect(r && r->status == 200, std::string{entry.path} + " succeeds with Host " + host);
    }
  }
}

void web02_host_alias_from_config_succeeds() {
  auto server = start_server({{"listener.host_aliases", "[\"strata.lan:8080\",\"box.lan\"]"}});
  if (!server) return;
  for (const std::string host : {"strata.lan:8080", "box.lan"}) {
    const auto r = raw(*server, raw_http::request("GET", "/health", host, {raw_http::bearer(token())}));
    expect(r && r->status == 200, "configured alias " + host);
  }
  const auto other = raw(*server, raw_http::request("GET", "/health", "strata.lan:8081", {raw_http::bearer(token())}));
  expect(other && other->status == 403, "the alias is exact (other port refused)");
}

void web03_untrusted_origin_no_cors_header() {
  auto server = start_server({{"listener.cors_origins", "[\"http://app.example:3000\"]"}});
  if (!server) return;
  const std::string port = std::to_string(server->port());
  for (const std::string& origin : std::vector<std::string>{"null", "http://app.example.evil:3000", "http://APP.example:3000",
                                                            "http://127.0.0.1:80", "https://127.0.0.1:" + port, "http://app.example:3000/"}) {
    const auto r = raw(*server, raw_http::request("GET", "/health", authority(*server), {raw_http::bearer(token()), "Origin: " + origin}));
    expect(r && r->status == 403 && has_no_cors_headers(*r), "origin " + origin + " is 403 without CORS headers");
  }
  const auto dup = raw(*server, raw_http::request("GET", "/health", authority(*server),
                                                  {raw_http::bearer(token()), "Origin: http://app.example:3000", "Origin: http://app.example:3000"}));
  expect(dup && dup->status == 403 && has_no_cors_headers(*dup), "duplicate Origin is 403");
}

void web04_default_emits_no_cors_header_anywhere() {
  const auto dir = test_support::make_temp_dir("web04");
  auto server = start_server({}, {"--record-file=" + test_support::utf8_path(dir / "record.txt")});
  if (!server) return;
  const std::string a = authority(*server);
  const std::string origin = "Origin: http://" + a;
  const std::vector<std::string> requests{
      raw_http::request("GET", "/health", a, {raw_http::bearer(token()), origin}),
      raw_http::request("GET", "/v1/models", a, {raw_http::bearer(token()), origin}),
      raw_http::request("GET", "/v1/models/fake-model", a, {raw_http::bearer(token()), origin}),
      raw_http::request("GET", "/v1/models/other", a, {raw_http::bearer(token()), origin}),
      chat_request(*server, chat_body(), {origin}),
      chat_request(*server, "{", {origin}),
      chat_request(*server, chat_body(R"("tools":[])"), {origin}),
      raw_http::request("GET", "/nope", a, {raw_http::bearer(token()), origin}),
      raw_http::request("DELETE", "/health", a, {raw_http::bearer(token()), origin}),
      raw_http::request("GET", "/health", a, {origin}),
      raw_http::request("GET", "/health", "evil:1", {origin}),
      raw_http::request("GET", "/health", a, {raw_http::bearer(token()), "Origin: http://evil.example"}),
      raw_http::request("OPTIONS", "/v1/chat/completions", a, {"Origin: http://evil.example", "Access-Control-Request-Method: POST"}),
      raw_http::request("POST", "/v1/chat/completions", a, {raw_http::bearer(token()), "Content-Type: text/plain"}, "{}"),
      raw_http::request("POST", "/v1/chat/completions", a, {raw_http::bearer(token()), "Transfer-Encoding: chunked"}),
      raw_http::request("POST", "/v1/chat/completions", a, {raw_http::bearer(token()), "Content-Type: application/json", "Expect: x"}, "{}"),
      "GET /health HTTP/1.0\r\nHost: " + a + "\r\n\r\n",
      "GET /" + std::string(5000, 'a') + " HTTP/1.1\r\nHost: " + a + "\r\n\r\n",
      raw_http::request("GET", "/health", a, {"X-Fill: " + std::string(17000, 'f')}),
      raw_http::request("POST", "/v1/chat/completions", a, {}, std::string(70000, ' '))};
  std::set<int> statuses;
  for (const auto& request : requests) {
    const auto r = raw(*server, request);
    if (!r) { expect(false, "no response for " + request.substr(0, 40)); continue; }
    statuses.insert(r->status);
    expect(has_no_cors_headers(*r), "no CORS header on a " + std::to_string(r->status));
  }
  for (const int s : {200, 400, 401, 403, 404, 405, 411, 413, 414, 415, 417, 431, 505}) {
    expect(statuses.count(s) == 1U, "status " + std::to_string(s) + " was exercised");
  }
}

void web05_only_exact_configured_origin_allowed() {
  auto server = start_server({{"listener.cors_origins", "[\"http://app.example:3000\"]"}});
  if (!server) return;
  const auto ok = raw(*server, raw_http::request("GET", "/v1/models", authority(*server), {raw_http::bearer(token()), "Origin: http://app.example:3000"}));
  expect(ok && ok->status == 200 && ok->header("Access-Control-Allow-Origin") == std::optional<std::string>{"http://app.example:3000"} &&
         ok->header("Vary") == std::optional<std::string>{"Origin"} && !ok->header("Access-Control-Allow-Credentials"),
         "the configured origin gets its exact value, Vary, never credentials");
  const auto other = raw(*server, raw_http::request("GET", "/v1/models", authority(*server), {raw_http::bearer(token()), "Origin: http://other.example:3000"}));
  expect(other && other->status == 403 && has_no_cors_headers(*other), "another origin is never reflected");
  const auto same = raw(*server, raw_http::request("GET", "/v1/models", authority(*server), {raw_http::bearer(token()), "Origin: http://" + authority(*server)}));
  expect(same && same->status == 200 && has_no_cors_headers(*same), "same origin needs no CORS headers");
}

void web06_preflight_matrix() {
  const auto dir = test_support::make_temp_dir("web06p");
  auto server = start_server({{"listener.cors_origins", "[\"http://app.example:3000\"]"}},
                             {"--record-file=" + test_support::utf8_path(dir / "record.txt")});
  if (!server) return;
  const std::string a = authority(*server);
  const auto preflight = [&](const std::string& origin, const std::string& method, const std::string& headers) {
    std::vector<std::string> lines{"Origin: " + origin, "Access-Control-Request-Method: " + method};
    if (!headers.empty()) lines.push_back("Access-Control-Request-Headers: " + headers);
    return raw(*server, raw_http::request("OPTIONS", "/v1/chat/completions", a, lines));
  };
  for (const std::string method : {"GET", "POST"}) {
    for (const std::string headers : {"", "authorization", "authorization, content-type",
                                      "Authorization,Content-Type,X-Stainless-OS,x-stainless-lang,x-stainless-arch,x-stainless-runtime,"
                                      "x-stainless-runtime-version,x-stainless-package-version,x-stainless-retry-count,x-stainless-timeout"}) {
      const auto r = preflight("http://app.example:3000", method, headers);
      expect(r && r->status == 204 && r->header("Access-Control-Allow-Origin") == std::optional<std::string>{"http://app.example:3000"} &&
             r->header("Access-Control-Allow-Methods") == std::optional<std::string>{"GET, POST"} &&
             r->header("Access-Control-Max-Age") == std::optional<std::string>{"600"},
             "allowed preflight " + method + " [" + headers + "] needs no token");
    }
  }
  for (const auto& [origin, method, headers] : std::vector<std::tuple<std::string, std::string, std::string>>{
           {"http://evil.example", "POST", ""}, {"http://app.example:3000", "PUT", ""}, {"http://app.example:3000", "POST", "x-api-key"},
           {"http://" + a, "POST", ""}, {"null", "POST", ""}}) {
    const auto r = preflight(origin, method, headers);
    expect(r && r->status == 403 && has_no_cors_headers(*r), "refused preflight " + origin + " " + method + " " + headers);
  }
  expect(record_of(dir / "record.txt").find("GEN") == std::string::npos, "no preflight reached a route");
}

void web06_cross_origin_post_without_trust_rejected() {
  const auto dir = test_support::make_temp_dir("web06");
  auto server = start_server({}, {"--record-file=" + test_support::utf8_path(dir / "record.txt")});
  if (!server) return;
  const auto r = raw(*server, chat_request(*server, chat_body(), {"Origin: http://evil.example"}));
  expect(r && r->status == 403 && has_no_cors_headers(*r), "a valid token from a foreign origin is 403");
  expect(record_of(dir / "record.txt").find("GEN") == std::string::npos, "the engine received no GEN");
}

void auth01_every_route_rejects_missing_malformed_wrong_token() {
  auto server = start_server();
  if (!server) return;
  const std::pair<std::string, int> variants[] = {
      {"", 401}, {"Authorization: bearer " + token(), 401}, {"Authorization: Bearer ", 401}, {"Authorization: Basic " + token(), 401},
      {"Authorization: Bearer wrong-token-0123456789abcdefghijklmn", 401},
      {"Authorization: Bearer " + token() + "\r\nAuthorization: Bearer " + token(), 400}};
  for (const auto& entry : secure_frontend::kRouteTable) {
    for (const auto& [line, status] : variants) {
      std::vector<std::string> lines;
      if (!line.empty()) lines.push_back(line);
      const std::string target = entry.prefix ? std::string{entry.path} + "fake-model" : std::string{entry.path};
      if (entry.method == "POST") lines.push_back("Content-Type: application/json");
      const auto r = raw(*server, raw_http::request(entry.method, target, authority(*server), lines, entry.method == "POST" ? chat_body() : ""));
      expect(r && r->status == status && r->body.find("fake-model") == std::string::npos,
             std::string{entry.method} + " " + target + " -> " + std::to_string(status) + " for [" + line.substr(0, 30) + "]");
    }
  }
}

// CFG-01 / NET-03, process half (plan note 12): the validation half is typed_config_tests (Task 4).
void cfg01_wildcard_bind_requires_host_aliases() {
  const auto dir = test_support::make_temp_dir("wild");
  test_support::ServerOptions options;
  options.config_literals = {{"listener.host", "\"0.0.0.0\""}, {"listener.allow_remote", "true"}, {"listener.allow_wildcard_bind", "true"}};
  options.engine_args = {"--record-file=" + test_support::utf8_path(dir / "record.txt")};
  auto server = test_support::ServerProcess::start(options);
  expect(server != nullptr, "the process starts");
  if (!server) return;
  const auto code = server->wait_exit(10s);
  expect(code.has_value() && *code != 0, "a wildcard bind without listener.host_aliases fails validation");
  expect(server->stderr_text().find("listener.host_aliases") != std::string::npos, "the error names the key: " + server->stderr_text());
  expect(!std::filesystem::exists(dir / "record.txt"), "no engine was spawned (the fake creates its record file at start)");
}
}  // namespace

int main(int argc, char** argv) {
  secure_frontend::WinsockGuard winsock;
  return secure_frontend_test::run_cases(argc, argv, {
      {"dos01_body_over_limit_is_413_before_reading", dos01_body_over_limit_is_413_before_reading},
      {"dos01_content_length_over_request_limit_is_413_before_auth", dos01_content_length_over_request_limit_is_413_before_auth},
      {"dos01_unauthenticated_gets_401_before_body_is_read", dos01_unauthenticated_gets_401_before_body_is_read},
      {"dos01_expect_continue_after_auth_only", dos01_expect_continue_after_auth_only},
      {"dos01_slow_header_is_408_at_header_deadline", dos01_slow_header_is_408_at_header_deadline},
      {"dos01_slow_body_is_408_at_request_deadline", dos01_slow_body_is_408_at_request_deadline},
      {"dos01_incomplete_body_then_close_frees_worker", dos01_incomplete_body_then_close_frees_worker},
      {"err_unauthenticated_is_401_on_every_path_and_method", err_unauthenticated_is_401_on_every_path_and_method},
      {"security_headers_on_every_response", security_headers_on_every_response},
      {"web01_bad_host_rejected_on_every_route", web01_bad_host_rejected_on_every_route},
      {"web01_ipv6_bound_host_rules", web01_ipv6_bound_host_rules},
      {"web02_bound_authority_and_localhost_alias_succeed", web02_bound_authority_and_localhost_alias_succeed},
      {"web02_host_alias_from_config_succeeds", web02_host_alias_from_config_succeeds},
      {"web03_untrusted_origin_no_cors_header", web03_untrusted_origin_no_cors_header},
      {"web04_default_emits_no_cors_header_anywhere", web04_default_emits_no_cors_header_anywhere},
      {"web05_only_exact_configured_origin_allowed", web05_only_exact_configured_origin_allowed},
      {"web06_preflight_matrix", web06_preflight_matrix},
      {"web06_cross_origin_post_without_trust_rejected", web06_cross_origin_post_without_trust_rejected},
      {"auth01_every_route_rejects_missing_malformed_wrong_token", auth01_every_route_rejects_missing_malformed_wrong_token},
      {"cfg01_wildcard_bind_requires_host_aliases", cfg01_wildcard_bind_requires_host_aliases},
  }, failures);
}

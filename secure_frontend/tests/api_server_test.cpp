#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/request_router.hpp"
#include "secure_frontend/socket_io.hpp"
#include "support/connection_scan.hpp"
#include "support/raw_http.hpp"
#include "support/server_harness.hpp"
#include "support/test_paths.hpp"
#include "support/test_support.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
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

// DOS-01 / §2.3: eight slow-header clients hold all eight workers in P1; a ninth
// connection evicts the oldest of them and is answered anyway (spec §2.3).
void dos01_eviction_over_tcp_admits_new_client() {
  auto server = start_server({{"limits.http.header_deadline_ms", "30000"}});
  if (!server) return;
  std::vector<raw_http::Connection> holders;
  for (int i = 0; i < 8; ++i) {
    auto c = raw_http::Connection::open("127.0.0.1", server->port());
    expect(c && c->send("GET /health HTTP/1.1\r\nHost: "), "slow-header client " + std::to_string(i));
    if (c) holders.push_back(std::move(*c));
    std::this_thread::sleep_for(20ms);
  }
  std::this_thread::sleep_for(200ms);   // all eight workers now sit in P1
  const auto r = raw(*server, raw_http::request("GET", "/health", authority(*server), {raw_http::bearer(token())}), 5s);
  expect(r && r->status == 200, "a ninth client completes while eight workers are held in P1");
  bool someone_closed = false;
  for (auto& h : holders) someone_closed = someone_closed || h.wait_closed(100ms);
  expect(someone_closed, "one P1 client was evicted (closed without a response)");
}

// DOS-01 / §2.3: 16 one-byte-per-second header clients can never hold every
// worker: eviction cycles through them and a real chat completes promptly.
void dos01_slowloris_cannot_starve_a_real_client() {
  auto server = start_server({{"limits.http.header_deadline_ms", "30000"}});
  if (!server) return;
  std::atomic<bool> stop{false};
  std::vector<std::thread> lorises;
  for (int i = 0; i < 16; ++i) {
    lorises.emplace_back([&stop, port = server->port()] {
      while (!stop) {
        auto c = raw_http::Connection::open("127.0.0.1", port);
        if (!c) continue;
        const std::string head = "GET /health HTTP/1.1\r\nHost: x\r\nX-Slow: ";
        for (std::size_t i = 0; i < head.size() && !stop; ++i) {
          if (!c->send(std::string_view{head}.substr(i, 1U))) break;
          std::this_thread::sleep_for(1s);
        }
      }
    });
  }
  std::this_thread::sleep_for(500ms);
  const auto started = std::chrono::steady_clock::now();
  const auto r = raw(*server, chat_request(*server, chat_body()), 20s);
  expect(r && r->status == 200, "a real chat completes under 16 one-byte-per-second header clients");
  expect(std::chrono::steady_clock::now() - started < 10s, "and promptly");
  stop = true;
  for (auto& t : lorises) t.join();
}

// DOS-01 / §2.2 + §2.3: an unauthenticated slow-body client never reaches P3 —
// it is answered at once with 401 (auth before the body, Task 9) or, while all
// eight workers drain a previous 401, refused with 503 server_busy at accept.
// Neither can starve a real client: every dribbler answer is instant and the
// real chat completes (Retry-After: 1 is honored by the retry loop).
void dos01_slow_body_clients_cannot_starve_a_real_client() {
  auto server = start_server();
  if (!server) return;
  std::vector<raw_http::Connection> dribblers;
  int fortyones = 0;
  for (int i = 0; i < 16; ++i) {
    auto c = raw_http::Connection::open("127.0.0.1", server->port());
    const auto started = std::chrono::steady_clock::now();
    expect(c && c->send("POST /v1/chat/completions HTTP/1.1\r\nHost: " + authority(*server) +
                        "\r\nAuthorization: Bearer nope-0123456789abcdefghijklmnopqrstuvw\r\nContent-Type: application/json\r\n"
                        "Content-Length: 40000\r\n\r\n{"), "header with a bad token, then a dribbled body");
    const std::string reply = c ? c->read_until_close(2s) : "";
    const bool refused = reply.rfind("HTTP/1.1 503", 0) == 0;
    expect((reply.rfind("HTTP/1.1 401", 0) == 0 || refused) && std::chrono::steady_clock::now() - started < 1s,
           "answered at once: 401, or 503 server_busy while every worker drains an earlier 401 (spec §2.3)");
    if (reply.rfind("HTTP/1.1 401", 0) == 0) ++fortyones;
    if (c) dribblers.push_back(std::move(*c));
  }
  expect(fortyones >= 1, "at least one dribbling bad-token client got the 401 auth-before-body answer");
  std::optional<raw_http::Response> r;
  for (int attempt = 0; attempt < 12 && !(r && r->status == 200); ++attempt) {
    r = raw(*server, chat_request(*server, chat_body()), 10s);
    if (!(r && r->status == 200)) std::this_thread::sleep_for(300ms);
  }
  expect(r && r->status == 200, "a real chat completes once the P8 drains free the workers");
}

// Ruling T12-net01: differential listener comparison helper (see below).
std::vector<std::string> listening_signature(const std::vector<test_support::SocketRow>& rows) {
  std::vector<std::string> sig;
  for (const auto& row : rows)
    if (row.listening) sig.push_back(row.kind + ":" + std::to_string(row.local_port) + ":" + row.local_address);
  std::sort(sig.begin(), sig.end());
  return sig;
}

// NET-01 / §2.1: a fixed worker pool adds no listener. D3: the traffic is
// asserted, not asserted-away. Ruling T12-net01b: the plan's fixed "20 x 200"
// expectation contradicts spec §2.3 — with ten concurrent chats holding all
// eight workers past P1 (one lease; the queue arrives in Task 16), later
// clients, GETs included, are legitimately refused 503 server_busy at accept.
// The asserted invariants: every client gets a COMPLETE response (no nulls, no
// hangs), every status is 200 or 503, at least one client got 200 (the pool
// served), a sequential health check succeeds after the burst (the workers
// came back), and the listening-socket set is unchanged (ruling T12-net01:
// differential, because the non-dumpable server forces uid attribution and the
// dev container has other same-uid listeners).
void net01_workers_add_no_listener() {
  auto server = start_server();
  if (!server) return;
  const auto before = listening_signature(test_support::sockets_of(server->pid()));
  std::atomic<int> twos{0};
  std::atomic<int> refused{0};
  std::atomic<int> evicted{0};
  std::atomic<int> wrong{0};
  std::vector<std::thread> clients;
  for (int i = 0; i < 20; ++i) {
    clients.emplace_back([&server, &twos, &refused, &evicted, &wrong, i] {
      const auto r = i % 2 == 0
          ? raw(*server, raw_http::request("GET", i % 4 == 0 ? "/health" : "/v1/models", authority(*server), {raw_http::bearer(token())}))
          : raw(*server, chat_request(*server, chat_body()));
      if (!r) ++evicted;   // closed without a response: the §2.3 eviction outcome
      else if (r->status == 200) ++twos;
      else if (r->status == 503) ++refused;
      else ++wrong;
    });
  }
  for (auto& t : clients) t.join();
  expect(wrong == 0, "no client of the burst got a status outside {200,503}");
  expect(twos >= 1, "at least one client of the burst got 200 (the pool served)");
  // A burst of 20 near-simultaneous clients is exactly the §2.3 admission
  // situation: late arrivals evict the oldest not-yet-authenticated connection
  // (closed without a response -> a nullopt exchange) or arrive with no idle
  // worker and no P1 victim (503 server_busy). Both are complete outcomes;
  // nothing may hang, and the server must serve again right after.
  std::cerr << "net01 burst: 200=" << twos.load() << " refused503=" << refused.load()
            << " evicted=" << evicted.load() << " wrong=" << wrong.load() << '\n';
  std::optional<raw_http::Response> health;
  for (int attempt = 0; attempt < 10 && !(health && health->status == 200); ++attempt) {
    health = raw(*server, raw_http::request("GET", "/health", authority(*server), {raw_http::bearer(token())}), 2s);
    if (!(health && health->status == 200)) std::this_thread::sleep_for(300ms);
  }
  expect(health && health->status == 200, "after the burst a sequential /health answers 200: the workers came back");
  const auto after_rows = test_support::sockets_of(server->pid());
  const auto after = listening_signature(after_rows);
  expect(after == before, "20 mixed requests added no listening socket to the server");
  bool server_listener = false;
  for (const auto& row : after_rows) {
    if (!row.listening || row.local_port != server->port()) continue;
    server_listener = true;
    expect(test_support::is_loopback_row(row), "the server's listener is the loopback one");
  }
  expect(server_listener, "the server still listens on its port after the traffic");
}

// NET-01: on a ::1 bind the server's listener is the v6 loopback one, serving
// adds no listener (differential, ruling T12-net01), and nothing answers on
// IPv4. D2: reuses wait_health_on.
void net01_ipv6_loopback_listener_only() {
  if (!test_support::ipv6_loopback_available()) test_support::skip("no IPv6 loopback on this host");
  test_support::ServerOptions options;
  options.config_literals = {{"listener.host", "\"::1\""}};
  auto server = test_support::ServerProcess::start(options);
  expect(server != nullptr, "server starts on ::1");
  if (!server) return;
  const auto r = wait_health_on("::1", server->port(), "[::1]:" + std::to_string(server->port()));
  expect(r && r->status == 200, "served on ::1");
  const auto rows = test_support::sockets_of(server->pid());
  const auto before = listening_signature(rows);
  std::size_t own_listeners = 0;
  for (const auto& row : rows) {
    if (!row.listening || row.local_port != server->port()) continue;
    ++own_listeners;
    expect(row.kind == "tcp6" && test_support::is_loopback_row(row), "the server's listener is ::1 only");
  }
  expect(own_listeners == 1U, "the server has exactly one listener, on its port");
  const auto again = test_support::sockets_of(server->pid());
  expect(listening_signature(again) == before, "the /health traffic added no listener");
  expect(!raw_http::Connection::open("127.0.0.1", server->port()).has_value(), "nothing listens on IPv4");
}

// SP3 Task 16 (ChatRoute; spec §5.4, B1/B2/B6, §3.5, DOS-02): the server-side
// budget/sampling/response cases read the engine's --record-file, so they can
// assert exactly what GEN reached the engine.
std::vector<std::string> gen_lines(const std::string& record) {
  std::vector<std::string> lines;
  std::istringstream in(record);
  for (std::string line; std::getline(in, line);) if (line.rfind("GEN ", 0) == 0) lines.push_back(line);
  return lines;
}
std::size_t gen_max(const std::string& gen) { return std::stoul(gen.substr(4, gen.find(' ', 4) - 4)); }
std::size_t gen_prompt(const std::string& gen) {
  const std::string ids = gen.substr(gen.rfind(' ') + 1U);
  return static_cast<std::size_t>(std::count(ids.begin(), ids.end(), ',')) + 1U;
}
struct Recorded final {
  std::filesystem::path record;
  std::unique_ptr<test_support::ServerProcess> server;
};
Recorded start_recorded(const std::string& tag, std::map<std::string, std::string> literals = {}, std::vector<std::string> engine = {}) {
  Recorded r;
  r.record = test_support::make_temp_dir(tag) / "record.txt";
  engine.push_back("--record-file=" + test_support::utf8_path(r.record));
  r.server = start_server(std::move(literals), std::move(engine));
  return r;
}

void max_tokens_above_limit_is_clamped() {
  auto r = start_recorded("mt1", {{"limits.chat.max_completion_tokens", "16"}, {"limits.chat.default_max_tokens", "0"}});
  if (!r.server) return;
  const auto response = raw(*r.server, chat_request(*r.server, chat_body(R"("max_tokens":16384)")));
  expect(response && response->status == 200, "an over-limit max_tokens is clamped, not rejected (B2)");
  const auto gens = gen_lines(record_of(r.record));
  expect(gens.size() == 1U && gen_max(gens.front()) == 16U, "GEN max_new is the configured cap");
}

void max_tokens_clamped_to_context_room() {
  auto r = start_recorded("mt2", {}, {"--ready-context=200"});
  if (!r.server) return;
  const auto response = raw(*r.server, chat_request(*r.server, chat_body(R"("max_tokens":1000)")));
  expect(response && response->status == 200, "clamped to the context room");
  const auto gens = gen_lines(record_of(r.record));
  expect(gens.size() == 1U && gen_max(gens.front()) == 200U - gen_prompt(gens.front()) - 8U, "max_new = ctx - n - 8");
}

void prompt_alone_over_context_is_400() {
  auto r = start_recorded("mt3", {}, {"--ready-context=64"});
  if (!r.server) return;
  const auto response = raw(*r.server, chat_request(*r.server, chat_body("", std::string(100, 'x'))));
  expect(response && response->status == 400 &&
         response->body == secure_frontend::render_error_body(ApiError::context_length_exceeded), "the prompt alone fills the context");
  expect(gen_lines(record_of(r.record)).empty(), "no GEN was written");
}

void absent_max_tokens_uses_auto() {
  auto r = start_recorded("mt4");
  if (!r.server) return;
  const auto response = raw(*r.server, chat_request(*r.server, chat_body("")));
  expect(response && response->status == 200, "a request without max_tokens");
  const auto gens = gen_lines(record_of(r.record));
  expect(gens.size() == 1U && gen_max(gens.front()) == std::min<std::size_t>(4096U, 4096U - gen_prompt(gens.front()) - 8U),
         "auto = min(max_completion_tokens, ctx - n - 8) (B1)");
}

void sampling_passthrough_reaches_gen() {
  auto r = start_recorded("smp");
  if (!r.server) return;
  const auto response = raw(*r.server, chat_request(*r.server, chat_body(R"("max_tokens":2,"temperature":0.5,"top_p":0.9,"seed":42,"presence_penalty":0)")));
  expect(response && response->status == 200, "sampling accepted");
  const auto gens = gen_lines(record_of(r.record));
  expect(gens.size() == 1U && gens.front().find(" temperature=0.5 top_p=0.9 seed=42 ") != std::string::npos, "GEN carries the keys: " +
         (gens.empty() ? std::string{} : gens.front()));
}

void dos01_context_rule_is_400_without_gen() {
  auto r = start_recorded("ctx", {}, {"--ready-context=64"});
  if (!r.server) return;
  const auto response = raw(*r.server, chat_request(*r.server, chat_body(R"("max_tokens":5)", std::string(100, 'y'))));
  expect(response && response->status == 400 && response->body.find("context_length_exceeded") != std::string::npos, "400");
  expect(gen_lines(record_of(r.record)).empty() && r.server->wait_for_health(test_support::kHealthReady, 2s),
         "no GEN; the engine never saw a request it would refuse and stays ready");
}

void chat_response_has_openai_shape() {
  auto r = start_recorded("shape");
  if (!r.server) return;
  const auto first = raw(*r.server, chat_request(*r.server, chat_body()));
  const auto second = raw(*r.server, chat_request(*r.server, chat_body()));
  expect(first && first->status == 200 && second && second->status == 200, "two chats");
  if (!first || !second) return;
  const auto id_of = [](const std::string& body) { const auto p = body.find("\"id\":\"chatcmpl-"); return p == std::string::npos ? std::string{} : body.substr(p + 15, 32); };
  expect(id_of(first->body).size() == 32U && id_of(first->body).find_first_not_of("0123456789abcdef") == std::string::npos, "32 lowercase hex");
  expect(id_of(first->body) != id_of(second->body), "a fresh id per response");
  expect(first->body.find("\"created\":0") == std::string::npos && first->body.find("\"finish_reason\":") != std::string::npos &&
         first->body.find("\"completion_tokens\":1") != std::string::npos, "created, finish_reason and usage are real");
}

void dos02_excess_connections_get_503_retry_after() {
  auto r = start_recorded("exc", {{"limits.concurrency.max_concurrent_requests", "2"}}, {"--tokens=60", "--token-interval-ms=50"});
  if (!r.server) return;
  std::thread chat([&] { (void)raw(*r.server, chat_request(*r.server, chat_body("")), 30s); });
  std::this_thread::sleep_for(300ms);   // worker 1 in P6
  auto body_holder = raw_http::Connection::open("127.0.0.1", r.server->port());
  expect(body_holder && body_holder->send("POST /v1/chat/completions HTTP/1.1\r\nHost: " + authority(*r.server) + "\r\n" +
                                          raw_http::bearer(token()) + "\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"),
         "worker 2 held in P3 by an authenticated slow body");
  std::this_thread::sleep_for(200ms);
  const auto refused = raw(*r.server, raw_http::request("GET", "/health", authority(*r.server), {raw_http::bearer(token())}), 5s);
  expect(refused && refused->status == 503 && refused->header("Retry-After") == std::optional<std::string>{"1"} &&
         refused->body == secure_frontend::render_error_body(ApiError::server_busy), "no worker free: 503 server_busy, Retry-After: 1, JSON, got " +
         (refused ? std::to_string(refused->status) + " " + refused->body : std::string{"<no response>"}));
  body_holder.reset();
  chat.join();
}

void dos02_queue_full_is_503() {
  auto r = start_recorded("qf", {}, {"--tokens=20", "--token-interval-ms=50"});
  if (!r.server) return;
  std::vector<std::thread> holders;
  for (int i = 0; i < 5; ++i) {
    holders.emplace_back([&] { (void)raw(*r.server, chat_request(*r.server, chat_body("")), 30s); });
    std::this_thread::sleep_for(50ms);
  }
  std::this_thread::sleep_for(200ms);   // 1 running + 4 queued
  const auto started = std::chrono::steady_clock::now();
  const auto refused = raw(*r.server, chat_request(*r.server, chat_body("")));
  expect(refused && refused->status == 503 && refused->body == secure_frontend::render_error_body(ApiError::server_busy) &&
         refused->header("Retry-After") == std::optional<std::string>{"1"}, "the sixth chat is refused at once");
  expect(std::chrono::steady_clock::now() - started < 500ms, "without waiting");
  for (auto& t : holders) t.join();
}

void dos02_queue_timeout_is_503() {
  auto r = start_recorded("qt", {{"limits.concurrency.queue_timeout_ms", "1000"}}, {"--tokens=30", "--token-interval-ms=100"});
  if (!r.server) return;
  std::thread running([&] { (void)raw(*r.server, chat_request(*r.server, chat_body("")), 30s); });
  std::this_thread::sleep_for(200ms);
  const auto started = std::chrono::steady_clock::now();
  const auto waited = raw(*r.server, chat_request(*r.server, chat_body("")), 10s);
  const auto elapsed = std::chrono::steady_clock::now() - started;
  expect(waited && waited->status == 503 && waited->body.find("server_busy") != std::string::npos, "queue timeout is 503 server_busy");
  expect(elapsed >= 900ms && elapsed < 2500ms, "after about 1 s");
  running.join();
}

void dos02_queue_is_fifo() {
  auto r = start_recorded("fifo", {}, {"--tokens=8", "--token-interval-ms=50"});
  if (!r.server) return;
  std::mutex m;
  std::vector<int> done;
  std::vector<std::thread> clients;
  for (int i = 0; i < 5; ++i) {
    clients.emplace_back([&, i] {
      const auto response = raw(*r.server, chat_request(*r.server, chat_body("", "client" + std::to_string(i))), 30s);
      std::lock_guard g(m);
      if (response && response->status == 200) done.push_back(i);
    });
    std::this_thread::sleep_for(100ms);
  }
  for (auto& t : clients) t.join();
  expect(done == std::vector<int>{0, 1, 2, 3, 4}, "completion order equals admission order");
}

void dos02_health_answers_while_generation_places_full() {
  auto r = start_recorded("hp", {}, {"--tokens=40", "--token-interval-ms=50"});
  if (!r.server) return;
  std::vector<std::thread> holders;
  for (int i = 0; i < 5; ++i) holders.emplace_back([&] { (void)raw(*r.server, chat_request(*r.server, chat_body("")), 60s); });
  std::this_thread::sleep_for(500ms);
  const auto started = std::chrono::steady_clock::now();
  const auto health = raw(*r.server, raw_http::request("GET", "/health", authority(*r.server), {raw_http::bearer(token())}));
  const auto models = raw(*r.server, raw_http::request("GET", "/v1/models", authority(*r.server), {raw_http::bearer(token())}));
  expect(health && health->status == 200 && health->body == "{\"status\":\"ok\",\"engine\":\"generating\"}\n", "/health answers at once");
  expect(models && models->status == 200, "/v1/models answers at once");
  expect(std::chrono::steady_clock::now() - started < 1s, "within one second while every generation place is taken");
  for (auto& t : holders) t.join();
}

void dos02_serial_mode_one_worker() {
  auto r = start_recorded("serial", {{"limits.concurrency.max_concurrent_requests", "1"}}, {"--tokens=40", "--token-interval-ms=50"});
  if (!r.server) return;
  std::thread first([&] { (void)raw(*r.server, chat_request(*r.server, chat_body("")), 30s); });
  std::this_thread::sleep_for(300ms);
  const auto second = raw(*r.server, chat_request(*r.server, chat_body("")));
  expect(second && second->status == 503 && second->body.find("server_busy") != std::string::npos, "the second chat is busy in serial mode");
  first.join();
}

// SP3 Task 17 (acceptance: DOS-02 cancel/release, §2.6, §2.8; the behavior was
// built in Tasks 6a/8a/8b/12/13/15/16 — these lock it in).
void dos02_queued_client_disconnect_leaves_queue() {
  auto r = start_recorded("qdc", {}, {"--tokens=40", "--token-interval-ms=50"});
  if (!r.server) return;
  std::thread a([&] { (void)raw(*r.server, chat_request(*r.server, chat_body("", "AAA")), 30s); });
  std::this_thread::sleep_for(300ms);
  {
    auto b = raw_http::Connection::open("127.0.0.1", r.server->port());
    expect(b && b->send(chat_request(*r.server, chat_body("", "BBB"))), "B queued");
    std::this_thread::sleep_for(300ms);
  }   // B goes away while queued
  const auto c = raw(*r.server, chat_request(*r.server, chat_body("", "CCC")), 30s);
  a.join();
  expect(c && c->status == 200, "C is served");
  expect(gen_lines(record_of(r.record)).size() == 2U, "only A and C reached the engine; B left the queue silently");
}

void dos02_non_stream_disconnect_cancels() {
  auto r = start_recorded("ndc", {}, {"--tokens=10000", "--token-interval-ms=5"});
  if (!r.server) return;
  {
    auto c = raw_http::Connection::open("127.0.0.1", r.server->port());
    expect(c && c->send(chat_request(*r.server, chat_body(""))), "a long chat");
    std::this_thread::sleep_for(300ms);
  }   // client gone during P6
  bool stopped = false;
  for (int i = 0; i < 50 && !stopped; ++i) {
    stopped = record_of(r.record).find("\nSTOP\n") != std::string::npos;
    if (!stopped) std::this_thread::sleep_for(20ms);
  }
  expect(stopped, "STOP reached the engine within 1 s of the disconnect");
  const auto started = std::chrono::steady_clock::now();
  const auto next = raw(*r.server, chat_request(*r.server, chat_body(R"("max_tokens":2)")), 5s);
  expect(next && next->status == 200 && std::chrono::steady_clock::now() - started < 1s, "the next request is served within 1 s");
  expect(r.server->stderr_text().find("killed_by_supervisor") == std::string::npos, "a drained cancel never kills the engine");
}

void dos02_resources_return_to_idle() {
  auto r = start_recorded("idle", {}, {"--tokens=10000", "--token-interval-ms=5"});
  if (!r.server) return;
  (void)raw(*r.server, raw_http::request("GET", "/health", authority(*r.server), {raw_http::bearer(token())}));
  std::this_thread::sleep_for(300ms);
  const auto threads0 = test_support::thread_count(r.server->pid());
  const auto handles0 = test_support::handle_count(r.server->pid());
  for (int i = 0; i < 100; ++i) {
    auto c = raw_http::Connection::open("127.0.0.1", r.server->port());
    if (c) (void)c->send(chat_request(*r.server, chat_body("")));
    std::this_thread::sleep_for(30ms);
  }
  bool idle = false;
  for (int i = 0; i < 100 && !idle; ++i) {
    std::this_thread::sleep_for(50ms);
    idle = test_support::thread_count(r.server->pid()) == threads0 && test_support::handle_count(r.server->pid()) == handles0;
  }
  expect(idle, "after 100 cancelled chats threads (" + std::to_string(test_support::thread_count(r.server->pid())) + "/" +
               std::to_string(threads0) + ") and handles (" + std::to_string(test_support::handle_count(r.server->pid())) + "/" +
               std::to_string(handles0) + ") return to their idle values");
  const auto health = raw(*r.server, raw_http::request("GET", "/health", authority(*r.server), {raw_http::bearer(token())}));
  expect(health && health->status == 200, "and the service is healthy");
}

void shutdown_errors_never_report_fatal() {
  auto r = start_recorded("sd", {}, {"--tokens=10000", "--token-interval-ms=5"});
  if (!r.server) return;
  std::optional<raw_http::Response> answer;
  std::string raw_answer;
  std::thread chat([&] {
    auto c = raw_http::Connection::open("127.0.0.1", r.server->port());
    if (c && c->send(chat_request(*r.server, chat_body("")))) raw_answer = c->read_until_close(10s);
  });
  std::this_thread::sleep_for(500ms);
  const auto started = std::chrono::steady_clock::now();
#if defined(_WIN32)
  r.server->stop(test_support::ServerProcess::Stop::ctrl_break);
#else
  r.server->stop(test_support::ServerProcess::Stop::term);
#endif
  const auto code = r.server->wait_exit(10s);
  chat.join();
  expect(code == std::optional<int>{0} && std::chrono::steady_clock::now() - started < 5s, "exit 0 within SP2's 5 s bound");
  answer = raw_http::parse_response(raw_answer);
  expect(raw_answer.empty() || (answer && answer->status == 503 && answer->body == secure_frontend::render_error_body(ApiError::server_shutting_down)),
         "the in-flight chat gets 503 server_shutting_down or a close");
  const std::string log = r.server->stderr_text();
  expect(log.find("drain_failed") == std::string::npos && log.find("protocol_failed") == std::string::npos &&
         log.find("write_timeout") == std::string::npos, "no worker-side failure was reported as fatal during shutdown");
}

void dos01_service_healthy_after_each_attack() {
  auto server = start_server({{"limits.http.header_deadline_ms", "500"}, {"limits.http.request_deadline_ms", "1000"}});
  if (!server) return;
  const std::string a = authority(*server);
  const std::vector<std::pair<std::string, std::function<void()>>> attacks{
      {"oversize header", [&] { (void)raw(*server, "GET /health HTTP/1.1\r\nHost: " + a + "\r\nX: " + std::string(20000, 'x') + "\r\n\r\n"); }},
      {"deep JSON", [&] { (void)raw(*server, chat_request(*server, R"({"model":"fake-model","messages":[{"role":"user","content":"Hi"}],"logit_bias":{"a":{"b":{"c":{"d":1}}}}})")); }},
      {"chunked body", [&] { (void)raw(*server, raw_http::request("POST", "/v1/chat/completions", a, {raw_http::bearer(token()), "Transfer-Encoding: chunked"})); }},
      {"slow then closed body", [&] {
         auto c = raw_http::Connection::open("127.0.0.1", server->port());
         if (c) (void)c->send(chat_request(*server, chat_body()).substr(0, 120));
       }},
      {"slow header", [&] {
         auto c = raw_http::Connection::open("127.0.0.1", server->port());
         if (c) { (void)c->send("GET /he"); (void)c->read_until_close(2s); }
       }},
      {"body over limit", [&] { (void)raw(*server, chat_request(*server, std::string(60000, ' '))); }},
      {"garbage", [&] { (void)raw(*server, std::string("\x16\x03\x01\x02\x00", 5) + std::string(100, '\x01')); }}};
  for (const auto& [name, attack] : attacks) {
    attack();
    const auto health = raw(*server, raw_http::request("GET", "/health", a, {raw_http::bearer(token())}));
    const auto chat = raw(*server, chat_request(*server, chat_body()));
    expect(health && health->status == 200 && chat && chat->status == 200, "healthy and serving after: " + name);
  }
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
      {"dos01_eviction_over_tcp_admits_new_client", dos01_eviction_over_tcp_admits_new_client},
      {"max_tokens_above_limit_is_clamped", max_tokens_above_limit_is_clamped},
      {"max_tokens_clamped_to_context_room", max_tokens_clamped_to_context_room},
      {"prompt_alone_over_context_is_400", prompt_alone_over_context_is_400},
      {"absent_max_tokens_uses_auto", absent_max_tokens_uses_auto},
      {"sampling_passthrough_reaches_gen", sampling_passthrough_reaches_gen},
      {"dos01_context_rule_is_400_without_gen", dos01_context_rule_is_400_without_gen},
      {"chat_response_has_openai_shape", chat_response_has_openai_shape},
      {"dos02_excess_connections_get_503_retry_after", dos02_excess_connections_get_503_retry_after},
      {"dos02_queue_full_is_503", dos02_queue_full_is_503},
      {"dos02_queue_timeout_is_503", dos02_queue_timeout_is_503},
      {"dos02_queue_is_fifo", dos02_queue_is_fifo},
      {"dos02_health_answers_while_generation_places_full", dos02_health_answers_while_generation_places_full},
      {"dos02_serial_mode_one_worker", dos02_serial_mode_one_worker},
      {"dos02_queued_client_disconnect_leaves_queue", dos02_queued_client_disconnect_leaves_queue},
      {"dos02_non_stream_disconnect_cancels", dos02_non_stream_disconnect_cancels},
      {"dos02_resources_return_to_idle", dos02_resources_return_to_idle},
      {"shutdown_errors_never_report_fatal", shutdown_errors_never_report_fatal},
      {"dos01_service_healthy_after_each_attack", dos01_service_healthy_after_each_attack},
      {"dos01_slowloris_cannot_starve_a_real_client", dos01_slowloris_cannot_starve_a_real_client},
      {"dos01_slow_body_clients_cannot_starve_a_real_client", dos01_slow_body_clients_cannot_starve_a_real_client},
      {"net01_workers_add_no_listener", net01_workers_add_no_listener},
      {"net01_ipv6_loopback_listener_only", net01_ipv6_loopback_listener_only},
  }, failures);
}

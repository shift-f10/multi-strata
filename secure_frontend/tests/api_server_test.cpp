#include "secure_frontend/api_errors.hpp"
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
#include <string>
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
[[maybe_unused]] std::string record_of(const std::filesystem::path& file) {
  std::ifstream in(file, std::ios::binary);
  return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
[[maybe_unused]] std::size_t count_of(const std::string& text, std::string_view needle) {
  std::size_t n = 0;
  for (std::size_t p = text.find(needle); p != std::string::npos; p = text.find(needle, p + 1U)) ++n;
  return n;
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
  }, failures);
}

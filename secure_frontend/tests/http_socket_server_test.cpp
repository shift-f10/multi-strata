#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/api_constants.hpp"
#include "secure_frontend/process_defaults.hpp"
#include "secure_frontend/socket_io.hpp"
#include "support/test_support.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include "secure_frontend/win32_prelude.hpp"
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {
int failures = 0;
void expect(bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kBad = INVALID_SOCKET;
void close_socket(NativeSocket s) { closesocket(s); }
int send_bytes(NativeSocket s, const std::string& b) { return send(s, b.data(), static_cast<int>(b.size()), 0); }
int recv_bytes(NativeSocket s, char* out, int n) { return recv(s, out, n, 0); }
int shutdown_send(NativeSocket s) { return shutdown(s, SD_SEND); }
#else
using NativeSocket = int;
constexpr NativeSocket kBad = -1;
void close_socket(NativeSocket s) { close(s); }
int send_bytes(NativeSocket s, const std::string& b) { return static_cast<int>(send(s, b.data(), b.size(), MSG_NOSIGNAL)); }
int recv_bytes(NativeSocket s, char* out, int n) { return static_cast<int>(recv(s, out, static_cast<std::size_t>(n), 0)); }
int shutdown_send(NativeSocket s) { return shutdown(s, SHUT_WR); }
#endif

struct Fixture final {
  std::optional<secure_frontend::HttpSocketServer> server;
  std::string error;
  std::string host{"127.0.0.1"};
  // Address clients connect to and name in Host. Equals host unless the
  // listener binds a wildcard, which clients cannot connect to by name.
  std::string client_host{"127.0.0.1"};

  explicit Fixture(secure_frontend::HttpSocketServerLimits limits = {}, std::string bind_host = "127.0.0.1",
                   std::string connect_host = {})
      : host(std::move(bind_host)), client_host(connect_host.empty() ? host : std::move(connect_host)) {
    const bool wildcard = host == "::" || host == "0.0.0.0";
    for (std::uint16_t port = 20000; port < 20100 && !server.has_value(); ++port) {
      const std::string authority = authority_for(host, port);
      const std::string client_authority = authority_for(client_host, port);
      // has_api_key, is_loopback, allow_remote, allow_wildcard_bind
      secure_frontend::Config config{host, port, true, !wildcard, wildcard, wildcard};
      // The bound and client authorities stay allowed as aliases (a wildcard
      // bind trusts only aliases), no CORS.
      secure_frontend::HttpPolicy policy = secure_frontend::make_http_policy(
          *secure_frontend::parse_listener_address(host), port, {authority, client_authority}, {});
      server = secure_frontend::HttpSocketServer::bind(
          config, std::move(policy),
          [](std::string_view token) { return secure_frontend::constant_time_token_equals(token, "test-token"); },
          [](std::string_view method, std::string_view target, std::string_view body) {
            if (method == "POST" && target == "/sink") {
              return secure_frontend::HttpResponse{200, {{"Content-Type", "text/plain"}}, std::to_string(body.size())};
            }
            if (method == "GET" && target == "/health") {
              return secure_frontend::HttpResponse{200, {{"Content-Type", "application/json; charset=utf-8"}}, "{\"status\":\"ok\"}\n"};
            }
            if (method == "GET" && target == "/big") {
              return secure_frontend::HttpResponse{200, {{"Content-Type", "text/plain"}}, std::string(32U * 1024U * 1024U, 'x')};
            }
            return secure_frontend::HttpResponse{404, {{"Content-Type", "application/json; charset=utf-8"}}, "{\"error\":\"Not Found\"}\n"};
          },
          &error, limits);
    }
  }
  static std::string authority_for(const std::string& h, std::uint16_t port) {
    const bool v6 = h.find(':') != std::string::npos;
    return (v6 ? "[" + h + "]" : h) + ":" + std::to_string(port);
  }
  std::string authority() const { return authority_for(client_host, server->port()); }
  std::string request_for(const std::string& target) const {
    return "GET " + target + " HTTP/1.1\r\nHost: " + authority() + "\r\nAuthorization: Bearer test-token\r\n\r\n";
  }
  std::string health_request() const { return request_for("/health"); }
  // Opens a client socket, optionally shrinking its receive buffer first
  // (SO_RCVBUF must be set before connect() for the window to take effect).
  NativeSocket connect_client(int receive_buffer_bytes = 0) const {
    const bool v6 = client_host.find(':') != std::string::npos;
    NativeSocket client = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == kBad) return kBad;
    if (receive_buffer_bytes > 0) {
      if (setsockopt(client, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&receive_buffer_bytes),
                     sizeof(receive_buffer_bytes)) != 0) {
        close_socket(client);
        return kBad;
      }
    }
    int rc = -1;
    if (v6) {
      sockaddr_in6 a{}; a.sin6_family = AF_INET6; a.sin6_port = htons(server->port());
      inet_pton(AF_INET6, client_host.c_str(), &a.sin6_addr);
      rc = connect(client, reinterpret_cast<const sockaddr*>(&a), sizeof(a));
    } else {
      sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(server->port());
      inet_pton(AF_INET, client_host.c_str(), &a.sin_addr);
      rc = connect(client, reinterpret_cast<const sockaddr*>(&a), sizeof(a));
    }
    if (rc != 0) { close_socket(client); return kBad; }
    return client;
  }
  // The listener has no accept timeout, so a worker thread blocked in
  // serve_one() would never return if the test's own connect failed. A
  // throwaway connection lets that worker finish before join().
  void unblock_accept() const {
    const NativeSocket throwaway = connect_client();
    if (throwaway != kBad) close_socket(throwaway);
  }
  // Sends one full health request and returns the whole response (read to EOF).
  std::string round_trip() {
    std::string response;
    bool served = false;
    std::thread worker([&] { served = server->serve_one(&error); });
    const NativeSocket client = connect_client();
    if (client == kBad) { unblock_accept(); worker.join(); return {}; }
    (void)send_bytes(client, health_request());
    char chunk[1024];
    for (;;) { const int n = recv_bytes(client, chunk, sizeof(chunk)); if (n <= 0) break; response.append(chunk, static_cast<std::size_t>(n)); }
    close_socket(client);
    worker.join();
    if (!served) response.clear();
    return response;
  }
};

void serves_a_loopback_request_without_outbound_connections() {
  Fixture f;
  expect(f.server.has_value(), "loopback listener should bind: " + f.error);
  if (!f.server) return;
  const std::string response = f.round_trip();
  expect(response.rfind("HTTP/1.1 200 OK", 0) == 0, "authorized loopback request should receive HTTP 200");
}

// S1: a client that sends a request and closes before reading must not kill
// the process (SIGPIPE) and must not stop the listener from serving the next client.
void socket_server_survives_client_early_close() {
  Fixture f;
  if (!f.server) { expect(false, "bind failed: " + f.error); return; }
  std::thread worker([&] { (void)f.server->serve_one(&f.error); });
  // A 1-byte receive window and a 32 MiB response: the response cannot be
  // absorbed by socket buffers before we close, so the server's send() is
  // guaranteed to hit a closed peer (EPIPE) instead of depending on timing.
  const NativeSocket client = f.connect_client(1);
  expect(client != kBad, "client should connect");
  if (client == kBad) { f.unblock_accept(); worker.join(); return; }
  (void)send_bytes(client, f.request_for("/big"));
  close_socket(client);
  worker.join();
  // Still alive here means no SIGPIPE killed us. The next client must be served.
  const std::string response = f.round_trip();
  expect(response.rfind("HTTP/1.1 200 OK", 0) == 0, "listener must serve the next client after an early close");
}

// S3: one byte every 400 ms must not hold the listener past the deadline.
void socket_server_rejects_slow_request_past_deadline() {
  Fixture f({.request_deadline = std::chrono::milliseconds(1000)});
  if (!f.server) { expect(false, "bind failed: " + f.error); return; }
  bool served = true;
  std::atomic<bool> returned{false};
  const auto start = std::chrono::steady_clock::now();
  auto returned_at = start;
  // Time the listener itself: when serve_one returns, not when the dripping
  // client next notices the closed connection (that depends on the close path).
  std::thread worker([&] {
    served = f.server->serve_one(&f.error);
    returned_at = std::chrono::steady_clock::now();
    returned = true;
  });
  const NativeSocket client = f.connect_client();
  if (client == kBad) { f.unblock_accept(); worker.join(); expect(false, "client should connect"); return; }
  const std::string request = f.health_request();
  for (std::size_t i = 0; i < request.size() - 1 && !returned; ++i) {  // never send the final byte
    if (send_bytes(client, request.substr(i, 1)) <= 0) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    if (std::chrono::steady_clock::now() - start > std::chrono::seconds(4)) break;
  }
  worker.join();
  const auto elapsed = returned_at - start;
  close_socket(client);
  std::cerr << "S3 elapsed ms: " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << '\n';
  expect(!served, "a dripping client must be rejected, not served");
  expect(elapsed >= std::chrono::milliseconds(900) && elapsed < std::chrono::milliseconds(2500),
         "listener must give up at the deadline, not per-recv");
}

// S2: a peer that never reads must not block send_all forever.
void socket_server_send_times_out_on_stalled_reader() {
  Fixture f({.request_deadline = std::chrono::milliseconds(1000)});
  if (!f.server) { expect(false, "bind failed: " + f.error); return; }
  bool served = true;
  std::thread worker([&] { served = f.server->serve_one(&f.error); });
  // SO_RCVBUF only shrinks the advertised window when set before connect(),
  // so use the fixture's pre-connect option rather than setting it afterwards.
  const NativeSocket client = f.connect_client(1);
  if (client == kBad) { f.unblock_accept(); worker.join(); expect(false, "client should connect"); return; }
  (void)send_bytes(client, "GET /big HTTP/1.1\r\nHost: " + f.authority() + "\r\nAuthorization: Bearer test-token\r\n\r\n");
  const auto start = std::chrono::steady_clock::now();
  worker.join();  // must return without us ever reading
  const auto elapsed = std::chrono::steady_clock::now() - start;
  close_socket(client);
  std::cerr << "S2 elapsed ms: " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << '\n';
  expect(!served && elapsed < std::chrono::seconds(3), "send to a stalled reader must time out at the deadline");
}

// S4: 64 KiB + 1 of headers over TCP -> bounded 400/413, listener stays usable.
void socket_server_rejects_oversize_request_over_tcp() {
  Fixture f({.request_deadline = std::chrono::seconds(5), .max_request_bytes = 64U * 1024U});
  if (!f.server) { expect(false, "bind failed: " + f.error); return; }
  bool served = true;
  std::thread worker([&] { served = f.server->serve_one(&f.error); });
  const NativeSocket client = f.connect_client();
  if (client == kBad) { f.unblock_accept(); worker.join(); expect(false, "client should connect"); return; }
  std::string request = "GET /health HTTP/1.1\r\nHost: " + f.authority() + "\r\nX-Pad: ";
  request.append(64U * 1024U + 1U, 'a');
  request += "\r\n\r\n";
  (void)send_bytes(client, request);
  std::string response; char chunk[512];
  for (;;) { const int n = recv_bytes(client, chunk, sizeof(chunk)); if (n <= 0) break; response.append(chunk, static_cast<std::size_t>(n)); }
  close_socket(client);
  worker.join();
  expect(!served, "oversize request is a client error");
  expect(response.rfind("HTTP/1.1 413", 0) == 0, "oversize request must get a 413, got: " + response.substr(0, 20));
  expect(f.round_trip().rfind("HTTP/1.1 200 OK", 0) == 0, "listener must serve the next client after an oversize request");
}

// S5: no client for 7 s must NOT make serve_one return (the old 5 s SO_RCVTIMEO on the listener did).
void socket_server_accept_waits_without_timeout() {
  Fixture f;
  if (!f.server) { expect(false, "bind failed: " + f.error); return; }
  std::atomic<bool> returned{false};
  std::thread worker([&] { (void)f.server->serve_one(&f.error); returned = true; });
  std::this_thread::sleep_for(std::chrono::seconds(7));
  const bool returned_while_idle = returned.load();
  expect(!returned_while_idle, "accept must block while idle; serve_one returned: " + (returned_while_idle ? f.error : std::string{}));
  expect(!f.server->listener_failed(), "idle is not a listener failure");
  // Unblock the worker with a real request so the thread can join.
  const NativeSocket client = f.connect_client();
  if (client != kBad) {
    (void)send_bytes(client, f.health_request()); char c[64]; (void)recv_bytes(client, c, sizeof(c)); close_socket(client);
  } else {
    f.unblock_accept();
  }
  worker.join();
}

// SP2 C4: the orderly shutdown wakes a serve_one() blocked in accept() from
// another thread; that call and every later one fail with listener_failed().
void socket_server_shutdown_listener_wakes_accept() {
  Fixture f;
  if (!f.server) { expect(false, "bind failed: " + f.error); return; }
  std::atomic<bool> returned{false};
  bool served = true;
  std::string worker_error;
  std::thread worker([&] { served = f.server->serve_one(&worker_error); returned = true; });
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  f.server->shutdown_listener();
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (!returned.load() && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  const bool woke = returned.load();
  expect(woke, "shutdown_listener() wakes the blocked accept()");
  if (!woke) f.unblock_accept();
  worker.join();
  expect(!served && f.server->listener_failed(), "the woken call fails as a listener failure: " + worker_error);
  std::string error;
  expect(!f.server->serve_one(&error) && f.server->listener_failed(), "every later call fails at once: " + error);
  f.server->shutdown_listener();  // idempotent
}

// SP2 C4 (final review I1): an accepted client that sends nothing must not hold
// serve_one() until its request deadline (30 s default) once the orderly
// shutdown has closed the listener; otherwise main never reaches shutdown()
// and the 5 s bound ends the process with exit 1.
void socket_server_shutdown_listener_wakes_idle_client() {
  Fixture f;  // default request_deadline (30 s)
  if (!f.server) { expect(false, "bind failed: " + f.error); return; }
  std::atomic<bool> returned{false};
  bool served = true;
  std::string worker_error;
  std::thread worker([&] { served = f.server->serve_one(&worker_error); returned = true; });
  const NativeSocket idle = f.connect_client();  // connected, sends nothing
  expect(idle != kBad, "the idle client connects");
  std::this_thread::sleep_for(std::chrono::milliseconds(300));  // serve_one() is now waiting on it
  expect(!returned.load(), "serve_one() is still waiting on the idle client");
  const auto started = std::chrono::steady_clock::now();
  f.server->shutdown_listener();
  const auto deadline = started + std::chrono::seconds(3);
  while (!returned.load() && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
  expect(returned.load() && waited <= std::chrono::milliseconds(500),
         "shutdown_listener() ends a serve_one() waiting on an idle client within 500 ms, took " + std::to_string(waited.count()) + " ms");
  if (idle != kBad) close_socket(idle);  // also ends serve_one() if the fix is missing (recv sees EOF)
  worker.join();
  expect(!served && worker_error == "listener shut down", "the woken call reports the shutdown: " + worker_error);
}

// S6: an IPv6 listener must be v6-only and must serve with a bracketed Host.
// Binds the wildcard '::' because only a wildcard IPv6 socket can receive
// IPv4-mapped traffic; a '::1' bind would refuse IPv4 even without V6ONLY.
void socket_server_ipv6_bind_is_v6only() {
  Fixture f({}, "::", "::1");
  if (!f.server) { std::cerr << "SKIP ipv6-wildcard: " << f.error << '\n'; return; }
  expect(f.round_trip().rfind("HTTP/1.1 200 OK", 0) == 0, "IPv6 loopback must serve with bracketed Host");
  // An IPv4 connect to the same port must be refused (no dual-stack mapping).
  NativeSocket v4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (v4 == kBad) { expect(false, "could not create the IPv4 probe socket"); return; }
  sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(f.server->port()); inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
  const int rc = connect(v4, reinterpret_cast<const sockaddr*>(&a), sizeof(a));
  close_socket(v4);
  expect(rc != 0, "an IPv6 listener must not accept IPv4 clients");
}

// S7: Content-Length matches the body and the whole body arrives.
void socket_server_response_is_complete() {
  Fixture f;
  if (!f.server) { expect(false, "bind failed: " + f.error); return; }
  const std::string response = f.round_trip();
  const auto header_end = response.find("\r\n\r\n");
  expect(header_end != std::string::npos, "response must have a header block");
  if (header_end == std::string::npos) return;
  const auto cl = response.find("Content-Length: ");
  expect(cl != std::string::npos && cl < header_end, "Content-Length must be present");
  if (cl == std::string::npos) return;
  const std::size_t declared = std::stoul(response.substr(cl + 16, response.find("\r\n", cl) - cl - 16));
  expect(response.size() - header_end - 4 == declared, "body length must equal Content-Length");
}

// A peer that connects and resets before the server accepts must never be
// treated as a listener failure; the next client must still be served.
void socket_server_survives_reset_before_accept() {
  Fixture f;
  if (!f.server) { expect(false, "bind failed: " + f.error); return; }
  // The kernel completes the handshake into the backlog, so no worker is
  // needed: connect, force an RST on close, and only then call serve_one.
  const NativeSocket client = f.connect_client();
  if (client == kBad) { expect(false, "client should connect"); return; }
  linger hard_reset{};
  hard_reset.l_onoff = 1;
  hard_reset.l_linger = 0;
  expect(setsockopt(client, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&hard_reset), sizeof(hard_reset)) == 0,
         "SO_LINGER {1,0} should be accepted");
  close_socket(client);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));  // let the RST land before accept
  const bool served = f.server->serve_one(&f.error);
  expect(!served, "a reset client is a client error, not a served request");
  expect(!f.server->listener_failed(), "a peer reset must not mark the listener failed: " + f.error);
  expect(f.round_trip().rfind("HTTP/1.1 200 OK", 0) == 0, "listener must serve the next client after a peer reset");
}
// A client that sends the whole request and then half-closes its send side
// (shutdown SHUT_WR / SD_SEND) must still receive the full response to EOF.
void socket_server_responds_after_client_half_close() {
  Fixture f;
  if (!f.server) { expect(false, "bind failed: " + f.error); return; }
  bool served = false;
  std::thread worker([&] { served = f.server->serve_one(&f.error); });
  const NativeSocket client = f.connect_client();
  if (client == kBad) { f.unblock_accept(); worker.join(); expect(false, "client should connect"); return; }
  (void)send_bytes(client, f.health_request());
  expect(shutdown_send(client) == 0, "client half-close should succeed");
  std::string response; char chunk[512];
  for (;;) { const int n = recv_bytes(client, chunk, sizeof(chunk)); if (n <= 0) break; response.append(chunk, static_cast<std::size_t>(n)); }
  close_socket(client);
  worker.join();
  expect(served, "a half-closed client with a complete request is served: " + f.error);
  expect(response.rfind("HTTP/1.1 200 OK", 0) == 0, "half-closed client must read a 200, got: " + response.substr(0, 20));
  expect(response.find("{\"status\":\"ok\"}") != std::string::npos, "half-closed client must read the whole body");
}

// C4 / defect (d): the parser must honor a configured max_request_bytes.
std::string post_sink(Fixture& f, const std::size_t body_bytes) {
  std::string response;
  bool served = false;
  std::thread worker([&] { served = f.server->serve_one(&f.error); });
  const NativeSocket client = f.connect_client();
  if (client == kBad) { f.unblock_accept(); worker.join(); return {}; }
  std::string request = "POST /sink HTTP/1.1\r\nHost: " + f.authority() +
                        "\r\nAuthorization: Bearer test-token\r\nContent-Length: " + std::to_string(body_bytes) + "\r\n\r\n";
  request.append(body_bytes, 'b');
  (void)send_bytes(client, request);
  char chunk[1024];
  for (;;) { const int n = recv_bytes(client, chunk, sizeof(chunk)); if (n <= 0) break; response.append(chunk, static_cast<std::size_t>(n)); }
  close_socket(client);
  worker.join();
  (void)served;
  return response;
}

void parser_honors_configured_max_request_bytes() {
  secure_frontend::HttpSocketServerLimits raised;
  raised.max_request_bytes = 256U * 1024U;
  Fixture big(raised);
  if (!big.server) { expect(false, "bind failed: " + big.error); return; }
  const auto accepted = post_sink(big, 128U * 1024U);
  expect(accepted.rfind("HTTP/1.1 200 OK", 0) == 0 && accepted.find("\r\n\r\n131072") != std::string::npos,
         "a 128 KiB body must pass a 256 KiB limit, got: " + accepted.substr(0, 24));
  Fixture standard;
  if (!standard.server) { expect(false, "bind failed: " + standard.error); return; }
  const auto rejected = post_sink(standard, 128U * 1024U);
  // A Content-Length beyond the bound is answered from the header alone,
  // without reading the body: 413 request_too_large (spec §4.2, §9.4; was the
  // SP0 generic 400).
  expect(rejected.rfind("HTTP/1.1 413", 0) == 0, "the default limit still rejects it: " + rejected.substr(0, 24));
}

// SP3 Task 8a: socket_io.

void send_retries_on_eintr() {
  static int calls = 0;
  calls = 0;
  const auto flaky = [](secure_frontend::NativeSocket, const char*, std::size_t size) noexcept -> long {
    if (++calls == 1) { secure_frontend::detail::set_last_socket_error(secure_frontend::detail::kInterruptedCode); return -1; }
    return static_cast<long>(size);
  };
  const auto result = secure_frontend::detail::send_some_with(flaky, secure_frontend::kInvalidNativeSocket, "hello");
  expect(result.status == secure_frontend::IoStatus::done && result.bytes == 5U && calls == 2, "an interrupted send is retried, not failed");
}

void accept_backs_off_on_transient_failure() {
#if defined(_WIN32)
  const int transient[] = {WSAECONNRESET, WSAEMFILE, WSAENOBUFS, WSAEINTR};
  const int fatal[] = {WSAENOTSOCK, WSAEINVAL, WSANOTINITIALISED};
#else
  const int transient[] = {ECONNABORTED, EMFILE, ENFILE, ENOBUFS, ENOMEM, EINTR, EPROTO, EPERM};
  const int fatal[] = {EBADF, ENOTSOCK, EINVAL};
#endif
  for (const int code : transient) {
    expect(secure_frontend::detail::accept_backoff_for(code) == std::optional<std::chrono::milliseconds>{std::chrono::milliseconds(50)},
           "50 ms backoff for transient accept error " + std::to_string(code));
  }
  for (const int code : fatal) {
    expect(!secure_frontend::detail::accept_backoff_for(code).has_value(), "fatal accept error " + std::to_string(code));
  }
}

// SP2 carry-in: every send is sliced to kMaxSendChunk on both platforms.
void send_some_slices_to_max_send_chunk() {
  static std::size_t largest = 0;
  largest = 0;
  const auto record = [](secure_frontend::NativeSocket, const char*, std::size_t size) noexcept -> long {
    largest = std::max(largest, size);
    return static_cast<long>(size);
  };
  const std::string payload(3U * secure_frontend::api_constants::kMaxSendChunk + 7U, 'p');
  const auto result = secure_frontend::detail::send_some_with(record, secure_frontend::kInvalidNativeSocket, payload);
  expect(result.status == secure_frontend::IoStatus::done && result.bytes == secure_frontend::api_constants::kMaxSendChunk &&
             largest == secure_frontend::api_constants::kMaxSendChunk,
         "one send call carries at most kMaxSendChunk bytes");
  const auto empty = secure_frontend::detail::send_some_with(record, secure_frontend::kInvalidNativeSocket, "");
  expect(empty.status == secure_frontend::IoStatus::done && empty.bytes == 0U, "an empty send is a no-op");
}

// A connected loopback pair on an ephemeral port: `server` is the accepted end.
struct LoopbackPair final {
  secure_frontend::Socket server;
  secure_frontend::Socket client;
};

std::optional<LoopbackPair> make_loopback_pair(const int client_receive_buffer = 0) {
  secure_frontend::Socket listener{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
  if (!listener.valid()) return std::nullopt;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = 0;
  inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
  if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) return std::nullopt;
  if (listen(listener.get(), 1) != 0) return std::nullopt;
  socklen_t length = sizeof(address);
  if (getsockname(listener.get(), reinterpret_cast<sockaddr*>(&address), &length) != 0) return std::nullopt;
  LoopbackPair pair;
  pair.client = secure_frontend::Socket{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
  if (!pair.client.valid()) return std::nullopt;
  if (client_receive_buffer > 0) {
    (void)setsockopt(pair.client.get(), SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&client_receive_buffer),
                     sizeof(client_receive_buffer));
  }
  if (connect(pair.client.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) return std::nullopt;
  pair.server = secure_frontend::Socket{accept(listener.get(), nullptr, nullptr)};
  if (!pair.server.valid() || !secure_frontend::set_non_blocking(pair.server.get())) return std::nullopt;
  return pair;
}

// SP2 carry-in (Winsock accepted one 32 MiB blocking send whole): a reader that
// never reads cannot hold send_all_bounded past the stall bound, on either OS.
void send_all_bounded_stops_at_stall_on_a_stalled_reader() {
  auto pair = make_loopback_pair(1);
  if (!pair) { expect(false, "loopback pair"); return; }
  const std::string payload(32U * 1024U * 1024U, 'x');
  const auto stall = std::chrono::milliseconds(300);
  const auto start = std::chrono::steady_clock::now();
  const auto outcome = secure_frontend::send_all_bounded(pair->server.get(), payload, stall, start + std::chrono::seconds(30));
  const auto elapsed = std::chrono::steady_clock::now() - start;
  std::cerr << "stall elapsed ms: " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << '\n';
  expect(outcome == secure_frontend::WriteOutcome::stalled, "a stalled reader yields WriteOutcome::stalled");
  expect(elapsed >= stall && elapsed < std::chrono::seconds(3), "the stall bound is honoured, not the deadline");
}

// A reader that keeps making progress is never `stalled`; the whole-write
// deadline still bounds it, and a reader that drains everything completes.
void send_all_bounded_meets_deadline_and_completes() {
  {
    auto pair = make_loopback_pair(1);
    if (!pair) { expect(false, "loopback pair"); return; }
    std::atomic<bool> stop{false};
    std::thread slow_reader([&] {
      char chunk[512];
      while (!stop.load()) {
        (void)recv_bytes(pair->client.get(), chunk, sizeof(chunk));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
    });
    const std::string payload(32U * 1024U * 1024U, 'd');
    const auto start = std::chrono::steady_clock::now();
    const auto outcome = secure_frontend::send_all_bounded(pair->server.get(), payload, std::chrono::seconds(5),
                                                           start + std::chrono::milliseconds(400));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    stop.store(true);
    pair->server.reset();  // unblocks the reader's recv with EOF
    slow_reader.join();
    expect(outcome == secure_frontend::WriteOutcome::deadline, "a slow but progressing reader hits the deadline");
    expect(elapsed >= std::chrono::milliseconds(400) && elapsed < std::chrono::seconds(3), "deadline honoured");
  }
  {
    auto pair = make_loopback_pair();
    if (!pair) { expect(false, "loopback pair"); return; }
    const std::string payload(1024U * 1024U + 3U, 'c');
    std::size_t received = 0;
    std::thread reader([&] {
      char chunk[16384];
      for (;;) { const int n = recv_bytes(pair->client.get(), chunk, sizeof(chunk)); if (n <= 0) break; received += static_cast<std::size_t>(n); }
    });
    const auto outcome = secure_frontend::send_all_bounded(pair->server.get(), payload, std::chrono::seconds(5),
                                                           std::chrono::steady_clock::now() + std::chrono::seconds(20));
    secure_frontend::half_close_and_drain(pair->server.get());
    reader.join();
    expect(outcome == secure_frontend::WriteOutcome::complete && received == payload.size(), "a draining reader gets every byte");
  }
}

// poll_sockets, recv_some, probe_peer and bytes_pending on a live pair.
void socket_io_poll_probe_and_recv() {
  auto pair = make_loopback_pair();
  if (!pair) { expect(false, "loopback pair"); return; }
  const secure_frontend::NativeSocket server = pair->server.get();
  secure_frontend::PollEntry entry{server, true, false};
  expect(secure_frontend::poll_sockets(std::span<secure_frontend::PollEntry>{&entry, 1U}, std::chrono::milliseconds(20)) == 0 &&
             !entry.readable,
         "an idle socket times out unreadable");
  expect(secure_frontend::probe_peer(server) == secure_frontend::PeerState::alive && !secure_frontend::bytes_pending(server),
         "an idle peer is alive with nothing pending");
  char buffer[16];
  expect(secure_frontend::recv_some(server, buffer, sizeof(buffer)).status == secure_frontend::IoStatus::would_block,
         "an empty non-blocking recv would block");
  (void)send_bytes(pair->client.get(), "ab");
  entry = secure_frontend::PollEntry{server, true, false};
  expect(secure_frontend::poll_sockets(std::span<secure_frontend::PollEntry>{&entry, 1U}, std::chrono::seconds(2)) == 1 &&
             entry.readable,
         "a pending byte makes the socket readable");
  expect(secure_frontend::bytes_pending(server) && secure_frontend::probe_peer(server) == secure_frontend::PeerState::gone,
         "any byte after the body means gone (spec 2.6)");
  const auto got = secure_frontend::recv_some(server, buffer, sizeof(buffer));
  expect(got.status == secure_frontend::IoStatus::done && got.bytes == 2U, "recv_some reads the bytes");
  pair->client.reset();
  entry = secure_frontend::PollEntry{server, true, false};
  (void)secure_frontend::poll_sockets(std::span<secure_frontend::PollEntry>{&entry, 1U}, std::chrono::seconds(2));
  expect(secure_frontend::probe_peer(server) == secure_frontend::PeerState::gone && !secure_frontend::bytes_pending(server),
         "EOF means gone with nothing pending");
  expect(secure_frontend::recv_some(server, buffer, sizeof(buffer)).status == secure_frontend::IoStatus::closed, "EOF is closed");
  std::vector<secure_frontend::PollEntry> too_many(secure_frontend::api_constants::kMaxPollEntries + 1U,
                                                   secure_frontend::PollEntry{server, true, false});
  expect(secure_frontend::poll_sockets(too_many, std::chrono::milliseconds(0)) == -1, "more than kMaxPollEntries is refused");
}

// Helper for Task 8b (pre-flight V12): a socket can be marked non-inheritable.
void set_no_inherit_marks_the_socket() {
  secure_frontend::Socket s{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
  if (!s.valid()) { expect(false, "socket"); return; }
  expect(secure_frontend::set_no_inherit(s.get()), "set_no_inherit succeeds");
#if defined(_WIN32)
  DWORD flags = 0;
  expect(GetHandleInformation(reinterpret_cast<HANDLE>(s.get()), &flags) != 0 && (flags & HANDLE_FLAG_INHERIT) == 0,
         "the handle is not inheritable");
#else
  expect((fcntl(s.get(), F_GETFD) & FD_CLOEXEC) != 0, "the descriptor is close-on-exec");
#endif
}
}  // namespace

int main(int argc, char** argv) {
  secure_frontend::install_process_defaults();
  const secure_frontend::WinsockGuard winsock;
  if (!winsock.ok()) { std::cerr << "WSAStartup failed\n"; return 1; }
  return secure_frontend_test::run_cases(argc, argv, {
      {"serves_a_loopback_request_without_outbound_connections", serves_a_loopback_request_without_outbound_connections},
      {"socket_server_survives_client_early_close", socket_server_survives_client_early_close},
      {"socket_server_rejects_slow_request_past_deadline", socket_server_rejects_slow_request_past_deadline},
      {"socket_server_send_times_out_on_stalled_reader", socket_server_send_times_out_on_stalled_reader},
      {"socket_server_rejects_oversize_request_over_tcp", socket_server_rejects_oversize_request_over_tcp},
      {"socket_server_accept_waits_without_timeout", socket_server_accept_waits_without_timeout},
      {"socket_server_ipv6_bind_is_v6only", socket_server_ipv6_bind_is_v6only},
      {"socket_server_response_is_complete", socket_server_response_is_complete},
      {"socket_server_survives_reset_before_accept", socket_server_survives_reset_before_accept},
      {"socket_server_responds_after_client_half_close", socket_server_responds_after_client_half_close},
      {"parser_honors_configured_max_request_bytes", parser_honors_configured_max_request_bytes},
      {"socket_server_shutdown_listener_wakes_accept", socket_server_shutdown_listener_wakes_accept},
      {"socket_server_shutdown_listener_wakes_idle_client", socket_server_shutdown_listener_wakes_idle_client},
      {"send_retries_on_eintr", send_retries_on_eintr},
      {"accept_backs_off_on_transient_failure", accept_backs_off_on_transient_failure},
      {"send_some_slices_to_max_send_chunk", send_some_slices_to_max_send_chunk},
      {"send_all_bounded_stops_at_stall_on_a_stalled_reader", send_all_bounded_stops_at_stall_on_a_stalled_reader},
      {"send_all_bounded_meets_deadline_and_completes", send_all_bounded_meets_deadline_and_completes},
      {"socket_io_poll_probe_and_recv", socket_io_poll_probe_and_recv},
      {"set_no_inherit_marks_the_socket", set_no_inherit_marks_the_socket},
  }, failures);
}

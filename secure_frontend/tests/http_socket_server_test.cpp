#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/process_defaults.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#ifdef _WIN32
#include "secure_frontend/win32_prelude.hpp"
#else
#include <arpa/inet.h>
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
#else
using NativeSocket = int;
constexpr NativeSocket kBad = -1;
void close_socket(NativeSocket s) { close(s); }
int send_bytes(NativeSocket s, const std::string& b) { return static_cast<int>(send(s, b.data(), b.size(), MSG_NOSIGNAL)); }
int recv_bytes(NativeSocket s, char* out, int n) { return static_cast<int>(recv(s, out, static_cast<std::size_t>(n), 0)); }
#endif

struct Fixture final {
  std::optional<secure_frontend::HttpSocketServer> server;
  std::string error;
  std::string host{"127.0.0.1"};

  explicit Fixture(secure_frontend::HttpSocketServerLimits limits = {}, std::string bind_host = "127.0.0.1")
      : host(std::move(bind_host)) {
    for (std::uint16_t port = 20000; port < 20100 && !server.has_value(); ++port) {
      const bool v6 = host.find(':') != std::string::npos;
      const std::string authority = (v6 ? "[" + host + "]" : host) + ":" + std::to_string(port);
      secure_frontend::Config config{host, port, true, true, false, false};
      secure_frontend::HttpPolicy policy{{authority}, {"http://" + authority}, {}, false};
      server = secure_frontend::HttpSocketServer::bind(
          config, std::move(policy),
          [](std::string_view token) { return secure_frontend::constant_time_token_equals(token, "test-token"); },
          [](std::string_view method, std::string_view target, std::string_view) {
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
  std::string authority() const {
    const bool v6 = host.find(':') != std::string::npos;
    return (v6 ? "[" + host + "]" : host) + ":" + std::to_string(server->port());
  }
  std::string request_for(const std::string& target) const {
    return "GET " + target + " HTTP/1.1\r\nHost: " + authority() + "\r\nAuthorization: Bearer test-token\r\n\r\n";
  }
  std::string health_request() const { return request_for("/health"); }
  // Opens a client socket, optionally shrinking its receive buffer first
  // (SO_RCVBUF must be set before connect() for the window to take effect).
  NativeSocket connect_client(int receive_buffer_bytes = 0) const {
    const bool v6 = host.find(':') != std::string::npos;
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
      inet_pton(AF_INET6, host.c_str(), &a.sin6_addr);
      rc = connect(client, reinterpret_cast<const sockaddr*>(&a), sizeof(a));
    } else {
      sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(server->port());
      inet_pton(AF_INET, host.c_str(), &a.sin_addr);
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
  const auto start = std::chrono::steady_clock::now();
  std::thread worker([&] { served = f.server->serve_one(&f.error); });
  const NativeSocket client = f.connect_client();
  if (client == kBad) { f.unblock_accept(); worker.join(); expect(false, "client should connect"); return; }
  const std::string request = f.health_request();
  for (std::size_t i = 0; i < request.size() - 1; ++i) {  // never send the final byte
    if (send_bytes(client, request.substr(i, 1)) <= 0) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    if (std::chrono::steady_clock::now() - start > std::chrono::seconds(4)) break;
  }
  worker.join();
  const auto elapsed = std::chrono::steady_clock::now() - start;
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
  expect(response.rfind("HTTP/1.1 4", 0) == 0, "oversize request must get a 4xx, got: " + response.substr(0, 20));
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

// S6: '::1' must be v6-only and must serve with a bracketed Host.
void socket_server_ipv6_bind_is_v6only() {
  Fixture f({}, "::1");
  if (!f.server) { std::cerr << "SKIP ipv6: " << f.error << '\n'; return; }
  expect(f.round_trip().rfind("HTTP/1.1 200 OK", 0) == 0, "IPv6 loopback must serve with bracketed Host");
  // An IPv4 connect to the same port must be refused (no dual-stack mapping).
  NativeSocket v4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
}  // namespace

int main() {
  secure_frontend::install_process_defaults();
  serves_a_loopback_request_without_outbound_connections();
  socket_server_survives_client_early_close();
  socket_server_rejects_slow_request_past_deadline();
  socket_server_send_times_out_on_stalled_reader();
  socket_server_rejects_oversize_request_over_tcp();
  socket_server_accept_waits_without_timeout();
  socket_server_ipv6_bind_is_v6only();
  socket_server_response_is_complete();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

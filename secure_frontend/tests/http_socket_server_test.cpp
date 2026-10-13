#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/process_defaults.hpp"

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

  explicit Fixture(std::string bind_host = "127.0.0.1") : host(std::move(bind_host)) {
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
              return secure_frontend::HttpResponse{200, {{"Content-Type", "text/plain"}}, std::string(256U * 1024U, 'x')};
            }
            return secure_frontend::HttpResponse{404, {{"Content-Type", "application/json; charset=utf-8"}}, "{\"error\":\"Not Found\"}\n"};
          },
          &error);
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
  // Sends one full health request and returns the whole response (read to EOF).
  std::string round_trip() {
    std::string response;
    bool served = false;
    std::thread worker([&] { served = server->serve_one(&error); });
    const NativeSocket client = connect_client();
    if (client == kBad) { worker.join(); return {}; }
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
  // A 1-byte receive window and a 256 KiB response: the response cannot be
  // absorbed by socket buffers before we close, so the server's send() is
  // guaranteed to hit a closed peer (EPIPE) instead of depending on timing.
  const NativeSocket client = f.connect_client(1);
  expect(client != kBad, "client should connect");
  if (client == kBad) { worker.join(); return; }
  (void)send_bytes(client, f.request_for("/big"));
  close_socket(client);
  worker.join();
  // Still alive here means no SIGPIPE killed us. The next client must be served.
  const std::string response = f.round_trip();
  expect(response.rfind("HTTP/1.1 200 OK", 0) == 0, "listener must serve the next client after an early close");
}
}  // namespace

int main() {
  secure_frontend::install_process_defaults();
  serves_a_loopback_request_without_outbound_connections();
  socket_server_survives_client_early_close();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

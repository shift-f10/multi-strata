#include "secure_frontend/http_socket_server.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#ifdef _WIN32
#include "secure_frontend/win32_prelude.hpp"
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {
int failures = 0;
void expect(bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}

void close_socket(int socket) {
#ifdef _WIN32
  closesocket(static_cast<SOCKET>(socket));
#else
  close(socket);
#endif
}

void serves_a_loopback_request_without_outbound_connections() {
  std::string error;
  std::optional<secure_frontend::HttpSocketServer> server;
  for (std::uint16_t port = 20000; port < 20100 && !server.has_value(); ++port) {
    secure_frontend::Config config{"127.0.0.1", port, true, true, false, false};
    secure_frontend::HttpPolicy policy{{"127.0.0.1:" + std::to_string(port)},
                                       {"http://127.0.0.1:" + std::to_string(port)}, {}, false};
    server = secure_frontend::HttpSocketServer::bind(
        config, std::move(policy),
        [](std::string_view token) { return secure_frontend::constant_time_token_equals(token, "test-token"); },
        [](std::string_view method, std::string_view target, std::string_view) {
          if (method == "GET" && target == "/health") {
            return secure_frontend::HttpResponse{
                .status = 200,
                .headers = {{"Content-Type", "application/json; charset=utf-8"}},
                .body = "{\"status\":\"ok\"}\n"};
          }
          return secure_frontend::HttpResponse{
              .status = 404,
              .headers = {{"Content-Type", "application/json; charset=utf-8"}},
              .body = "{\"error\":\"Not Found\"}\n"};
        },
        &error);
  }
  expect(server.has_value(), "loopback listener should bind: " + error);
  if (!server) return;

  bool served = false;
  std::thread worker([&] { served = server->serve_one(&error); });
  const int client = static_cast<int>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  expect(client >= 0, "test client socket should open");
  if (client < 0) { worker.join(); return; }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(server->port());
  inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
  expect(connect(client, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0,
         "test client should connect only to loopback");
  const std::string request = "GET /health HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(server->port()) +
                              "\r\nAuthorization: Bearer test-token\r\n\r\n";
#ifdef _WIN32
  expect(send(static_cast<SOCKET>(client), request.data(), static_cast<int>(request.size()), 0) == static_cast<int>(request.size()), "request should send");
#else
  expect(send(client, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()), "request should send");
#endif
  char response[512]{};
#ifdef _WIN32
  const int received = recv(static_cast<SOCKET>(client), response, static_cast<int>(sizeof(response) - 1), 0);
#else
  const ssize_t received = recv(client, response, sizeof(response) - 1, 0);
#endif
  expect(received > 0 && std::string(response, static_cast<std::size_t>(received)).find("HTTP/1.1 200 OK") == 0,
         "authorized loopback request should receive HTTP 200");
  close_socket(client);
  worker.join();
  expect(served, "listener should serve the accepted request: " + error);
}
}  // namespace

int main() {
  serves_a_loopback_request_without_outbound_connections();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

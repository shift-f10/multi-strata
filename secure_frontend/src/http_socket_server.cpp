#include "secure_frontend/http_socket_server.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>

#ifdef _WIN32
#include "secure_frontend/win32_prelude.hpp"
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace secure_frontend {
namespace {
constexpr std::size_t kMaximumRequestBytes = 64U * 1024U;

#ifdef _WIN32
using NativeSocket = SOCKET;
using NativeAddressLength = int;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
using NativeAddressLength = socklen_t;
constexpr NativeSocket kInvalidSocket = -1;
#endif

void close_socket(const NativeSocket socket) {
  if (socket == kInvalidSocket) return;
#ifdef _WIN32
  closesocket(socket);
#else
  close(socket);
#endif
}

bool set_timeout(const NativeSocket socket) {
#ifdef _WIN32
  const DWORD timeout_ms = 5000;
  return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms),
                    sizeof(timeout_ms)) == 0;
#else
  const timeval timeout{5, 0};
  return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0;
#endif
}

bool ascii_case_equal(const std::string_view left, const std::string_view right) {
  if (left.size() != right.size()) return false;
  for (std::size_t index = 0; index < left.size(); ++index) {
    const unsigned char a = static_cast<unsigned char>(left[index]);
    const unsigned char b = static_cast<unsigned char>(right[index]);
    const unsigned char lower_a = a >= 'A' && a <= 'Z' ? static_cast<unsigned char>(a + ('a' - 'A')) : a;
    const unsigned char lower_b = b >= 'A' && b <= 'Z' ? static_cast<unsigned char>(b + ('a' - 'A')) : b;
    if (lower_a != lower_b) return false;
  }
  return true;
}

// Returns the body size required by a syntactically simple Content-Length
// field. A malformed or duplicate field leaves the whole message to the HTTP
// policy layer, which will issue its generic 400 response without waiting for
// untrusted bytes.
std::size_t required_message_size(const std::string& bytes, const std::size_t headers_end) {
  std::size_t start = bytes.find("\r\n") + 2U;
  std::optional<std::size_t> content_length;
  while (start < headers_end) {
    const std::size_t end = bytes.find("\r\n", start);
    if (end == std::string::npos || end > headers_end) return headers_end + 4U;
    const std::string_view line{bytes.data() + start, end - start};
    const std::size_t colon = line.find(':');
    if (colon != std::string_view::npos && ascii_case_equal(line.substr(0, colon), "content-length")) {
      if (content_length.has_value()) return headers_end + 4U;
      std::string_view value = line.substr(colon + 1U);
      while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1U);
      std::size_t parsed = 0;
      if (value.empty()) return headers_end + 4U;
      for (const char character : value) {
        if (character < '0' || character > '9' || parsed > (kMaximumRequestBytes / 10U)) {
          return headers_end + 4U;
        }
        parsed = (parsed * 10U) + static_cast<std::size_t>(character - '0');
      }
      content_length = parsed;
    }
    start = end + 2U;
  }
  const std::size_t base = headers_end + 4U;
  if (!content_length.has_value() || *content_length > kMaximumRequestBytes - base) return base;
  return base + *content_length;
}

const char* reason_phrase(const int status) {
  switch (status) {
    case 200: return "OK";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 503: return "Service Unavailable";
    default: return "Internal Server Error";
  }
}

bool send_all(const NativeSocket socket, const std::string_view bytes) {
  std::size_t sent = 0;
  while (sent < bytes.size()) {
    const std::size_t remaining = bytes.size() - sent;
#ifdef _WIN32
    const int result = send(socket, bytes.data() + sent,
                            static_cast<int>(std::min(remaining, static_cast<std::size_t>(INT_MAX))), 0);
#else
#if defined(MSG_NOSIGNAL)
    const ssize_t result = send(socket, bytes.data() + sent, remaining, MSG_NOSIGNAL);
#else
    const ssize_t result = send(socket, bytes.data() + sent, remaining, 0);
#endif
#endif
    if (result <= 0) return false;
    sent += static_cast<std::size_t>(result);
  }
  return true;
}

std::string serialize_response(const HttpResponse& response) {
  std::string output{"HTTP/1.1 "};
  output += std::to_string(response.status);
  output += ' ';
  output += reason_phrase(response.status);
  output += "\r\nConnection: close\r\nContent-Length: ";
  output += std::to_string(response.body.size());
  output += "\r\n";
  for (const auto& [name, value] : response.headers) {
    // Response fields are produced by local policy code, never copied from a
    // client request. Defend this boundary anyway if a future route adds one.
    if (name.find_first_of("\r\n") == std::string::npos && value.find_first_of("\r\n") == std::string::npos) {
      output += name;
      output += ": ";
      output += value;
      output += "\r\n";
    }
  }
  output += "\r\n";
  output += response.body;
  return output;
}

}  // namespace

struct HttpSocketServer::State final {
  NativeSocket socket{kInvalidSocket};
  std::uint16_t port{0};
  HttpPolicy policy;
  BearerTokenValidator validator;
  RequestDispatcher dispatcher;
#ifdef _WIN32
  bool winsock_started{false};
#endif
  ~State() {
    close_socket(socket);
#ifdef _WIN32
    if (winsock_started) WSACleanup();
#endif
  }
};

HttpSocketServer::HttpSocketServer(std::unique_ptr<State> state) : state_(std::move(state)) {}
HttpSocketServer::HttpSocketServer(HttpSocketServer&&) noexcept = default;
HttpSocketServer& HttpSocketServer::operator=(HttpSocketServer&&) noexcept = default;
HttpSocketServer::~HttpSocketServer() = default;

std::optional<HttpSocketServer> HttpSocketServer::bind(const Config& listener_config, HttpPolicy policy,
                                                        BearerTokenValidator validator,
                                                        RequestDispatcher dispatcher, std::string* error) {
  if (error != nullptr) error->clear();
  // Config is a public value type, so do not assume a caller obtained it via
  // validate_config. Re-apply the bind-related policy before opening a socket.
  const ConfigInput verification_input{.host = listener_config.host,
                                       .port = listener_config.port,
                                       .api_key = listener_config.has_api_key ? std::optional<std::string>{"present"}
                                                                             : std::nullopt,
                                       .allow_remote = listener_config.allow_remote,
                                       .allow_wildcard_bind = listener_config.allow_wildcard_bind};
  if (!std::holds_alternative<Config>(validate_config(verification_input)) || !validator || !dispatcher) {
    if (error != nullptr) *error = "invalid listener configuration";
    return std::nullopt;
  }
  auto state = std::make_unique<State>();
#ifdef _WIN32
  WSADATA data{};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
    if (error != nullptr) *error = "Winsock initialization failed";
    return std::nullopt;
  }
  state->winsock_started = true;
#endif
  sockaddr_storage address{};
  NativeAddressLength address_size = 0;
  int family = AF_UNSPEC;
  auto* address4 = reinterpret_cast<sockaddr_in*>(&address);
  auto* address6 = reinterpret_cast<sockaddr_in6*>(&address);
  if (inet_pton(AF_INET, listener_config.host.c_str(), &address4->sin_addr) == 1) {
    family = AF_INET;
    address4->sin_family = AF_INET;
    address4->sin_port = htons(listener_config.port);
    address_size = static_cast<NativeAddressLength>(sizeof(sockaddr_in));
  } else if (inet_pton(AF_INET6, listener_config.host.c_str(), &address6->sin6_addr) == 1) {
    family = AF_INET6;
    address6->sin6_family = AF_INET6;
    address6->sin6_port = htons(listener_config.port);
    address_size = static_cast<NativeAddressLength>(sizeof(sockaddr_in6));
  } else {
    if (error != nullptr) *error = "listener host must be a numeric IP literal";
    return std::nullopt;
  }
  state->socket = socket(family, SOCK_STREAM, IPPROTO_TCP);
  if (state->socket == kInvalidSocket || !set_timeout(state->socket) ||
      ::bind(state->socket, reinterpret_cast<const sockaddr*>(&address), address_size) != 0 ||
      listen(state->socket, 16) != 0) {
    if (error != nullptr) *error = "listener socket setup failed";
    return std::nullopt;
  }
  state->port = listener_config.port;
  state->policy = std::move(policy);
  state->validator = std::move(validator);
  state->dispatcher = std::move(dispatcher);
  return HttpSocketServer{std::move(state)};
}

bool HttpSocketServer::serve_one(std::string* error) {
  if (error != nullptr) error->clear();
  if (!state_) { if (error != nullptr) *error = "listener is not initialized"; return false; }
  const NativeSocket client = accept(state_->socket, nullptr, nullptr);
  if (client == kInvalidSocket) { if (error != nullptr) *error = "accept failed"; return false; }
#if defined(SO_NOSIGPIPE)
  { const int one = 1; (void)setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)); }
#endif
  struct ClientCloser final { NativeSocket value; ~ClientCloser() { close_socket(value); } } closer{client};
  if (!set_timeout(client)) { if (error != nullptr) *error = "client timeout setup failed"; return false; }
  std::string request;
  request.reserve(4096U);
  std::array<char, 4096> chunk{};
  std::size_t expected_size = 0;
  while (request.size() < kMaximumRequestBytes) {
#ifdef _WIN32
    const int received = recv(client, chunk.data(), static_cast<int>(chunk.size()), 0);
#else
    const ssize_t received = recv(client, chunk.data(), chunk.size(), 0);
#endif
    if (received <= 0) { if (error != nullptr) *error = "incomplete client request"; return false; }
    const std::size_t count = static_cast<std::size_t>(received);
    if (count > kMaximumRequestBytes - request.size()) break;
    request.append(chunk.data(), count);
    const std::size_t headers_end = request.find("\r\n\r\n");
    if (headers_end != std::string::npos && expected_size == 0U) {
      expected_size = required_message_size(request, headers_end);
      if (expected_size > kMaximumRequestBytes) break;
    }
    if (expected_size != 0U && request.size() >= expected_size) {
      request.resize(expected_size);
      const std::string response = serialize_response(
          handle_http_request(request, state_->policy, state_->validator, state_->dispatcher));
      if (!send_all(client, response)) { if (error != nullptr) *error = "response send failed"; return false; }
      return true;
    }
  }
  const HttpResponse bad{.status = 400, .headers = {{"Content-Type", "text/plain; charset=utf-8"}}, .body = "Bad Request\n"};
  static_cast<void>(send_all(client, serialize_response(bad)));
  if (error != nullptr) *error = "request exceeded listener bounds";
  return false;
}

std::uint16_t HttpSocketServer::port() const { return state_ ? state_->port : 0U; }

}  // namespace secure_frontend

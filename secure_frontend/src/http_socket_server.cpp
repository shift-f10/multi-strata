#include "secure_frontend/http_socket_server.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>
#include <thread>
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
using Clock = std::chrono::steady_clock;
// A response that is ready to go always gets at least this long to be sent,
// so a legitimate large response is not cut off by a nearly spent deadline.
constexpr std::chrono::milliseconds kMinimumSendBudget{1000};

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

// Applies the same receive and send timeout. Values below 1 ms are clamped to
// 1 ms because a zero timeout means "wait forever" to the socket layer.
bool set_socket_timeouts(const NativeSocket socket, const std::chrono::milliseconds remaining) {
  const auto clamped = std::clamp<long long>(remaining.count(), 1, 3600000);
#ifdef _WIN32
  const DWORD ms = static_cast<DWORD>(clamped);
  return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0 &&
         setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms)) == 0;
#else
  timeval tv{static_cast<time_t>(clamped / 1000), static_cast<suseconds_t>((clamped % 1000) * 1000)};
  return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
         setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

// Whole milliseconds left until deadline, rounded up so a timeout derived
// from it never fires before the deadline itself.
std::chrono::milliseconds remaining_until(const Clock::time_point deadline) {
  return std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now());
}

// True when the last socket call failed only because its timeout elapsed (or
// it was interrupted), so the caller should re-check its deadline and retry.
bool last_call_timed_out() {
#ifdef _WIN32
  const int code = WSAGetLastError();
  return code == WSAETIMEDOUT || code == WSAEWOULDBLOCK || code == WSAEINTR;
#else
  return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

// After the last response byte: half-close our send side and briefly drain
// what the peer still sends, so close() does not discard unread request bytes
// with an RST that (on Windows especially) can destroy the response before the
// client reads it -- e.g. S4's 413. Bounded by kDrainBudget and kDrainBytes.
constexpr std::chrono::milliseconds kDrainBudget{100};
constexpr std::size_t kDrainBytes = 256U * 1024U;

void finish_response(const NativeSocket socket) {
#ifdef _WIN32
  if (shutdown(socket, SD_SEND) != 0) return;
#else
  if (shutdown(socket, SHUT_WR) != 0) return;
#endif
  const Clock::time_point drain_deadline = Clock::now() + kDrainBudget;
  std::array<char, 4096> sink{};
  std::size_t drained = 0;
  while (drained < kDrainBytes) {
    const std::chrono::milliseconds budget = remaining_until(drain_deadline);
    if (budget.count() <= 0 || !set_socket_timeouts(socket, budget)) return;
#ifdef _WIN32
    const int received = recv(socket, sink.data(), static_cast<int>(sink.size()), 0);
#else
    const ssize_t received = recv(socket, sink.data(), sink.size(), 0);
#endif
    if (received < 0 && last_call_timed_out()) continue;  // the deadline check above decides
    if (received <= 0) return;                             // peer closed (0) or reset (-1)
    drained += static_cast<std::size_t>(received);
  }
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
std::size_t required_message_size(const std::string& bytes, const std::size_t headers_end,
                                  const std::size_t maximum_request_bytes) {
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
        if (character < '0' || character > '9' || parsed > (maximum_request_bytes / 10U)) {
          return headers_end + 4U;
        }
        parsed = (parsed * 10U) + static_cast<std::size_t>(character - '0');
      }
      content_length = parsed;
    }
    start = end + 2U;
  }
  const std::size_t base = headers_end + 4U;
  if (!content_length.has_value() || *content_length > maximum_request_bytes - base) return base;
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
    case 408: return "Request Timeout";
    case 413: return "Content Too Large";
    case 503: return "Service Unavailable";
    default: return "Internal Server Error";
  }
}

// Sends every byte or gives up at send_deadline. Each send() gets only the
// time left, so a peer that stops reading cannot hold the listener.
bool send_all(const NativeSocket socket, const std::string_view bytes, const Clock::time_point send_deadline) {
  std::size_t sent = 0;
  while (sent < bytes.size()) {
    const std::chrono::milliseconds budget = remaining_until(send_deadline);
    if (budget.count() <= 0 || !set_socket_timeouts(socket, budget)) return false;
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
  HttpSocketServerLimits limits;
  bool listener_failed{false};
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
                                                        RequestDispatcher dispatcher, std::string* error,
                                                        HttpSocketServerLimits limits) {
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
  if (state->socket == kInvalidSocket) {
    if (error != nullptr) *error = "listener socket setup failed";
    return std::nullopt;
  }
  {
    const int one = 1;
    // Quick restarts must not fail on TIME_WAIT (POSIX); on Windows the
    // equivalent protection is exclusive use so no other socket can hijack
    // the port.
#ifdef _WIN32
    (void)setsockopt(state->socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one));
#else
    (void)setsockopt(state->socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
    // An IPv6 listener serves IPv6 only; IPv4 needs its own explicit bind.
    if (family == AF_INET6 &&
        setsockopt(state->socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&one), sizeof(one)) != 0) {
      if (error != nullptr) *error = "listener socket setup failed";
      return std::nullopt;
    }
  }
  // No timeout on the listening socket: accept() blocks until a client
  // arrives. Per-client bounds are applied to each accepted socket.
  if (::bind(state->socket, reinterpret_cast<const sockaddr*>(&address), address_size) != 0 ||
      listen(state->socket, 16) != 0) {
    if (error != nullptr) *error = "listener socket setup failed";
    return std::nullopt;
  }
  state->port = listener_config.port;
  state->policy = std::move(policy);
  state->validator = std::move(validator);
  state->dispatcher = std::move(dispatcher);
  // Same bounds as the socket timeout clamp, so now + request_deadline can
  // never overflow the clock for extreme caller values.
  limits.request_deadline = std::clamp(limits.request_deadline, std::chrono::milliseconds(1), std::chrono::milliseconds(3600000));
  state->limits = limits;
  return HttpSocketServer{std::move(state)};
}

bool HttpSocketServer::serve_one(std::string* error) {
  if (error != nullptr) error->clear();
  if (!state_) { if (error != nullptr) *error = "listener is not initialized"; return false; }
  const NativeSocket client = accept(state_->socket, nullptr, nullptr);
  if (client == kInvalidSocket) {
    // Inverted on purpose: only errors that mean the listening socket itself
    // is broken stop serving. Anything a peer or the network can cause (resets,
    // pending protocol errors, resource pressure) is transient, so no client
    // behaviour can ever shut the listener down.
#ifdef _WIN32
    const int code = WSAGetLastError();
    const bool fatal = code == WSAENOTSOCK || code == WSAEINVAL || code == WSANOTINITIALISED;
    const bool exhausted = code == WSAEMFILE || code == WSAENOBUFS;
#else
    const int code = errno;
    const bool fatal = code == EBADF || code == ENOTSOCK || code == EINVAL;
    const bool exhausted = code == EMFILE || code == ENFILE || code == ENOBUFS || code == ENOMEM;
#endif
    const bool transient = !fatal;
    // Prevents a hot spin in the serve loops under resource exhaustion.
    if (exhausted) std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (fatal) state_->listener_failed = true;
    if (error != nullptr) *error = transient ? "accept interrupted" : "accept failed";
    return false;
  }
#if defined(SO_NOSIGPIPE)
  { const int one = 1; (void)setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)); }
#endif
  struct ClientCloser final { NativeSocket value; ~ClientCloser() { close_socket(value); } } closer{client};
  // One total budget for the whole request (header and body), measured from
  // accept(). A per-recv timeout alone lets a client drip one byte at a time.
  const Clock::time_point deadline = Clock::now() + state_->limits.request_deadline;
  const std::size_t maximum_request_bytes = state_->limits.max_request_bytes;
  const auto send_deadline = [&deadline] { return std::max(deadline, Clock::now() + kMinimumSendBudget); };
  std::string request;
  request.reserve(4096U);
  std::array<char, 4096> chunk{};
  std::size_t expected_size = 0;
  while (request.size() < maximum_request_bytes) {
    const std::chrono::milliseconds remaining = remaining_until(deadline);
    if (remaining.count() <= 0) {
      const HttpResponse timed_out{.status = 408, .headers = {{"Content-Type", "text/plain; charset=utf-8"}},
                                   .body = "Request Timeout\n"};
      if (send_all(client, serialize_response(timed_out), Clock::now() + kMinimumSendBudget)) finish_response(client);
      if (error != nullptr) *error = "request deadline exceeded";
      return false;
    }
    if (!set_socket_timeouts(client, remaining)) {
      if (error != nullptr) *error = "client timeout setup failed";
      return false;
    }
#ifdef _WIN32
    const int received = recv(client, chunk.data(), static_cast<int>(chunk.size()), 0);
#else
    const ssize_t received = recv(client, chunk.data(), chunk.size(), 0);
#endif
    if (received < 0 && last_call_timed_out()) continue;  // the deadline check above decides
    if (received <= 0) { if (error != nullptr) *error = "incomplete client request"; return false; }
    const std::size_t count = static_cast<std::size_t>(received);
    if (count > maximum_request_bytes - request.size()) break;
    request.append(chunk.data(), count);
    const std::size_t headers_end = request.find("\r\n\r\n");
    if (headers_end != std::string::npos && expected_size == 0U) {
      expected_size = required_message_size(request, headers_end, maximum_request_bytes);
      if (expected_size > maximum_request_bytes) break;
    }
    if (expected_size != 0U && request.size() >= expected_size) {
      request.resize(expected_size);
      const std::string response = serialize_response(
          handle_http_request(request, state_->policy, state_->validator, state_->dispatcher));
      if (!send_all(client, response, send_deadline())) { if (error != nullptr) *error = "response send failed"; return false; }
      finish_response(client);
      return true;
    }
  }
  const HttpResponse too_large{.status = 413, .headers = {{"Content-Type", "text/plain; charset=utf-8"}},
                               .body = "Content Too Large\n"};
  if (send_all(client, serialize_response(too_large), send_deadline())) finish_response(client);
  if (error != nullptr) *error = "request exceeded listener bounds";
  return false;
}

std::uint16_t HttpSocketServer::port() const { return state_ ? state_->port : 0U; }
bool HttpSocketServer::listener_failed() const noexcept { return state_ && state_->listener_failed; }

}  // namespace secure_frontend

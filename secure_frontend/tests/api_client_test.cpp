#include "secure_frontend/api_client.hpp"
#include "secure_frontend/config.hpp"
#include "support/test_support.hpp"

#include <atomic>
#include <cstdio>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <type_traits>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
using NativeSocket = SOCKET;
using socklen_t = int;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using NativeSocket = int;
#endif

namespace {

using namespace std::chrono_literals;
using secure_frontend::ChatExchangeEnd;
using secure_frontend::ChunkedSseReader;
using secure_frontend::SseItem;
using secure_frontend::SseReadState;

int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

void close_native(const NativeSocket socket) {
#if defined(_WIN32)
  closesocket(socket);
#else
  close(socket);
#endif
}

std::string chunk(const std::string& bytes) {
  char size[16];
  std::snprintf(size, sizeof(size), "%zx", bytes.size());
  return std::string(size) + "\r\n" + bytes + "\r\n";
}

const std::string kHead = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
const std::string kGoodBody = chunk("data: {\"a\":1}\n\n") + chunk(": keep-alive\n\n") + chunk("data: [DONE]\n\n") + "0\r\n\r\n";

// One canned HTTP response on 127.0.0.1:<port>: reads the request head, writes `response`, closes.
struct CannedServer final {
  NativeSocket listener;
  std::uint16_t port{0};
  std::thread thread;
  explicit CannedServer(std::string response) {
    listener = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    (void)bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    (void)listen(listener, 1);
    socklen_t length = sizeof(address);
    (void)getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length);
    port = ntohs(address.sin_port);
    thread = std::thread([this, response = std::move(response)] {
      const NativeSocket client = accept(listener, nullptr, nullptr);
      std::string request;
      char buffer[4096];
      while (request.find("\r\n\r\n") == std::string::npos) {
        const auto got = recv(client, buffer, sizeof(buffer), 0);
        if (got <= 0) break;
        request.append(buffer, static_cast<std::size_t>(got));
      }
      (void)send(client, response.data(), static_cast<int>(response.size()), 0);
      close_native(client);
    });
  }
  ~CannedServer() {
    thread.join();
    close_native(listener);
  }
};

secure_frontend::LoopbackAddress loopback() {
  return *secure_frontend::LoopbackAddress::from(*secure_frontend::parse_listener_address("127.0.0.1"));
}

void client_reads_chunked_stream_and_requires_done_and_terminal_chunk() {
  {  // pure reader, fed one byte at a time
    ChunkedSseReader reader;
    std::vector<SseItem> items;
    for (const char byte : kGoodBody) {
      reader.feed(std::string_view(&byte, 1));
      SseItem item{};
      SseReadState state;
      while ((state = reader.next(item)) == SseReadState::item) items.push_back(item);
      expect(state != SseReadState::error, "valid framing never errors");
    }
    expect(items.size() == 3U && items[0].text == R"({"a":1})" && items[1].kind == secure_frontend::SseItemKind::comment &&
               items[2].text == "[DONE]", "data, comment, [DONE] in order");
    expect(reader.done_seen() && reader.terminal_chunk_seen(), "both end markers seen");
  }
  {
    ChunkedSseReader reader;
    reader.feed("zz\r\n");
    SseItem item{};
    expect(reader.next(item) == SseReadState::error, "a non-hex chunk size is a framing error");
  }
  const auto exchange = [](const std::string& body) {
    CannedServer server(kHead + body);
    return secure_frontend::post_chat_completion(loopback(), server.port, "token", "{}", {.timeout = 5s});
  };
  expect(exchange(kGoodBody).end == ChatExchangeEnd::complete, "[DONE] + terminal chunk = complete");
  expect(exchange(chunk("data: {\"a\":1}\n\n") + chunk("data: [DONE]\n\n")).end == ChatExchangeEnd::cut, "no terminal chunk = cut");
  expect(exchange(chunk("data: {\"a\":1}\n\n") + "0\r\n\r\n").end == ChatExchangeEnd::cut, "terminal chunk without [DONE] = cut");
  const auto plain = [] {
    CannedServer server("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    return secure_frontend::post_chat_completion(loopback(), server.port, "token", "{}", {.timeout = 5s});
  }();
  expect(plain.end == ChatExchangeEnd::complete && !plain.streamed && plain.head.status == 503 && plain.body == "{}", "complete responses are read too");
}

void client_rejects_event_over_cap() {
  ChunkedSseReader reader(1024U);
  reader.feed(chunk("data: " + std::string(2000U, 'x') + "\n\n"));
  SseItem item{};
  expect(reader.next(item) == SseReadState::error, "one chunk larger than the cap");
  ChunkedSseReader split(1024U);
  for (int index = 0; index < 4; ++index) split.feed(chunk(index == 0 ? "data: " + std::string(400U, 'y') : std::string(400U, 'y')));
  expect(split.next(item) == SseReadState::error, "an event growing over the cap across chunks");
  CannedServer server(kHead + chunk("data: " + std::string(2000U, 'x') + "\n\n") + "0\r\n\r\n");
  const auto result = secure_frontend::post_chat_completion(loopback(), server.port, "token", "{}", {.timeout = 5s, .max_event_bytes = 1024U});
  expect(result.end == ChatExchangeEnd::protocol_error, "the client refuses an oversized event");
}

void client_accepts_only_loopback_address() {
  using secure_frontend::LoopbackAddress;
  using secure_frontend::parse_listener_address;
  expect(LoopbackAddress::from(*parse_listener_address("127.0.0.1")).has_value(), "127.0.0.1");
  expect(LoopbackAddress::from(*parse_listener_address("::1")).has_value(), "::1");
  expect(!LoopbackAddress::from(*parse_listener_address("192.168.1.10")).has_value(), "a LAN address is refused");
  expect(!LoopbackAddress::from(*parse_listener_address("0.0.0.0")).has_value(), "the wildcard is refused");
  static_assert(!std::is_invocable_v<decltype(&secure_frontend::post_chat_completion), const secure_frontend::IpAddress&, std::uint16_t,
                                     std::string_view, std::string_view, const secure_frontend::ChatRequestOptions&>,
                "a plain IpAddress is a compile error at the call site");
}

}  // namespace

int main(int argc, char* argv[]) {
#if defined(_WIN32)
  WSADATA data{};
  (void)WSAStartup(MAKEWORD(2, 2), &data);
#endif
  return secure_frontend_test::run_cases(argc, argv,
                                         {
                                             {"client_reads_chunked_stream_and_requires_done_and_terminal_chunk", client_reads_chunked_stream_and_requires_done_and_terminal_chunk},
                                             {"client_rejects_event_over_cap", client_rejects_event_over_cap},
                                             {"client_accepts_only_loopback_address", client_accepts_only_loopback_address},
                                         },
                                         failures);
}

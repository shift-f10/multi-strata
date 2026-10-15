#include "secure_frontend/api_constants.hpp"
#include "secure_frontend/connection_pool.hpp"
#include "secure_frontend/http_socket_server.hpp"
#include "secure_frontend/socket_io.hpp"
#include "support/raw_http.hpp"
#include "support/test_support.hpp"

#include <chrono>
#include <iostream>
#include <optional>
#include <algorithm>
#include <string>
#include <vector>

namespace {
using namespace std::chrono_literals;
using secure_frontend::AdmissionState;
int failures = 0;
void expect(bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}
secure_frontend::PeerKey peer(unsigned char last) { secure_frontend::PeerKey k{}; k[0] = 4; k[1] = 192; k[2] = 168; k[3] = 1; k[4] = last; return k; }
const secure_frontend::PeerKey kLoop = [] { secure_frontend::PeerKey k{}; k[0] = 4; k[1] = 127; k[4] = 1; return k; }();

void dos01_oldest_header_phase_connection_is_evicted() {
  AdmissionState state(3, 3);
  const auto t0 = AdmissionState::Clock::time_point{} + 1s;
  const auto a = state.admit(secure_frontend::AddressScope::loopback, kLoop, t0);
  const auto b = state.admit(secure_frontend::AddressScope::loopback, kLoop, t0 + 10ms);
  const auto c = state.admit(secure_frontend::AddressScope::loopback, kLoop, t0 + 20ms);
  expect(a.kind == AdmissionState::Kind::assign && b.kind == AdmissionState::Kind::assign && c.kind == AdmissionState::Kind::assign,
         "three idle workers take three connections");
  expect(state.header_complete(a.worker, a.connection), "a authenticates and leaves P1");
  const auto d = state.admit(secure_frontend::AddressScope::loopback, kLoop, t0 + 30ms);
  expect(d.kind == AdmissionState::Kind::evict && d.worker == b.worker, "the longest-waiting P1 connection (b) is evicted, never a");
  expect(!state.header_complete(b.worker, b.connection), "the evicted connection learns it was evicted");
  expect(state.phase(b.worker) == secure_frontend::WorkerPhase::header, "the worker now serves the new connection in P1");
  expect(state.header_complete(c.worker, c.connection) && state.header_complete(d.worker, d.connection), "c and d authenticate");
  const auto e = state.admit(secure_frontend::AddressScope::loopback, kLoop, t0 + 40ms);
  expect(e.kind == AdmissionState::Kind::refuse, "no idle and no P1 worker: refuse");
  state.finished(b.worker, b.connection);   // stale id: ignored
  expect(state.phase(b.worker) == secure_frontend::WorkerPhase::busy, "a stale finish does not free the worker");
  state.finished(d.worker, d.connection);
  expect(state.phase(d.worker) == secure_frontend::WorkerPhase::idle, "the real finish frees it");
}

void dos01_remote_address_cap() {
  AdmissionState state(8, 2);
  const auto t0 = AdmissionState::Clock::time_point{} + 1s;
  const auto first = state.admit(secure_frontend::AddressScope::remote, peer(5), t0);
  const auto second = state.admit(secure_frontend::AddressScope::remote, peer(5), t0);
  const auto third = state.admit(secure_frontend::AddressScope::remote, peer(5), t0);
  expect(first.kind == AdmissionState::Kind::assign && second.kind == AdmissionState::Kind::assign, "two connections from one remote address");
  expect(third.kind == AdmissionState::Kind::refuse, "the third is refused although workers are idle");
  expect(state.admit(secure_frontend::AddressScope::remote, peer(6), t0).kind == AdmissionState::Kind::assign, "another address is admitted");
  for (int i = 0; i < 4; ++i) {
    expect(state.admit(secure_frontend::AddressScope::loopback, kLoop, t0).kind == AdmissionState::Kind::assign,
           "loopback is exempt from the per-address cap");
  }
  state.finished(first.worker, first.connection);
  expect(state.remote_count(peer(5)) == 1U, "finishing releases the address count");
  expect(state.admit(secure_frontend::AddressScope::remote, peer(5), t0).kind == AdmissionState::Kind::assign, "admitted again under the cap");

  // Evicting a remote peer's P1 connection releases that address's count.
  AdmissionState one(1, 2);
  const auto held = one.admit(secure_frontend::AddressScope::remote, peer(7), t0);
  expect(held.kind == AdmissionState::Kind::assign && one.remote_count(peer(7)) == 1U, "the remote peer holds the only worker in P1");
  const auto evictor = one.admit(secure_frontend::AddressScope::loopback, kLoop, t0 + 10ms);
  expect(evictor.kind == AdmissionState::Kind::evict && evictor.worker == held.worker, "a new connection evicts it");
  expect(one.remote_count(peer(7)) == 0U, "eviction releases the evicted remote peer's count");
  one.finished(held.worker, held.connection);   // stale: must not underflow or free the worker
  expect(one.remote_count(peer(7)) == 0U && one.phase(evictor.worker) == secure_frontend::WorkerPhase::header,
         "a stale finish after eviction changes nothing");
}

std::optional<secure_frontend::HttpSocketServer> loopback_listener() {
  secure_frontend::Config listener{};
  listener.host = "127.0.0.1"; listener.port = 0; listener.has_api_key = true;
  std::string error;
  auto server = secure_frontend::HttpSocketServer::bind(listener, 128, &error);
  expect(server.has_value(), "listener: " + error);
  return server;
}

// Opens a client that sends a partial request and accepts it on `server`.
bool connect_and_accept(secure_frontend::HttpSocketServer& server, std::optional<raw_http::Connection>* client,
                        secure_frontend::HttpSocketServer::Accepted* accepted) {
  *client = raw_http::Connection::open("127.0.0.1", server.port());
  expect(client->has_value(), "client connects");
  if (!client->has_value()) return false;
  expect((*client)->send("GET /health HTTP/1.1\r\n"), "client sends a partial request it will never finish");
  auto status = secure_frontend::HttpSocketServer::AcceptStatus::timeout;
  for (int tries = 0; tries < 50 && status != secure_frontend::HttpSocketServer::AcceptStatus::accepted; ++tries) {
    status = server.accept_next(100ms, accepted);
  }
  expect(status == secure_frontend::HttpSocketServer::AcceptStatus::accepted, "accepted");
  return status == secure_frontend::HttpSocketServer::AcceptStatus::accepted;
}

std::vector<secure_frontend::NativeSocket> lingering_natives(const secure_frontend::LingerList& linger) {
  std::vector<secure_frontend::PollEntry> entries;
  linger.append_poll_entries(entries);
  std::vector<secure_frontend::NativeSocket> natives;
  for (const auto& entry : entries) {
    expect(entry.want_read && !entry.want_write, "every lingering socket is polled for reading only");
    natives.push_back(entry.socket);
  }
  return natives;
}

// Pre-flight T11: the socket the overflowing add() closed was closed WITHOUT
// draining (an RST may destroy its 503), so the 503 is read from clients[1],
// which still lingers (half-closed: the 503 then FIN); the evicted one is only
// asserted closed. Which socket was evicted is pinned by native handle: no
// accept happens after the last add(), so no handle can have been reused.
void dos01_linger_list_overflow_closes_oldest() {
  constexpr std::size_t kMax = secure_frontend::api_constants::kLingerListMax;
  auto server = loopback_listener();
  if (!server) return;
  secure_frontend::LingerList linger;
  std::vector<raw_http::Connection> clients;
  std::vector<secure_frontend::NativeSocket> natives;
  const auto now = secure_frontend::LingerList::Clock::now();
  for (std::size_t i = 0; i < kMax + 1U; ++i) {
    std::optional<raw_http::Connection> client;
    secure_frontend::HttpSocketServer::Accepted accepted;
    if (!connect_and_accept(*server, &client, &accepted)) return;
    natives.push_back(accepted.socket.get());
    secure_frontend::refuse_connection(std::move(accepted.socket), linger, now);
    clients.push_back(std::move(*client));
  }
  expect(linger.size() == kMax, "at most kLingerListMax refused sockets are kept");
  const auto held = lingering_natives(linger);
  expect(std::find(held.begin(), held.end(), natives.front()) == held.end(), "the oldest refused socket left the list");
  expect(held == std::vector<secure_frontend::NativeSocket>(natives.begin() + 1, natives.end()),
         "the list holds exactly the newer refused sockets, oldest first");
  expect(clients.front().wait_closed(1s), "the oldest refused socket was closed when the list overflowed");
  const std::string lingering = clients[1].read_until_close(1s);
  expect(lingering.rfind("HTTP/1.1 503 ", 0) == 0 && lingering.find("server_busy") != std::string::npos,
         "a lingering refused client reads the fixed 503");
  expect(lingering.size() <= secure_frontend::api_constants::kRefusalMaxBytes, "refusal is at most 512 bytes");
  linger.service(now + 150ms);
  expect(linger.size() == 0U, "every lingering socket is closed 100 ms after its refusal");
  expect(clients.back().wait_closed(1s), "the newest refused client sees the close");
}

void dos01_linger_closes_on_peer_eof() {
  auto server = loopback_listener();
  if (!server) return;
  secure_frontend::LingerList linger;
  std::optional<raw_http::Connection> client;
  secure_frontend::HttpSocketServer::Accepted accepted;
  if (!connect_and_accept(*server, &client, &accepted)) return;
  const auto now = secure_frontend::LingerList::Clock::now();
  secure_frontend::refuse_connection(std::move(accepted.socket), linger, now);
  linger.service(now);
  expect(linger.size() == 1U, "a refused socket whose peer is still open lingers within the budget");
  const std::string response = client->read_until_close(1s);
  expect(response.rfind("HTTP/1.1 503 ", 0) == 0, "the client reads the 503 before closing its side");
  expect(client->shutdown_send(), "the client half-closes");
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (linger.size() != 0U && std::chrono::steady_clock::now() < deadline) {
    std::vector<secure_frontend::PollEntry> entries;
    linger.append_poll_entries(entries);
    (void)secure_frontend::poll_sockets(entries, 20ms);
    linger.service(now);   // the clock stays inside the 100 ms budget: only EOF can close it
  }
  expect(linger.size() == 0U, "peer EOF closes the lingering socket before its budget runs out");
}

void refusal_response_is_fixed_and_small() {
  const std::string r = secure_frontend::refusal_response(std::chrono::system_clock::now());
  expect(r.rfind("HTTP/1.1 503 Service Unavailable\r\n", 0) == 0 && r.find("Retry-After: 1\r\n") != std::string::npos &&
         r.find("\"code\":\"server_busy\"") != std::string::npos && r.size() <= secure_frontend::api_constants::kRefusalMaxBytes,
         "fixed 503 server_busy with Retry-After: 1 in at most 512 bytes (" + std::to_string(r.size()) + ")");
}
}  // namespace

int main(int argc, char** argv) {
  secure_frontend::WinsockGuard winsock;
  return secure_frontend_test::run_cases(argc, argv, {
      {"dos01_oldest_header_phase_connection_is_evicted", dos01_oldest_header_phase_connection_is_evicted},
      {"dos01_remote_address_cap", dos01_remote_address_cap},
      {"dos01_linger_list_overflow_closes_oldest", dos01_linger_list_overflow_closes_oldest},
      {"dos01_linger_closes_on_peer_eof", dos01_linger_closes_on_peer_eof},
      {"refusal_response_is_fixed_and_small", refusal_response_is_fixed_and_small},
  }, failures);
}

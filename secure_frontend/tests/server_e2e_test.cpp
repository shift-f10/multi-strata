#include "support/server_fixture.hpp"
#include "support/test_support.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <iphlpapi.h>
#endif

namespace {
int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}
using secure_frontend_test::contains;
using secure_frontend_test::ServerFixture;

std::vector<std::string> with(std::vector<std::string> base, const std::vector<std::string>& extra) {
  base.insert(base.end(), extra.begin(), extra.end());
  return base;
}

// Every listening TCP socket on `port`: {"v4", "<hex addr>"} / {"v6", ...}.
std::vector<std::pair<std::string, std::string>> listeners_on_port(const std::uint16_t port, const long pid) {
  std::vector<std::pair<std::string, std::string>> found;
#if defined(_WIN32)
  for (const ULONG family : {static_cast<ULONG>(AF_INET), static_cast<ULONG>(AF_INET6)}) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
    std::vector<unsigned char> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR) continue;
    if (family == AF_INET) {
      const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
      for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (static_cast<long>(row.dwOwningPid) == pid || ntohs(static_cast<u_short>(row.dwLocalPort)) == port) {
          found.emplace_back("v4", row.dwLocalAddr == htonl(INADDR_LOOPBACK) ? "loopback" : "other");
        }
      }
    } else {
      const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
      for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (static_cast<long>(row.dwOwningPid) == pid || ntohs(static_cast<u_short>(row.dwLocalPort)) == port) {
          found.emplace_back("v6", "other");
        }
      }
    }
  }
#else
  (void)pid;
  char port_hex[8];
  std::snprintf(port_hex, sizeof(port_hex), "%04X", port);
  for (const auto& [file, family] : {std::pair{"/proc/net/tcp", "v4"}, std::pair{"/proc/net/tcp6", "v6"}}) {
    std::ifstream table(file);
    std::string line;
    std::getline(table, line);  // header
    while (std::getline(table, line)) {
      std::istringstream fields(line);
      std::string slot, local, remote, state;
      fields >> slot >> local >> remote >> state;
      const auto colon = local.rfind(':');
      if (state != "0A" || colon == std::string::npos || local.substr(colon + 1) != port_hex) continue;
      const std::string address = local.substr(0, colon);
      found.emplace_back(family, address == "0100007F" ? "loopback" : "other");
    }
  }
#endif
  return found;
}

void cfg01_invalid_config_fails_before_listener_and_child() {
  ServerFixture f;
  const auto marker = f.dir / "engine-started";
  // (a) an invalid key value
  auto literals = f.base_literals();
  literals["limits.http.max_headers"] = "1";
  literals["engine.args"] = "[" + secure_frontend_test::json_literal("--marker=" + marker.string()) + "]";
  f.write_config(literals);
  const auto invalid = f.run({"--config", f.config.string()});
  expect(invalid.exit_code != 0 && contains(invalid.err, "limits.http.max_headers"), "invalid config exits: " + invalid.err);
  expect(!std::filesystem::exists(marker), "the engine must not start on an invalid config");
  expect(!secure_frontend_test::can_connect(f.port), "no listener remains");
  // (b) a valid config whose address cannot be bound (TEST-NET-1 is never local)
  const auto unbindable = f.run(with(f.base_flags(), {"--host", "192.0.2.10", "--allow-remote", "--engine-arg",
                                                      "--marker=" + marker.string()}));
  expect(unbindable.exit_code != 0 && contains(unbindable.err, "Unable to bind"), "unbindable address exits");
  expect(!std::filesystem::exists(marker), "the engine must not start when the listener cannot bind");
}

void net01_default_listener_is_loopback_only() {
  ServerFixture f;
  secure_frontend_test::ChildProcess server;
  expect(f.start(server, f.base_flags()), "server starts with defaults: " + server.stderr_text());
  const auto listeners = listeners_on_port(f.port, server.pid());
  expect(!listeners.empty(), "the server listens");
  for (const auto& [family, scope] : listeners) {
    expect(family == "v4" && scope == "loopback", "only 127.0.0.1 listens by default, found " + family + "/" + scope);
  }
}

void net02_remote_addresses_need_opt_in() {
  ServerFixture f;
  const auto marker = f.dir / "engine-started";
  for (const char* host : {"0.0.0.0", "::", "192.168.1.10", "10.0.0.1", "203.0.113.5", "2001:db8::1", "fd00::1"}) {
    const auto result = f.run(with(f.base_flags(), {"--host", host, "--engine-arg", "--marker=" + marker.string()}));
    expect(result.exit_code != 0 && contains(result.err, "listener.host: a non-loopback address needs listener.allow_remote"),
           std::string{"remote address without opt-in must fail: "} + host);
  }
  expect(!std::filesystem::exists(marker), "no engine was started for any of them");
}

void net02_error_is_non_secret_and_exits_before_bind() {
  ServerFixture f;
  const auto marker = f.dir / "engine-started";
  const auto result = f.run(with(f.base_flags(), {"--host", "203.0.113.5", "--engine-arg", "--marker=" + marker.string()}));
  expect(result.exit_code != 0, "startup fails");
  expect(contains(result.err, "listener.host"), "the error names the key");
  expect(!contains(result.err, secure_frontend_test::kTestToken) && !contains(result.out, secure_frontend_test::kTestToken),
         "the error never contains the token");
  expect(!contains(result.err, "203.0.113.5"), "the error does not echo the value");
  expect(!std::filesystem::exists(marker), "the engine was not launched");
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"cfg01_invalid_config_fails_before_listener_and_child", cfg01_invalid_config_fails_before_listener_and_child},
      {"net01_default_listener_is_loopback_only", net01_default_listener_is_loopback_only},
      {"net02_remote_addresses_need_opt_in", net02_remote_addresses_need_opt_in},
      {"net02_error_is_non_secret_and_exits_before_bind", net02_error_is_non_secret_and_exits_before_bind},
  }, failures);
}

#pragma once
// Test-only process socket/thread/handle inspection (spec §6.2 table scan,
// DOS-02 idle counts, NET-01). Linux: /proc/<pid>/fd + /proc/<pid>/net/*;
// Windows: GetExtendedTcpTable/GetExtendedUdpTable filtered by pid, Toolhelp
// threads, GetProcessHandleCount.
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#include <iphlpapi.h>
#include <tlhelp32.h>
#else
#include <netinet/in.h>
#include <unistd.h>
#endif

namespace test_support {

struct SocketRow final {
  std::string kind;           // tcp, tcp6, udp, udp6, unix
  bool listening{false};
  std::uint16_t local_port{0};
  std::string local_address;  // kernel hex (Linux) or dotted/hex (Windows); compared only for loopback checks
};

#if defined(_WIN32)
inline std::vector<SocketRow> sockets_of(const long pid) {
  std::vector<SocketRow> rows;
  for (const ULONG family : {static_cast<ULONG>(AF_INET), static_cast<ULONG>(AF_INET6)}) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<unsigned char> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
      if (family == AF_INET) {
        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
          const auto& r = table->table[i];
          if (static_cast<long>(r.dwOwningPid) != pid) continue;
          rows.push_back({"tcp", r.dwState == MIB_TCP_STATE_LISTEN, ntohs(static_cast<u_short>(r.dwLocalPort)), std::to_string(r.dwLocalAddr)});
        }
      } else {
        const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
          const auto& r = table->table[i];
          if (static_cast<long>(r.dwOwningPid) != pid) continue;
          std::string addr(reinterpret_cast<const char*>(r.ucLocalAddr), 16U);
          rows.push_back({"tcp6", r.dwState == MIB_TCP_STATE_LISTEN, ntohs(static_cast<u_short>(r.dwLocalPort)), addr});
        }
      }
    }
    size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
    std::vector<unsigned char> udp(size);
    if (GetExtendedUdpTable(udp.data(), &size, FALSE, family, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
      if (family == AF_INET) {
        const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(udp.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
          if (static_cast<long>(table->table[i].dwOwningPid) == pid) rows.push_back({"udp", false, ntohs(static_cast<u_short>(table->table[i].dwLocalPort)), {}});
        }
      } else {
        const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(udp.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
          if (static_cast<long>(table->table[i].dwOwningPid) == pid) rows.push_back({"udp6", false, ntohs(static_cast<u_short>(table->table[i].dwLocalPort)), {}});
        }
      }
    }
  }
  return rows;
}
inline std::size_t thread_count(const long pid) {
  const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return 0;
  THREADENTRY32 entry{};
  entry.dwSize = sizeof(entry);
  std::size_t n = 0;
  for (BOOL ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry)) {
    if (static_cast<long>(entry.th32OwnerProcessID) == pid) ++n;
  }
  CloseHandle(snapshot);
  return n;
}
inline std::size_t handle_count(const long pid) {
  const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
  if (process == nullptr) return 0;
  DWORD count = 0;
  GetProcessHandleCount(process, &count);
  CloseHandle(process);
  return count;
}
#else
inline std::set<std::string> socket_inodes(const long pid) {
  std::set<std::string> inodes;
  std::error_code ec;
  for (const auto& entry : std::filesystem::directory_iterator("/proc/" + std::to_string(pid) + "/fd", ec)) {
    std::error_code link_error;
    const std::string target = std::filesystem::read_symlink(entry.path(), link_error).string();
    if (target.rfind("socket:[", 0) == 0) inodes.insert(target.substr(8, target.size() - 9));
  }
  return inodes;
}
// Ruling T12-scan: the server sets PR_SET_DUMPABLE(0) (SP0 hardening), so
// /proc/<pid>/fd is unreadable from the test even at the same uid. When the fd
// scan yields nothing, rows are attributed by uid instead: the net tables below
// are the process's network-namespace view, and the server shares uid and
// namespace with the test. Dumpable processes (the fake engine) keep the exact
// inode mapping. Either way a listening socket the pid does not own is caught
// as soon as it belongs to this uid/namespace (NET-01, spec §6.2 scan).
inline std::vector<SocketRow> sockets_of(const long pid) {
  const auto inodes = socket_inodes(pid);
  const bool by_inode = !inodes.empty();
  const std::string uid_field = std::to_string(static_cast<long>(geteuid()));
  std::vector<SocketRow> rows;
  for (const std::string kind : {"tcp", "tcp6", "udp", "udp6"}) {
    std::ifstream table("/proc/" + std::to_string(pid) + "/net/" + kind);
    if (!table) table = std::ifstream("/proc/net/" + kind);
    std::string line;
    std::getline(table, line);   // header
    while (std::getline(table, line)) {
      std::istringstream fields(line);
      std::string slot, local, remote, state, queues, timer, retransmit, uid, timeout, inode;
      fields >> slot >> local >> remote >> state >> queues >> timer >> retransmit >> uid >> timeout >> inode;
      if (by_inode ? !inodes.count(inode) : uid != uid_field) continue;
      const auto colon = local.rfind(':');
      rows.push_back({kind, state == "0A", static_cast<std::uint16_t>(std::stoul(local.substr(colon + 1U), nullptr, 16)), local.substr(0, colon)});
    }
  }
  std::ifstream unix_table("/proc/" + std::to_string(pid) + "/net/unix");
  if (!unix_table) unix_table = std::ifstream("/proc/net/unix");
  std::string line;
  std::getline(unix_table, line);
  while (std::getline(unix_table, line)) {
    std::istringstream fields(line);
    std::string num, refs, protocol, flags, type, st, inode;
    fields >> num >> refs >> protocol >> flags >> type >> st >> inode;
    if (by_inode ? inodes.count(inode) : true) rows.push_back({"unix", false, 0, {}});
  }
  return rows;
}
inline std::size_t count_entries(const std::string& dir) {
  std::size_t n = 0;
  std::error_code ec;
  for (auto it = std::filesystem::directory_iterator(dir, ec); !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) ++n;
  return n;
}
inline std::size_t thread_count(const long pid) { return count_entries("/proc/" + std::to_string(pid) + "/task"); }
inline std::size_t handle_count(const long pid) { return count_entries("/proc/" + std::to_string(pid) + "/fd"); }
#endif

// Loopback in the kernel's /proc hex form (127.x.y.z little-endian ends in "7F"; ::1 is ...01000000) or Windows numbers.
inline bool is_loopback_row(const SocketRow& row) {
#if defined(_WIN32)
  if (row.kind == "tcp") return (std::stoul(row.local_address) & 0xffU) == 127U;
  return row.local_address == std::string("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01", 16);
#else
  if (row.kind == "tcp") return row.local_address.size() == 8U && row.local_address.substr(6) == "7F";
  return row.local_address == "00000000000000000000000001000000";
#endif
}

}  // namespace test_support

// LD_PRELOAD shim for the DL-01/PRIV-01 socket audit (spec §10.3). Records every
// non-loopback connect/sendto and every getaddrinfo of a non-loopback name to
// $SF_CONNECT_AUDIT; with $SF_CONNECT_AUDIT_BLOCK set it refuses them, so a test
// can prove the shim works (positive control) without any real network access.
// With $SF_CONNECT_AUDIT_LOADED set it also appends "loaded" there when it is
// mapped, so an empty audit is proven to come from a process the shim was in.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

void audit(const char* what, const char* detail) {
  const char* file = std::getenv("SF_CONNECT_AUDIT");
  if (file == nullptr) return;
  const int fd = ::open(file, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) return;
  char line[512];
  const int n = std::snprintf(line, sizeof line, "%s %s\n", what, detail);
  if (n > 0) (void)!::write(fd, line, static_cast<std::size_t>(n));
  ::close(fd);
}

void write_line(const char* file, const char* text) {
  const int fd = ::open(file, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) return;
  (void)!::write(fd, text, std::strlen(text));
  ::close(fd);
}

__attribute__((constructor)) void announce_loaded() {
  if (const char* file = std::getenv("SF_CONNECT_AUDIT_LOADED")) write_line(file, "loaded\n");
}

bool blocking() { return std::getenv("SF_CONNECT_AUDIT_BLOCK") != nullptr; }

// Ruling I17: only AF_INET/AF_INET6 can leave the host; every other family
// (AF_UNIX, AF_NETLINK, ...) is local.
bool loopback(const sockaddr* address) {
  if (address == nullptr) return true;
  if (address->sa_family == AF_INET) {
    const auto* in = reinterpret_cast<const sockaddr_in*>(address);
    return (ntohl(in->sin_addr.s_addr) >> 24U) == 127U;
  }
  if (address->sa_family == AF_INET6) {
    const auto* in6 = reinterpret_cast<const sockaddr_in6*>(address);
    static const unsigned char kLoopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return std::memcmp(&in6->sin6_addr, kLoopback, 16) == 0;
  }
  return true;
}

template <typename Fn>
Fn next(const char* name) {
  return reinterpret_cast<Fn>(::dlsym(RTLD_NEXT, name));
}

}  // namespace

extern "C" {

int connect(int fd, const sockaddr* address, socklen_t length) {
  static const auto real = next<int (*)(int, const sockaddr*, socklen_t)>("connect");
  if (!loopback(address)) {
    audit("connect", address->sa_family == AF_INET6 ? "inet6" : "inet");
    if (blocking()) {
      errno = ECONNREFUSED;
      return -1;
    }
  }
  return real(fd, address, length);
}

ssize_t sendto(int fd, const void* buffer, size_t size, int flags, const sockaddr* address, socklen_t length) {
  static const auto real = next<ssize_t (*)(int, const void*, size_t, int, const sockaddr*, socklen_t)>("sendto");
  if (address != nullptr && !loopback(address)) {
    audit("sendto", "datagram");
    if (blocking()) {
      errno = ENETUNREACH;
      return -1;
    }
  }
  return real(fd, buffer, size, flags, address, length);
}

int getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** result) {
  static const auto real = next<int (*)(const char*, const char*, const addrinfo*, addrinfo**)>("getaddrinfo");
  if (node != nullptr && std::strcmp(node, "localhost") != 0 && std::strncmp(node, "127.", 4) != 0 && std::strcmp(node, "::1") != 0) {
    audit("getaddrinfo", node);
    if (blocking()) return EAI_NONAME;
  }
  return real(node, service, hints, result);
}

}  // extern "C"

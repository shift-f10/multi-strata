// The socket audit's positive control (spec §10.1): one name lookup, nothing else.
#include <netdb.h>

int main() {
  addrinfo* result = nullptr;
  const int rc = ::getaddrinfo("fixture.example", "443", nullptr, &result);
  if (rc == 0 && result != nullptr) ::freeaddrinfo(result);
  return 0;
}

#include "support/binary_imports.hpp"
#include "support/test_paths.hpp"
#include "support/test_support.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {
int failures = 0;
void expect(bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}
bool has(const std::vector<std::string>& values, std::string_view wanted) {
  return std::any_of(values.begin(), values.end(), [wanted](const std::string& v) {
    return v.size() == wanted.size() && std::equal(v.begin(), v.end(), wanted.begin(), [](char a, char b) {
             return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
           });
  });
}

void egress_server_imports_no_resolver_or_http_client() {
  const auto report = test_support::read_binary_imports(test_support::server_path());
  expect(report.ok, "the server binary has an import table: " + report.error);
  // Positive controls: the reader really sees the socket imports the listener needs.
#if defined(_WIN32)
  expect(has(report.libraries, "ws2_32.dll"), "ws2_32.dll is imported");
#else
  expect(has(report.symbols, "accept") || has(report.symbols, "accept4"), "accept is an undefined dynamic symbol");
#endif
  const auto forbidden = test_support::forbidden_imports(report);
  std::string list;
  for (const auto& f : forbidden) list += f + " ";
  expect(forbidden.empty(), "no resolver, HTTP client or outbound-connect import: " + list);
}

// Little-endian writers for the synthetic images (ruling R-I: they go through the real parsers).
void put(std::vector<unsigned char>& b, std::size_t at, std::uint64_t value, std::size_t width) {
  if (b.size() < at + width) b.resize(at + width, 0);
  for (std::size_t i = 0; i < width; ++i) b[at + i] = static_cast<unsigned char>(value >> (8U * i));
}
void put_text(std::vector<unsigned char>& b, std::size_t at, std::string_view text) {
  if (b.size() < at + text.size() + 1U) b.resize(at + text.size() + 1U, 0);
  std::copy(text.begin(), text.end(), b.begin() + static_cast<std::ptrdiff_t>(at));
}
// ELF64 x86-64: .dynstr at 64, optional .dynsym at 96 (null + getaddrinfo + accept, all undefined),
// .dynamic at 168 (DT_NEEDED libc.so.6), section table at 200.
std::vector<unsigned char> synthetic_elf(const bool with_dynsym) {
  std::vector<unsigned char> b(64, 0);
  b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F'; b[4] = 2; b[5] = 1; b[6] = 1;
  put(b, 0x10, 2, 2);      // ET_EXEC
  put(b, 0x12, 0x3e, 2);   // EM_X86_64
  put_text(b, 65, "getaddrinfo");   // dynstr: "\0getaddrinfo\0accept\0libc.so.6\0" (offsets 1, 13, 20)
  put_text(b, 77, "accept");
  put_text(b, 84, "libc.so.6");
  put(b, 96 + 24 * 1, 1, 4);   // sym 1: st_name = 1, st_shndx = 0 (undefined)
  put(b, 96 + 24 * 2, 13, 4);  // sym 2: st_name = 13
  put(b, 168, 1, 8);           // DT_NEEDED
  put(b, 176, 20, 8);          //   -> "libc.so.6"
  put(b, 199, 0, 1);           // zero DT_NULL terminator up to the section table
  const std::size_t table = 200;
  std::size_t index = 1;       // section 0 is the null section
  const auto section = [&](std::uint32_t type, std::uint64_t offset, std::uint64_t size, std::uint32_t link, std::uint64_t entsize) {
    const std::size_t base = table + index * 64U;
    put(b, base + 4, type, 4);
    put(b, base + 0x18, offset, 8);
    put(b, base + 0x20, size, 8);
    put(b, base + 0x28, link, 4);
    put(b, base + 0x38, entsize, 8);
    ++index;
  };
  section(3, 64, 30, 0, 0);                    // 1: .dynstr (SHT_STRTAB)
  if (with_dynsym) section(11, 96, 72, 1, 24); // 2: .dynsym (SHT_DYNSYM) -> strtab 1
  section(6, 168, 32, 1, 16);                  // .dynamic (SHT_DYNAMIC) -> strtab 1
  put(b, table + index * 64U - 1U, 0, 1);      // size the buffer to the whole table
  put(b, 0x28, table, 8);                      // e_shoff
  put(b, 0x3a, 64, 2);                         // e_shentsize
  put(b, 0x3c, index, 2);                      // e_shnum
  return b;
}
// PE32+: one section (VA 0x1000, raw 0x200); import directory at RVA 0x1000 naming WS2_32.dll
// with one ordinal-only thunk (52 = gethostbyname).
std::vector<unsigned char> synthetic_pe() {
  std::vector<unsigned char> b(0x400, 0);
  b[0] = 'M'; b[1] = 'Z';
  put(b, 0x3c, 0x40, 4);              // e_lfanew
  put_text(b, 0x40, "PE");            // "PE\0\0"
  put(b, 0x44, 0x8664, 2);            // machine x64
  put(b, 0x46, 1, 2);                 // one section
  put(b, 0x54, 240, 2);               // SizeOfOptionalHeader
  put(b, 0x58, 0x20b, 2);             // PE32+ magic (optional header at 0x58)
  put(b, 0x58 + 120, 0x1000, 4);      // import directory RVA
  put(b, 0x58 + 124, 40, 4);          // import directory size
  const std::size_t section = 0x58 + 240;
  put(b, section + 8, 0x200, 4);      // VirtualSize
  put(b, section + 12, 0x1000, 4);    // VirtualAddress
  put(b, section + 16, 0x200, 4);     // SizeOfRawData
  put(b, section + 20, 0x200, 4);     // PointerToRawData
  put(b, 0x200 + 0, 0x1040, 4);       // descriptor 0: OriginalFirstThunk
  put(b, 0x200 + 12, 0x1060, 4);      //               Name
  put(b, 0x200 + 16, 0x1040, 4);      //               FirstThunk (descriptor 1 stays zero)
  put(b, 0x240, (1ULL << 63U) | 52U, 8);   // ordinal-only thunk, then a zero thunk
  put_text(b, 0x260, "WS2_32.dll");
  return b;
}

void egress_static_tripwire_fails_on_binary_without_dynamic_section() {
  const auto stripped = test_support::read_elf_imports(synthetic_elf(false));
  expect(!stripped.ok && stripped.error.find("no dynamic section") != std::string::npos,
         "SHT_DYNAMIC without SHT_DYNSYM fails the tripwire, never passes vacuously: " + stripped.error);
  const auto resolver = test_support::read_elf_imports(synthetic_elf(true));
  expect(resolver.ok && has(resolver.symbols, "getaddrinfo") && has(resolver.symbols, "accept") && has(resolver.libraries, "libc.so.6"),
         "the parser reads .dynsym and DT_NEEDED: " + resolver.error);
  const auto flagged = test_support::forbidden_imports(resolver);
  expect(flagged.size() == 1U && flagged.front() == "getaddrinfo", "an undefined getaddrinfo is flagged");
  const auto pe = test_support::read_pe_imports(synthetic_pe());
  expect(pe.ok && has(pe.libraries, "ws2_32.dll") && pe.ordinals.size() == 1U && pe.ordinals.front().second == 52U,
         "the PE parser walks the import directory to the ordinal thunk: " + pe.error);
  expect(!test_support::forbidden_imports(pe).empty(), "an ordinal-only ws2_32 import (gethostbyname #52) is flagged");
  std::vector<unsigned char> no_imports = synthetic_pe();
  put(no_imports, 0x58 + 120, 0, 8);   // clear the import directory entry
  const auto empty = test_support::read_pe_imports(no_imports);
  expect(!empty.ok && empty.error.find("no import directory") != std::string::npos, "a PE without an import directory fails");
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"egress_server_imports_no_resolver_or_http_client", egress_server_imports_no_resolver_or_http_client},
      {"egress_static_tripwire_fails_on_binary_without_dynamic_section", egress_static_tripwire_fails_on_binary_without_dynamic_section},
  }, failures);
}

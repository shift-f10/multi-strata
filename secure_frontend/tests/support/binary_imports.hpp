#pragma once
// Test-only readers for the static egress tripwire (spec §6.2). Standard library only.
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace test_support {

struct ImportReport final {
  bool ok{false};
  std::string error;
  std::vector<std::string> libraries;
  std::vector<std::string> symbols;
  std::vector<std::pair<std::string, std::uint16_t>> ordinals;   // (dll, ordinal) for ordinal-only imports
};

namespace detail_imports {
template <typename T>
bool read_le(const std::vector<unsigned char>& bytes, std::uint64_t offset, T* out) {
  if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) return false;
  T value = 0;
  for (std::size_t i = 0; i < sizeof(T); ++i) value |= static_cast<T>(static_cast<T>(bytes[offset + i]) << (8U * i));
  *out = value;
  return true;
}
inline std::string c_string(const std::vector<unsigned char>& bytes, std::uint64_t offset) {
  std::string out;
  while (offset < bytes.size() && bytes[offset] != 0) out.push_back(static_cast<char>(bytes[offset++]));
  return out;
}
inline std::string lower(std::string value) {
  for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return value;
}
}  // namespace detail_imports

inline ImportReport read_elf_imports(const std::vector<unsigned char>& b) {
  using detail_imports::read_le;
  ImportReport r;
  if (b.size() < 64U || b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F' || b[4] != 2 || b[5] != 1) {
    r.error = "not a 64-bit little-endian ELF";
    return r;
  }
  std::uint64_t shoff = 0;
  std::uint16_t shentsize = 0, shnum = 0;
  if (!read_le(b, 0x28, &shoff) || !read_le(b, 0x3a, &shentsize) || !read_le(b, 0x3c, &shnum)) { r.error = "truncated header"; return r; }
  struct Section { std::uint32_t type; std::uint64_t offset, size, entsize; std::uint32_t link; };
  std::vector<Section> sections;
  for (std::uint16_t i = 0; i < shnum; ++i) {
    const std::uint64_t base = shoff + static_cast<std::uint64_t>(i) * shentsize;
    Section s{};
    if (!read_le(b, base + 4, &s.type) || !read_le(b, base + 0x18, &s.offset) || !read_le(b, base + 0x20, &s.size) ||
        !read_le(b, base + 0x28, &s.link) || !read_le(b, base + 0x38, &s.entsize)) {
      r.error = "truncated section table";
      return r;
    }
    sections.push_back(s);
  }
  const auto dynsym = std::find_if(sections.begin(), sections.end(), [](const Section& s) { return s.type == 11U; });
  if (dynsym == sections.end() || dynsym->link >= sections.size()) { r.error = "no dynamic section (static binary?)"; return r; }
  const Section& strtab = sections[dynsym->link];
  for (std::uint64_t off = dynsym->offset; off + 24U <= dynsym->offset + dynsym->size; off += 24U) {
    std::uint32_t name = 0;
    std::uint16_t shndx = 0;
    if (!read_le(b, off, &name) || !read_le(b, off + 6, &shndx)) break;
    if (shndx == 0U && name != 0U) r.symbols.push_back(detail_imports::c_string(b, strtab.offset + name));
  }
  for (const Section& dynamic : sections) {
    if (dynamic.type != 6U || dynamic.link >= sections.size()) continue;
    for (std::uint64_t off = dynamic.offset; off + 16U <= dynamic.offset + dynamic.size; off += 16U) {
      std::uint64_t tag = 0, value = 0;
      if (!read_le(b, off, &tag) || !read_le(b, off + 8, &value) || tag == 0U) break;
      if (tag == 1U) r.libraries.push_back(detail_imports::c_string(b, sections[dynamic.link].offset + value));
    }
  }
  r.ok = true;
  return r;
}

inline ImportReport read_pe_imports(const std::vector<unsigned char>& b) {
  using detail_imports::read_le;
  ImportReport r;
  std::uint32_t pe = 0;
  if (b.size() < 0x40U || b[0] != 'M' || b[1] != 'Z' || !read_le(b, 0x3c, &pe) || pe + 24U > b.size() ||
      std::memcmp(b.data() + pe, "PE\0\0", 4) != 0) {
    r.error = "not a PE image";
    return r;
  }
  std::uint16_t sections = 0, optional_size = 0, magic = 0;
  read_le(b, pe + 6, &sections);
  read_le(b, pe + 20, &optional_size);
  const std::uint64_t optional = pe + 24U;
  if (!read_le(b, optional, &magic) || magic != 0x20bU) { r.error = "not PE32+"; return r; }
  std::uint32_t import_rva = 0, import_size = 0;
  if (optional_size < 128U || !read_le(b, optional + 120, &import_rva) || !read_le(b, optional + 124, &import_size) || import_rva == 0U) {
    r.error = "no import directory";
    return r;
  }
  (void)import_size;
  const std::uint64_t table = optional + optional_size;
  const auto to_offset = [&](std::uint64_t rva) -> std::uint64_t {
    for (std::uint16_t i = 0; i < sections; ++i) {
      std::uint32_t vsize = 0, vaddr = 0, raw_size = 0, raw = 0;
      const std::uint64_t s = table + static_cast<std::uint64_t>(i) * 40U;
      if (!read_le(b, s + 8, &vsize) || !read_le(b, s + 12, &vaddr) || !read_le(b, s + 16, &raw_size) || !read_le(b, s + 20, &raw)) break;
      if (rva >= vaddr && rva < vaddr + std::max(vsize, raw_size)) return raw + (rva - vaddr);
    }
    return std::numeric_limits<std::uint64_t>::max();
  };
  for (std::uint64_t d = to_offset(import_rva); d != std::numeric_limits<std::uint64_t>::max() && d + 20U <= b.size(); d += 20U) {
    std::uint32_t oft = 0, name = 0, ft = 0;
    read_le(b, d, &oft);
    read_le(b, d + 12, &name);
    read_le(b, d + 16, &ft);
    if (oft == 0U && name == 0U && ft == 0U) break;
    const std::string dll = detail_imports::c_string(b, to_offset(name));
    r.libraries.push_back(dll);
    for (std::uint64_t t = to_offset(oft != 0U ? oft : ft); t != std::numeric_limits<std::uint64_t>::max() && t + 8U <= b.size(); t += 8U) {
      std::uint64_t thunk = 0;
      read_le(b, t, &thunk);
      if (thunk == 0U) break;
      if ((thunk & (1ULL << 63U)) != 0U) r.ordinals.emplace_back(dll, static_cast<std::uint16_t>(thunk & 0xffffU));
      else r.symbols.push_back(detail_imports::c_string(b, to_offset(thunk & 0x7fffffffULL) + 2U));
    }
  }
  r.ok = true;
  return r;
}

inline ImportReport read_binary_imports(const std::filesystem::path& file) {
  std::ifstream in(file, std::ios::binary);
  const std::vector<unsigned char> bytes{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
  if (bytes.size() >= 2U && bytes[0] == 'M' && bytes[1] == 'Z') return read_pe_imports(bytes);
  return read_elf_imports(bytes);
}

inline std::vector<std::string> forbidden_imports(const ImportReport& report) {
  static const std::vector<std::string> kSymbols{"getaddrinfo", "gethostbyname", "gethostbyname2", "gethostbyaddr", "getnameinfo",
                                                 "res_query", "res_search", "res_nquery", "getaddrinfow", "getaddrinfoexw", "wsaconnect"};
  static const std::vector<std::string> kLibraries{"winhttp.dll", "wininet.dll", "urlmon.dll", "dnsapi.dll"};
  std::vector<std::string> found;
  for (const auto& symbol : report.symbols) {
    std::string bare = symbol;
    bare.erase(0, bare.find_first_not_of('_'));
    if (std::find(kSymbols.begin(), kSymbols.end(), detail_imports::lower(bare)) != kSymbols.end()) found.push_back(symbol);
  }
  for (const auto& library : report.libraries) {
    if (std::find(kLibraries.begin(), kLibraries.end(), detail_imports::lower(library)) != kLibraries.end()) found.push_back(library);
  }
  for (const auto& [dll, ordinal] : report.ordinals) {
    if (detail_imports::lower(dll) == "ws2_32.dll") found.push_back(dll + "#" + std::to_string(ordinal));
  }
  return found;
}

}  // namespace test_support

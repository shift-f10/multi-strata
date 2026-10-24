#include "u_dispatch.hpp"

#include <array>

namespace u {
namespace {

struct Entry final {
  std::string_view arch;
  FamilyId family;
};

// The one fixed arch -> family table (design §3.1). Adding a family means adding a row here
// (and its geometry spec in u_geometry); there is no runtime registry.
constexpr std::array<Entry, 6> kTable{{
    {"glm5next", FamilyId::glm5next},
    {"ds4", FamilyId::ds4},
    {"raon1", FamilyId::raon1},
    {"qwen35moe", FamilyId::qwen35moe},
    {"qwen4exp", FamilyId::qwen4exp},
    {"gemma4", FamilyId::gemma4},
}};

}  // namespace

std::string_view arch_of(FamilyId family) {
  for (const auto& e : kTable) {
    if (e.family == family) return e.arch;
  }
  return {};
}

std::string_view name_of(FamilyId family) { return arch_of(family); }

std::optional<FamilyId> family_for_arch(std::string_view arch) {
  for (const auto& e : kTable) {
    if (e.arch == arch) return e.family;
  }
  return std::nullopt;
}

}  // namespace u

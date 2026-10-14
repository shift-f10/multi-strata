#include "secure_frontend/engine_gate.hpp"

#include "secure_frontend/catalog.hpp"

namespace secure_frontend {

std::optional<AcquireError> engine_gate(const AcquireManifest& manifest) {
  if (manifest.profile != ManifestProfile::qwen || manifest.family != EngineFamily::strata) {
    return AcquireError{AcquireReason::engine_profile_unavailable, std::string{profile_name(manifest.profile)}};
  }
  if (compare_versions(manifest.min_version, built_engine_version()) > 0) {
    return AcquireError{AcquireReason::engine_too_old, "needs engine strata >= " + render_engine_version(manifest.min_version) +
                                                           ", this release has " + std::string{built_engine_version_text()}};
  }
  return std::nullopt;
}

std::string engine_state_text(const AcquireManifest& manifest) {
  if (!engine_gate(manifest)) return "runnable";
  if (manifest.family == EngineFamily::none) return "not runnable (profile " + std::string{profile_name(manifest.profile)} + ")";
  return "needs engine " + std::string{family_name(manifest.family)} + " >= " + render_engine_version(manifest.min_version);
}

}  // namespace secure_frontend

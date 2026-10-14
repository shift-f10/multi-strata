#include "secure_frontend/model_index_model.hpp"
#include "support/test_support.hpp"

#include <cstdint>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

using secure_frontend::IndexEntry;
using secure_frontend::ModelIndex;
using secure_frontend::ModelOrigin;

IndexEntry entry(const std::string& name, const std::string& tag, const std::uint32_t sequence, const char digit) {
  const std::string digest(64, digit);
  return IndexEntry{name, tag, "2026.10.14." + std::to_string(sequence), sequence,
                    secure_frontend::version_directory_name(sequence, digest), digest, ModelOrigin::catalog};
}

void index_render_is_deterministic() {
  ModelIndex index;
  index = secure_frontend::with_installed(index, entry("zeta", "a", 1, 'b'));
  index = secure_frontend::with_installed(index, entry("alpha", "b", 2, 'c'));
  const std::string expected =
      "{\"format\":\"strata-model-index\",\"schema_version\":1,\"models\":["
      "{\"name\":\"alpha\",\"tag\":\"b\",\"version\":\"2026.10.14.2\",\"sequence\":2,\"dir\":\"v2-cccccccccccc\","
      "\"manifest_sha256\":\"" + std::string(64, 'c') + "\",\"origin\":\"catalog\"},"
      "{\"name\":\"zeta\",\"tag\":\"a\",\"version\":\"2026.10.14.1\",\"sequence\":1,\"dir\":\"v1-bbbbbbbbbbbb\","
      "\"manifest_sha256\":\"" + std::string(64, 'b') + "\",\"origin\":\"catalog\"}],\"retired\":[]}\n";
  expect(secure_frontend::render_model_index(index) == expected, "sorted, compact, one trailing newline");
}

void install_retires_previous_version() {
  ModelIndex index = secure_frontend::with_installed({}, entry("m", "t", 1, 'a'));
  index = secure_frontend::with_installed(index, entry("m", "t", 2, 'b'));
  expect(index.models.size() == 1 && index.models.front().sequence == 2, "one entry per name:tag");
  expect(index.retired.size() == 1 && index.retired.front().dir == "v1-aaaaaaaaaaaa", "old version retired");
  index = secure_frontend::without_retired(index, "m", "t", "v1-aaaaaaaaaaaa");
  expect(index.retired.empty(), "retired entry removed");
  index = secure_frontend::without_model(index, "m", "t");
  expect(index.models.empty() && secure_frontend::find_model(index, "m", "t") == nullptr, "model removed");
}

void reinstall_same_version_does_not_retire() {
  ModelIndex index = secure_frontend::with_installed({}, entry("m", "t", 1, 'a'));
  index = secure_frontend::with_installed(index, entry("m", "t", 1, 'a'));
  expect(index.models.size() == 1 && index.retired.empty(), "--verify re-publish of the same dir retires nothing");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"index_render_is_deterministic", index_render_is_deterministic},
      {"install_retires_previous_version", install_retires_previous_version},
      {"reinstall_same_version_does_not_retire", reinstall_same_version_does_not_retire},
  }, failures);
}

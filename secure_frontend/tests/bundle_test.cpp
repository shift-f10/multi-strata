#include "secure_frontend/bundle_text.hpp"
#include "support/test_support.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

secure_frontend::AcquireManifest sample() {
  secure_frontend::AcquireManifest m;
  m.files = {secure_frontend::ManifestFile{"weights/b.gguf", secure_frontend::FileRole::weights, 5, std::string(64, 'b'),
                                           {"https://h.example/b"}, {}},
             secure_frontend::ManifestFile{"pack/a.txt", secure_frontend::FileRole::pack, 5, std::string(64, 'a'), {}, {}},
             secure_frontend::ManifestFile{"Pack/Z.txt", secure_frontend::FileRole::pack, 5, std::string(64, 'c'), {}, {}}};
  return m;
}

void sha256sums_render_sorted_bytewise() {
  const std::string manifest_digest(64, 'f');
  const std::string expected = std::string(64, 'c') + "  files/Pack/Z.txt\n" + std::string(64, 'a') + "  files/pack/a.txt\n" +
                               std::string(64, 'b') + "  files/weights/b.gguf\n" + manifest_digest + "  manifest.json\n";
  expect(secure_frontend::render_sha256sums(manifest_digest, sample()) == expected,
         "bytewise order: files/Pack < files/pack < files/weights < manifest.json");
}

void sha256sums_parse_is_strict() {
  const std::string good = std::string(64, 'a') + "  files/x\n" + std::string(64, 'b') + "  manifest.json\n";
  expect(secure_frontend::parse_sha256sums(good).has_value(), "well-formed");
  for (const std::string& bad : {std::string(64, 'a') + " files/x\n", std::string(64, 'A') + "  files/x\n",
                                 std::string(64, 'a') + "  files/x", std::string(64, 'a') + "  files/x\r\n",
                                 std::string(64, 'b') + "  manifest.json\n" + std::string(64, 'a') + "  files/x\n",
                                 std::string(64, 'a') + "  files/x\n" + std::string(64, 'a') + "  files/x\n", std::string{}}) {
    expect(!secure_frontend::parse_sha256sums(bad).has_value(), "rejected sums text");
  }
}

void sums_agreement_rules() {
  const std::string manifest_digest(64, 'f');
  const auto lines = *secure_frontend::parse_sha256sums(secure_frontend::render_sha256sums(manifest_digest, sample()));
  expect(secure_frontend::sums_agree(lines, manifest_digest, sample()), "rendered sums agree");
  expect(!secure_frontend::sums_agree(lines, std::string(64, 'e'), sample()), "manifest digest differs");
  auto changed = sample();
  changed.files[0].sha256 = std::string(64, 'd');
  expect(!secure_frontend::sums_agree(lines, manifest_digest, changed), "a file digest differs");
  auto fewer = lines;
  fewer.pop_back();
  expect(!secure_frontend::sums_agree(fewer, manifest_digest, sample()), "a line is missing");
}

void missing_list_names_sourceless_files() {
  expect(secure_frontend::render_missing(sample()) == "Pack/Z.txt\npack/a.txt\n", "sorted sourceless paths");
  const auto parsed = secure_frontend::parse_missing("Pack/Z.txt\npack/a.txt\n");
  expect(parsed && parsed->size() == 2, "parse");
  expect(!secure_frontend::parse_missing("a\n\nb\n").has_value(), "empty line rejected");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"sha256sums_render_sorted_bytewise", sha256sums_render_sorted_bytewise},
      {"sha256sums_parse_is_strict", sha256sums_parse_is_strict},
      {"sums_agreement_rules", sums_agreement_rules},
      {"missing_list_names_sourceless_files", missing_list_names_sourceless_files},
  }, failures);
}

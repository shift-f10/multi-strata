#include "secure_frontend/acquire_manifest.hpp"
#include "secure_frontend/acquire_url.hpp"
#include "secure_frontend/engine_version.hpp"
#include "secure_frontend/test_hooks.hpp"
#include "support/test_support.hpp"

#include <cstdint>
#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

bool problem_is(const std::variant<secure_frontend::HttpsUrl, secure_frontend::UrlProblem>& result,
                const secure_frontend::UrlProblem expected) {
  const auto* problem = std::get_if<secure_frontend::UrlProblem>(&result);
  return problem != nullptr && *problem == expected;
}

void source_url_grammar_matrix() {
  using P = secure_frontend::UrlProblem;
  const auto ok = secure_frontend::parse_source_url(
      "https://huggingface.co/ISTA-DASLab/Qwen3.8-Flash-Next-GSQ-RCO-GGUF/resolve/ed59f92082b1e93c0e96d60a8b11aab089b52f09/"
      "IQ2_XS/Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS-00001-of-00002.gguf");
  expect(std::holds_alternative<secure_frontend::HttpsUrl>(ok), "Hugging Face resolve URL accepted");
  if (const auto* url = std::get_if<secure_frontend::HttpsUrl>(&ok)) {
    expect(url->host == "huggingface.co", "host split");
    expect(secure_frontend::render_url(*url).starts_with("https://huggingface.co/ISTA-DASLab/"), "round trip");
  }
  expect(std::holds_alternative<secure_frontend::HttpsUrl>(secure_frontend::parse_source_url("https://h.example:443/a%20b")),
         "explicit :443 and %XX accepted");
  expect(problem_is(secure_frontend::parse_source_url("http://huggingface.co/a"), P::not_https), "http rejected");
  expect(problem_is(secure_frontend::parse_source_url("HTTPS://huggingface.co/a"), P::not_https), "scheme is exact");
  expect(problem_is(secure_frontend::parse_source_url("https://huggingface.co:8443/a"), P::port_not_allowed), "port 8443");
  expect(problem_is(secure_frontend::parse_source_url("https://huggingface.co:/a"), P::port_not_allowed), "empty port");
  expect(problem_is(secure_frontend::parse_source_url("https://user@huggingface.co/a"), P::userinfo), "userinfo");
  expect(problem_is(secure_frontend::parse_source_url("https://huggingface.co/a?x=1"), P::query_not_allowed), "query");
  expect(problem_is(secure_frontend::parse_source_url("https://huggingface.co/a#f"), P::fragment), "fragment");
  for (const auto* bad : {"https://h.example/a[1]", "https://h.example/a{b}", "https://h.example/a b",
                          "https://h.example/a\"b", "https://h.example/a\\b", "https://h.example/%zz",
                          "https://h.example/a%2"}) {
    expect(problem_is(secure_frontend::parse_source_url(bad), P::bad_character), std::string{"bad character: "} + bad);
  }
  expect(problem_is(secure_frontend::parse_source_url("https://h.example"), P::missing_path), "no path");
  expect(problem_is(secure_frontend::parse_source_url("https://h.example/"), P::missing_path), "root path only");
  expect(problem_is(secure_frontend::parse_source_url("https://H.example/a"), P::bad_host), "manifest hosts are lowercase");
  expect(problem_is(secure_frontend::parse_source_url("https://127.0.0.1/a"), P::bad_host), "IPv4 literal");
  expect(problem_is(secure_frontend::parse_source_url("https://[::1]/a"), P::bad_host), "IPv6 literal");
  expect(problem_is(secure_frontend::parse_source_url("https://localhost/a"), P::bad_host), "single label");
  expect(problem_is(secure_frontend::parse_source_url("https://h.example/" + std::string(2100, 'a')), P::too_long),
         "longer than 2048 bytes");
}

void dns_names_and_wildcards() {
  expect(secure_frontend::is_valid_dns_name("huggingface.co"), "two labels");
  expect(secure_frontend::is_valid_dns_name("us.aws.cdn.hf.co"), "five labels");
  for (const auto* bad : {"", "co", "-a.co", "a-.co", "a..co", "a.co.", "A.co", "a_b.co", "1.2.3.4", "a.123"}) {
    expect(!secure_frontend::is_valid_dns_name(bad), std::string{"invalid dns name: "} + bad);
  }
  expect(secure_frontend::is_valid_redirect_pattern("*.aws.cdn.hf.co"), "wildcard over 4 labels");
  expect(secure_frontend::is_valid_redirect_pattern("cas-bridge.xethub.hf.co"), "plain host");
  expect(!secure_frontend::is_valid_redirect_pattern("*.co"), "wildcard base needs two labels");
  expect(!secure_frontend::is_valid_redirect_pattern("*"), "bare star");
  expect(!secure_frontend::is_valid_redirect_pattern("a.*.co"), "star only leftmost");
  expect(secure_frontend::host_matches("*.aws.cdn.hf.co", "us.aws.cdn.hf.co"), "one extra label matches");
  expect(!secure_frontend::host_matches("*.aws.cdn.hf.co", "aws.cdn.hf.co"), "zero extra labels do not match");
  expect(!secure_frontend::host_matches("*.aws.cdn.hf.co", "a.b.aws.cdn.hf.co"), "two extra labels do not match");
  expect(!secure_frontend::host_matches("*.aws.cdn.hf.co", "evilaws.cdn.hf.co"), "label boundary");
  expect(secure_frontend::host_matches("huggingface.co", "huggingface.co"), "exact");
  expect(!secure_frontend::host_matches("huggingface.co", "x.huggingface.co"), "exact means exact");
}

void proxy_grammar() {
  const auto http = secure_frontend::parse_proxy("http://proxy.corp:3128");
  expect(std::holds_alternative<secure_frontend::ProxySetting>(http), "http proxy with single-label-free name");
  const auto single = secure_frontend::parse_proxy("http://proxy:8080");
  expect(std::holds_alternative<secure_frontend::ProxySetting>(single), "single-label proxy name");
  expect(std::holds_alternative<secure_frontend::ProxySetting>(secure_frontend::parse_proxy("https://10.0.0.5:443")),
         "IPv4 literal proxy (may be private)");
  expect(std::holds_alternative<secure_frontend::ProxySetting>(secure_frontend::parse_proxy("http://[fd00::1]:3128")),
         "IPv6 literal proxy");
  if (const auto* p = std::get_if<secure_frontend::ProxySetting>(&http)) {
    expect(secure_frontend::render_proxy(*p) == "http://proxy.corp:3128", "render");
  }
  for (const auto* bad : {"proxy:3128", "socks5://p.example:1080", "http://u:p@p.example:3128", "http://p.example",
                          "http://p.example:0", "http://p.example:65536", "http://p.example:3128/path",
                          "http://p.example:03128"}) {
    expect(std::holds_alternative<secure_frontend::UrlProblem>(secure_frontend::parse_proxy(bad)),
           std::string{"proxy rejected: "} + bad);
  }
}

using secure_frontend::AcquireManifest;
using secure_frontend::AcquireReason;
using secure_frontend::FileRole;
using secure_frontend::ManifestProfile;

std::string hex64(const char c) { return std::string(64, c); }

secure_frontend::ManifestFile file(const std::string& path, const FileRole role) {
  return secure_frontend::ManifestFile{path, role, 10, hex64('a'), {"https://fixture.example/" + path}, std::nullopt};
}

AcquireManifest valid_qwen_manifest() {
  AcquireManifest m;
  m.name = "qwen3.8-flash-next";
  m.tag = "iq2_xs";
  m.version = "2026.10.14.1";
  m.sequence = 1;
  m.profile = ManifestProfile::qwen;
  m.family = secure_frontend::EngineFamily::strata;
  m.min_version = *secure_frontend::parse_engine_version("0.1.43");
  m.license = {"Apache-2.0", "https://fixture.example/license", true, "Notice."};
  m.hosts = {"fixture.example"};
  m.redirect_hosts = {"*.cdn.fixture.example"};
  m.files = {file("weights/m-00001-of-00002.gguf", FileRole::weights), file("weights/m-00002-of-00002.gguf", FileRole::weights),
             file("pack/index.txt", FileRole::pack), file("pack/dense.bin", FileRole::pack),
             file("pack/native_experts.txt", FileRole::pack), file("pack/conversions.json", FileRole::pack),
             file("pack/tokenizer/vocab.json", FileRole::tokenizer), file("pack/tokenizer/merges.txt", FileRole::tokenizer),
             file("pack/tokenizer/token_type.json", FileRole::tokenizer),
             file("pack/tokenizer/tokenizer.json", FileRole::tokenizer)};
  m.launch = {"weights/m-00001-of-00002.gguf", "weights/m-00002-of-00002.gguf", "pack", "pack/tokenizer"};
  return m;
}

secure_frontend::ManifestRules rules() { return secure_frontend::ManifestRules{}; }

void expect_issue(const AcquireManifest& m, const std::string& key, const std::string& why,
                  const AcquireReason reason = AcquireReason::manifest_invalid) {
  const auto issue = secure_frontend::validate_manifest(m, rules());
  expect(issue.has_value() && issue->reason == reason && issue->key_path == key,
         why + " (got " + (issue ? issue->key_path : std::string{"no issue"}) + ")");
}

void valid_qwen_manifest_accepted() {
  const auto issue = secure_frontend::validate_manifest(valid_qwen_manifest(), rules());
  expect(!issue.has_value(), "a complete qwen manifest is valid: " + (issue ? issue->key_path : std::string{}));
}

void manifest_field_rules_matrix() {
  struct Mutation final {
    std::string key;
    std::string why;
    std::function<void(AcquireManifest&)> change;
  };
  const std::vector<Mutation> mutations{
      {"name", "uppercase name", [](auto& m) { m.name = "Qwen"; }},
      {"name", "name starting with '.'", [](auto& m) { m.name = ".hidden"; }},
      {"name", "device name", [](auto& m) { m.name = "con"; }},
      {"name", "device name with extension", [](auto& m) { m.name = "aux.json"; }},
      {"name", "trailing dot", [](auto& m) { m.name = "model."; }},
      {"name", "129 characters", [](auto& m) { m.name = std::string(129, 'a'); }},
      {"tag", "tag default reserved", [](auto& m) { m.tag = "default"; }},
      {"tag", "colon in tag", [](auto& m) { m.tag = "a:b"; }},
      {"version", "bad version label", [](auto& m) { m.version = "2026.13.01.1"; }},
      {"version", "N above 999", [](auto& m) { m.version = "2026.10.14.1000"; }},
      {"sequence", "sequence 0", [](auto& m) { m.sequence = 0; }},
      {"sequence", "sequence above 2^31-1", [](auto& m) { m.sequence = 0x80000000U; }},
      {"engine.family", "family must follow profile", [](auto& m) { m.family = secure_frontend::EngineFamily::glm; }},
      {"license.id", "license id grammar", [](auto& m) { m.license.id = "Apache 2.0"; }},
      {"license.url", "license url https", [](auto& m) { m.license.url = "http://x.example/l"; }},
      {"license.notice", "notice over 512", [](auto& m) { m.license.notice = std::string(513, 'n'); }},
      {"license.notice", "control byte in notice", [](auto& m) { m.license.notice = "a\x1b[31mb"; }},
      {"hosts", "no hosts", [](auto& m) { m.hosts.clear(); }},
      {"hosts[0]", "IP literal host", [](auto& m) { m.hosts = {"1.2.3.4"}; }},
      {"hosts", "17 hosts", [](auto& m) { m.hosts.assign(17, "a.example"); }},
      {"redirect_hosts[0]", "single-label wildcard base", [](auto& m) { m.redirect_hosts = {"*.co"}; }},
      {"files", "no files", [](auto& m) { m.files.clear(); }},
      {"files[0].path", "dot-dot", [](auto& m) { m.files[0].path = "weights/../x"; }},
      {"files[0].path", "absolute", [](auto& m) { m.files[0].path = "/etc/passwd"; }},
      {"files[0].path", "backslash", [](auto& m) { m.files[0].path = "weights\\x"; }},
      {"files[0].path", "hidden component", [](auto& m) { m.files[0].path = "weights/.x"; }},
      {"files[0].path", "control byte", [](auto& m) { m.files[0].path = "weights/a\nb"; }},
      {"files[1].path", "case-fold collision", [](auto& m) { m.files[1].path = "WEIGHTS/M-00001-OF-00002.GGUF"; }},
      {"files[0].size", "size 0", [](auto& m) { m.files[0].size = 0; }},
      {"files[0].size", "size above 2^40", [](auto& m) { m.files[0].size = (std::uint64_t{1} << 40U) + 1U; }},
      {"files[0].sha256", "uppercase hex", [](auto& m) { m.files[0].sha256 = std::string(64, 'A'); }},
      {"files[0].sha256", "short hex", [](auto& m) { m.files[0].sha256 = std::string(63, 'a'); }},
      {"files[0].sources[0]", "http source", [](auto& m) { m.files[0].sources = {"http://fixture.example/a"}; }},
      {"files[0].sources[0]", "[ in source URL", [](auto& m) { m.files[0].sources = {"https://fixture.example/a[1]"}; }},
      {"files[0].sources[0]", "source host not in hosts", [](auto& m) { m.files[0].sources = {"https://other.example/a"}; }},
      {"files[0].sources", "9 sources", [](auto& m) { m.files[0].sources.assign(9, "https://fixture.example/a"); }},
      {"files[0].license.url", "file license validated",
       [](auto& m) { m.files[0].license = secure_frontend::ManifestLicense{"MIT", "ftp://x", true, ""}; }},
      {"files", "incomplete shard set", [](auto& m) { m.files.erase(m.files.begin() + 1); m.launch.ple_gguf.reset(); }},
      {"launch.native", "launch names an unlisted file", [](auto& m) { m.launch.native = "weights/other.gguf"; }},
      {"launch.native", "native must be shard 00001", [](auto& m) { m.launch.native = "weights/m-00002-of-00002.gguf"; }},
      {"launch.pack", "pack must be a directory prefix", [](auto& m) { m.launch.pack = "pack/index.txt"; }},
      {"launch.tokenizer_pack", "tokenizer_pack must be <pack>/tokenizer", [](auto& m) { m.launch.tokenizer_pack = "pack"; }},
      {"launch.pack", "qwen requires pack", [](auto& m) { m.launch.pack.reset(); }},
  };
  for (const auto& mutation : mutations) {
    auto m = valid_qwen_manifest();
    mutation.change(m);
    expect_issue(m, mutation.key, mutation.why);
  }
}

void reserved_manifest_names_rejected() {
  for (const auto* reserved : {"manifest.json", "MANIFEST", "Strata-Bundle", "SHA256SUMS", "missing", "manifest.json/x"}) {
    auto m = valid_qwen_manifest();
    m.files.push_back(file(reserved, FileRole::pack));
    expect_issue(m, "files[10].path", std::string{"reserved top-level name: "} + reserved);
  }
  auto nested = valid_qwen_manifest();
  nested.files.push_back(file("pack/MISSING", FileRole::pack));
  expect(!secure_frontend::validate_manifest(nested, rules()).has_value(), "reserved names only at the top level");
}

void model_name_index_json_rejected() {
  auto m = valid_qwen_manifest();
  m.name = "index.json";
  expect_issue(m, "name", "index.json is a file in roots.models");
  expect(!secure_frontend::parse_model_reference("INDEX.JSON:x").has_value(), "references are case-folded first");
}

void part_suffix_path_rejected() {
  for (const auto* path : {"pack/dense.bin.part", "pack/X.PART", "pack.part/index.txt"}) {
    auto m = valid_qwen_manifest();
    m.files.push_back(file(path, FileRole::pack));
    expect_issue(m, "files[10].path", std::string{".part is the in-progress suffix: "} + path);
  }
}

void file_and_directory_prefix_collision_rejected() {
  auto file_is_dir = valid_qwen_manifest();
  file_is_dir.files.push_back(file("pack/tokenizer", FileRole::pack));
  expect_issue(file_is_dir, "files[10].path", "a file path that is another file's directory");
  auto folded = valid_qwen_manifest();
  folded.files.push_back(file("Pack/Extra.bin", FileRole::pack));
  folded.files.push_back(file("PACK", FileRole::pack));
  expect_issue(folded, "files[11].path", "case-folded file/directory collision");
}

void shard_set_must_be_complete_in_one_directory() {
  auto split = valid_qwen_manifest();
  split.files[1].path = "other/m-00002-of-00002.gguf";
  split.launch.ple_gguf = "other/m-00002-of-00002.gguf";
  expect_issue(split, "files", "shards must share one directory");
  auto three = valid_qwen_manifest();
  three.files[1].path = "weights/m-00003-of-00002.gguf";
  three.launch.ple_gguf = "weights/m-00003-of-00002.gguf";
  expect_issue(three, "files", "shard number above the count");
}

void launch_keys_follow_profile() {
  auto glm = valid_qwen_manifest();
  glm.profile = ManifestProfile::glm53;
  glm.family = secure_frontend::EngineFamily::glm;
  expect_issue(glm, "launch.ple_gguf", "glm53 has only launch.native in schema 1");
  glm.launch.pack.reset();
  glm.launch.tokenizer_pack.reset();
  glm.launch.ple_gguf.reset();
  expect(!secure_frontend::validate_manifest(glm, rules()).has_value(), "glm53 with native only is valid");
}

void wildcard_redirect_hosts_validated() {
  auto m = valid_qwen_manifest();
  m.redirect_hosts = {"*.aws.cdn.hf.co", "cas-bridge.xethub.hf.co"};
  expect(!secure_frontend::validate_manifest(m, rules()).has_value(), "valid redirect hosts");
  m.redirect_hosts.assign(17, "a.example");
  expect_issue(m, "redirect_hosts", "17 redirect hosts");
}

void total_size_above_budget_is_total_budget_exceeded() {
  auto m = valid_qwen_manifest();
  secure_frontend::ManifestRules small;
  small.max_total_bytes = 50;
  const auto issue = secure_frontend::validate_manifest(m, small);
  expect(issue && issue->reason == AcquireReason::total_budget_exceeded && issue->key_path == "files",
         "total of 100 bytes exceeds a 50-byte budget");
}

AcquireManifest raw_manifest() {
  AcquireManifest m = valid_qwen_manifest();
  m.profile = ManifestProfile::raw;
  m.family = secure_frontend::EngineFamily::none;
  m.min_version = *secure_frontend::parse_engine_version("0.0.0");
  m.files = {file("vocab.gguf", FileRole::weights)};
  m.launch = {};
  return m;
}

void raw_profile_rejected_in_release_build() {
  expect(!secure_frontend::kTestHooksEnabled, "this case runs only in the hooks-OFF configuration");
  expect_issue(raw_manifest(), "profile", "raw is rejected as manifest_invalid in release builds");
}

#if defined(SECURE_FRONTEND_TEST_HOOKS)
void raw_profile_accepted_with_test_hooks() {
  expect(!secure_frontend::validate_manifest(raw_manifest(), rules()).has_value(), "raw accepted in hooks builds");
  auto launched = raw_manifest();
  launched.launch.native = "vocab.gguf";
  expect_issue(launched, "launch.native", "raw has no launch keys");
}
#endif

void engine_version_parsed_with_fourth_component() {
  const auto four = secure_frontend::parse_engine_version("0.1.44.1");
  const auto three = secure_frontend::parse_engine_version("0.1.44");
  expect(four.has_value() && four->count == 4 && four->parts[3] == 1, "four components");
  expect(three && four && secure_frontend::compare_versions(*four, *three) > 0, "0.1.44.1 > 0.1.44");
  expect(three && secure_frontend::compare_versions(*three, *secure_frontend::parse_engine_version("0.1.44.0")) == 0,
         "a missing fourth part is 0");
  expect(four && secure_frontend::render_engine_version(*four) == "0.1.44.1", "render");
  for (const auto* bad : {"0.1", "0.1.44.1.2", "v0.1.44", "0.01.44", "0.1.10000", "0.1.-1", "0.1.44 "}) {
    expect(!secure_frontend::parse_engine_version(bad).has_value(), std::string{"rejected: "} + bad);
  }
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"source_url_grammar_matrix", source_url_grammar_matrix},
      {"dns_names_and_wildcards", dns_names_and_wildcards},
      {"proxy_grammar", proxy_grammar},
      {"valid_qwen_manifest_accepted", valid_qwen_manifest_accepted},
      {"manifest_field_rules_matrix", manifest_field_rules_matrix},
      {"reserved_manifest_names_rejected", reserved_manifest_names_rejected},
      {"model_name_index_json_rejected", model_name_index_json_rejected},
      {"part_suffix_path_rejected", part_suffix_path_rejected},
      {"file_and_directory_prefix_collision_rejected", file_and_directory_prefix_collision_rejected},
      {"shard_set_must_be_complete_in_one_directory", shard_set_must_be_complete_in_one_directory},
      {"launch_keys_follow_profile", launch_keys_follow_profile},
      {"wildcard_redirect_hosts_validated", wildcard_redirect_hosts_validated},
      {"total_size_above_budget_is_total_budget_exceeded", total_size_above_budget_is_total_budget_exceeded},
      {"raw_profile_rejected_in_release_build", raw_profile_rejected_in_release_build},
#if defined(SECURE_FRONTEND_TEST_HOOKS)
      {"raw_profile_accepted_with_test_hooks", raw_profile_accepted_with_test_hooks},
#endif
      {"engine_version_parsed_with_fourth_component", engine_version_parsed_with_fourth_component},
  }, failures);
}

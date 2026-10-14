#include "secure_frontend/acquire_manifest.hpp"
#include "secure_frontend/acquire_reason.hpp"
#include "secure_frontend/model_index_model.hpp"
#include "secure_frontend/staging_plan.hpp"
#include "support/test_support.hpp"

#include <cstddef>
#include <iostream>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

using secure_frontend::AcquireReason;
using secure_frontend::ExitCode;
using secure_frontend::SameSource;

// A copy of spec §8.2, kept independent of the implementation's table.
struct Expected final {
  AcquireReason reason;
  const char* name;
  ExitCode exit;
  SameSource same;
  bool resumable;
};

const std::vector<Expected>& spec_table() {
  using R = AcquireReason;
  using E = ExitCode;
  using S = SameSource;
  static const std::vector<Expected> table{
      {R::manifest_invalid, "manifest_invalid", E::manifest, S::not_applicable, false},
      {R::manifest_unsupported_version, "manifest_unsupported_version", E::manifest, S::not_applicable, false},
      {R::manifest_untrusted, "manifest_untrusted", E::manifest, S::not_applicable, false},
      {R::manifest_shadows_catalog, "manifest_shadows_catalog", E::manifest, S::not_applicable, false},
      {R::manifest_downgrade, "manifest_downgrade", E::manifest, S::not_applicable, false},
      {R::manifest_conflict, "manifest_conflict", E::manifest, S::not_applicable, false},
      {R::manifest_requires_bundle, "manifest_requires_bundle", E::manifest, S::not_applicable, false},
      {R::model_unknown, "model_unknown", E::manifest, S::not_applicable, false},
      {R::dns_failed, "dns_failed", E::transport, S::retried, true},
      {R::connect_failed, "connect_failed", E::transport, S::retried, true},
      {R::tls_failed, "tls_failed", E::transport, S::retried, true},
      {R::stalled, "stalled", E::transport, S::retried, true},
      {R::size_short, "size_short", E::transport, S::retried, true},
      {R::transport_failed, "transport_failed", E::transport, S::next_source, true},
      {R::range_mismatch, "range_mismatch", E::transport, S::restart_file, true},
      {R::size_mismatch_announced, "size_mismatch_announced", E::transport, S::restart_file, true},
      {R::host_not_allowed, "host_not_allowed", E::transport, S::next_source, true},
      {R::redirect_not_allowed, "redirect_not_allowed", E::transport, S::next_source, true},
      {R::redirect_limit, "redirect_limit", E::transport, S::next_source, true},
      {R::response_malformed, "response_malformed", E::transport, S::next_source, true},
      {R::address_not_allowed, "address_not_allowed", E::transport, S::next_source, true},
      {R::tls_untrusted, "tls_untrusted", E::transport, S::next_source, true},
      {R::http_status, "http_status", E::transport, S::next_source, true},
      {R::size_exceeded, "size_exceeded", E::verification, S::next_source_file_deleted, false},
      {R::digest_mismatch, "digest_mismatch", E::verification, S::next_source_file_deleted, false},
      {R::pack_layout_invalid, "pack_layout_invalid", E::verification, S::not_applicable, false},
      {R::bundle_invalid, "bundle_invalid", E::verification, S::not_applicable, false},
      {R::bundle_layout, "bundle_layout", E::filesystem, S::not_applicable, false},
      {R::bundle_incomplete, "bundle_incomplete", E::filesystem, S::not_applicable, false},
      {R::bundle_target_fat32, "bundle_target_fat32", E::filesystem, S::not_applicable, false},
      {R::bundle_target_not_empty, "bundle_target_not_empty", E::filesystem, S::not_applicable, false},
      {R::time_budget_exceeded, "time_budget_exceeded", E::transport, S::not_applicable, true},
      {R::total_budget_exceeded, "total_budget_exceeded", E::space, S::not_applicable, false},
      {R::disk_space, "disk_space", E::space, S::not_applicable, true},
      {R::models_busy, "models_busy", E::filesystem, S::not_applicable, true},
      {R::publish_failed, "publish_failed", E::filesystem, S::not_applicable, true},
      {R::index_write_failed, "index_write_failed", E::filesystem, S::not_applicable, true},
      {R::index_inconsistent, "index_inconsistent", E::filesystem, S::not_applicable, false},
      {R::license_forbids_bundle, "license_forbids_bundle", E::license, S::not_applicable, false},
      {R::downloader_missing, "downloader_missing", E::downloader, S::not_applicable, true},
      {R::downloader_version, "downloader_version", E::downloader, S::not_applicable, true},
      {R::downloader_untrusted_path, "downloader_untrusted_path", E::downloader, S::not_applicable, true},
      {R::downloader_unsupported, "downloader_unsupported", E::downloader, S::not_applicable, true},
      {R::downloader_confinement_failed, "downloader_confinement_failed", E::downloader, S::not_applicable, true},
      {R::declined, "declined", E::declined, S::not_applicable, false},
      {R::interrupted, "interrupted", E::interrupted, S::not_applicable, true},
      {R::engine_profile_unavailable, "engine_profile_unavailable", E::engine, S::not_applicable, false},
      {R::engine_too_old, "engine_too_old", E::engine, S::not_applicable, false},
      {R::usage_error, "usage_error", E::usage, S::not_applicable, false},
      {R::program_update_unavailable, "program_update_unavailable", E::program_update, S::not_applicable, false},
  };
  return table;
}

void exit_classes_match_spec_table() {
  for (const auto& row : spec_table()) {
    const auto& info = secure_frontend::reason_info(row.reason);
    expect(info.name == row.name, std::string{"name of "} + row.name);
    expect(info.exit == row.exit, std::string{"exit class of "} + row.name);
    expect(info.same_source == row.same, std::string{"same-source rule of "} + row.name);
    expect(info.resumable == row.resumable, std::string{"resumable flag of "} + row.name);
    expect(secure_frontend::exit_class(row.reason) == row.exit, std::string{"exit_class of "} + row.name);
  }
  expect(secure_frontend::reason_table().size() == spec_table().size(), "every reason is in the spec table");
}

void reason_table_is_complete_and_ordered() {
  std::set<std::string_view> names;
  const auto table = secure_frontend::reason_table();
  for (std::size_t i = 0; i < table.size(); ++i) {
    expect(static_cast<std::size_t>(table[i].reason) == i, "row " + std::to_string(i) + " is in enum order");
    expect(names.insert(table[i].name).second, "unique name " + std::string{table[i].name});
    for (const char c : table[i].name) expect((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_', "snake_case");
  }
  expect(secure_frontend::exit_code_value(ExitCode::program_update) == 12, "exit code values are the enum values");
}

void error_text_states_resumable() {
  expect(secure_frontend::format_error({AcquireReason::digest_mismatch, "weights/a.gguf"}) ==
             "error: digest_mismatch: weights/a.gguf (resumable: no)",
         "detail and resumable: no");
  expect(secure_frontend::format_error({AcquireReason::interrupted, ""}) == "error: interrupted (resumable: yes)",
         "no detail");
}

void version_dir_name_unique_for_same_version_label() {
  const std::string first(64, 'a');
  std::string second = first;
  second[11] = 'b';
  expect(secure_frontend::version_directory_name(3, first) == "v3-aaaaaaaaaaaa", "v<sequence>-<12 hex>");
  expect(secure_frontend::version_directory_name(3, first) != secure_frontend::version_directory_name(3, second),
         "two manifests with the same version label never share a directory");
  expect(secure_frontend::staging_key(first) == std::string(32, 'a'), "staging key is 32 hex");
}

secure_frontend::AcquireManifest staging_manifest() {
  secure_frontend::AcquireManifest m;
  m.files = {secure_frontend::ManifestFile{"weights/a.gguf", secure_frontend::FileRole::weights, 100, std::string(64, 'a'), {}, {}},
             secure_frontend::ManifestFile{"pack/index.txt", secure_frontend::FileRole::pack, 10, std::string(64, 'b'), {}, {}},
             secure_frontend::ManifestFile{"pack/dense.bin", secure_frontend::FileRole::pack, 10, std::string(64, 'c'), {}, {}},
             secure_frontend::ManifestFile{"pack/extra.bin", secure_frontend::FileRole::pack, 10, std::string(64, 'd'), {}, {}}};
  return m;
}

void staging_plan_classifies_partials() {
  using secure_frontend::FileStep;
  const std::vector<secure_frontend::StagedEntry> staged{
      {"MANIFEST", 900, true},          {"weights/a.gguf.part", 40, true}, {"pack/index.txt.part", 10, true},
      {"pack/dense.bin.part", 11, true}, {"pack/extra.bin", 10, true},     {"pack/extra.bin.part", 3, true},
      {"stray.bin", 5, true},            {"weights/link", 0, false}};
  const auto plan = secure_frontend::plan_staging(staging_manifest(), staged);
  expect(plan.files.size() == 4, "one plan per manifest file");
  expect(plan.files[0].step == FileStep::rehash_then_resume && plan.files[0].existing_bytes == 40, "short .part resumes at L");
  expect(plan.files[1].step == FileStep::rehash_complete_part && plan.files[1].existing_bytes == 10, "full .part is hashed");
  expect(plan.files[2].step == FileStep::fetch_from_zero && plan.files[2].existing_bytes == 0, "oversize .part is deleted");
  expect(plan.files[3].step == FileStep::rehash_verified_candidate, "a suffix-less file is re-hashed before it is trusted");
  const std::vector<std::string> remove{"pack/dense.bin.part", "pack/extra.bin.part", "stray.bin", "weights/link"};
  expect(plan.remove == remove, "oversize part, shadowed part, strays and non-regular entries are removed");
  expect(plan.staged_bytes == 60, "40 + 10 + 10 staged bytes count toward the preflight");
}

void abandoned_keys_match_same_model_only() {
  const std::vector<secure_frontend::StagingKeyInfo> keys{
      {std::string(32, 'a'), "m", "t", 100}, {std::string(32, 'b'), "m", "t", 200}, {std::string(32, 'c'), "m", "u", 300}};
  const auto abandoned = secure_frontend::abandoned_keys(keys, std::string(32, 'a'), "m", "t");
  expect(abandoned.size() == 1 && abandoned.front().key == std::string(32, 'b'), "other manifests of the same name:tag only");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"exit_classes_match_spec_table", exit_classes_match_spec_table},
      {"reason_table_is_complete_and_ordered", reason_table_is_complete_and_ordered},
      {"error_text_states_resumable", error_text_states_resumable},
      {"version_dir_name_unique_for_same_version_label", version_dir_name_unique_for_same_version_label},
      {"staging_plan_classifies_partials", staging_plan_classifies_partials},
      {"abandoned_keys_match_same_model_only", abandoned_keys_match_same_model_only},
  }, failures);
}

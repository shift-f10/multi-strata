// parity_table_test.cpp — SP5 M1 Task 2 meta-tests (Review Focus 1).
//
// Every option name the pinned upstream reads must have exactly one
// dispositioned row; a name in no bucket — or in two — is a defect. Typed rows
// must name where the value lands; rejected rows must cite the excluding rule;
// mapped-away rows must cite a governing read site.

#include "parity_keys_upstream.hpp"
#include "parity_keys_maya.hpp"
#include "secure_frontend/parity_table.hpp"
#include "support/test_support.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

using secure_frontend::parity::ParityDisposition;
using secure_frontend::parity::ParityRow;
using secure_frontend::parity::maya_config_keys;
using secure_frontend::parity::maya_env_knobs;
using secure_frontend::parity::maya_parity_row;
using secure_frontend::parity::maya_parity_rows;
using secure_frontend::parity::strata_parity_row;
using secure_frontend::parity::strata_parity_rows;
using secure_frontend::parity::upstream_config_keys;
using secure_frontend::parity::upstream_env_knobs;

int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::printf("FAILED: %s\n", message.c_str()); }
}

std::size_t row_count_named(std::string_view name) {
  std::size_t hits = 0;
  for (const auto& row : strata_parity_rows()) {
    if (row.key == name) ++hits;
  }
  return hits;
}

std::size_t maya_row_count_named(std::string_view name) {
  std::size_t hits = 0;
  for (const auto& row : maya_parity_rows()) {
    if (row.key == name) ++hits;
  }
  return hits;
}

void every_upstream_key_has_exactly_one_disposition() {
  const auto keys = upstream_config_keys();
  expect(keys.size() == 87U, "the generated config-key inventory holds the pin's 87 keys");
  for (const auto key : keys) {
    expect(row_count_named(key) == 1U,
           std::string("config key '") + std::string(key) + "' must have exactly one parity row");
    const auto* row = strata_parity_row(key);
    expect(row != nullptr, std::string("strata_parity_row('") + std::string(key) + "') must resolve");
  }
}

void every_env_knob_is_dispositioned() {
  const auto knobs = upstream_env_knobs();
  expect(knobs.size() == 31U, "the generated env-knob inventory holds the pin's 31 names");
  for (const auto knob : knobs) {
    expect(row_count_named(knob) == 1U,
           std::string("env knob '") + std::string(knob) + "' must have exactly one parity row");
    const auto* row = strata_parity_row(knob);
    expect(row != nullptr, std::string("strata_parity_row('") + std::string(knob) + "') must resolve");
  }
}

void typed_rows_name_a_destination() {
  for (const auto& row : strata_parity_rows()) {
    switch (row.disposition) {
      case ParityDisposition::typed:
        expect(row.destination != secure_frontend::parity::ParityDestination::none,
               std::string("typed row '") + std::string(row.key) + "' must name a destination");
        expect(!row.citation.empty(),
               std::string("typed row '") + std::string(row.key) + "' must cite the pinned read site");
        break;
      case ParityDisposition::rejected:
      case ParityDisposition::mapped_away:
        expect(!row.citation.empty(),
               std::string("dispositioned row '") + std::string(row.key) + "' must carry a citation");
        break;
    }
    if (row.disposition == ParityDisposition::rejected) {
      // D-3: every reject is an exclusion of the spec's own rule set — the
      // citation must name the rule so the reject rows are auditable.
      expect(row.citation.find("spec ") == 0U,
             std::string("rejected row '") + std::string(row.key) + "' must cite the excluding rule");
    }
  }
  // A row for a name no inventory grep sees is allowed only as an extra rule
  // row (e.g. mcpServers, vram_reserve_mib); nothing may duplicate a name.
  for (const auto& row : strata_parity_rows()) {
    expect(row_count_named(row.key) == 1U,
           std::string("row name '") + std::string(row.key) + "' must be unique in the table");
  }
}

void every_maya_key_has_exactly_one_disposition() {
  const auto keys = maya_config_keys();
  expect(keys.size() == 37U, "the generated Maya config-key inventory holds the vendored pin's 37 keys");
  for (const auto key : keys) {
    expect(maya_row_count_named(key) == 1U,
           std::string("Maya config key '") + std::string(key) + "' must have exactly one parity row");
    const auto* row = maya_parity_row(key);
    expect(row != nullptr, std::string("maya_parity_row('") + std::string(key) + "') must resolve");
    if (row == nullptr) continue;
    expect(!row->citation.empty(),
           std::string("Maya row '") + std::string(key) + "' must cite the vendored read site");
    if (row->disposition == ParityDisposition::typed) {
      expect(row->destination != secure_frontend::parity::ParityDestination::none,
             std::string("typed Maya row '") + std::string(key) + "' must name a destination");
    }
    if (row->disposition == ParityDisposition::rejected) {
      expect(row->citation.find("spec ") == 0U,
             std::string("rejected Maya row '") + std::string(key) + "' must cite the excluding rule");
    }
  }
}

void every_maya_env_knob_is_dispositioned() {
  const auto knobs = maya_env_knobs();
  expect(knobs.size() == 119U, "the generated Maya env-knob inventory holds the pin's 119 names");
  for (const auto knob : knobs) {
    expect(maya_row_count_named(knob) == 1U,
           std::string("Maya env knob '") + std::string(knob) + "' must have exactly one parity row");
    const auto* row = maya_parity_row(knob);
    expect(row != nullptr, std::string("maya_parity_row('") + std::string(knob) + "') must resolve");
    if (row == nullptr) continue;
    expect(!row->citation.empty(),
           std::string("Maya row '") + std::string(knob) + "' must cite the vendored read site");
    if (row->disposition == ParityDisposition::typed) {
      expect(row->destination != secure_frontend::parity::ParityDestination::none,
             std::string("typed Maya row '") + std::string(knob) + "' must name a destination");
    }
    if (row->disposition == ParityDisposition::rejected) {
      expect(row->citation.find("spec ") == 0U,
             std::string("rejected Maya row '") + std::string(knob) + "' must cite the excluding rule");
    }
  }
  // Nothing may name a row twice in the GLM table (extra rule rows included).
  for (const auto& row : maya_parity_rows()) {
    expect(maya_row_count_named(row.key) == 1U,
           std::string("GLM row name '") + std::string(row.key) + "' must be unique in the table");
  }
}

void dflash_is_rejected_on_licence() {
  // C-5: the DFlash2 drafter and its knobs stay rejected on the A7 licence
  // ground (CC BY-NC-ND weights) even under D-7 — not a knob-visibility call.
  for (const std::string_view name :
       {std::string_view("STRATA_GLM_DFLASH"), std::string_view("STRATA_GLM_DFLASH_MIN"),
        std::string_view("STRATA_GLM_DFLASH_STATS"), std::string_view("STRATA_GLM_DFLASH_PROF"),
        std::string_view("--dflash")}) {
    const auto* row = maya_parity_row(name);
    expect(row != nullptr, std::string("maya_parity_row('") + std::string(name) + "') must resolve");
    if (row == nullptr) continue;
    expect(row->disposition == ParityDisposition::rejected,
           std::string("'") + std::string(name) + "' is rejected on the licence ground (C-5)");
    expect(row->citation.find("C-5") != std::string_view::npos &&
               row->citation.find("licence") != std::string_view::npos,
           std::string("'") + std::string(name) + "' must cite the C-5/A7 licence exclusion");
  }
}

void updater_and_installer_rows_are_rejected() {
  // PRIV-01: no update checks, no self-updater (spec §4 Maya block).
  for (const std::string_view name :
       {std::string_view("MAYA_UPDATE_CHECK"), std::string_view("MAYA_RESTART_ON_UPDATE"),
        std::string_view("installer")}) {
    const auto* row = maya_parity_row(name);
    expect(row != nullptr, std::string("maya_parity_row('") + std::string(name) + "') must resolve");
    if (row == nullptr) continue;
    expect(row->disposition == ParityDisposition::rejected,
           std::string("'") + std::string(name) + "' must be rejected (PRIV-01)");
    expect(row->citation.find("PRIV-01") != std::string_view::npos,
           std::string("'") + std::string(name) + "' must cite PRIV-01");
  }
}

} // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"every_upstream_key_has_exactly_one_disposition", every_upstream_key_has_exactly_one_disposition},
      {"every_env_knob_is_dispositioned", every_env_knob_is_dispositioned},
      {"typed_rows_name_a_destination", typed_rows_name_a_destination},
      {"every_maya_key_has_exactly_one_disposition", every_maya_key_has_exactly_one_disposition},
      {"every_maya_env_knob_is_dispositioned", every_maya_env_knob_is_dispositioned},
      {"dflash_is_rejected_on_licence", dflash_is_rejected_on_licence},
      {"updater_and_installer_rows_are_rejected", updater_and_installer_rows_are_rejected},
  }, failures);
}

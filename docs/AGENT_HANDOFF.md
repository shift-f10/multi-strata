# Secure Strata agent handoff

> **Agents: read `docs/superpowers/handoff/2026-10-16-controller-resume.md` first.**
> It holds the orchestration-level state at the owner's stop (2026-10-15), the
> owner's binding rules, the sub-controller briefs and lane reports, what waits
> on the owner, and the exact resume procedure. The project is stopped until the
> owner says otherwise. This document is the code-level truth it points at.

## Purpose

This repository is a Windows-and-Linux, security- and privacy-first successor
to Strata. It must retain the model/backend flexibility of upstream Strata
`v0.2.1.3` while replacing its public service boundary with a small portable
native frontend. UnbiasedStrata is a security-design reference, not a direct
code base.

Read this document, [`PROVENANCE.md`](PROVENANCE.md), and
[`security/threat-model.md`](security/threat-model.md) before modifying the
service, installer, download, telemetry, or process-supervision code.
Also read [`security/privacy-migration.md`](security/privacy-migration.md)
before packaging or replacing any baseline installer/service behavior.

Sub-project 0 (foundation and hardening of `secure_frontend`) is specified in
[`superpowers/specs/2026-10-13-sp0-foundation-hardening-design.md`](superpowers/specs/2026-10-13-sp0-foundation-hardening-design.md)
(§4 lists every T/S/E/P/M/D item) and planned task by task in
[`superpowers/plans/2026-10-13-sp0-foundation-hardening.md`](superpowers/plans/2026-10-13-sp0-foundation-hardening.md).

### Owner decisions and constraints (rflores, 2026-10-13)

These are decisions, not facts derivable from the code. Do not reverse them
without asking the owner.

1. **Scope is the full release path**, split into sub-projects SP0–SP7:
   - SP0 — foundation and hardening of `secure_frontend`. **Done on branch
     `sp0-foundation-hardening`** (not yet pushed or merged).
   - SP1 — typed configuration, canonical paths, CSPRNG tokens. **Done;
     merged into `main` at `e7f01b9e`.** CI run `38540719307` ran
     `windows-msys2-clang` 193/193 on SP1, so its `windows-runtime` cases are
     verified there (exceptions in the SP1 rows below).
   - SP2 — child supervision (`PROC-*` tests). **Done on branch
     `sp2-portable-supervision` for Linux (all L and B rows green locally);
     Windows (W) rows pending the `windows-msys2-clang` job** (not pushed; no
     CI run covers SP2).
   - SP3 — API concurrency, streaming, and `NET-*`/`WEB-*`/`DOS-*`/`EXT-*` tests.
   - SP4 — the explicit `acquire` command. **Tasks 1–24b merged into `main`
     at `4b9fdd31`**; their `windows-runtime` rows passed in
     `windows-msys2-clang` (CI run `38625663621` on `557a2cc7`, 488/488).
     **Tasks 25–29 done on branch `sp4-acquire-part2`** (`06630dbd` …
     Task 29; not pushed); their new `windows-runtime` cases passed on real
     Windows in CI run `38655938748` (`9044a5bc`, 515/516); the one failure,
     PRIV-04's link-set reader (CRLF), is fixed and its re-run is pending.
   - SP5 — frontend parity with the upstream service.
   - SP6 — GLM engine port, in its own directory, tracking
     `lighttransport/Strata` branch `glm53f` and, since 2026-10-14,
     `mw00/project-maya` (see `docs/PROVENANCE.md`).
   - SP7 — release, plus an offline GPU validation kit.
2. **Windows toolchain is open source**: llvm-mingw (cross from Linux) and
   MSYS2 clang (native). MSVC is an informational CI job only. Caveat: CUDA
   engine builds on Windows still need MSVC as the nvcc host compiler.
3. **No GPU and no `nvcc` on the dev host.** GPU work (SP5, SP6) waits for an
   NVIDIA host the owner is building. Offline test boxes exist for both Linux
   and Windows.
4. **Product north star: "as easy as Ollama".** One `strata` binary with
   `pull`, `run`, `serve`, `list` and `key show`; a zero-config loopback first
   run with an auto-generated token that the client uses automatically (the
   token-on-loopback rule is **kept**); one install per OS; explicit
   `strata update` through a verified manifest; never auto-update. A
   product-experience spec is written between SP0 and SP1.
5. **Launch, install and configuration must be user-friendly and secure.** This
   lands in SP1 and SP7.
6. **Upstream-trackability.** Upstream Strata is the git submodule `upstream/`
   (`https://github.com/Niko1221/Strata.git`), pinned by its gitlink at
   `cbfd5b926b794b356195d3cb600191b0c3567540` (tag `v0.2.1.3`) and never
   edited, inside or outside the submodule. The repository root holds only our
   code; our additions to upstream behavior are wrappers that import upstream
   (`tools/secure/secure_tokenizer.py`). The upstream Python service stays in
   the submodule, untouched, and is quarantined at package time
   (`scripts/secure_distribution_check.py` rejects any `upstream` path). An
   upstream update is "Update upstream" below: bump the pointer, run the gates.
   The SP6 engine is never woven into `upstream/src/`.
7. **Routine pytest runs our tests only.** `pytest.ini` collects
   `tools/secure/` with no ignores or deselects. Upstream's own suites
   (`pytest upstream/tools` with its recorded exclusions, `pytest
   upstream/serve`) run explicitly after each submodule bump; the exact
   commands are in [`PROVENANCE.md`](PROVENANCE.md), "Updating the baseline".
8. **Pre-push hook.** The owner's pre-push hook runs `pytest -q`. With
   `pytest.ini` it collects `tools/secure/` only (13 tests). `conftest.py`
   stops the run with "run `git submodule update --init`" when `upstream/` is
   not checked out.
9. **CI status: all blocking jobs green on Windows and Linux** (run
   `38458255140`, branch `ci/windows-runtime-fixes`, 2026-10-13). The first
   real run (`38456682352`) failed three tests on `windows-msys2-clang`; the
   fixes are listed under "Verification performed". The wine results below
   remain a smoke test only. After the submodule layout: run `38478775552`
   (branch `layout/upstream-submodule` @ `4aa742c9`), all blocking jobs green.
   SP1: run `38540719307`, `windows-msys2-clang` 193/193 (reported by the
   controller, 2026-10-14). SP2 has not been pushed; no CI run covers it.

### Owner decisions, 2026-10-14

Approved by rflores ("approve all"); binding for plans and implementation.

- Upstream bump to `Niko1221/Strata` v0.1.44.1 merged (main `c07f2429`).
- SP2 Task 22 = bound: engine-stdin writes get an overall bound (the request's
  remaining deadline) in SP2's second run (Task R1); documented by Task 28
  (`docs/security/engine-protocol-limits.md`, "Windows stdin writes").
- SP3 and SP4 specs APPROVED, all recommendations (see the specs' "Decisions
  taken"). SP3 plans: two, M1 (concurrency and hardening) and M2 (streaming).
  SP4 D5 stays open between (A) and (C); (D) ships meanwhile.
- SP6: A1-A11 recorded in the research doc, section 6.
- Details: `docs/superpowers/specs/2026-10-14-sp3-api-concurrency-streaming-design.md`
  (section 11), `docs/superpowers/specs/2026-10-14-sp4-acquire-design.md`
  (section 12), `docs/superpowers/research/2026-10-14-sp6-glm-engine-sources.md`
  (section 6).

### Owner decisions, 2026-10-20

Approved by rflores during the upstream update; binding.

- Upstream bumped to `Niko1221/Strata` **`v0.2.1.3`** (owner chose the latest
  tag of the 0.2.1 line); the `RESUME`/`REUSED` protocol gap was fixed as a
  hotfix on main immediately before the bump (`01ad7226`).
- **Tag version governs:** `upstream.version` → `kEngineVersion`, and manifest
  `min_version` compare against the tag number (`0.2.1.3`); the engine's CMake
  self-version `0.1.46.2` is informational for the frontend.
- **GitHub is storage only:** Actions disabled at the repo level by the owner
  ("do not do GitHub Actions on GitHub, we just need to save there"). Push to
  save; never rely on, await, or watch workflow runs.
- **Windows runtime proof deferred:** agents prove only the local
  `windows-llvm-mingw-cross` cross-build (`-Werror`); real-Windows runtime
  claims wait for the owner's own hardware. The green `windows-msys2-clang`
  run at `7bddb9e1` is the last CI-authorized Windows runtime proof and stands
  for the `v0.2.1.3` pin.
- New commits drop the `Claude-Session:` trailer (keep `Co-Authored-By`
  literal; existing trailers never rewritten). wine stays uninstalled locally.
- **Host toolchain 2026-10-21 (controller):** clang 18 + compiler-rt (TSan) +
  `llvm-symbolizer` live under `.toolchains/clang18/` with `clang`/`clang++`
  wrapper scripts in `.venv-dev/bin` (they pass `-resource-dir` because the
  Ubuntu driver hardcodes `/usr/lib/llvm-18`). The `linux-clang` preset with
  `-fsanitize=thread` builds and runs here; set
  `TSAN_OPTIONS=external_symbolizer_path=<repo>/.venv-dev/bin/llvm-symbolizer`.
  SP3 M1's merge gate ran the filtered concurrency suites under TSan: 90/90,
  zero ThreadSanitizer reports. The `linux-clang-tsan` CI job stays a
  definition only — the controller runs this gate locally.

## Current baseline

- Upstream baseline: the `upstream` submodule gitlink, `Niko1221/Strata` tag
  `v0.2.1.3`, commit `cbfd5b926b794b356195d3cb600191b0c3567540`
  (`git submodule status`).
- Git remotes: `origin` is the owner's repository. Only the owner pushes. The
  older `upstream` remote of this repository is no longer used for tracking;
  the submodule has its own `origin`.
- Secure baseline commit on `main`: `7de35b0c` (the native `secure_frontend`
  as handed off before SP0), followed by the SP0 spec and plan (`4884e9a8`,
  `4dce6f79`). SP0 is the branch `sp0-foundation-hardening` on top of `4dce6f79`.
- UnbiasedStrata reference: commit
  `46c46ecfc11d2315512f21f7549b0a7792ccd2ae`; no code has been copied from it.
- GLM-5.3 reference: `lighttransport/Strata` branch `glm53f`, commit
  `4894c9967f5754a2052d7b05f10a01b6071bb6e4`; the fixed native serving profile
  and Python `glm4`/`chatglm-bpe` tokenizer handling were implemented against
  its observable contracts. The separate GLM engine, CUDA/HIP kernels, and
  remote tensor-parallel worker are not yet ported (SP6).
- Second GLM-5.3 reference (owner, 2026-10-14): `mw00/project-maya` tag
  `v1.1.8`, commit `5c970a863ce2fdd87b6e23ffb4822f6d76522b1c` (MIT, Strata
  derivative: NVIDIA + AMD HIP, experimental Windows, MTP, quant tooling). No
  code has been taken from it; SP6 planning weighs it against `glm53f`.
- Supported target platforms: native Windows 10/11 and Linux. The intended
  compatibility target is every upstream-supported model profile, model
  quantization, vision option, context option, GPU backend, and multi-GPU
  configuration. Do not silently reduce that scope to one model or NVIDIA.

## Repository layout

Upstream Strata is the git submodule `upstream/`; the repository root holds
only our code. Deleting `upstream/` leaves exactly our code.

| Ours, at the root | Pristine, under `upstream/` (submodule @ `cbfd5b92`, tag `v0.2.1.3`) |
| --- | --- |
| `CMakeLists.txt` (builds `secure_frontend/` and, by default, the engine from `upstream/`) | `upstream/CMakeLists.txt`, `upstream/src/`, `upstream/include/`, `upstream/cmake/`, `upstream/third_party/`, `upstream/sycl/` |
| `secure_frontend/` (own `CMakePresets.json`; builds without `upstream/`) | `upstream/serve/`, `upstream/setup.py`, `upstream/setup.sh`, `upstream/requirements.txt`, `upstream/chat.py`, the launchers |
| `tools/secure/` (GLM tokenizer wrapper and our pytest suite) | `upstream/tools/` (incl. `strata_tokenizer.py`, `test_setup_*.py`) |
| `scripts/`, `tests/security/`, `docs/` (this file, `PROVENANCE.md`, `secure-frontend-ci.md`, `security/`, `superpowers/`) | `upstream/docs/`, `upstream/tests/`, `upstream/bench/`, `upstream/data/`, `upstream/ref/` |
| `.github/workflows/secure-frontend.yml`, `.gitignore`, `.gitattributes`, `.gitmodules`, `pytest.ini`, `conftest.py`, `LICENSE`, `README.md` | `upstream/.github/`, `upstream/LICENSE`, `upstream/README*.md`, `upstream/AGENTS.md`, `upstream/SECURITY.md`, `upstream/Dockerfile` |

Getting the code: `git clone --recurse-submodules`, or `git submodule update
--init` after a plain clone. Inside a `.worktrees/<name>` worktree run `git
submodule update --init` once as well. After a `git pull` that moves the
gitlink, run `git submodule update --init` again (or set `git config
submodule.recurse true` once); `git submodule status` showing a `+` prefix
means the `upstream/` checkout differs from the recorded gitlink (either direction). The presets need no submodule;
`pytest -q` and the root build do, and both say so when it is missing.

Root build (GPU backends off, nothing fetched): `cmake -S . -B out/root -G
Ninja && cmake --build out/root && ctest --test-dir out/root`.
`-DSECURE_STRATA_BUILD_ENGINE=OFF` builds the frontend alone. Details:
[`secure-frontend-ci.md`](secure-frontend-ci.md), "Root build".

### Update upstream

Follow [`PROVENANCE.md`](PROVENANCE.md), "Updating the baseline" (the only copy of the runbook: gates at the old pin, bump, gates, pin sites, one commit).

## What has changed

### SP4 (branch `sp4-acquire`)

Plan: `docs/superpowers/plans/2026-10-14-sp4-acquire.md`. One line per task.

Real-Windows status: CI run `38625663621` (base `557a2cc7`: the SP4 merge `4b9fdd31`
plus its merge-time handoff commit) ran `windows-msys2-clang`
488/488 and the `linux-gcc-release` job green, so every `windows-runtime`
case named in the Task 1–24b lines and in merge-time change (a) below is
**verified on real Windows** there (merge-time change (c), the `strata`
binary's own argv, had no case there; Known small gaps). Tasks 25–28 did not change
that code except where their own lines say so (Task 26's additive SP1
`ExecutableWriters::also_trusted_installer` option). The new
`windows-runtime` cases of Tasks 25–28 are **verified on real Windows** by
CI run `38655938748` (`9044a5bc`, `windows-msys2-clang` 515/516); the one
failure, `privacy.priv04_secure_server_does_not_link_acquisition`, is fixed
(see SP4 part 2) and its MSYS2 re-run is pending.

- Task 1: `SECURE_FRONTEND_TEST_HOOKS` option (ON in test presets), `linux-gcc-release` preset (hooks OFF; runs `release-only|release-also`), in-tree FIPS 180-4 SHA-256; `secure_frontend_sha256_tests` (7 cases; 2 `release-also`).
- Task 2: §8 reasons, exit classes and error text in `secure_frontend_manifest_core`; `acquire.exit_classes_match_spec_table`, `reason_table_is_complete_and_ordered`, `error_text_states_resumable`.
- Task 3: URL/host/wildcard/proxy grammar (spec §2.2, §3.4, §3.8); manifest.source_url_grammar_matrix, dns_names_and_wildcards, proxy_grammar; fetch.dl03_location_with_glob_characters_rejected, location_resolution_and_host_normalization, location_query_characters.
- Task 4: §3.5 address policy (`secure_frontend_acquire_core`); fetch.address_policy_* (5 cases).
- Task 5: §3.3 argv/stdin, probe parsing, C3 floors, §3.4 curl exit map; fetch.transfer_argv_exact_order, config_line_is_single_quoted_url, probe_argv_is_version_only, probe_output_parsing_and_floor, curl_exit_codes_map_to_reasons.
- Task 6: §3.4 header-block parser and status table; fetch.informational_header_blocks_skipped, header_block_limits_enforced, split_feed_reports_exact_body_offset, status_table_decisions.
- Task 7: §3.6 retry schedule, run budget, clock seam; fetch.retry_backoff_follows_schedule, non_transient_moves_to_next_source, exhausted_class_follows_last_source_reason, run_budget_remaining_seconds.
- Task 8: manifest model and §2 struct rules, engine version grammar; manifest.* (13 cases, 1 release-only, 1 hooks-only).
- Task 9: index model (render/install/retire), staging plan, key and version-dir names; model_index.* (3), acquire.version_dir_name_unique_for_same_version_label, staging_plan_classifies_partials, abandoned_keys_match_same_model_only, fetch.staging_cwd_not_treated_as_key.
- Task 10: SHA256SUMS/MISSING/marker formats and §6.1 manifest diff (url/notice/per-file license shown old -> new, F-21); bundle.* (4), acquire.update_diff_lists_changed_files_and_license.
- Task 11: Landlock rights/dirs planning, readable-root rule, confinement labels, CRT descriptor block; fetch.landlock_rights_per_abi, confinement_plan_detects_readable_roots, confinement_label_texts, crt_fd_block_layout.
- Task 12: fake downloader secure_frontend_fake_curl (scenario format, §3.3 grammar, record over fd 4 / CRT entry 4); fetch.fake_curl_* (2 portable + 3 POSIX + 1 windows-runtime; record-channel cases hooks-only).
- Task 13: dev-only tools/secure/make_bundle.py (D5 (B′): local pack via upstream iq_pack.py, third-party manifest <quant>-local, SHA256SUMS, STRATA-BUNDLE last, 0-byte pack files refused per F-26) + Hub-read shard pins for the four D4 quants (iq3_xxs/iq3_s/iq1_m await owner confirmation, F-25); tools/secure/test_make_bundle.py (7).
- Task 14: strict manifest parser, embedded catalog (production empty; hooks-only fixture-qwen:t1), --trust-manifest rules, kEngineVersion from upstream.version (checked against a reachable submodule tag), linux-release CI job; validate_manifest now enforces P1 paths for every caller; manifest.dl03_invalid_manifest_matrix, dl03_http_url_rejected, dl05_catalog_pins_match_committed_list (release-also), +4; pytest test_catalog_provenance.py.
- Task 15: SP1 deltas a (inventory skips dot entries), b (scan_model_root_files), e (pull.* keys, lazy downloader); model_inventory.dl04_staging_ignored_by_inventory_scan, model_index.scan_tolerates_repeated_shard_names_across_versions, typed_config.cfg01_pull_keys_table_driven; server_cli auth04 allow-lists pull.allow_private_addresses.
- Task 16: models store primitives on POSIX (lock, part files with KEEP_SIZE preallocation, no-replace rename with fallback, tree removal, hashing, seams); acquire.concurrent_pull_same_manifest_second_is_models_busy +7 (incl. overlong_joined_paths_fail_closed_without_throwing, F-6). Store skipped on WIN32 until Task 17 adds models_store_windows.cpp (F-34 guard; Task 17 removes it).
- Task 17: models store primitives on Windows (pinned parents, CREATE_NEW private DACL, FileAllocationInfo, LockFileEx, MoveFileExW without replace, sharing retries); acquire.store_primitives_windows + store_adopts_only_private_files_windows (windows-runtime; passed in MSYS2, CI run `38625663621`; adopted .lock/.part need owner + protected DACL). F-34 guard removed: the store and its 8+2 cases build on every platform.
- Task 18: index.json strict read/write, installed-model load with manifest re-hash; model_index.index_inconsistent_manifest_fails_closed +3 (round trip windows-runtime). Ruling A: validate_manifest rejects a files[].path whose longest stored form (.staging/<key>/…part, <name>/<tag>/v…/…, files/…) exceeds P1's kRelativePathMaxBytes; manifest.stored_path_length_fits_p1.
- Task 19: §4.4 checks, §4.5 publish/retire/orphan adoption, §4.7 install decisions, §4.8 rm library; acquire.dl04_publish_uses_noreplace_and_never_overwrites, publish_falls_back_when_noreplace_unsupported, dl04_crash_between_publish_and_index_is_not_loaded (hooks), dl04_orphan_adopted_after_rehash_by_digest, replace_loaded_model_retires_old_version(_windows), +9 (F-39 key check, read-only retire/rm, downgrade single-live, unreachable rm is an error). remove_tree_within restores owner write (0500/FRFX) by handle; remove_*_within report an unreachable parent as publish_failed, only a missing one as absent.
- Task 20: bundles (open/verify/import/export, finish with SHA256SUMS + marker last, FAT and license refusals) and SP1 delta f RootPolicy::external; bundle.dl02_import_bundle_publishes_same_as_pull, dl03_bundle_digest_mismatch_publishes_nothing, bundle_rejects_* (traversal, symlink|junction, hard link, unlisted), bundle_sha256sums_must_match_manifest, export_refuses_*, export_rehashes_and_rejects_bit_rot, verify_writes_nothing, import_from_read_only_bundle_directory, export_onto_shared_writable_target, +5 (per-file license exit 10, drive root F-46 (read: "/"/"X:\\" only; write also refuses a mount point), mount-root bundle imports, F-6 over-long/odd names, make_bundle.py fixture with pytest drift guard); paths.external_root_skips_ownership_checks.
- Task 21: fetch_file over HopTransport (our redirects, DNS policy + --resolve, retries/sources/budget, resume, refetch-once, 1 GiB free-space re-checks), SystemResolver, hop_request (url+host from one HttpsUrl); fetch.dl03_* (11) +9 (5 from the brief, then ScriptedTransport fails loudly on unscripted requests and checks argv grammar + pin host per hop, F-49; IPv6-only hop, 200-to-range cap once per file, proxy hop, test_cacert in hook builds F-51). run_pull must still plumb FetchSettings::test_cacert (Task 22).
- Task 22: pull orchestration (catalog/--manifest trust, summary + [y/N], probe after confirmation, stale/abandoned staging and --discard-partial only after the answer (F-56), preflight + budgets, resume at the .part length, update reuse + license prompt, --bundle with MISSING and re-hashed files/, --verify, test_cacert in hook builds F-51); acquire.dl02_* (5, +1 Windows DACL), dl03_* (4), dl04_* (3), +14; bundle.pull_bundle_* (3); fetch.dl03_wrong_digest_rejected_prior_version_intact.
- Task 23: strata binary (local verbs import/verify/export/list/show/rm, program update exit 12 for `strata update` and `strata --config <f> update` (fix 1; Task 27's update branch must reject only non---models operands), hooks banner; engine_gate + find_installed shared in model_store for 24b (F-58), shared CLI helpers in src/strata_cli_internal.hpp for 27 (F-57)); acquire.program_update_exits_12_without_network (release-also), rm_refuses_loaded_model, rm_retired_deletes_unheld_versions, rm_partials_deletes_other_staging, +4; bundle.import_works_without_downloader +3 (export leftover hint, orphan hint); model_index +3 (find_installed, engine_gate family, skipped-entry count).
- Task 24a: SP1 deltas c/d config side: optional roots.tokenizer_pack and engine.profile, name:tag model references, strata-secure-server --expert; SP1 tests and fixtures updated; typed_config.typed_config_model_reference_accepts_name_tag.
- Task 24b: manifest-composed launch (index → --native/--pack/--ple-gguf as UTF-8, tokenizer root from the manifest), engine gate exit 11 (shared engine_gate), --expert keeps SP1's inventory path and messages, --check reports the managed-model config errors (F-8), server hooks banner; engine_arguments.launch_composed_from_manifest_qwen, managed_launch_argv_is_utf8_for_non_ascii_models_root, launch_refuses_model_not_installed, engine_args_reject_weight_flags_for_managed_model, launch_refuses_engine_too_old; typed_config.cfg01_engine_profile_rejected_for_managed_model, cfg01_tokenizer_pack_root_rejected_for_managed_model, cfg01_model_reference_rejected_for_managed_model, describe_reports_unset_expert_keys; server_cli.cli_expert_flag_parsing.
- Final-review fixes: C1 import decides under .lock, then §6.1 diff + license questions --yes never answers (shared review_update/confirm_license_change with pull); I1 staged manifest.json (publish failed after step 2) still trusted and renamed back; I2 rm retires before deleting, corrupt orphan not adoptable; I3 directory case variants manifest_invalid; M1 typed digest checked first; M10 EOPNOTSUPP fallback; bundle.import_license_change_needs_interactive_yes +2, acquire.rm_failed_delete_stays_retired (+_windows), publish_failure_after_step_2_resumes_without_download, manifest.typed_digest_must_match_catalog_bytes_too.

Merge into `main` (`4b9fdd31`, SP2 run 2 + SP4; merge-time changes, report `merge-sp4-report.md`):

- (a) GPU list: `compose_engine_launch` renders SP2's typed `engine.gpu` list in both modes (SP2 §3.9): `--expert` passes `config.engine.gpus` to `build_engine_arguments`; a managed model appends `--gpu <list>` after `engine.args` (`--gpu` in `engine.args` stays refused); engine_arguments.managed_launch_renders_typed_gpu_list (windows-runtime).
- (b) SP4's manifest-side `EngineFamily { strata, glm, none }` is renamed `ManifestFamily` (beside `ManifestProfile`) so it coexists with SP2's environment `EngineFamily { strata, glm }`; no behaviour change (the SP4 plan text still says `EngineFamily`).
- (c) Shared Windows UTF-8 argv: `utf8_command_line(argc, argv)` (`include/secure_frontend/utf8_argv.hpp`, `src/utf8_argv.cpp`) in library `secure_frontend_utf8_argv` (links `shell32`), used by `strata-secure-server` and `strata`; POSIX returns argv as given. `strata`'s Windows runtime proof is pending MSYS2 (Known small gaps): CI run `38625663621` ran the in-process CLI cases only; no case at `557a2cc7` starts the `strata` binary. Task 25 later added only a POSIX `SIGPIPE` ignore to `strata_main.cpp`.
- (d) The supervisor's chat profile and protocol flavor come from `launch.profile` (the manifest's for a managed model), not `config.engine.profile` (`--expert` only); identical today (managed is qwen).
- SP2's `tests/support/server_harness.cpp` passes `--expert` (SP1-style inventory fixture); server fixtures pass `--expert` and `--state-dir`.
- Task 25: confined downloader on Linux (SP2 seam: keep_fds + pre-exec hook; NO_NEW_PRIVS, Landlock read-only system dirs, record fd 4 in hooks builds; probe + C3 floor); fetch.priv04_downloader_argv_exact, priv04_downloader_env_is_empty, dl03_downloader_untrusted_path_rejected, dl03_downloader_cannot_write_files, dl03_downloader_cannot_read_home, pre_exec_failure_fails_closed_exit_9, record_fd_does_not_clobber_report_pipe, downloader_below_floor_exits_9, redirect_url_absent_from_downloader_argv, confinement_reduced_is_announced_without_landlock.
  Commit "sp4: confined curl downloader on Linux via the SP2 pre-exec seam (SP4 Task 25; spec §3.1-§3.3)". Controller rulings: B2 ruleset creation failure with Landlock present → downloader_confinement_failed, no spawn (fetch.ruleset_failure_fails_closed_exit_9, EMFILE via RLIMIT_NOFILE); R2 SP2 read_report/classify_report (fetch.downloader_spawn_report_classified, all builds); I7 record fd opened before the ruleset; I8 downloader-specific path texts; `strata` ignores SIGPIPE. Library `secure_frontend_downloader` is POSIX-only until Task 26; not yet linked by `secure_frontend_strata_cli`.
- Task 26: confined downloader on Windows (restricted Low-integrity primary token in a Job, SystemRoot-only env, explicit handle list, CRT block entry 4 in hooks builds, TrustedInstaller-aware executable check); fetch.*_windows (4, windows-runtime: MSYS2 CI).
  Commit "sp4: confined curl downloader on Windows: Low-integrity token, Job, explicit handles (SP4 Task 26; spec §3.2, §11)". Cases fetch.downloader_transfer_through_job_windows, dl03_default_windows_curl_path_accepted_windows (all builds), dl03_downloader_runs_at_low_integrity_windows, priv04_downloader_env_is_systemroot_only_windows (hooks only; ruling I11) — pending MSYS2 (not triggered by us; wine smoke: the transfer case passes, the integrity/env cases fail only on wine artifacts — wine ignores token integrity and injects WINE* variables). Controller rulings: B3 link secure_frontend_engine_stdio_process + advapi32 (no userenv); I2 WinLaunched::thread closed, Job limits left ON; R5 record OPEN_ALWAYS + append per spawn; I12 MSVCRT quoting copied file-locally; classify_spawn_report stays POSIX-only (launch_in_job DWORD mapped directly). `secure_frontend_downloader` now builds on both platforms; still not linked by `secure_frontend_strata_cli`.
  Fix round 1: validate_downloader is shared (downloader_common.cpp) and uses SP1 open_executable with the new default-preserving `ExecutableWriters::also_trusted_installer` (threaded to `windows_security::write_access_is_private(handle, also_trusted_installer = false)` and `detail::open_existing_root`), so Windows gets GetFullPathNameW normalisation, root-form/UNC refusal, FILE_TYPE_DISK and a prefix-free path; argv uses path_to_utf8 (POSIX bytes unchanged); fetch.dl03_downloader_path_normalised_windows, dl03_downloader_unc_path_rejected_windows (wine-runnable; wine 258/258).
- Task 27: strata pull/run (D6)/update --models/doctor [--downloader], SIGINT/SIGTERM/console interrupts → exit 8, §7.3 acquire.log with confinement; acquire.run_missing_model_prompts_and_decline_exits_2, run_missing_model_non_interactive_exits_2, run_refuses_glm53_without_engine, dl04_interrupt_during_download_never_indexed_windows, +3; fetch.confinement_reduced_written_to_log_record, confinement_reduced_when_root_beneath_allowed_dir, doctor_downloader_probes_on_fresh_store.
  Commit "sp4: strata pull, run (D6), update --models and doctor with interrupts and log records (SP4 Task 27; spec §1.3, §6.1, §7.3, D6)". `secure_frontend_strata_cli` now links `secure_frontend_downloader` (src/strata_cli_network.cpp; stub removed); hooks-only global options `--test-record-file <path>` / `--test-force-no-landlock` before `--config` (a release build rejects them: exit 1); fake-curl scenario directive `delay-ms <N>`. Controller rulings: B1 the downloader cwd `roots.models/.staging/.cwd` is created before any probe or transfer spawn (pull, pull --bundle, doctor --downloader; plain doctor writes nothing) — fetch.doctor_downloader_probes_on_fresh_store; R1 hooks builds copy CliServices::test_cacert into the pull request; R3 strata_cli_internal.hpp helpers reused; R8 the root/config-beneath-the-downloader case also checks `reduced:readable:config file` and a hooks pull through the fake logging `confinement=reduced:readable:roots.models`; R11 `run` of a model neither installed nor in the catalog → `model_unknown`, exit 5, plus a `strata import` hint; R12 acquire.log is one record per **transferred** file (reused, bundle-copied or already-staged files get none); I13 ForwardTransport/ForwardProbe in tests/support/pull_harness.hpp. update_models_pulls_outdated_catalog_models answers the §6.1 license question interactively (the committed catalog fixture's license url/notice differ, so --yes alone declines). Label form stays the merged `reduced:readable:<key>` (spec §3.2/§7.3 text differs; I20). Every new acquire/fetch CLI case on Windows is windows-runtime (wine cannot open the private-DACL roots; existing CLI cases fail the same way there): pending MSYS2 CI, including the Ctrl-Break DL-04 case (it calls AllocConsole when the runner has no console window; ruling I15).
  Fix round 1: InterruptScope now covers the whole network verb; a SIGINT/SIGTERM at a pending [y/N] ends `interrupted`, exit 8, nothing spawned (spec §8.2 controller ruling; EOF/Ctrl-D stays `declined`, exit 2); acquire.dl04_sigint_during_download_exits_8, dl04_sigterm_during_download_exits_8, interrupt_at_confirmation_prompt_exits_8 (Linux, hooks: a real strata child with the fake curl; the prompt case uses a pseudo-terminal stdin).
- Task 28: privacy lifecycle proofs (record channel with positive controls, LD_PRELOAD socket audit with a blocked positive control, Windows TCP table, link-set check) and hooks-OFF proofs (fd census, marker scan in C++ and in secure_distribution_check.py); privacy.* (13), fetch.release_spawn_has_no_fd4.
  Commit "sp4: DL-01 and PRIV-01..04 lifecycle proofs, release-only checks and the hooks marker scan (SP4 Task 28; spec §7, §10.3, §10.5)". New targets: `secure_frontend_privacy_tests`, `secure_frontend_connect_audit` (Linux LD_PRELOAD shim; `SF_CONNECT_AUDIT`, `SF_CONNECT_AUDIT_BLOCK`, plus `SF_CONNECT_AUDIT_LOADED` so an empty audit is proven to come from a process the shim was loaded into), `secure_frontend_resolve_probe`, `secure_frontend_fd_census`; `${CMAKE_BINARY_DIR}/strata-secure-server.link-set.txt` (written at the end of CMakeLists.txt). DL-01 = tripwire + socket audit + link-set check together (R10). Controller rulings: R6 doctor --downloader's strata child runs under the shim (audit empty); R7 Windows DL-01 also scans the UDP tables (and TCP/UDP IPv6); R9 every local verb's exit code asserted (update 12, the rest 0) plus `update --models` on fixture-qwen:t1 installed at sequence 1, declined both non-interactively and with an explicit `n` (exit 2, no spawn); R10 lifecycle waits for READY and asserts a 200 chat — the crash case kills the engine with SIGSEGV after READY (classified `crashed`) instead of `--crash-after-ready`, because that SP2 fake mode stops reading stdin until it crashes, so no chat could ever succeed; it then sees /health leave ready and return before auditing; I17 non-INET families are local; I18 dependencies. `linux-release` CI step stages strata + strata-secure-server and runs `secure_distribution_check.py` (no `--release` until SP7). Counts: linux-gcc 556/556 (+2 skips), linux-gcc-release 523/523 (10/10 `release-only|release-also`), wine 260/260, pytest 25. Pending MSYS2 CI: privacy.dl01_server_makes_no_outbound_connection_windows and the windows-runtime privacy cases.
  Fix round 1: the Windows DL-01 scan fails on any GetExtended{Tcp,Udp}Table error and must find the server's own 127.0.0.1:<port> listener under its pid each round (positive control); the link closure follows names inside generator expressions ($<LINK_ONLY:…>, conditional) and is also written for `strata`, whose set must contain secure_frontend_acquire/downloader/strata_cli (positive control); the shim also audits sendmsg/sendmmsg/getnameinfo/gethostbyname[_r]/gethostbyaddr (raw syscalls and io_uring are out of its reach) and the blocked probe must record all 9 calls, including connect.
- Task 29: docs only — threat-model amendment (spec §7.4: "Privacy and offline operation" names `strata pull`/`update`/`run`-on-missing as the networked operations; "Artifact acquisition" states the manifest pins, our-redirects-only rule and what confinement does not stop), `PROVENANCE.md` "Model catalog (SP4)" (empty v1 catalog, developer-bundle shard pins) and the `upstream.version` pin site in runbook step 5, the part-2 verification record below; no tests added.
  Commit "docs: SP4 threat-model amendment, catalog provenance, handoff verification (SP4 Task 29; spec §7.4, §13.5)". CI check (Step 4): `grep -n SECURE_STRATA_ENGINE_VERSION .github/workflows/secure-frontend.yml` prints nothing, and both `paths:` filters list `upstream.version`.
- Final-review fix wave: commit "sp4: final-review fixes — interruptible hashing and copying, probe interrupt exit 8, update --models interrupt exit, SP1 SID literal (SP4 final review; spec §8.3)". F1 `hash_into`, `copy_verified`, `verify_tree` and `adopt_orphan` take an optional interrupt flag (default nullptr: unchanged for import/export) checked before every 8 MiB chunk; `run_pull` passes its flag, so Ctrl-C/SIGTERM during a resume re-hash, an update's reuse copy, `pull --verify` or orphan adoption exits 8 within one chunk (the half copy removed, a `.part` never restarted from zero, nothing indexed); F3 a probe killed by the interrupt flag is `interrupted` (exit 8), not `downloader_unsupported`; F4 `update --models` returns 8 when a target is interrupted even after an earlier failure; F6 strata_cli.hpp comments; F7 DL-01 scope line (Part 2 deviations); C1 SP1 `windows_security.cpp` uses a file-local TrustedInstaller SID (no SP4 include); C2 Windows `untrusted_owner` text names the current user, SYSTEM, Administrators or TrustedInstaller. Tests added: acquire.hash_into_stops_when_interrupted, acquire.update_reuse_copy_interrupted_mid_file_exits_8, acquire.pull_verify_interrupted_exits_8 (windows-runtime label like their neighbours), fetch.probe_interrupted_exits_8 (Linux, hooks). Counts: linux-gcc 560/560 (+2 skips), linux-gcc-release 526/526 (10/10 `release-only|release-also`), wine 260/260 (518 registered), pytest 25. F4 has no case (the test catalog has one entry, so no two-target update exists).

Part 2 deviations from the spec text (controller rulings, recorded here so a
spec reader is not surprised):

- **R5, spec §10.1 "record channel":** the hooks-only record file is opened
  `O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC|O_NOFOLLOW` 0600 (Windows
  `OPEN_ALWAYS` + `FILE_APPEND_DATA`) once per spawn, **not** `O_EXCL`, so one
  file collects the probe and every transfer of a run. Tests always use a
  fresh scratch directory.
- **I20, labels:** the code and log use the merged form `full`,
  `reduced:no_landlock`, `reduced:readable:<key>` (for example
  `reduced:readable:roots.models`, `reduced:readable:config file`). Spec
  §3.2 prints `confinement: reduced (readable: <key path>)` and §7.3 writes
  `reduced:<cause>`; the spec text is inconsistent with itself and with the
  code. The key may contain a space (`config file`), so a strict
  `key=value` log parser must take the rest of the field.
- **Spec §8.2 over the Task 27 brief:** SIGINT/SIGTERM (Ctrl-C) at a pending
  `[y/N]` ends `interrupted`, **exit 8**, nothing spawned; EOF/Ctrl-D stays
  `declined`, exit 2. Known race: a SIGINT landing after the prompt flush and
  before `read()` starts needs a second Ctrl-C (the result is still exit 8).
- **R10, Task 28 crash case:** the crash-restart lifecycle kills the fake
  engine with SIGSEGV after READY (classified `crashed`) instead of SP2's
  `--crash-after-ready`, under which the fake stops reading stdin and no 200
  chat is possible.
- **Additive SP1 change (Task 26 fix round 1):** `ExecutableWriters
  { standard, also_trusted_installer }` and `open_executable(requested,
  ExecutableWriters = standard)` in `canonical_path.hpp`;
  `windows_security::write_access_is_private(HANDLE, bool
  also_trusted_installer = false)`; `detail::open_existing_root(…, bool
  also_trusted_installer = false)`. Defaults keep every SP1 caller's
  behaviour; only `validate_downloader` passes `also_trusted_installer` (spec
  §3.2 "same rules as `engine.executable`" plus TrustedInstaller for
  `System32\curl.exe`).
- **B1, spec §3.2 cwd row:** `pull`, `pull --bundle`, `run` → pull,
  `update --models` and `doctor --downloader` create
  `roots.models/.staging` and the read-only `.staging/.cwd` before any
  downloader spawn (and before the `[y/N]`, so a declined pull leaves that
  empty 0500 directory); plain `doctor` writes nothing.
- **Shim scope (Task 28):** the `LD_PRELOAD` connect audit hooks the libc
  entry points (`connect`, `sendto`, `sendmsg`, `sendmmsg`, `getaddrinfo`,
  `getnameinfo`, `gethostbyname[_r]`, `gethostbyaddr`); raw `syscall()` and
  io_uring are out of its reach, so DL-01 rests on the tripwire, the audit
  and the link-set check together.
- **`classify_spawn_report` is POSIX-only** (Windows has no report pipe;
  `launch_in_job`'s DWORD is mapped directly).
- **DL-01 audit scope (Task 28):** the Linux shim audits the `strata-secure-server` process only (the engine child's allowlisted environment drops `LD_PRELOAD`), and the Windows socket-table scan filters by the server's pid; the engine child's network isolation is SP2's.

SP4 closing summary (after Task 29).

New user-visible surface, all through the new `strata` binary (never
`strata-secure-server`): `strata --config <file> import|verify|export|list|show|rm|pull|run|update|doctor`
(`update --models [<name:tag> …]` is the models part; bare `strata update` is
the program part and exits 12 until SP7; `doctor --downloader` probes curl).
`--config <file>` is required on every verb. The production catalog is empty
(D5 (D)), so a model arrives today through `make_bundle.py` + `strata import
--trust-manifest sha256:<hex>` or `pull --manifest <file> --trust-manifest
sha256:<hex>`.

Open items (plan "Controller notes", one line each):

1. `strata` is SP4's own binary with its own verbs; the later PX CLI skeleton must absorb `secure_frontend_strata_cli`.
2. No default config location: every verb needs `--config <file>` until PX/SP1 picks one.
3. `strata run` stops at "model ready" + the `strata-secure-server` hint; the chat client (SP2 auto-start + SP3 streaming) replaces that tail.
4. `--expert` exists only on `strata-secure-server`, not on `strata`.
5. No server discovery: `LoadedVersions` = `NoServerDiscovery` ("not held"); the OS is the backstop and `rm --force` has nothing to override yet (SP2/CLI).
6. Spec §4.4's `load_tokenizer_pack` is SP1's `load_local_tokenizer_pack(const CanonicalRoot&)` (spec text to align).
7. Spec §4.1's `atomic_replace_within` is `replace_small_file` over SP1's `write_private_file(…, replace)` (spec text to align).
8. SP4's `cfg01_*` cases live in `secure_frontend_typed_config_tests` (spec §4.9 names `config_tests`).
9. `kEngineVersion` is `0.1.44.1` (spec cites `v0.1.43` line numbers); GSQ-RCO packs are still built by upstream `tools/iq_pack.py` without `pack_args`.
10. The v1 production catalog is EMPTY until D5 (A) owner determinism check or (C) a C++ pack builder; Hub-read shard pins await owner confirmation (`PROVENANCE.md`, "Model catalog (SP4)").
11. `upstream.version` is the engine-version source and a runbook pin site; no CI `-D` or env pin.
12. Retry schedule read as 5 attempts per source, 2/4/8/16 s between them, 32 s before the next source (spec §3.6 wording).
13. Unknown curl exits → `transport_failed`, next source, not retried (§3.4 over §8.2; spec text to align).
14. Landlock ABI ≥ 6 `scoped` rights are left unhandled (review with SP2).
15. SP2 seam names are authoritative (`ExecOptions`, `PreExecHook`, `WinLaunchSpec`, `launch_in_job`); Tasks 25/26 used them as built.
16. `strata update` = program part (exit 12); `strata update --models` = models part.
17. SP4 is the first writer of `roots.logs` (`acquire.log`; one record per transferred file, see Known small gaps).
18. SP1 delta f `RootPolicy::external` (bundle source/target only) is an SP1 addition to note in the SP1 docs.
19. CI runs `secure_distribution_check.py` without `--release` until SP7 provides the release manifest and SBOM.
20. Facts SP3 M1 must re-anchor on (`FrontendConfig::pull`, optional `tokenizer_pack`/`profile`, +7 schema rows, `compose_engine_launch`, `--expert` fixtures, the connect-audit shim to reuse).

PX amendments of spec §13.3 — **to apply in a PX addendum (owner/controller)**:
`pull.manifest_sources` dropped (catalog in the binary, D2); staging is
`roots.models/.staging/`, no `paths.staging`; bundle manifests trusted by
catalog digest or `--trust-manifest` (D7), signatures SP7; publish to
`models/<name>/<tag>/v<sequence>-<h12>/` with retired older versions; file
roles `weights`/`pack`/`tokenizer` plus the manifest `launch` block; PX §3
step 6 "`run` … asks Download?" — **kept (D6 (a))**; the TLS question
answered by D1; `strata update` model part §6.1, program part exit 12 until
SP7; `STRATA_CONFIG` untouched (open for the PX addendum, §3.9); SP4 row
signatures move to SP7.

### Upstream bump to `v0.2.1.3` (2026-10-20)

Owner lifted the stop and named the target; after analysis of `v0.2.1` →
`v0.2.1.3` (engine code identical to `v0.2.1.2` plus Windows-HIP fixes) the
owner chose the latest tag. Pin: `v0.1.44.1` (`296b59d2`) → **`v0.2.1.3`**
(gitlink `cbfd5b926b794b356195d3cb600191b0c3567540`, tag object
`1ab44ace2e4db985503ab9388b65405a63600dd7`). Pin sites re-pointed:
`upstream.version`, `README.md`, the CI workflow header, this file,
`docs/secure-frontend-ci.md` (offline bundle names), `docs/PROVENANCE.md`
(baseline, runbook, license links, ggml `FetchContent` lines 1552–1555),
`docs/security/*` headers, and the `engine_arguments` code comments
(`--gpu` re-anchored to `generate.cpp:2334-2352`, usage `:797`). The limits
doc was fully re-pinned to `v0.2.1.3` line numbers and gained rows for the
`DONE` tail, HIP-Windows `rocm\bin` delay-load, batch telemetry and the
version-numbering split.

Owner rulings (2026-10-20, this bump): **tag version governs** —
`kEngineVersion` (from `upstream.version`) and manifest `min_version` carry
`0.2.1.3`; the engine's CMake self-version `0.1.46.2` (`strata --version`) is
informational only. **wine stays off this host** — Windows proof comes from the
`windows-msys2-clang` CI job. New commits drop the `Claude-Session:` trailer
(keep `Co-Authored-By`).

Gates this host, old pin → new pin (linux-gcc build 0 warnings both):

| Gate | `v0.1.44.1` | `v0.2.1.3` |
| --- | --- | --- |
| pytest (ours) | 25 | 25 |
| linux-gcc ctest | 560 reg., 556 pass, 4 env skips | 561 reg., 557 pass, 4 env skips |
| windows-llvm-mingw-cross build (`-Werror`) | 0 warnings, 47 exes | 0 warnings |
| root build + ctest | 239 steps; 526 reg., 522 pass, 4 skips | 240 steps; 527 reg., 523 pass, 4 skips |
| upstream tools (own venv) | 760/2 skipped/5 desel. | 1027/13/6 |
| upstream serve (own venv) | 774/11 | 878/14/1 |

(Registered grew by one at both ctest levels from the `RESUME`/`REUSED`
hotfix, `01ad7226`, landed immediately before the bump.)

Two upstream tests fail deterministically at `v0.2.1.3` — both NEW in the
0.2.1.x range, both quarantined Python, diagnosed to root cause (see the
runbook bullet list): the parallel-download test (`04221c3e`/`e2071c2f`: the
new length probe issues a whole-file ranged GET its own `asked()` counts
twice) and the lifeline watcher test (`48e6d64c`: the `ps lstart,stat` token
is unstable because `stat` flips `R`→`S`; the `pdeathsig` production path
passes). Both added to the exclusion list with reasons. Nothing we build or
ship failed.

Upstream changes relevant to us (audited against the checked-out tag; full
facts in `docs/security/engine-protocol-limits.md`): the `RESUME`/`REUSED`
serve records (fixed in `01ad7226`); the main engine's `DONE` gained a
` chunk=… experts_streamed=…` tail (opaque to our client, finish field
position unchanged); `qwen35moe` now PARSES `--vision`/`--batch`/`--slots` —
the frontend deny-list is now the only guard, and it holds; `qwen35moe`
answers stray lines with `ERR expected: GEN …` instead of exiting; HIP
gfx906 builds exclude the qwen35 engine; HIP-Windows gained the
`<exe>\rocm\bin` delay-load search (SP7 packaging item, like `strata_kq`);
`STRATA_MMQ_TQ_OVERLAY` defaults ON (GPU builds only, no CPU/root effect);
`apps/desktop` and `apps/host` are new upstream trees — not packaged, and SP7
must keep them out; the ggml pin `3cf03257` is unchanged; CMake surface
re-audited: one `FetchContent` at `:1552`, no `tests/CMakeLists.txt`, option
defaults compatible with our root seeds. The engine CLI gained three local
tuning flags (pass-through candidates; deny-list unchanged and still
complete for everything it refuses).

### Protocol hotfix: `RESUME`/`REUSED` prompt-progress records are consumed (2026-10-20)

Found while re-auditing the `--serve` protocol for the upstream v0.2.1.x bump:
the main engine family's serve loop prints `RESUME <n>` before reading the
prompt and `REUSED <n>` once it is read, for **every** accepted GEN and
unconditionally (`generate.cpp:11214`/`:11849` at `v0.1.44.1`, `:12809`/`:13910`
at `v0.2.1.3`; upstream's own server consumes both). The strict client failed
such a response with `unexpected_line`, so **every real-engine chat would have
failed at both pins** — the same latent-blocker class as the PP fix (`c9629e6e`),
found by reading, never yet observed against a real engine. Fix mirrors PP: under
the Strata profile a `RESUME`/`REUSED` line with exactly two fields and a
32-bit decimal count is consumed silently; any other shape still fails closed;
the GLM profile keeps its exact record and refuses them. `YIELDED <slot>
<tokens>` is left strict — it needs the `--batch`/`--slots` paths, which the
frontend refuses at argv level.

Tests: `secure_frontend_engine_protocol_client_tests.resume_and_reused_progress_is_consumed_in_the_strata_profile`
(RED on the unfixed client: "RESUME/REUSED records of the main engine family
must be consumed silently" + "a held-state reuse count must be accepted as a
decimal"; GREEN after). Limits doc: new `RESUME`/`REUSED` row in
`docs/security/engine-protocol-limits.md`.

### Upstream bump to `v0.1.44.1` (2026-10-14, branch `upstream/bump-v0.1.44.1`)

`7695859a` (`v0.1.43`) → `296b59d2` (`v0.1.44.1`), 315 commits. Gates old →
new: `pytest -q` 13 → 13; `secure_frontend` linux-gcc 111/111 → 111/111;
`windows-llvm-mingw-cross` (-Werror, wine) 102/102 → 102/102; root build
94/94 steps, 0 warnings, ctest 111/111, no `_deps` → identical (same engine
targets); upstream `tools` 616/2/3 → 760/2/5 (two `test_setup_golden.py`
deselects added: upstream `12be1059` recorded `strata-vision.exe` on
Windows); upstream `serve` 695/11 → 774/11. CMake: no new FetchContent, no
`tests/CMakeLists.txt`, ggml/llama.cpp pin unchanged (`3cf03257`);
`STRATA_NATIVE_EXPERTS` moved up to L107 (our seed still wins);
`STRATA_MMQ_KQUANTS` and `STRATA_Q6K_EXPERTS` now default ON (CUDA/HIP only).
`strata_tokenizer.py` byte-identical. Main engine CLI/protocol: additive only
(`--prefill-head-alias`, `--families`, new ERR texts, GENI `img_keys=`), no
network code. Upstream changes that matter to the frontend:

- `qwen35moe` family switch (CUDA/HIP builds): such a GGUF runs a separate
  serve loop (`upstream/src/qwen35/q36_engine.cu`) — QUIT ignored (exits on
  stdin EOF), unknown flags skipped instead of fatal, no `--pack`, no
  `nonfinite`, context rule without the `+ 8` margin (our stricter check keeps
  us safe). See [`security/engine-protocol-limits.md`](security/engine-protocol-limits.md).
- Runtime-loaded `strata_kq` library (`strata_kq.dll` / `libstrata_kq.so`
  from the engine's folder when `STRATA_MMQ_KQ=1`, forced on by the qwen35
  path): a DLL search-order and packaging question for GPU builds.
- New family check: the engine refuses any `general.architecture` other than
  `qwen4exp` / `qwen35moe` — affects the SP6 GLM port.
- RESOLVED 2026-10-14 (commit on `main`, "protocol: Strata-profile PP prefill
  heartbeats are consumed"): the engine emits `PP <position> <prompt tokens>
  <ms> <tok/s>` during batched prompt reads (`generate.cpp`), and the
  `qwen35moe` engine emits `PP <done> <fresh> <ms> <tok/s>` (`q36_engine.cu`);
  `engine_protocol_client.cpp` used to reject `PP` outside the GLM profile, so
  every real Strata-profile request with a batched prefill would have failed
  with a generic `503`. It now consumes bounded `PP` records (3–5 fields, two
  decimal counters, optional non-negative metrics, no ordering assumed) under
  the Strata profile; the GLM profile keeps its exact 3-/5-field record with
  `read <= total`. Case `engine_protocol_client_tests.prefill_progress_is_bounded_in_both_profiles`
  (RED against the old client on the first Strata-shaped line). Still never
  observed against a real engine (no GPU here).

The runbook in `PROVENANCE.md` was corrected on its first real run (gates at
the old pin first, per-run `out/<name>-<L>` dirs, rule for new upstream test
failures, tag object and CMake line numbers in the pin sweep, history rows
left alone, `docs/security` facts re-checked) and is now the only copy.


### Submodule layout (branch `layout/upstream-submodule`)

Spec: [`superpowers/specs/2026-10-13-upstream-submodule-layout-design.md`](superpowers/specs/2026-10-13-upstream-submodule-layout-design.md);
plan: [`superpowers/plans/2026-10-13-upstream-submodule-layout.md`](superpowers/plans/2026-10-13-upstream-submodule-layout.md).

| Item | What changed | Check |
| --- | --- | --- |
| U2 | `upstream/` = submodule `https://github.com/Niko1221/Strata.git` at `7695859a` (`v0.1.43`), tree byte-identical to the tag | `git submodule status` |
| U3 | Our root `CMakeLists.txt`: frontend first, then `upstream/` unmodified; Release default, `include(CTest)`, `SECURE_FRONTEND_WERROR=ON`, CUDA/HIP/native experts seeded `OFF`, `SECURE_STRATA_BUILD_ENGINE` | root build 94 steps / 0 warnings, `ctest` 20/20, no `_deps`; `-D` overrides; empty `upstream/` message |
| U4, U5 | `tools/secure/secure_tokenizer.py` wraps upstream's tokenizer (GLM aliases, `extract()` ships the declared pattern); tests in `tools/secure/`; `pytest.ini` `testpaths = tools/secure`; `conftest.py` names `git submodule update --init` | `pytest -q` 12 passed (13 since the final fix wave: `extract()` refuses when upstream did not write `tokenizer/tokenizer.json`) |
| U1, U6, U7 | 2 971 upstream files removed from our tree; ours-only `.gitignore`, `.gitattributes`, `README.md`, `LICENSE` | `git ls-files` shows only our paths plus the `upstream` gitlink |
| U8 | `bootstrap-linux.sh` reads only `scripts/dev/requirements-dev.txt` (now pins cmake 4.4.3, ninja 1.13.2, regex 2026.9.10) | fresh venv bootstraps; `pytest -q` passes without numpy |
| U9 | `secure_distribution_check.py` rejects any `upstream` path component and quarantined names at any depth | `tools/secure/test_secure_distribution_check.py` (6 tests) |
| U10 | CI: submodule checkout in `linux` and `top-level-integration`; the latter configures our root (first with no `-D` flags, asserting the OFF seeds, `Release` and no `_deps` — added in the final fix wave); collection and submodule-status steps | run `38478775552` (`4aa742c9`): all five blocking jobs green; `windows-msvc` informational red (known) |
| U11–U14 | `PROVENANCE.md` baseline = gitlink, no ledger; this file, `secure-frontend-ci.md`, security docs, product spec §9, SP1/SP2 path patches; "Update upstream" runbook; offline bundle in `secure-frontend-ci.md` | doc greps in the plan, Task 6 |

### Secure baseline (commit `7de35b0c` on `main`)

| Area | Files | Status |
| --- | --- | --- |
| Provenance | `docs/PROVENANCE.md` | Complete baseline/attribution record. Since the submodule layout the baseline is the `upstream` gitlink and there are no upstream edits. |
| Security/privacy contract | `docs/security/threat-model.md`, `tests/security/README.md`, `docs/security/privacy-migration.md`, `docs/security/deployment.md` | Complete specification, legacy-network inventory, platform deployment prerequisites, and package-readiness procedure; most acceptance tests are not implemented yet. |
| Secure package gate | `scripts/secure_distribution_check.py` | Checks a selected staging directory (never this source tree) for quarantined Python installer/service/MCP/update artifacts and symlinks; `--release` additionally requires a privacy declaration manifest and SBOM. |
| Native frontend foundation | `secure_frontend/` | C++20 configuration, secret/token-reader, HTTP policy/request-handler/socket adapter, API router, local model inventory, and process-supervision libraries with unit tests. |
| Runnable smoke executables | `secure-frontend-smoke`, `strata-secure-smoke-server` | Authenticated local `/health` and `/v1/models`; no engine inference. |
| Native serial chat executable | `strata-secure-server` | Starts one supervised local `--serve` engine child and offers authenticated text-only, non-streaming Qwen or explicitly selected GLM-5.3 `/v1/chat/completions` plus health/models. It is intentionally not a claim of universal upstream model/template/vision compatibility. |
| GLM tokenizer tooling | `tools/secure/secure_tokenizer.py` (wraps `upstream/tools/strata_tokenizer.py`), `tools/secure/test_glm_tokenizer.py` | Offline support for the `glm4` and `chatglm-bpe` byte-BPE pre-tokenizer aliases, preserving GLM's 1–3-digit segmentation, with emitted pack metadata. `secure_frontend` does not yet consume tokenizer-pack metadata, so native GLM execution still needs matching-pack validation. |
| Top-level integration | `CMakeLists.txt` (ours since the submodule layout) | Builds `secure_frontend/` and the engine from `upstream/`; `SECURE_STRATA_BUILD_ENGINE=OFF` builds the frontend alone. Before the layout it was an opt-in hunk in upstream's root file. |

### SP0 deliverables (branch `sp0-foundation-hardening` on `4dce6f79`, including the docs commits and the final fix wave)

Item IDs are from §4 of the SP0 spec. Each row names its regression test, or
says why it has none.

| Item | What changed | Regression test / check |
| --- | --- | --- |
| Tooling (T1, T5) | `scripts/dev/bootstrap-linux.sh` creates `.venv-dev` (no root) with `-r scripts/dev/requirements-dev.txt` (since the submodule layout the only file it reads: cmake 4.4.3, ninja 1.13.2, regex, pytest 9.1.1 and its dependencies). Offline (`STRATA_WHEEL_DIR` set) needs every wheel that file names **plus** a pip wheel, which the pip-bootstrap step now takes from `STRATA_WHEEL_DIR` too; nothing is fetched from the network then. `pytest.ini` collects `tools/secure/` only (submodule layout). | Bootstrap is idempotent (re-run on the existing venv: exit 0); a fresh scratch checkout bootstraps with network (exit 0) and offline from a wheel directory with the network blocked (exit 0); `pytest -q` passes from the repository root. |
| CMake hygiene (T3, T4) | (before the submodule layout) Top-level `STRATA_BUILD_SECURE_FRONTEND` defaults `OFF` (opt-in). `SECURE_FRONTEND_WERROR` (default `ON`, follows `STRATA_WERROR` from the root). One `secure_frontend_set_warnings()` helper replaces the per-target flag blocks; dead `if(MSVC)`-inside-`if(UNIX)` blocks removed. Under our own root (submodule layout) the frontend is added before `upstream/` and the root declares `SECURE_FRONTEND_WERROR=ON`, so the follow-`STRATA_WERROR` default is inert there (SP1 may simplify it). | Configure with each setting. |
| llvm-mingw (T2, P5) | `scripts/dev/bootstrap-llvm-mingw.sh` (llvm-mingw `20261006`, sha256 pinned), toolchain file, `windows-llvm-mingw-cross` preset. `win32_prelude.hpp` (`NOMINMAX`, `WIN32_LEAN_AND_MEAN`); paths converted with `path::wstring()`. Two further Windows fixes found by the cross build: unused POSIX helpers in `engine_process.cpp` guarded; `token_reader.cpp` uses `std::next(it) == end()` (libc++ `path::iterator` is an input iterator). | Cross build with `-Werror`; `wine strata-secure-server.exe --help` exits 0. |
| Early close (S1) | `install_process_defaults()` ignores `SIGPIPE` in all three mains; `send()` uses `MSG_NOSIGNAL` (`SO_NOSIGPIPE` where that is the only option). | `socket_server_survives_client_early_close` |
| Request deadline, send timeout (S2, S3) | `HttpSocketServerLimits{request_deadline = 30 s, max_request_bytes = 64 KiB}`, a defaulted `bind()` parameter until SP1's typed configuration. Total monotonic deadline for header and body; send timeout, with each `send()` capped at 64 KiB (Winsock accepted one 32 MiB blocking `send()` whole, bypassing the deadline; found by the first MSYS2 run). | `socket_server_rejects_slow_request_past_deadline`, `socket_server_send_times_out_on_stalled_reader` |
| Listener robustness (S4–S7) | Oversize request answered `413`; accept blocks without a timeout (smoke server no longer exits after 5 s idle); `IPV6_V6ONLY` on IPv6 binds; `SO_REUSEADDR` (`SO_EXCLUSIVEADDRUSE` on Windows); complete responses. `listener_failed()` is set only for a broken listener (`EBADF`/`ENOTSOCK`/`EINVAL` and the Winsock equivalents); peer and network errors are transient; 50 ms backoff on descriptor/buffer exhaustion. The mains stop only on listener failure. | `socket_server_rejects_oversize_request_over_tcp`, `socket_server_accept_waits_without_timeout`, `socket_server_ipv6_bind_is_v6only` (binds `::`), `socket_server_response_is_complete`, `socket_server_survives_reset_before_accept`, `socket_server_responds_after_client_half_close`. After the last response byte (normal, `408`, `413`) the server half-closes its send side and drains the peer for at most 100 ms / 256 KiB before closing, so a Windows client reads the `413` rather than an RST. The socket tests are portable (run under wine and in the MSYS2 job). |
| Generation deadline and recovery (E1, E2) | Total generation deadline; on timeout the client sends `STOP` and drains to `DONE` within `ChatExecutionLimits::stop_drain_timeout` (5 s), returning to idle (`idle()`), or marks the engine failed (`abandon()`). The request gets the `generation_timed_out` error; a `nonfinite` result is a `503` for that request only and the engine stays ready. | `generation_total_deadline_is_enforced`, `chat_recovers_after_generation_timeout`, `chat_marks_engine_failed_when_drain_fails`, `chat_rejects_nonfinite_done_and_stays_ready` |
| Health (E3) | `EngineHealth` / `health()`; `ApiRouter` takes an optional `EngineStateProvider` and `/health` returns `{"status":"ok"|"unavailable","engine":"<state>"}` with the state one of four fixed literals (anything else fails closed). `starting` → `200` with `engine=starting` (READY is consumed on the first request; eager READY is SP2), `ready`/`generating` → `200`, `failed` or a stopped child → `503`. The server samples the child and protocol state once per request and derives both fields from that snapshot. No secrets or paths. | `health_reflects_protocol_state`, `health_is_failed_after_engine_closed_mid_generation`, `health_is_failed_when_engine_closes_before_ready`, `health_includes_engine_state_when_provided`, `health_is_503_with_engine_state_when_unavailable`, `health_samples_status_before_state_once_each` |
| Protocol limits (E4, D4) | Limits derived from `READY`: `max_line_bytes = 0` means `min(32 + 11 × ctx, 16 MiB kProtocolMaxLineBytes)` for the outbound `GEN` line; inbound records capped at `kMaxReadLineBytes = 8192`; `kMaxWriteLineBytes = kProtocolMaxLineBytes`. The engine's `+8` context rule is applied before `GEN` (`400`). Facts in `docs/security/engine-protocol-limits.md`. | `gen_line_fits_max_prompt_tokens`, `chat_applies_engine_context_rule_with_eight_token_margin`, 100 KB `GEN` write in `engine_stdio_process_tests`, 16 MiB clamp case in `engine_protocol_client_tests` |
| POSIX launch (P1–P3) | `secure_frontend/src/posix_child_launch.hpp`: argv/env built before `fork`, `pipe2(O_CLOEXEC)`, descriptor sweep (`close_range`, bounded fallback), reap after `SIGKILL`. | `child_inherits_only_stdio_descriptors`, `child_receives_exact_argv_and_env`, `terminate_reaps_killed_child` (asserts pid `-1` and `ECHILD`) |
| Windows launch (P4, P6, P7) | `CREATE_SUSPENDED` → Job Object → `ResumeThread`. Iterative bounded `read_line` shared with POSIX through `take_pending_line()`. Stdin pipe created with `CreateNamedPipeW`, buffer **requested** at `kMaxWriteLineBytes + 4096` (advisory per Win32; overlapped writes deferred to SP2). `engine_stdio_process_tests` is now portable. `read_line` keeps one deadline across chunks (POSIX polls with the remaining budget) and treats `WAIT_FAILED` as a failure on Windows. | `read_line_rejects_oversize_on_all_platforms`, `read_line_waits_for_a_record_split_across_writes` (both pass under wine); P4: `job_object_terminates_grandchild` (Windows only: the fake engine spawns a 30 s sleeper grandchild, which must be gone after `terminate()`; passes under wine, authoritative only in the MSYS2 job). |
| Engine arguments (M1, M2) | `secure_frontend_engine_arguments` library, profile-aware (`EngineArgumentsProfile`). Strata profile: the frontend supplies shard 1 by appending `--native <models_root/artifact>` (last) from the inventory entry for `--model-id` and rejects `--native`, `--serve`, `--batch`, `--slots`, `--vision` in `--flag` and `--flag=value` forms; the expert pack (`--pack`, loaded unconditionally, default cwd-relative `pack/full`) and other weight sources (`--ple-gguf`, `--embd-gguf`, `--native-head-gguf`, `--native-dense-gguf`, `--mtp`) pass through and are operator-supplied until SP1/SP5 model the whole launch. An invalid manifest artifact path (`../x.gguf`, `/abs.gguf`) is `invalid_value`. GLM-5.3 profile: arguments pass through (only NUL and `--serve` rejected), no model path is supplied; `strata-secure-server --profile glm53` requires at least one `--engine-arg`. | `engine_receives_model_path_from_inventory`, `engine_args_reject_owned_and_network_flags`, `strata_profile_passes_pack_and_weight_flags_through`, `rejects_invalid_relative_artifact_path`, `glm_profile_passes_arguments_through_without_native`, ctest `strata_secure_server_glm_requires_engine_arg` |
| CI (T6) | `.github/workflows/secure-frontend.yml`: blocking `linux-gcc` (+ `pytest -q`), `linux-clang`, `windows-llvm-mingw-cross`, `windows-msys2-clang`, `top-level-integration` (root CMake, `STRATA_NATIVE_EXPERTS=OFF`, no llama.cpp clone); non-blocking `windows-msvc`. Green on run `38458255140` (all blocking jobs; `windows-msys2-clang` 19/19). `windows-msys2-clang` links with `-static` (preset) so a child launched with the allowlisted environment, which has no `PATH`, needs no runtime DLL. See [`secure-frontend-ci.md`](secure-frontend-ci.md). |
| Docs (D1–D4) | `secure_frontend/README.md` build section and current behavior; `token_reader.hpp` comment describes the Windows checks that run, unreachable `protected_file_unsupported_on_platform` removed; this handoff; `secure-frontend-ci.md`; `engine-protocol-limits.md`. | Builds and tests re-run after the header change (below). |

### SP1 deliverables (branch `sp1-typed-config-paths-tokens`)

Spec: [`superpowers/specs/2026-10-13-sp1-typed-config-paths-tokens-design.md`](superpowers/specs/2026-10-13-sp1-typed-config-paths-tokens-design.md)
(§8 lists every N/C/P/K/A/D item); plan:
[`superpowers/plans/2026-10-13-sp1-typed-config-paths-tokens.md`](superpowers/plans/2026-10-13-sp1-typed-config-paths-tokens.md).
Task 2 is a shared pre-task committed on `main` (SP2 consumes it); every other
row is a commit on the SP1 branch (fix rounds are separate commits, listed in
the same row). Each row names the regression tests from its commit message.
Every test with the CTest label `windows-runtime` is **verified in MSYS2**:
CI run `38540719307` ran the authoritative `windows-msys2-clang` job on SP1,
193/193 (before the SP2 merge). What no CTest case covers stays unverified on
Windows and says so in its row (the Task 20 environment scrub, the Task 17
ancestor-rename assumption). wine is a smoke test only (see "Verification
performed", SP1).

| Task / commit | Items | What changed | Regression tests / check |
| --- | --- | --- | --- |
| 2 — `17d2452d` (on `main`) | §3.10 | `secure_frontend_add_cases(<binary> <case>... [ARGS] [LABELS] [TIMEOUT])` registers one CTest test per case (`<binary>.<case>`), dispatched through `secure_frontend_test::run_cases` (`--case`, `--list`); label `windows-runtime` (empty off Windows), excluded by the `windows-llvm-mingw-cross` test preset; scratch directories via `mkdtemp` (0700) under `<build>/test-tmp` (Windows: explicit protected DACL), removed on every exit path. Helper names, `<binary>.<case>`, the label and the preset exclusion are frozen for SP2. | Linux 111/111, wine 102/102 at that commit |
| 1 — `6be5042e` | N1, N2; defect a | Listener addresses are classified from the parsed bytes (`parse_listener_address`): every spelling of the unspecified address needs `--allow-wildcard-bind`; `::ffff:127.0.0.1` and the long loopback form are loopback; `localhost` (ASCII case-insensitive) maps to `127.0.0.1` without a resolver call; every other hostname is rejected; `bind()` uses the canonical text. `inet_ntop` runs during validation, before `WSAStartup` on Windows (wine passed; **verified in MSYS2, CI run `38540719307`**). | `net03_wildcard_spellings_need_wildcard_opt_in`, `net03_remote_opt_in_alone_rejects_wildcard`, `net01_loopback_spellings_classified_from_bytes`, `net02_hostname_rejected_before_bind`, `net01_localhost_maps_to_ipv4_loopback` |
| 3 — `828daac8` | C1 | One strict bounded JSON reader (`json.hpp`: duplicate keys, depth, size, integers only, BOM, trailing data) shared by the chat schema and the tokenizer pack. | `json_rejects_duplicate_keys`, `json_rejects_depth_over_limit`, `json_rejects_non_integer_numbers` (+ BOM/trailing/size cases) |
| 4 — `95ca08ad`, fix `67634f81` | C2 | Typed `FrontendConfig`, the schema table `config_schema()` (one row per key: type, range, default, option, description) and `validate()` collecting every issue by key path with a fixed reason; `ready_timeout` 900 s; `limits.chat.max_body_bytes` default 49152. Fix: member names that are empty or contain `.` are unknown keys (no aliasing of nested keys); a duplicate path on insert is an error. | `cfg01_unknown_key_rejected`, `cfg01_duplicate_key_rejected`, `cfg01_type_confusion_rejected`, `cfg01_missing_required_rejected`, `cfg01_out_of_range_rejected`, `typed_config_cross_field_rules`, `typed_config_errors_never_contain_values` (all `windows-runtime` from Task 9: **verified in MSYS2, CI run `38540719307`**) |
| 5 — `67ac645a` | C6, C8 | `strata-secure-server --config FILE` and `--check` go through the one validator; an option wins over the file and `--check` reports each overridden key; option values are never echoed. End-to-end harness (process runner, HTTP client, server fixture, fake engine). | `cli_config_file_and_flags_share_validator`, `cli_flag_overrides_file_and_is_reported`, `cli_check_prints_no_token`, `cli_unknown_option_does_not_echo_value` (`windows-runtime` from Task 9: **verified in MSYS2, CI run `38540719307`**) |
| 6 — `2b0f83b4`, fix `e6e82aa1` | C3, N3, N4 | The server binds before it spawns the engine; process-level NET tests. Fix: the C3 guard is deterministic (an unstartable engine plus an unbindable address must report the bind error). | `cfg01_invalid_config_fails_before_listener_and_child`; acceptance `net01_default_listener_is_loopback_only` (`GetExtendedTcpTable`), `net02_remote_addresses_need_opt_in`, `net02_error_is_non_secret_and_exits_before_bind` — all four `windows-runtime` from Task 9: **verified in MSYS2, CI run `38540719307`** (the C3 guard's RED was never shown on Windows) |
| 7 — `d9613548` | C4, C5; defect d | Listener, parser, chat schema and chat execution take their limits from `FrontendConfig`; defaults live only in `config_defaults.hpp`. Accepted deviation: an over-bound declared `Content-Length` is answered `400` from the headers alone (`413` is for bytes actually received past the bound). | `parser_honors_configured_max_request_bytes`, `ready_timeout_is_configurable`, `ready_timeout_defaults_to_900_seconds`, `subsystem_limits_follow_config` (`windows-runtime` from Task 9: **verified in MSYS2, CI run `38540719307`**) |
| 8 — `51059af4` | P1 | One relative-path grammar (`RelativePath`) for secret sources and model artifacts; the two disagreeing grammars are deleted. | `cfg02_rejects_traversal_and_absolute`, `cfg02_rejects_nul_and_control_bytes`, `cfg04_rejects_reserved_and_device_names`, `cfg04_rejects_trailing_dot_space_and_8dot3`, `cfg04_rejects_ads_and_drive_forms`, `relative_path_accepts_portable_forms` |
| 9 — `b36dd17a`, fix `5d6232e5` | P2, P3, P7; defect e | `CanonicalRoot`/`CanonicalFile` (`open_root`, `open_executable`); the engine receives the canonical models root; Windows root forms (UNC, device, `\\?\`) rejected and network/redirected final paths reported actionably. Fix: `roots.secret` defaults to the config file's folder only for a `file:` token source; an `env:` source never opens it. From here 24 cases that open real roots are `windows-runtime` (engine_arguments, typed_config, subsystem_limits, server_cli, server_e2e): **verified in MSYS2, CI run `38540719307`**. | `cfg03_engine_receives_canonical_models_root`, `cfg02_rejects_relative_root`, `cfg02_rejects_shared_writable_root`, `cfg02_root_may_traverse_symlink`, `cfg02_sibling_prefix_root_rejected`, `cfg02_engine_executable_must_be_private_regular_file`, `cfg04_rejects_unc_device_and_extended_roots`, `cfg04_final_path_on_network_share_is_actionable`; fix: `cfg02_env_token_ignores_config_folder_permissions`, `cfg02_file_token_default_secret_root_reports_one_issue` (POSIX) |
| 10 — `e07b0601` | P4 | Linux: `openat2(RESOLVE_BENEATH\|NO_SYMLINKS\|NO_MAGICLINKS\|NO_XDEV)` below a root, with an `openat(O_NOFOLLOW)` walk on `ENOSYS`/`EPERM`; the Linux token reader uses it; hard-linked token files rejected. | `cfg03_rejects_hardlinked_token_file`, `cfg03_rejects_symlinked_intermediate_directory`, `cfg03_rejects_symlinked_final_file`, `cfg03_fallback_walk_matches_openat2`, `cfg03_rejects_mount_crossing` |
| 11 — `9d9b1fba` | P5; defect b | Windows: `READ_CONTROL` handle walk below the root with reparse-point and hard-link rejection; the Windows token reader uses it (the old reader is deleted). The defect-b fix (handles that can read the DACL) was verified by reading only at the time; the Windows cases below have since passed in MSYS2. | `auth02_windows_token_file_reads_with_private_dacl`, `cfg03_rejects_junction_below_root`, `cfg03_rejects_symlink_below_root`, `paths_handle_non_ascii_and_long_names` (Review Focus 4; passes on Linux) — the Windows four are **verified in MSYS2, CI run `38540719307`** (wine 0/4: `GetFinalPathNameByHandleW` beyond `MAX_PATH`, `D:P` dropped, no junctions, symlink seen as not-found) |
| 12 — `ccd7c63b` | C7 | Config files and their folders are opened through the path module and refused when other users can write them (or when owned by neither euid nor root). | `cfg01_group_writable_config_rejected` (Linux), `cfg01_config_with_everyone_write_ace_rejected` (`windows-runtime`; wine passes but does not model DACLs: **verified in MSYS2, CI run `38540719307`**) |
| 13 — `96aaf699`, fix `56a60c5d` | P6 | Inventory and tokenizer pack enumerate (`list_directory`) and open through the canonical-path module; symlinks/junctions and case-folded duplicate IDs fail naming the entry; non-portable `.gguf` names and non-portable directory names fail; other non-portable non-model files are ignored. | `inventory_symlink_error_names_entry` (Review Focus 1), `inventory_duplicate_detection_is_case_insensitive` (Review Focus 5), `inventory_ignores_non_portable_non_model_names`, `inventory_rejects_non_portable_directory`, `cfg03_inventory_rejects_symlink_entry`, `cfg03_tokenizer_file_swapped_to_symlink_rejected`; Windows junction variants `cfg03_inventory_rejects_junction_entry`, `cfg03_tokenizer_file_swapped_to_junction_rejected` and the root-opening inventory/tokenizer cases: **verified in MSYS2, CI run `38540719307`** (wine cannot create junctions) |
| 14 — `264edde1` | P8, P9 | `create_directory_within` a root (symlinked components rejected); `roots.logs`/`roots.cache` are checked by `validate()` (absent-but-creatable under a private parent) and created 0700 only by serve and `init`; `--check` creates nothing; duplicate path checks outside the module removed (P9 grep). | `cfg02_create_within_root_writes_nothing_outside`, `cfg02_logs_and_cache_roots_are_created_private`, `cli_check_has_no_side_effects` (all `windows-runtime`: **verified in MSYS2, CI run `38540719307`**; wine: the junction case fails, the other two pass) |
| 15 — `5cc8a91f` | K1, K6 (type) | `SecretBytes` (fixed capacity, wiped on destroy and move), CSPRNG token generator (`getrandom`, fails closed; `BCryptGenRandom` on Windows), base64url; tokens are 43 characters. | `base64url_known_vectors`, `token_generate_is_43_base64url_chars`, `token_generate_differs_across_calls`, `secret_bytes_wiped_on_destroy_and_move`, `secret_bytes_rejects_over_capacity` (wine 5/5; BCryptGenRandom/SecureZeroMemory **verified in MSYS2, CI run `38540719307`**) |
| 16 — `e0f4294c`, fix `510617b5` | K2 | Linux token store: `O_EXCL\|O_NOFOLLOW` temp, `fsync`, `renameat2(RENAME_NOREPLACE)` (or replace with `--force`), 0600 file in a 0700 directory. Fix: rotate asserted; a target that cannot be inspected fails closed. | `token_store_creates_0600_file_in_0700_dir`, `token_store_rotate_is_atomic`, `token_store_refuses_symlinked_target` |
| 17 — `25ba2270`, fix `013f540a` | K3 | Windows token store: DPAPI (user scope) `STRATAK1` + blob, protected DACL `O:<user>D:P(A;;FA;;;<user>)(A;;FA;;;SY)`, `CREATE_NEW` temp, `FlushFileBuffers`, `MoveFileExW(WRITE_THROUGH)`; the reader unwraps DPAPI and still reads plaintext operator files. Fix: the holding directory is opened with `open_beneath` and pinned (no `FILE_SHARE_DELETE`) across create and move; creation and move are still by path (handle-relative `NtCreateFile` deferred); protection against renaming an ancestor relies on NTFS refusing to rename directories with open handles below them — unverified. | `token_store_windows_round_trips_through_dpapi`, `token_store_windows_file_has_private_dacl`, `token_reader_windows_accepts_plaintext_under_private_dacl` — **verified in MSYS2, CI run `38540719307`** (wine 0/3 at the `D:P` gate; a DPAPI probe round-trips under wine) |
| 18 — `f9f146ac` | K4, K5, K6; defect c | `secure_frontend_token_reader_tests` runs on every platform; one trailing LF or CRLF; result is `SecretBytes`; 32-byte floor, 256-byte cap, 4 KiB file cap; quoted tokens rejected with a reason; read buffers wiped. | `auth02_token_file_with_trailing_lf_accepted`, `auth02_token_file_with_trailing_crlf_accepted`, `auth02_short_operator_token_rejected`, `auth02_token_file_over_4k_rejected`, `token_store_round_trips_through_reader`, `auth02_token_file_with_two_newlines_rejected`, `auth02_token_file_with_bom_rejected`, `auth02_notepad_edits_rejected_with_reason` (Review Focus 3); the 8 Windows file cases are **verified in MSYS2, CI run `38540719307`** (wine fails on the DACL) |
| 19 — `137f2b4a` | K6, K7 (AUTH-03, A3) | One `TokenVerifier` in the library; `detail::fixed_window_equals` compares zero-padded 256-byte windows, folds the length difference in, never matches an empty stored value. Reviewer disassembly: at `-O2` the compare is branch-free and both `explicit_bzero` calls survive. | `auth03_compare_touches_fixed_window`, `auth03_prefix_and_suffix_variants_rejected`, `auth03_router_uses_verifier` |
| 20 — `2b480430` | K8, K9 | Environment token wiped and unset after reading; `install_process_defaults()` sets `RLIMIT_CORE` 0 and `PR_SET_DUMPABLE` 0 (Linux) or `SetErrorMode` (Windows) for every binary that calls it. Windows scrub: accepted deviation (gaps below). | `cfg05_env_token_absent_from_proc_environ`, `server_process_is_not_dumpable` (POSIX). Windows scrub has no ctest case (wine probe only: `getenv`/`_wgetenv` null, Win32 entry absent): **unverified on Windows** (no CTest case, so CI run `38540719307` does not cover it) |
| 21 — `92a8419a`, fix `dae07073` | K10 | `strata-secure-server init --config FILE [--force]` writes the token first, then an owner-only config, atomically; refuses to replace either without `--force`; never prints the token. Fix: one JSON tree renderer shared with the tests; a non-regular config target is refused before anything is written; nothing is created on bad input. | `init_writes_config_and_token_then_server_starts`, `init_refuses_to_overwrite_without_force`, `init_force_refuses_a_non_regular_config_target`, `init_failure_creates_nothing` (`windows-runtime`: **verified in MSYS2, CI run `38540719307`**; wine fails three on the `D:P` gap) |
| 22 — `792b7651` | K11, K12 | CFG-05 end to end; CFG-06 at the type level. | `cfg05_token_absent_from_child_argv_env_and_outputs`, `cfg06_config_has_no_secret_typed_member`, `cfg06_validated_config_bytes_do_not_contain_token` (the first and third `windows-runtime`: **verified in MSYS2, CI run `38540719307`**) |
| 23 — `3810a67b`, fix `1904f827` | A1, A2, A4 | AUTH acceptance. Fix: the AUTH-04 sweep derives flags and `STRATA_*` names from the schema and usage text; AUTH-01 also sends a tab separator and a duplicate `Authorization` header over TCP. | `auth01_every_route_rejects_missing_malformed_wrong_token`, `auth01_socket_rejects_missing_and_wrong_token_on_every_route`, `auth02_valid_token_succeeds_and_is_not_echoed`, `auth04_empty_token_rejected_on_loopback`, `auth04_no_switch_disables_auth` (the four socket/process cases `windows-runtime`, pass under direct wine: **verified in MSYS2, CI run `38540719307`**) |
| 24 — this commit | D1–D5 | `render_config_schema_markdown()` generates the README key table from `config_schema()`; `secure_frontend/README.md` "Configuration" section and updated security contract; `docs/security/deployment.md` token and Windows ACL bullets; `engine-protocol-limits.md` keys vs internal constants (and the `EngineProtocolLimits` classification); this handoff; `secure-frontend-ci.md` label note; `bootstrap-llvm-mingw.sh` deletes an archive whose digest does not match. | `readme_config_table_matches_schema` (unlabelled; runs under wine too); D4 probe on a scratch copy (no network): before `exit=1` with the corrupt archive kept, after `exit=1` and an empty `downloads` |

Accepted deviations from the SP1 spec (controller and owner rulings):

- `limits.chat.max_body_bytes` defaults to 49152, not 262144: the spec's own
  cross-field rule (`≤ max_request_bytes − max_header_bytes` = 65536 − 16384)
  rejects 262144.
- `roots.tokenizer_pack` is required (spec §4 says optional) (R7).
- A config file and its directory may be owned by root as well as by the
  effective user (spec C7 says euid) (R7).
- The Windows root is opened through its own link or junction and its final
  path is taken (spec §3.4 says open with `OPEN_REPARSE_POINT`); every
  component **below** the root is opened with `OPEN_REPARSE_POINT` and reparse
  points are rejected (R7).
- `install_process_defaults()` hardening (non-dumpable, `RLIMIT_CORE` 0,
  `SetErrorMode`) applies to every binary that calls it, not only
  `strata-secure-server` (R7).
- Windows environment-token scrub: owner-ruled deviation from spec §3.6 (gap 3
  below).
- `parser_honors_configured_max_request_bytes` asserts `400`, not `413`, for
  an over-bound declared `Content-Length` (Task 7).
- `roots.secret` defaults to the config file's folder only for a `file:` token
  source; an `env:` source never opens it (Task 9 fix).
- `read_token(path)` and the smoke server's `--secret-root` must be absolute
  (spec §3.4) (Task 10).
- Under the models root, entries whose names fail the grammar are ignored only
  when they are non-`.gguf` files; non-portable directory names, `.gguf` files
  with bad names, symlinks and case-fold duplicates fail the inventory, naming
  the entry (Task 13).
- JSON config member names that are empty or contain `.` are rejected as
  unknown keys (Task 4 fix).
- `readme_config_table_matches_schema` strips `\r` before comparing, so a
  Windows checkout with `core.autocrlf=true` (GitHub's `windows-latest`) does
  not fail it (Task 24; the brief's version compared raw bytes).

### SP2 deliverables (branch `sp2-portable-supervision`; SP1 merged in at `9ded0a5c`)

Item IDs are from §4 of the SP2 spec. W rows are verified only by the
`windows-msys2-clang` CI job (pending rflores's push); the wine column is a smoke result.

Merge with SP1: `9ded0a5c` merges `main` (SP1 `e7f01b9e`, upstream
`v0.1.44.1`) into this branch. Since then the server, its command line
(`kFlags`) and its configuration (`FrontendConfig`) are SP1's, as described in
the SP1 section above; SP2's options become SP1 schema keys in later tasks
(18, 19, 26; verified in 29b). The rows from F1 to R2/R3 record counts on the
branch before the merge (N₀ = 111, W₀ = 102 after SP1 Task 2). **Post-merge
baseline (`9ded0a5c`):** linux-gcc 244 of 247 registered cases passed (the 3
server-harness cases failed because SP1's engine trust check refuses the
group-writable build-tree fake under the dev host's umask 0002; fixed by Task
29a, last row); wine `100% tests passed out of 141`; pytest `13 passed`; no
warnings in either preset.

| Item | What changed | Regression test | Local result (linux-gcc; wine) |
| --- | --- | --- | --- |
| F1 | Standalone test-only `strata-supervision-fake-engine` with the SP2 failure modes (crash modes never wait on WER); SP2 tests registered by acceptance ID through SP1's `secure_frontend_add_cases` (`<binary>.<case>`); baseline after SP1 Task 2: N₀ = 111, W₀ = 102. Naming deviation (ruling PF5): spec F1 says `strata-fake-engine`; the target is `strata-supervision-fake-engine` because SP1 owns `secure_frontend_fake_engine` — behaviour matches spec F1. `engine_stdio_process_tests` now launch the standalone fake (the in-binary `--fake-engine`/`--fake-sleeper` self-exec is gone). | `secure_frontend_fake_engine_tests.fake_engine_modes_selftest` | `100% tests passed out of 112`; wine `100% tests passed out of 102` (label `windows-runtime` excluded; a direct wine run of the case exits 0, with winedbg noise from the SEGV mode — authoritative in MSYS2, pending rflores's push) |
| F2 | DUMP reports FDS/HANDLES, ARGV (Windows via `CommandLineToArgvW`), sorted ENV, SIG masks, CWD, IDS (uid/gid/NoNewPrivs/CapEff; Windows SID/elevation/integrity), END; `--dump-file`; parser `tests/support/fake_engine_dump.hpp`. `child_inherits_only_stdio_descriptors` and `child_receives_exact_argv_and_env` read the report through the parser. | `secure_frontend_fake_engine_tests.fake_engine_dump_is_parseable` | `100% tests passed out of 113`; wine `100% tests passed out of 102` (label `windows-runtime` excluded); a direct wine run of the case exits 1 with only `FAILED: ENV is the sorted child environment` (wine's loader adds its own variables to the exact environment block the launcher passes; ARGV, HANDLES, CWD, IDS and `--dump-file` pass) — authoritative in MSYS2, pending rflores's push |
| F3 | `tests/support/server_harness.{hpp,cpp}` starts `strata-secure-server` with the fake engine (0700 fixture dirs, 0600 files, 43-character token, free port); on Windows always with a LUA-restricted non-elevated token (Safer `NORMALUSER` fallback; no override flag) and asserts it; stops it by signal / `CTRL_BREAK_EVENT` / kill; the destructor kills every descendant it has seen (Linux subreaper reaps orphans; Windows Job); counts descendants; reads stderr; `test_tokenizer.hpp` (byte tokenizer pack, real GPT-2 byte alphabet per ruling PF6). Runs against the server (SP1's since the merge); since Task 6b its `/health` answers `503` `engine=starting` until READY, then `200` `engine=ready`, so the self-test keeps the tolerant 200-or-503 assertion. Since Task 29a the harness copies the engine into a private `<root>/bin` (0700) and passes that copy (`ServerProcess::engine_path()`). Since the winfix branch (after CI run `38598235525`), on Windows: `root()` is in the server's canonical form (`GetFinalPathNameByHandleW`, `FILE_NAME_NORMALIZED`, `\\?\` removed), so A2's expected argv[0] and model path match an 8.3 `%TEMP%`; `descendants()` and `active_processes()` leave out console hosts (`%SystemRoot%\System32\conhost.exe`, the OS console server for the engine's `CREATE_NO_WINDOW` console, which sits in the harness Job) and `describe_processes()` lists every Job member as `pid:image` in the count assertions' failure text — pending the next MSYS2 run. | `secure_frontend_server_tests.harness_server_lifecycle_selftest` | `100% tests passed out of 114`; no fake engine left running afterwards; wine `100% tests passed out of 102` (label `windows-runtime` excluded); a direct wine run of the case exits 1 with `harness: no non-elevated token for strata-secure-server (LUA and Safer NORMALUSER both elevated)` (wine has no UAC; its token answers are not authoritative); Windows token path authoritative in MSYS2, pending rflores's push |
| K1, K3, K5 | `deadline.hpp`: one `deadline_after`/`remaining_until` rule in `await_ready`, `read_generation`, `read_line`; a zero budget is an immediate timeout everywhere. `terminate` contract documented (false only when still unreaped = abandoned). `current_executable()` checks `readlink`/`GetModuleFileNameW`. | `deadline_zero_timeout_is_immediate_everywhere` | `100% tests passed out of 115`; wine `100% tests passed out of 103` (the new deadline case is portable and unlabeled and passes under wine) |
| V1 | `EngineStdioProcess::try_reap()` keeps the raw `waitpid` / `GetExitCodeProcess` status; `classify_exit` maps it to `clean_exit`/`error_exit`/`spawn_failed`/`abort`/`killed_external`/`killed_by_supervisor(reason)`/`crashed` (log only); Windows Job kill code `0x20000001`, and Windows `terminate()` records it through `try_reap()`. | `secure_frontend_engine_child_tests.proc04_exit_status_is_classified` (B) | `100% tests passed out of 116`; wine `100% tests passed out of 103` (label `windows-runtime` excluded); a direct wine run of the case exits 1 with only `FAILED: the child must end: --crash-after-ready=SEGV` (wine starts winedbg on the page fault, so the child does not end in 10 s); the table, exit-1, ABRT and supervisor-kill (`0x20000001` via `try_reap()`) checks pass under wine; Windows authoritative in MSYS2, pending rflores's push |
| V2, V11 (core) | `EngineSupervisor` library: one supervisor thread spawns, consumes READY eagerly, watches and kills; the serving thread borrows the generation via `Lease`. `health_for`: `starting` → 503, `ready`/`generating` → 200; router's optional `recovery` literal (`restarting`/`exhausted`) only with `engine=failed`. Fresh `EngineInstance` per spawn. Restarts follow the V3 restart policy (Task 7). SP1-bound values in `supervision_defaults.hpp` (folded into SP1's `config_defaults.hpp` by Task 29a). Wired into the server by Task 6b (the V2, V11 row below). A spawn failure is logged by the supervisor as `engine generation <n> ended: spawn_failed`. Interface members not yet read in this run are kept for later tasks: `SupervisorConfig::shutdown_stdin_wait`, `SupervisedProcess::close_stdin`/`signal_group_terminate`, `kShutdownStdinWait` (Task 15 reads them now); `SupervisorConfig::no_new_privileges_hint`, `kNoNewPrivilegesDefault` (Task 26). | `secure_frontend_engine_supervisor_tests.supervisor_health_literals_per_state`, `secure_frontend_api_router_tests.health_samples_status_before_state_once_each` (updated), `secure_frontend_api_router_tests.health_carries_recovery_only_with_failed`, `secure_frontend_chat_execution_tests.chat_uses_adopted_ready_without_waiting` | `100% tests passed out of 119`; wine `100% tests passed out of 106` (all three new cases are unit cases and unlabeled, and pass under wine) |
| V3 | `RestartTracker`: 3 consecutive failures open the circuit; backoff 1 s → 2 s → … ≤ 60 s; 300 s healthy window resets the count; spawn failures count. Injectable `SupervisorClock` (`ManualClock` in tests; `tests/support/fake_supervised_process.hpp`). Three client-triggerable ERR lines in a row open the circuit until a restart (Review Focus 6, accepted). Spec §3.1: an ended generation still held by a `Lease` waits in the supervisor's `retired_` list and is destroyed by the supervisor thread once the Lease lets go (never on the serving thread); an unreaped generation at shutdown goes to `abandoned_`. | `secure_frontend_engine_supervisor_tests.proc04_restart_backoff_then_circuit_open`, `secure_frontend_engine_supervisor_tests.proc04_healthy_window_resets_failure_count`, `secure_frontend_engine_supervisor_tests.proc04_recovers_after_transient_crash`, `secure_frontend_engine_supervisor_tests.proc04_missing_engine_opens_circuit_without_spinning` (Review Focus 2), `secure_frontend_engine_supervisor_tests.proc04_client_err_lines_open_circuit_until_restart` (Review Focus 6), `secure_frontend_engine_supervisor_tests.supervisor_retires_ended_generation_on_its_own_thread` | `100% tests passed out of 125`; wine `100% tests passed out of 111` (five new unit cases pass under wine; `proc04_recovers_after_transient_crash` is a process case, labeled windows-runtime — authoritative in MSYS2, pending rflores's push) |
| V4 | The supervisor waits on the child: pidfd (Linux 5.3+; the test asserts `monitor_handle() != kNoMonitorHandle` on Linux, so the pidfd path is proven, not just the fallback), process handle (Windows), else a 100 ms `waitpid(WNOHANG)` poll. Spec V4's "`/health` leaves ready within 1 s" was first proven at supervisor level (`wait_for_state`, ruling PF11); Task 6b (fix round 1) adds the `/health` form against the wired server: the engine is killed externally (POSIX SIGKILL, Windows TerminateProcess) with no request in flight and `/health` must stop reporting `ready` within 1 s. Linux proven; Windows pending MSYS2. Spec §3.3 (carried from the V3 review): a wake that is not shutdown — a released Lease, a stale `report_fatal` notify — no longer cuts the backoff short: `schedule_restart` sleeps out the remainder to the deadline and sweeps on each wake; `release()` of a retired generation wakes the supervisor so it is swept promptly, also in `circuit_open`. | `secure_frontend_engine_supervisor_tests.proc04_monitor_detects_idle_crash`, `secure_frontend_engine_supervisor_tests.proc04_monitor_fallback_without_pidfd`, `secure_frontend_engine_supervisor_tests.proc04_backoff_survives_stale_wake` (§3.3), `secure_frontend_server_tests.proc04_health_leaves_ready_after_idle_engine_death` (B, Task 6b fix round 1; `100% tests passed out of 254`; labeled windows-runtime, wine `100% tests passed out of 142` — Windows authoritative in MSYS2, pending rflores's push) | `100% tests passed out of 128`; wine `100% tests passed out of 113` (`proc04_monitor_fallback_without_pidfd` and `proc04_backoff_survives_stale_wake` pass under wine; `proc04_monitor_detects_idle_crash` is a process case, labeled windows-runtime — authoritative in MSYS2, pending rflores's push) |
| V5 | The four upstream `FATAL_PREFIXES` (`kEngineFatalPrefixes`, verbatim from `upstream/serve/server.py:734-735` at `v0.1.44.1`; the earlier `:587-588` citation does not match this tag) fail the protocol (`fatal_engine_line`, fixed message, trailing `DONE` not accepted), checked in both `await_ready` and `read_generation` right after `validate_incoming`; `kill_reason_for` maps it to `KillReason::fatal_line`, so the supervisor kills the group and restarts (`killed_by_supervisor(fatal_line)`). Correction (Task 10, spec §3.8): until Task 10 a fatal line before READY was logged `killed_by_supervisor(protocol_failed)`, because the supervisor's `await_ready` hard-mapped every non-timeout READY failure; it now maps them through `kill_reason_for`, so a pre-READY fatal line is `fatal_line` too (`proc04_fatal_line_before_ready_kills_as_fatal_line`, V6/V7 row). Other `ERR` lines keep SP0's per-request behavior; the failed generation is replaced. | `secure_frontend_engine_supervisor_tests.proc04_fatal_prefix_kills_engine` (protocol level for each prefix, then supervisor level with `--fatal-line=0..3`) | `100% tests passed out of 129`; wine `100% tests passed out of 113` (process case, labeled windows-runtime — authoritative in MSYS2, pending rflores's push; a direct wine run of the case also passes) |
| V6, V7 | READY deadline `ready_timeout` (900 s default) kills and counts (`killed_by_supervisor(ready_timeout)`); an engine that ignores STOP is killed and replaced (`drain_failed`): `abandon()` records `EngineProtocolErrorCode::abandoned` when no earlier failure was recorded, and `kill_reason_for` maps it to `KillReason::drain_failed`. Spec §3.8: non-timeout READY failures are mapped through `kill_reason_for` (a fatal line before READY is `fatal_line`, not `protocol_failed`). (V8: Task 6b.) | `secure_frontend_engine_supervisor_tests.proc04_ready_timeout_kills_and_counts`, `secure_frontend_engine_supervisor_tests.proc04_drain_failure_kills_and_restarts`, `secure_frontend_engine_supervisor_tests.proc04_fatal_line_before_ready_kills_as_fatal_line` (§3.8) | `100% tests passed out of 132`; wine `100% tests passed out of 114` (`proc04_fatal_line_before_ready_kills_as_fatal_line` is a unit case and passes under wine; the V6 and V7 cases are process cases, labeled windows-runtime — authoritative in MSYS2, pending rflores's push; a direct wine run of each also passes) |
| V9, V10 | Ten forced restarts leave one live engine, no zombie, a stable descriptor/handle count and an empty stdout buffer in each new generation. A killed child that cannot be reaped within `reap_timeout` (30 s) is abandoned and opens the circuit; nothing respawns while it lives. | `secure_frontend_engine_supervisor_tests.proc04_no_leak_across_restarts`, `secure_frontend_engine_supervisor_tests.proc04_unreaped_child_opens_circuit` | `100% tests passed out of 134`; wine `100% tests passed out of 115` (`proc04_unreaped_child_opens_circuit` is a unit case and passes under wine; `proc04_no_leak_across_restarts` is a process case, labeled windows-runtime — authoritative in MSYS2, pending rflores's push; a direct wine run of it also passes). Winfix ruling: CI run `38598235525` showed exactly +1 handle from generation 2 on, never growing (88 vs 87 at generations 2..11); on Windows the baseline is now generation 2 (9 restarts compared against it), and the case prints the handle types that changed between generations 1 and 2 to name the one-time allocation — pending the next MSYS2 run |
| C1 | POSIX `terminate()` always ends with `kill(-pgid, SIGKILL)`, also after the leader was reaped; the group id is forgotten only after success. | `secure_frontend_engine_child_tests.proc05_group_killed_after_leader_reaped` (L) | `100% tests passed out of 135`; wine unchanged, `100% tests passed out of 115` (Linux-only case, not registered in the cross build; cross build `-Werror` clean) |
| C2 | The frontend is the child subreaper (`PR_SET_CHILD_SUBREAPER`). When a generation ends and its leader is reaped (restart path, 1 s bound) and at shutdown (250 ms bound, inside the shutdown budget), it SIGKILLs and reaps every child that is not a live engine, so `setsid`/`setpgid`/double-fork escapes die and leave no zombie. If the leader stays unreaped, the circuit opens without a sweep. | `secure_frontend_engine_supervisor_tests.proc05_setsid_grandchild_is_reaped` (L), `secure_frontend_engine_supervisor_tests.proc05_setsid_grandchild_is_reaped_at_shutdown` (L) | `100% tests passed out of 137`; wine unchanged, `100% tests passed out of 115` (Linux-only cases, not registered in the cross build; cross build `-Werror` clean) |
| C3 | Pre-exec `PR_SET_PDEATHSIG(SIGKILL)` + `getppid()` recheck against the pid `prepare` records before fork (mismatch → `_exit(127)`); forks only from the supervisor thread (the server too since Task 6b). Residual risk (spec §3.7): without a delegated cgroup, the engine's own descendants survive a frontend SIGKILL — logged by the test as "residual risk (spec 3.7): grandchild survived after a frontend SIGKILL without a delegated cgroup". The test waits for the grandchild pidfile, not `/health`. Task 16 (fix round 1 ruling): with a delegated cgroup, nothing writes `cgroup.kill` after a frontend SIGKILL, so the test does not assert that the grandchild dies. It asserts that `/proc/<grandchild>/cgroup` names the generation directory `strata-engine-<frontend pid>-1`. It logs "grandchild remains until the scope's cgroup.kill (frontend SIGKILL residual, delegated)". It then cleans up itself: writes `cgroup.kill` and removes the directory. | `secure_frontend_server_tests.proc05_frontend_sigkill_kills_engine` (L) | `100% tests passed out of 138`; wine unchanged, `100% tests passed out of 115` (Linux-only case, not registered in the cross build; cross build `-Werror` clean) |
| C4, C7 | SIGTERM/SIGINT → `shutdown_signal.cpp` (`sigaction` without `SA_RESTART`; the handler sets a lock-free `std::atomic<int>` flag (final review M3), fires the supervisor's self-pipe with one `write(2)` and restores `errno`) → supervisor thread runs the spec §3.7 order in `shutdown_generation`: EOF on engine stdin (skipped while a Lease is out, so no EOF lands under a request), wait 2 s, SIGTERM group, wait 1 s, SIGKILL group always, reap, 250 ms sweep, retire (ruling RF5: `retire(instance, reaped)`, `sweep_retired()` and the one 250 ms sweep kept; no second sweep in `finish()`; worst case 4.35 s with the ~100 ms delegated-cgroup removal, matching `cgroup_scope.hpp` and `engine_supervisor.cpp`); log `engine generation <n> ended: killed_by_supervisor(shutdown)` (an exit 0 on our EOF is an exit we requested, §3.6); then `finish()` calls `HttpSocketServer::shutdown_listener()` (POSIX `shutdown(2)` wakes `accept()`; Windows `closesocket`; since final review I1 it also `shutdown()`s the client `serve_one()` is handling and the request read re-checks every 100 ms, so an idle client cannot hold `main`: worst case 4.35 s + 0.1 s), reports `stopped`, and waits for `main`'s `shutdown()`; `main` leaves the serve loop on `stop_requested()` and returns 0, or 1 when a generation was never reaped (final review I2: `finish()` logs `engine supervisor stopped with an unreaped engine: exit 1` and `engine_left_unreaped()` is true); past 5 s either side `_exit(1)`. An RAII guard in `run` stops the supervisor on every exit path while the listener still exists. RF4: a Lease reaches the supervisor through a `LeaseLink` that `shutdown()` and the destructor detach, so a Lease that outlives `shutdown()` (or the supervisor) never touches it; `~EngineSupervisor` unhooks its wake from the signal handlers. The production binary's only child is the engine, executed directly (argv[0] = `--engine` path). | `secure_frontend_server_tests.proc05_frontend_sigterm_stops_all_descendants`, `secure_frontend_server_tests.proc05_frontend_sigint_stops_all_descendants` (L; `--spawn-grandchild`: exit 0 within 5 s, engine and grandchild gone, port refuses, shutdown log line), `secure_frontend_server_tests.proc05_frontend_has_only_engine_children` (C7, L; spec Fix "—": passed first run; `/proc/<child>/exe` = canonical `engine_path()` and argv[0] = `engine_path()`), `secure_frontend_server_tests.proc05_sigterm_during_generation_exits_cleanly` (Review Focus 3), `secure_frontend_server_tests.proc05_double_sigterm_is_idempotent` (Review Focus 5); unit: `secure_frontend_engine_supervisor_tests.supervisor_shutdown_sends_eof_first_then_kills`, `secure_frontend_engine_supervisor_tests.supervisor_lease_outliving_shutdown_is_safe` (RF4; destroys the supervisor and poisons its memory before the Lease ends — aborted with `std::system_error` before the fix), `secure_frontend_engine_supervisor_tests.shutdown_signal_preserves_errno` (L; full self-pipe so the handler's write fails with `EAGAIN`), `secure_frontend_http_socket_server_tests.socket_server_shutdown_listener_wakes_accept` | `100% tests passed out of 263` (1 skipped: `proc03_other_uid_cannot_open_engine_fd`); wine `100% tests passed out of 145` (the EOF, Lease and listener cases are portable and pass under wine; the server cases are labeled windows-runtime and the errno case is Linux-only); cross build `-Werror` clean; pytest 13 passed |
| C5 | Delegated cgroup v2 detected (writable own cgroup with `cgroup.kill` and an empty `cgroup.subtree_control`, never created with privileges): each generation joins `strata-engine-<frontend pid>-<n>` before `execve`. The directory name is unique per frontend. A `mkdir` that fails, EEXIST included, means the generation runs without a cgroup and logs the fixed literal `engine generation <n>: cgroup unavailable` (no path). Cleanup writes `cgroup.kill`, waits for `populated 0` for at least `kCgroupRemoveBound` (100 ms, so the 0 ms shutdown and exception callers also remove the directory; shutdown worst case 4.35 s < 5 s), then removes the directory. A failed removal keeps the directory recorded, and `cleanup()` kills and retries it. A spawn that fails (open_cgroup, fork or execve) removes its empty directory. Off unless detected. Ruling RF8: `posix_launch::prepare` stays `void`; the cgroup fd is opened by `[[nodiscard]] bool posix_launch::open_cgroup(PreparedExec&, const EngineCommand&)`, called after `prepare` at both engine call sites (failure → `platform_failure` "engine cgroup setup failed"); the child writes it right after `setpgid` (preflight D-9 order). The server sets `plan.use_delegated_cgroup = true` (detected, no config key). | `secure_frontend_engine_supervisor_tests.proc05_cgroup_kill_when_delegated` (L; SKIPPED here: no delegated cgroup — this host runs in `/user.slice/user-1000.slice/session-3.scope`; prints "SKIP: no delegated cgroup v2 is writable here; run under systemd-run --user --scope -p Delegate=yes to exercise it", exit 77), the C5 case asserts the setsid grandchild's `/proc/<pid>/cgroup` names the generation directory before the kill; C3 `proc05_frontend_sigkill_kills_engine` asserts cgroup membership (not death) when delegated, logs the residual and cleans up (delegated branches not exercised here) | `100% tests passed out of 264` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine unchanged, `100% tests passed out of 145` (Linux-only case, not registered in the cross build; cross build `-Werror` clean); pytest 13 passed. RED/GREEN inside a delegated scope pending rflores's approval to run `systemd-run --user --scope -p Delegate=yes ctest --preset linux-gcc -R proc05_cgroup --output-on-failure` |
| C6 | Windows launch (`engine_stdio_process.cpp` and its SP0 twin `engine_process.cpp`): `CREATE_NEW_PROCESS_GROUP` (Ctrl-C is disabled in the engine's group; group-targeted Ctrl-Break reaches only the frontend) and, since Task 15 (ruling RF4), `CREATE_NO_WINDOW`: the engine runs without the frontend's console, so a console-wide Ctrl-Break or a closed console window reaches only the frontend; the Job adds `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION` to `KILL_ON_JOB_CLOSE`; `SetErrorMode(GetErrorMode() \| SEM_NOGPFAULTERRORBOX \| SEM_FAILCRITICALERRORS)` once per process before spawn, inherited by the engine. Task 15: `SetConsoleCtrlHandler` (CTRL_C, CTRL_BREAK, CTRL_CLOSE) sets the shutdown flag and fires the supervisor's wake, then holds the handler thread (at most 5 s) until the supervisor reports every engine gone, so the same §3.7 order as C4 runs. New fake flag `--default-error-mode` (the fake skips its own `SetErrorMode` and runs with the mode it inherited). | `secure_frontend_server_tests.proc05_windows_ctrl_break_stops_all_descendants` (W; `--spawn-grandchild`: CTRL_BREAK to the server's group → exit 0, Job `ActiveProcesses` 0), `secure_frontend_server_tests.proc05_windows_terminate_frontend_kills_job` (W; TerminateProcess → kill-on-close Job takes engine and grandchild); supervisor-level smokes of the launch settings: `secure_frontend_engine_supervisor_tests.proc04_windows_abort_does_not_stall` (W; `--abort-in-gen --default-error-mode`: abort / fastfail path, error mode only), `secure_frontend_engine_supervisor_tests.proc04_windows_crash_does_not_stall` (W; `--crash-after-ready=SEGV --default-error-mode`: a real unhandled exception, so the Job's `DIE_ON_UNHANDLED_EXCEPTION` is on the path; end classified `crashed` within 5 s) | Task 17: `100% tests passed out of 138`; wine `100% tests passed out of 115`. Task 15: `100% tests passed out of 263`; wine `100% tests passed out of 145` (the two server cases are labeled windows-runtime and excluded); cross build `-Werror` clean; direct wine runs of both server cases exit 1 with `FAILED: ready` because the harness prints `harness: no non-elevated token for strata-secure-server (LUA and Safer NORMALUSER both elevated)` (wine has no UAC, as in the F3 row), so wine cannot show the console handler; Task 17's direct wine runs: `proc04_windows_abort_does_not_stall` exits 0 (wine has no WER dialog), `proc04_windows_crash_does_not_stall` exits 1 (wine starts winedbg on the access violation) — **authoritative in MSYS2, pending rflores's push** (watch: the engine's stdio with `CREATE_NO_WINDOW`). Known limits (Task 15 review): the `CTRL_CLOSE` handler's return races the process exit code; on Windows `signal_group_terminate` is a no-op, so the 1 s TERM wait of the §3.7 order is idle there (EOF, then the Job kill). `SetErrorMode` pair: SP1's `install_process_defaults()` replaces the process error mode, then SP2's launch ORs `SEM_NOGPFAULTERRORBOX \| SEM_FAILCRITICALERRORS` into it; both set the same bits, so the order does not matter |
| N4 | Fork with every signal blocked (`posix_launch::BlockAllSignals` around `fork()` in `engine_stdio_process.cpp` and its SP0 twin `engine_process.cpp`); the child (`posix_launch::reset_signal_state()`, called in `exec_child` immediately before `execve`) resets every disposition but SIGKILL/SIGSTOP to `SIG_DFL` and clears the mask before `execve`. | `secure_frontend_engine_child_tests.proc02_child_signal_state_is_default` (L) | `100% tests passed out of 139`; wine unchanged, `100% tests passed out of 115` (Linux-only case, not registered in the cross build; cross build `-Werror` clean) |
| N5 | Canaries: a non-CLOEXEC fd, a listening socket and an open token file never reach the engine (Linux: `FDS 0,1,2`); Windows: an inheritable file, event and socket are absent from the engine's handle table (parent-side `NtQueryInformationProcess(ProcessHandleInformation)` + `CompareObjectHandles`, both resolved via `GetProcAddress`; the snapshot must list at least 3 handles and at least one must duplicate, and a positive control plants the event in the engine with `DuplicateHandle` and requires the same inspection to find it, so a failed inspection cannot pass as "absent"). No production change (existing sweep / handle list); both passed on their first run where runnable. | `secure_frontend_engine_child_tests.proc02_canary_descriptors_absent` (L), `secure_frontend_engine_child_tests.proc02_canary_handles_absent` (W) | `100% tests passed out of 140`; wine unchanged, `100% tests passed out of 115` (W case labeled windows-runtime, excluded); cross build `-Werror` clean; a direct wine run of `proc02_canary_handles_absent` exits 1 with `FAILED: inspection APIs are available (Windows 10 1607+)` (wine 6.0.3's kernelbase does not export `CompareObjectHandles`; not a leak finding) — **W authoritative in MSYS2, pending rflores's push** |
| N6, R1, K2 | Windows stdin pipe: protected DACL with one ACE for the current user, `\\.\pipe\secure_frontend-<pid>-<128-bit random>` (SP1's `fill_random()` since Task 29a; `BCryptGenRandom` directly before), single instance, remote clients rejected, `GetNamedPipeClientProcessId` must be our pid (a mismatch fails start with ERROR_ACCESS_DENIED; that path is untested, it cannot be provoked without racing our own client open); frontend end `FILE_FLAG_OVERLAPPED`, 64 KiB buffer and chunks, 1 s no-progress deadline per 64 KiB chunk (plus, since R1, an overall bound: see the "R1 (Task 22 / K2 overall bound)" row) then `CancelIoEx` → write failure → `killed_by_supervisor(write_timeout)`. Limits doc updated by Task 28 (`docs/security/engine-protocol-limits.md`, "Windows stdin writes": both bounds). | `secure_frontend_engine_child_tests.proc02_stdin_pipe_dacl_is_owner_only`, `secure_frontend_engine_child_tests.proc03_windows_pipe_second_open_fails` (a `GENERIC_READ` client open must fail with exactly `ERROR_PIPE_BUSY`, and a rival `CreateNamedPipeW` on the name must be refused), `secure_frontend_engine_supervisor_tests.proc04_windows_write_timeout_kills_engine` (all W; K2: 60,000-token prompt, ~240 KB GEN line, 2 s generation timeout, CTest timeout 300 s) | Linux unchanged, `100% tests passed out of 140`; wine unchanged, `100% tests passed out of 115` (W cases labeled windows-runtime, excluded); cross build `-Werror` clean; direct wine runs: all three exit 0 (K2 in ~1.5 s), also after fix round 1; RED under wine before the fix: K2 failed `the blocked write is cancelled at its deadline` / `killed as write_timeout` (the write fit the old 16 MiB buffer) — **W authoritative in MSYS2, pending rflores's push** |
| A1, A2 | Windows argv twin: quotes, backslashes (incl. trailing), `%PATH%`, `^&\|<>()`, newline, UTF-8, empty string round-trip through the frontend's quoting and `CommandLineToArgvW`. End to end: `--engine-arg` values with shell metacharacters and the inventory `--native` reach the engine as literal argv entries with no shell (since Task 19 the case also passes the typed `--gpu 0,1` and expects `--gpu`, `0,1` directly before `--native`). No production change; both passed on their first run where runnable (A2 runs against the current server; the fake writes `--dump-file` before READY; since Task 29a the expected argv[0] is the private engine copy, `ServerProcess::engine_path()`, which SP1 passes in canonical form). | `secure_frontend_engine_child_tests.proc01_windows_argv_round_trip` (W), `secure_frontend_server_tests.proc01_server_passes_literal_argv` (B) | `100% tests passed out of 141`; wine unchanged, `100% tests passed out of 115` (both cases labeled windows-runtime, excluded); cross build `-Werror` clean; direct wine run of `proc01_windows_argv_round_trip` exits 0; direct wine run of `proc01_server_passes_literal_argv` exits 1 with `harness: no non-elevated token for strata-secure-server` / `FAILED: the server must listen` (known wine limit: no UAC, the restricted-token harness cannot launch the server; not an argv finding) — **W and the Windows run of B authoritative in MSYS2, pending rflores's push** |
| R2, R3 | Linux PROC-03 = other user context: `nobody` cannot open `/proc/<engine>/fd/0` (CI via `sudo -n -u nobody`, env `STRATA_TEST_SECOND_UID_SUDO=1`, set on the Linux ctest step for both linux-gcc and linux-clang; skipped locally with its reason printed, never run with the variable set outside CI). With the variable set, a failing `sudo -n -u nobody` is a failure, not a skip; a same-uid run of the identical probe must open the path (positive control), the `nobody` probe must exit 4 (open refused, not engine gone/hidepid), and the engine must still answer DUMP afterwards. Same-uid reopen and injection is the recorded accepted risk (threat model "Engine process isolation"; release record). No production change; R3 passed on its first run. | `secure_frontend_engine_child_tests.proc03_other_uid_cannot_open_engine_fd` (L, CI only, `SKIP_RETURN_CODE 77`), `secure_frontend_engine_child_tests.proc03_same_uid_reopen_is_accepted_risk` (L) | `100% tests passed out of 143` (1 skipped: `proc03_other_uid_cannot_open_engine_fd`, printing `SKIP: needs a second uid: CI sets STRATA_TEST_SECOND_UID_SUDO=1 where` … `is allowed`); wine unchanged, `100% tests passed out of 115` (Linux-only cases compiled out); cross build `-Werror` clean — **R2 authoritative in the GitHub Linux jobs, pending rflores's push** |
| SP1 reconcile (29a) | Post-merge reconcile. (1) `ServerProcess::start` copies the engine (default the fake) into a private `<root>/bin` (directory 0700, file 0700 on POSIX; Windows: the protected owner-only DACL of `make_private_directory`, as SP1's `ServerFixture`) and passes the copy; `ServerProcess::engine_path()` exposes it (canonical on POSIX) and A2 expects it as argv[0]. SP1's engine trust check is unchanged. The harness's own free-port helper is gone; it calls SP1's `secure_frontend_test::pick_free_port`. (2) `supervision_defaults.hpp` folded into `config_defaults.hpp` and deleted; `RestartPolicy::ready_timeout` defaults to `kEngineReadyTimeoutS` (900 s, one copy); `SupervisorConfig supervisor_config(const FrontendConfig&)` in `subsystem_limits` (chat limits, `policy.ready_timeout` from `limits.engine.ready_timeout_s`, profile and protocol flavor); not yet used by the server (Task 6b). (3) The Windows stdin pipe name's 128 random bits come from SP1's `fill_random()`; `secure_frontend_engine_stdio_process` links `secure_frontend_secrets` instead of `bcrypt`. (4) `EngineProcess` (SP0) is marked test-only; its `terminate` keeps its behaviour without C1's unconditional group SIGKILL (ruling RF12). | `secure_frontend_server_tests.harness_server_lifecycle_selftest`, `secure_frontend_server_tests.proc01_server_passes_literal_argv`, `secure_frontend_server_tests.proc05_frontend_sigkill_kills_engine` (all three RED on the merged tree, GREEN now), `secure_frontend_subsystem_limits_tests.supervisor_policy_follows_config` (new; labeled windows-runtime like its binary's other cases); the pipe-name change is covered by the existing N6/R1/K2 cases | `100% tests passed out of 248` (1 skipped: `proc03_other_uid_cannot_open_engine_fd`); wine `100% tests passed out of 141` (the new case is labeled windows-runtime and excluded; direct wine runs of `supervisor_policy_follows_config`, `proc02_stdin_pipe_dacl_is_owner_only` and `proc04_windows_write_timeout_kills_engine` exit 0); cross build `-Werror` clean — W authoritative in MSYS2, pending rflores's push |
| V2, V11 | The production server runs the engine through `EngineSupervisor` (Task 6a): READY is consumed eagerly; `/health` `starting` → `503` (reverses SP0's `200`, true now that READY is eager), `ready`/`generating` → `200`, optional `recovery` only with `engine=failed`; one snapshot per `/health`. A chat outside `ready` is an immediate generic `503`; parse before acquire (SP1's pre-parse `engine.running()` check is gone, EXT-01). The supervisor's configuration is `supervisor_config(config)` (Task 29a: chat limits, profile, flavor, READY deadline from `limits.engine.ready_timeout_s`); `supervisor.start()` runs after the bind and after the token read (CFG-01); the supervisor is declared before the listener and router, and a `Lease` lives only inside one `execute_with_lease()` call. `server_usage()` describes supervision. SP1 e2e cases that chat or expect a `200` `/health` first call `ServerFixture::wait_engine_ready()` (Task 29 Step 6 + ruling RF3: `auth02_valid_token_succeeds_and_is_not_echoed`, `init_writes_config_and_token_then_server_starts`, `cfg03_engine_receives_canonical_models_root`, `cfg05_token_absent_from_child_argv_env_and_outputs`, the `5` branch of `ready_timeout_is_configurable`). `ready_timeout_is_configurable` is now a true test of the supervisor's READY deadline (fix round 1): with `ready_timeout_s=1` against a 2 s READY the engine never becomes ready within 4 s and the server logs `killed_by_supervisor(ready_timeout)`; with `5` it becomes ready, the chat is `200` and no such kill is logged (a mutation that drops the config→policy line in `supervisor_config` fails it). SP1's CFG-01 case asserts neither `Unable to start the engine supervisor` nor an `engine generation` line was printed. | `secure_frontend_server_tests.proc04_ready_is_eager_and_health_starting_is_503`, `secure_frontend_server_tests.proc04_chat_during_restart_is_generic_503` | `100% tests passed out of 254` (1 skipped: `proc03_other_uid_cannot_open_engine_fd`; 253 at `0e23d220`, +1 V4 server case in fix round 1); wine `100% tests passed out of 142` (server cases labeled windows-runtime, excluded) — Windows authoritative in MSYS2, pending rflores's push |
| V8 | An abort mid-generation answers the client with the fixed generic `503`, logs `abort`, and the supervisor recovers. No production change of its own. | `secure_frontend_server_tests.proc04_abort_in_generation_is_generic_503` | `100% tests passed out of 254` (1 skipped: `proc03_other_uid_cannot_open_engine_fd`; 253 at `0e23d220`, +1 V4 server case in fix round 1); wine `100% tests passed out of 142` (labeled windows-runtime, excluded) — Windows authoritative in MSYS2, pending rflores's push |
| Supervisor hardening (RF4, Task 6b) | `EngineSupervisor::start()` is `[[nodiscard]] bool`: it refuses (false, nothing spawned) when `SupervisorWake` could not create its pipe/event (`SupervisorWake::valid()`) or the thread cannot be created, and the server then exits with `Unable to start the engine supervisor.` An exception escaping the supervisor thread (factory, log sink, clock, allocation) never reaches `std::terminate`: the thread kills and reaps the current generation, opens the circuit (`/health` `failed`/`exhausted`, logged `engine supervisor failed: circuit open`; a reaped generation gets the 250 ms orphan sweep and `release_resources` first, as in `end_generation`/`shutdown_generation`, spec §3.7(b)) and still ends in `stopped` on shutdown. The descendant sweep's `/proc/self/task` loop uses `directory_iterator::increment(ec)`. | `secure_frontend_engine_supervisor_tests.supervisor_exception_opens_circuit` (factory, log sink, and clock with a live generation), `secure_frontend_engine_supervisor_tests.supervisor_start_refuses_without_wake` (L; `RLIMIT_NOFILE` 0 while the supervisor is built) | `100% tests passed out of 254` (1 skipped: `proc03_other_uid_cannot_open_engine_fd`; 253 at `0e23d220`, +1 V4 server case in fix round 1); wine `100% tests passed out of 142` (`supervisor_exception_opens_circuit` is a unit case and passes under wine; the wake case is Linux-only) |
| N1, N2, N3 | `EngineEnvironment` → the child gets exactly: POSIX `PATH=/usr/bin:/bin`, `LD_LIBRARY_PATH`, `TMPDIR=<state>/engine-tmp/<gen>`, `CUDA_CACHE_PATH=<state>/cache/cuda` (`<roots.cache>/cuda` when `roots.cache` is set, since Task 29b) (+ optional `STRATA_HIPBLASLT_TUNING`, `STRATA_WATCHDOG_S`, `STRATA_WATCHDOG_IO_S`); Windows `PATH=<lib dirs>;%SystemRoot%\System32`, `TEMP`, `TMP`, `CUDA_CACHE_PATH`, `SystemRoot`, `WINDIR`, `SystemDrive`, `NUMBER_OF_PROCESSORS`. Never the token variable, `STRATA_API_KEY`, other `STRATA_*`, `LD_PRELOAD`/`LD_AUDIT`, `CUDA_LAUNCH_BLOCKING`, `HOME`/`USERPROFILE`/`APPDATA`, proxies, or GPU-selection variables. New required `--state-dir` (SP1 key `roots.state`: `validate()` checks only absolute / non-empty / no NUL, so `--check` stays side-effect free; serve refuses with `roots.state (--state-dir) is required to serve.` when unset and, before anything is created, bound or spawned, with `--state-dir must be an existing owner-only directory.` unless `is_private_state_root` holds: POSIX `lstat` shows a real directory (not a symlink) owned by the effective uid with `mode & 077 == 0`; Windows opens it with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`, refuses a junction/symlink (`is_reparse_point`) and requires SP1's `has_private_owner_dacl` for the current user (owner = user, protected DACL, allow-ACEs only for the user, SYSTEM, Administrators — a read ACE for anyone else is refused). **Accepted limitation:** POSIX `lstat` checks only the final component, so a parent directory writable by another user could swap the state root after the check; place `--state-dir` below owner-controlled parents. **MSYS2 watch:** the Windows check requires the state root's owner to be the current user (an elevated admin's default owner is Administrators); test state roots are therefore created with `make_owner_private_directory` (explicit `O:<user>`, SP1's `ProtectedAttributes`) in the harness, `ServerFixture` and the state-dir cases — not observable under wine. `--engine-lib-dir` (SP1 key `engine.lib_dirs`, repeatable, each absolute and free of the platform list separator `:`/`;`; default the engine executable's directory). Serve creates `<state>/engine`, `engine-tmp` and the CUDA cache owner-only: `<state>/cache/cuda` (with `<state>/cache`) only when `roots.cache` is unset, otherwise `<roots.cache>/cuda` (Task 29b). Per-generation temp `<state>/engine-tmp/<n>` is removed by `release_resources()` after the generation is reaped; `engine-tmp/*` is cleared at startup. SP1 test support updated (RF7): `ServerFixture` gains a 0700 `state` root in `base_flags()`/`base_literals()`, `server_cli_test` `init_flags` passes `--state-dir`; the README key table is regenerated (`readme_config_table_matches_schema`) and the README serve example gains `--state-dir`. **Not GPU-verified** (offline GPU box, rflores). | `secure_frontend_engine_supervisor_tests.proc02_child_env_is_exact_allowlist`, `secure_frontend_engine_stdio_process_tests.child_receives_exact_argv_and_env` (now asserts env), `secure_frontend_engine_process_tests.proc02_engine_process_env_checks_windows_names`, `secure_frontend_server_tests.state_dir_must_be_owner_only` (Review Focus 1), `secure_frontend_server_tests.state_dir_must_be_owner_only_windows` (Users read ACE, junction root; MSYS2 pending), `secure_frontend_server_tests.state_dir_stale_engine_tmp_is_cleared`, `secure_frontend_server_cli_tests.serve_requires_state_root`, `secure_frontend_typed_config_tests.engine_lib_dirs_must_be_absolute_directories` (fix round 1) | `100% tests passed out of 267` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine unchanged, `100% tests passed out of 145` (the three new process/server cases are labeled windows-runtime: authoritative in MSYS2 — pending rflores's push; a direct wine smoke of N3 passes, and of N1 shows every rendered entry present plus only wine's own injected `WINE*`, `ProgramFiles*`, `CommonProgramFiles*` names); cross build `-Werror` clean; pytest 13 passed |
| §3.9 GPU | `--gpu LIST` (typed, 0–255, distinct, ≤ 16; no sign, space or leading zero; SP1 key `engine.gpu` with its `kFlags` row and `EngineLaunch::gpus`) is parsed by `parse_gpu_list` in `validate()`, so a malformed value (`0,0`, `-1`, `1,,2`, ` 1`, `256`, `01`, 17 entries; empty is SP1's `empty value for --gpu`) is a startup error with the fixed text `engine.gpu: must be a comma-separated list of distinct device indices 0-255, at most 16` that never echoes the value and never reaches the engine. `build_engine_arguments(..., gpus)` renders the engine's own `--gpu i,j` directly before `--native`; the engine sets `CUDA_DEVICE_ORDER`/`CUDA_VISIBLE_DEVICES` (or HIP) itself (upstream `src/program/generate.cpp:1844-1865`, usage `:706-708`, at v0.1.44.1; the spec's `:1765-1786` predates the bump). `--gpu` is frontend-owned for `--engine-arg`/`engine.args` in both profiles (`owned_flag`, refused by `validate_engine_user_arguments` before anything is spawned; the GLM branch refused only `--serve` before); the GLM profile refuses a typed GPU list (`engine.gpu: is not supported with engine.profile glm53`; `unsupported_mode` in `build_engine_arguments`). Strata family: no GPU variable in the engine environment (a later SP6 glm family renders `CUDA_DEVICE_ORDER`/`CUDA_VISIBLE_DEVICES` from typed configuration; not implemented here). `server_usage()` lists `--gpu` and says `--engine-arg` refuses `--native`, `--serve` and `--gpu`; `--check` prints `engine.gpu`; README key table regenerated (RF7). **Not GPU-verified** (offline GPU box, rflores). | `secure_frontend_engine_arguments_tests.engine_args_render_typed_gpu_and_deny_gpu_passthrough` (incl. GLM `--gpu` passthrough refused; labeled windows-runtime like its canonical-root siblings, passes in a direct wine smoke), `secure_frontend_engine_arguments_tests.gpu_list_rejects_malformed_values` (Review Focus 4), CTest `strata_secure_server_rejects_malformed_gpu` (Review Focus 4; fails if the output contains `0,0`), A2 `secure_frontend_server_tests.proc01_server_passes_literal_argv` extended | `100% tests passed out of 273` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 147` (145 + `gpu_list_rejects_malformed_values` + `strata_secure_server_rejects_malformed_gpu`); cross build `-Werror` clean; pytest 13 passed |
| G1, G3 | The engine's cwd is `<state_dir>/engine` (`EngineCommand::working_directory{}`, empty = inherit; POSIX `chdir` pre-exec in `posix_launch::exec_child` after the `dup2` block and before the descriptor sweep, Windows `lpCurrentDirectory` in both `CreateProcessW` twins; serve sets it from the validated `roots.state`); same uid/gid (POSIX) and same SID, never MORE elevated, never a higher integrity level than the frontend (Windows; relative check by owner decision, Global Constraints). `ERROR_ELEVATION_REQUIRED` (740) is `spawn_failed` with the fixed message `engine requires elevation; refused` in `EngineStdioProcess::start` and `EngineProcess::start`, never `runas`. Test-only `strata-supervision-fake-engine-elevated` (Windows; embedded `requireAdministrator` manifest, `/MANIFEST:NO` under MSVC); `secure_frontend_set_warnings` now scopes its flags to C++ so the RC compiler receives none. | `secure_frontend_engine_child_tests.proc06_child_ids_and_cwd` (B); G3: `proc06_elevation_required_is_spawn_failed` (W) — **UNVERIFIED in CI and wine; validation-kit item, not a CTest test** | `100% tests passed out of 274` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine unchanged, `100% tests passed out of 147` (G1 is labeled windows-runtime: authoritative in MSYS2 — pending rflores's push; a direct wine smoke of `proc06_child_ids_and_cwd` exits 0; G3 is not run under wine: no UAC); cross build `-Werror` clean, `strata-supervision-fake-engine-elevated.exe` produced with the manifest embedded; pytest 13 passed |
| G2, G4 | Linux: `PR_SET_NO_NEW_PRIVS` pre-exec (`posix_launch::exec_child`, after `chdir`, before the descriptor sweep; `EngineCommand::no_new_privileges{false}` at the type, `prepare` stays void), **on by default** (owner decision; `config_defaults::kNoNewPrivilegesDefault`); SP1 key `engine.allow_new_privileges` / kFlags `--allow-new-privileges` turns it off (documented for the GPU validation kit; README key table regenerated). A one-time log hint (`kNoNewPrivilegesHint`) names the `/dev/nvidia-uvm` / `nvidia-modprobe -u -c=0` / `nvidia-persistenced` fix when an engine dies before READY on its own under NNP. The frontend refuses euid 0 / an elevated Windows token with a fixed error (`privilege_check.{hpp,cpp}`), right after `--help` and before `init`, `--check` and serve; no override flag. **Test-support change (ruling, Option A):** the Task 3 harness's non-elevated launch (LUA token, Safer NORMALUSER fallback, still-elevated → fixed STOP message) moved into the shared `tests/support/non_elevated_launch.hpp`; the harness, SP1's `process_runner.hpp` (only for `strata-secure-server`; other executables keep `CreateProcessW`) and the new Windows launcher `secure_frontend_non_elevated_run` all use it, and one shared Windows argument quoter (`quote_windows_argument`, `tests/support/windows_command_line.hpp`); the launcher holds the server in a kill-on-close Job. On Windows, `strata_secure_server_glm_requires_engine_arg` and `strata_secure_server_rejects_malformed_gpu` run through that launcher and are windows-runtime (wine cannot get a non-elevated token); on Linux they run unlabeled as before. **SP1 security-test edit (owner-visible):** `auth04_no_switch_disables_auth`'s boolean allow-list now also admits `engine.allow_new_privileges`. | `secure_frontend_engine_child_tests.proc06_child_has_no_new_privs` (L), `secure_frontend_server_tests.proc06_nnp_startup_hint_names_nvidia_uvm_fix` (L), `secure_frontend_engine_supervisor_tests.proc06_refuses_privileged_start` (B unit) | `100% tests passed out of 277` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 146` (147 + 1 for `proc06_refuses_privileged_start` − 2 CLI checks now windows-runtime; under wine the launcher reports "no non-elevated token ... STOP" exactly like the harness); cross build `-Werror` clean; pytest 13 passed. MSYS2 (authoritative for the de-elevated SP1 server cases and the two CLI checks) — pending rflores's push |
| X1, X2 | Tool/function/MCP/stream fields and a `tool` role are answered with the fixed `400 {"error":"Bad Request"}` before any lease: no GEN, no process change. `STRATA_*`, `LD_PRELOAD`, `CUDA_LAUNCH_BLOCKING` in the server's environment never reach the engine; `--vision`/`--batch`/`--gpu` via `--engine-arg` and unknown options fail with exit 1 before any spawn. The inventory has no manifest fields to abuse (IDs come from file names), so there is no manifest extension to attempt. No production change; the tests passed on their first run. | `secure_frontend_server_tests.ext01_extension_fields_spawn_nothing`, `secure_frontend_server_tests.ext02_extension_env_never_reaches_child`, `secure_frontend_server_tests.ext02_rejected_before_spawn` (L, W-runtime label) | `100% tests passed out of 280` (2 skipped: proc03 other-uid, proc05 cgroup delegation); wine `100% tests passed out of 146` (unchanged; server cases are labeled out) |
| SP1 integration (Task 29: 29a + 29b) | SP2 options are SP1 schema keys with `kFlags` rows, verified against Task 29 Step 3 (landed by Tasks 18, 19, 26): `--state-dir` → `roots.state` (required to serve), `--engine-lib-dir` → `engine.lib_dirs`, `--gpu` → `engine.gpu`, `--allow-new-privileges` → `engine.allow_new_privileges`; `engine.gpu` with `engine.profile glm53` is an `engine.gpu` `conflicting_values` issue (now tested). `limits.engine.ready_timeout_s` drives `RestartPolicy::ready_timeout` (`supervisor_config`, 29a); `supervision_defaults.hpp` folded into `config_defaults.hpp` (29a); the Windows pipe name uses SP1's `fill_random` (29a); SP1's e2e chat cases poll `/health` until `engine=ready` (6b). 29b: `engine_environment_for(state_dir, cache_root, lib_dirs)` — the CUDA cache is `<roots.cache>/cuda` when `roots.cache` is set (serve creates it owner-only; nothing is created at `<state>/cache`), else `<state>/cache/cuda`; the server builds the engine environment through it. `roots.cache`'s schema description now says it holds the CUDA cache (was "unused in SP1"); README key table regenerated. Test hardening: A2 asserts the engine's cwd is `<state>/engine` (production `working_directory` wiring); X1 asserts its record file opened and adds a positive control (a valid chat records `GEN`); X2 asserts the dumped environment holds the allowlisted `CUDA_CACHE_PATH` and that each startup rejection prints its fixed message (`engine.args: …` / `unknown option: --enable-mcp`); the X1/X2 case functions moved into the anonymous namespace. | `secure_frontend_server_cli_tests.cli_sp2_flags_map_to_schema_keys` (unit, unlabeled), `secure_frontend_subsystem_limits_tests.supervisor_policy_follows_config` (29a), `secure_frontend_engine_supervisor_tests.engine_environment_uses_cache_root_when_set` (unit, unlabeled), `secure_frontend_server_tests.engine_cuda_cache_follows_roots_cache` (new, windows-runtime), `secure_frontend_server_tests.proc01_server_passes_literal_argv`, `secure_frontend_server_tests.ext01_extension_fields_spawn_nothing`, `secure_frontend_server_tests.ext02_extension_env_never_reaches_child`, `secure_frontend_server_tests.ext02_rejected_before_spawn` (extended) | `100% tests passed out of 283` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 148` (the two unit cases run and pass; the server case is windows-runtime, excluded; a direct wine run of it exits 1 with the known `harness: no non-elevated token` wine limit); cross build `-Werror` clean; pytest 13 passed — W authoritative in MSYS2, pending rflores's push |
| SP3 D-1 | Lease-release notification and a documented thread-safety contract for SP3's worker pool (SP3 spec §1.5 D-1, §2.5). New `EngineSupervisor::wait_for_change(SupervisorState from, std::chrono::milliseconds timeout) const` → `HealthSnapshot`: blocks until the state is no longer `from` or the timeout passes and returns the state then (still `from` on timeout). It waits on the existing `changed_` condition variable (the same one `wait_for_state` uses, so there is no second wait mechanism). Every state change already notifies it under `mutex_`: release (`generating` → `ready`), `report_fatal`/crash (→ `stopping`), `backoff`, `circuit_open`, shutdown (→ `shutting_down`, `stopped`). `wait_for_change(generating, t)` therefore wakes on a release and never sleeps through a failure or a shutdown. No polling. The notification is a condition-variable notify only, so the serving thread still never forks, reaps or kills (SP2 spec §3.1), and the shutdown sequence and its 5 s bound are unchanged. Header contract in `engine_supervisor.hpp`: `acquire`, `snapshot`, `report_fatal`, `wait_for_change`, `wait_for_state`, `stop_requested`, `generations_started` and `~Lease` are safe from any number of threads (each takes `mutex_` or reads an atomic); there is at most one Lease, so `acquire()` needs no caller lock; a Lease is used by one thread at a time but may move between threads; `set_on_stopped`/`start` run once on the owning thread before serving; `shutdown()` is called from one thread and may run concurrently with the serving API; nothing calls in once the destructor has begun, except that a Lease may outlive the supervisor (RF4, kept). | `secure_frontend_engine_supervisor_tests.supervisor_wait_wakes_on_lease_release` (unit: timeout returns `generating` after ≥ 200 ms and < 1 s; a blocked waiter sees `ready` < 1 s after another thread destroys the Lease), `secure_frontend_engine_supervisor_tests.supervisor_wait_wakes_on_shutdown` (unit: a waiter with a Lease out wakes < 1 s after `shutdown()`), `secure_frontend_engine_supervisor_tests.supervisor_serving_api_is_thread_safe` (process, fake engine: 8 threads × 2 s of snapshot/acquire/release/`wait_for_change`; bounded join (exits 1 on deadlock), no two Leases, `acquire()` empty while leased, holder sees `generating`, no restart; TIMEOUT 120; labeled windows-runtime like its siblings) | `100% tests passed out of 286` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 150` (148 + the two unit cases; the stress case is windows-runtime and excluded, and passes in a direct wine smoke, exit 0); cross build `-Werror` clean; pytest 13 passed; stress case checked by mutation (`acquire()` also allowed in `generating` → 1,347,693 violations, FAILED) and 8 clean repeat runs |
| SP3 D-2 | A drain that fails after a CLIENT-requested `STOP` kills and restarts the engine but does not count toward the circuit (SP3 spec §1.5 D-2, risk R4; controller ruling R3). Carrier: new `enum class EngineStopCause { generation_timeout, client_cancelled }` (`engine_protocol_client.hpp`); `EngineProtocolClient::stop(EngineStopCause cause = generation_timeout)` records the cause only when `STOP` was written, `stop_cause()` reads it, and every `begin_generation()` call forgets it at its top, even a refused one (fix round 1). `ChatExecutionService` (today the only `STOP` issuer, after `generation_timeout`) now passes `generation_timeout` explicitly; SP3's P6 cancel (SP3 spec §2.6) passes `client_cancelled`. `kill_reason_for` maps `abandoned` to new `KillReason::client_stop_drain_failed` when the cause is `client_cancelled`, else `drain_failed` (unchanged); SP3 must derive it through `kill_reason_for(protocol)` (recorded `client_cancelled` + `abandoned`); passing it to `report_fatal` directly is test-only (fix round 1). Supervisor: `end_generation` returns `GenerationEnd { counted, uncounted, unreaped }`; `uncounted` only when the end classifies as `killed_by_supervisor(client_stop_drain_failed)` (an engine that ended by itself still counts). `schedule_restart` then skips `RestartTracker::record_failure`: no failure added, no delay, no backoff growth, but the healthy-window reset still applies through new `RestartTracker::note_healthy(healthy_for)` (spec §3.3/§3.8; fix round 1); the state goes `stopping` → `backoff` (zero length, `/health` failed/restarting as for any restart) → `starting` → `ready`. Unreaped still opens the circuit (V10). **Owner-visible bound (controller ruling):** at most `config_defaults::kMaxConsecutiveUncountedRestarts` = 3 uncounted client-STOP restarts in a row with no successful DONE between them; from the 4th on, a client-STOP drain failure is counted like `drain_failed`, so an engine that always ignores STOP still reaches `circuit_open`. A successful DONE on any generation (new atomic `EngineProtocolClient::completed_generations()`, read by the supervisor thread at each generation end; a `nonfinite` DONE is not one) resets the streak; a counted failure does not. New fixed log literal: `engine generation <n> ended: killed_by_supervisor(client_stop_drain_failed)`. It EXTENDS the plan state-machine `<reason>` list (`fatal_line`, `ready_timeout`, `drain_failed`, `write_timeout`, `protocol_failed`, `shutdown`) and is a ruled exception to SP2 spec §3.6 "all kinds count as failures"; it carries no client data (privacy rule). Timeout-STOP drain failures still count: V7 `proc04_drain_failure_kills_and_restarts` unchanged and green. Thread-safety contract (D-1) unchanged: no new entry point, `report_fatal` still only takes `mutex_`. | `secure_frontend_engine_supervisor_tests.sp3_d2_kill_reason_follows_stop_cause` (unit, protocol level: client STOP + failed drain → `client_stop_drain_failed`; timeout or default STOP → `drain_failed`; a drained client STOP does not carry over to the next GEN; literal), `secure_frontend_engine_supervisor_tests.sp3_d2_client_stop_drain_failure_restarts_uncounted` (unit, fake: three client-STOP drain failures in a row (the bound) → each generation killed and logged with the new literal, generation 4 ready, no backoff delay; then three counted failures open the circuit with delays 1 s, 2 s, proving the count stayed 0), `secure_frontend_engine_supervisor_tests.sp3_d2_timeout_stop_drain_failure_still_counts` (unit, fake: three timeout-STOP drain failures through `execute_with_lease` → circuit open, delays 1 s, 2 s, `drain_failed`), `secure_frontend_engine_supervisor_tests.sp3_d2_client_stop_counts_when_engine_ended_itself` (unit: engine exit 1 before the client-STOP report → `error_exit`, counted, delay 1 s), `secure_frontend_engine_supervisor_tests.sp3_d2_uncounted_end_resets_count_after_healthy_window` (unit: 2 counted, client-STOP end after > healthy_window, then 3 more counted needed; delays 1, 2, 1, 2 s), `secure_frontend_engine_supervisor_tests.sp3_d2_uncounted_streak_is_bounded` (unit: 3 uncounted, the 4th counts (1 s), 5th and 6th open the circuit), `secure_frontend_engine_supervisor_tests.sp3_d2_done_resets_uncounted_streak` (unit: a DONE on generation 3 resets the streak, five uncounted in all, no delay; mutation without the reset fails it), `secure_frontend_engine_protocol_client_tests.stop_cause_and_completed_generations` (unit: cause forgotten by a refused GEN; successful DONE counted, `nonfinite` not), `secure_frontend_engine_supervisor_tests.proc04_drain_failure_kills_and_restarts` (V7, kept); all TIMEOUT 120 | Fix round 1: `100% tests passed out of 294` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 158` (150 + the eight new unit cases); V7 process case is windows-runtime (authoritative in MSYS2, pending rflores's push), direct wine smoke exit 0; cross build `-Werror` clean; pytest 13 passed; the seven `sp3_d2_*` cases 105/105 clean in 15 repeat runs |
| R1 (Task 22 / K2 overall bound) | Owner ruling 2026-10-14 (controller ruling RF10): every engine-stdin write is bounded overall by an absolute deadline as well as by the 1 s per 64 KiB chunk deadline (`config_defaults::kStdinWriteDeadline` / `kStdinWriteChunk`); each chunk waits `min(kStdinWriteDeadline, time left to the deadline)`, and a write past the deadline fails exactly like a stalled chunk (`transport_write_failed` → protocol failed → `killed_by_supervisor(write_timeout)`, counted, restart; no new kind). Interface: `EngineLineTransport::write_line(line, MonotonicClock::time_point deadline, error)`; `EngineProtocolClient::begin_generation(max_new, ids, write_deadline)`. `ChatExecutionService` fixes one generation deadline (`now + generation_timeout`) before GEN: it bounds the GEN write and the read to DONE then gets only what is left of it (`remaining_until`). STOP and QUIT (no request deadline) are bounded by one `kStdinWriteDeadline` from the call. POSIX: the literal `poll(..., 1000)` is gone; the frontend's stdin end is now `O_NONBLOCK` (set in `start()`), writes go in 64 KiB chunks and every wait is a bounded `poll` (a blocking write could otherwise outlast both deadlines). Windows: the overlapped wait uses the same `min`. New supervision-fake mode `--slow-stdin=BYTES` (+ `--slow-stdin-interval-ms=MS`, default 100): after READY it only drains stdin, BYTES per interval, and never answers. Limits doc updated by Task 28 ("Windows stdin writes" row: per-chunk and overall bounds, shared generation deadline, 1 s STOP/QUIT, POSIX `O_NONBLOCK`). | `secure_frontend_engine_supervisor_tests.proc04_slow_stdin_write_bounded_by_request_deadline` (process case, labeled windows-runtime on Windows like its group; ~960 KB GEN line drained at 16 KiB / 100 ms, 2 s generation timeout: request fails in < 3.5 s and the engine is killed as `write_timeout`; RED before the change: took 12654 ms, no `write_timeout`), `secure_frontend_engine_stdio_process_tests.write_line_fails_once_deadline_passed`, `secure_frontend_engine_protocol_client_tests.write_deadlines_reach_the_transport`, `secure_frontend_chat_execution_tests.chat_gen_write_bounded_by_generation_deadline`; K2 `proc04_windows_write_timeout_kills_engine` kept; all TIMEOUT 120 or the binary's existing value | `100% tests passed out of 298` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 161` (the slow-stdin process case is windows-runtime and excluded; direct wine run exit 0 in ~3.6 s); cross build `-Werror` clean; pytest 13 passed — Windows path authoritative in MSYS2, pending rflores's push |
| SP6 env family (mechanism) | SP6 prerequisite, mechanism only (SP6 spec §4.9 DRAFT; SP2 §3.9; controller rulings RF9 and R5 fix round 1). `EngineEnvironment` gains `EngineFamily family{EngineFamily::strata}` (`enum class EngineFamily { strata, glm }`; default member initializer, so designated initializers keep compiling). A family hook (`FamilyEnvironmentHook`, production `family_environment_rows(const EngineEnvironment&)`) derives owning rows from the environment (`FamilyEnvironmentRows`: `forced` name/value pairs, `suppressed` names), so SP6 can derive `CUDA_VISIBLE_DEVICES` from the gpu list. `merge_forced_environment` validates, then suppresses and forces (replace or add); it is all-or-nothing and order-independent. It refuses a forced name off the closed `kFamilyForcibleEnvironment` (`STRATA_GLM_SLOTS`, `STRATA_GLM_LOOP_THINK`, `STRATA_GLM_LOOP_ANSWER`, `STRATA_GLM_SPLIT` (controller ruling), `STRATA_WATCHDOG_S`, `CUDA_DEVICE_ORDER`, `CUDA_VISIBLE_DEVICES`), a never-list name other than the two `kFamilyGpuSelectors` (RF9: the never-list stays the "never inherited" list), a NUL in a value, a suppressed name off the fixed `kFamilySuppressibleEnvironment` (`STRATA_WATCHDOG_IO_S`, `STRATA_HIPBLASLT_TUNING`, `STRATA_WATCHDOG_S`), and any name that appears twice. `STRATA_GLM_DFLASH` and the rest of the never-list stay refused. The constant part of each family's rows is validated by a `static_assert`, and the same check runs at run time on derived rows. `render_posix_environment`/`render_windows_environment`/`render_engine_environment` stay the generic §3.9 rows. `apply_family_environment`/`render_family_environment` add the family step and return `std::optional`. The spawn path (`make_stdio_process_factory`, hook `EngineLaunchPlan::family_hook`) turns a refused merge into a spawn failure (`engine environment refused`), logs the fixed literal `engine generation <n>: family environment refused` (no value or path) and removes the generation's temp dir. It never spawns with an empty or partial environment. **strata: no rows, so the rendering is byte-identical** (pinned; N1 green). **glm currently renders strata rows; not reachable from config; SP6 fills its table.** Strata family: still no GPU variable. | `secure_frontend_engine_supervisor_tests.sp6_env_strata_family_renders_unchanged` (POSIX + Windows byte pins, unchanged rows; strata/glm through the family step equal the pin), `.sp6_env_forced_values_override_and_add`, `.sp6_env_forced_values_reject_never_list` (incl. refused derived rows yield nullopt), `.sp6_env_forcible_names_are_the_ruled_set`, `.sp6_env_hook_derives_values_from_environment` (test-only derivation through the real renderer, absent → 0), `.sp6_env_hook_suppresses_only_optional_rows`, `.sp6_env_refused_family_is_spawn_failure` (duplicate and NUL rows), `.sp6_env_derived_value_reaches_child` (process case: the derived rows reach a real child's environment); N1 `proc02_child_env_is_exact_allowlist` unchanged | `100% tests passed out of 306` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 168` (the process case `sp6_env_derived_value_reaches_child` is windows-runtime and excluded; direct wine run exit 0); cross build `-Werror` clean; pytest 13 passed — Windows path authoritative in MSYS2, pending rflores's push |
| SP4 seam | SP4 launch seam on SP2's launch primitives (controller ruling R4 + RF11; SP4 spec §3.2; binding names in the run-2 seam contract and its controller addendum). **POSIX** (`src/posix_child_launch.hpp`, `secure_frontend::posix_launch`): `PreExecHook = int (*)(const void* ctx, std::span<const int> lifted) noexcept`; `struct ExecOptions { std::span<const int> keep_fds; PreExecHook pre_exec{nullptr}; const void* ctx{nullptr}; }`; `kHookFailureMarker = 'H'`; `exec_child(prepared, stdin_fd, stdout_fd, null_stderr, report_fd, const ExecOptions& options = {})` (new last parameter, defaulted, so existing callers compile unchanged); `kReportFd = 3` and `kLiftFloor = 10` already existed; new `kMaxKeepFds = 16` (the child lifts into a fixed array, no allocation; more entries fail closed with `E2BIG`). In the child, each `keep_fds` entry is lifted with `fcntl(fd, F_DUPFD_CLOEXEC, kLiftFloor)` right after the report descriptor is lifted and before the 0..3 `dup2` sequence, so a parent fd 0–3 survives. The sweep (`close_range` per gap, else one `close()` per fd below the sweep limit) spares the lifted numbers. After the sweep and the signal reset, immediately before `execve`, `pre_exec(ctx, lifted)` runs with the lifted numbers in `keep_fds` order. A non-zero return (an errno) makes the child write `'H'` + that int in one write on `kReportFd` and `_exit(127)`. A lift failure is reported the same way (fail closed). The lifted copies stay close-on-exec, so only what the hook `dup2`s survives `execve`. The hook must not close or `dup2` onto fds 0..`kReportFd`: a hook that clobbers `kReportFd` could make a failure read as success (header contract, fix round 1). SP2 never reserves or touches fd 4. Parent side: new `read_report(fd)` (to EOF or 16 bytes, whichever comes first; EINTR retried; fix round 1 bounded it, it could keep 32), `classify_report(bytes)` → `ChildReport{none | exec_failed | hook_failed | malformed, error}` (SP4's rule: `size == 1 + sizeof(int) && front() == 'H'`), and `describe_report()`. Both POSIX launchers (`engine_stdio_process.cpp`, the SP0 twin `engine_process.cpp`) now read the report through these: `execve failed: <strerror>` (text unchanged), `pre-exec hook failed: <strerror>`, `child launch report malformed` (never success). The engine passes `ExecOptions{}`, so its child behaviour is unchanged. **Windows** (new `src/win_child_launch.hpp` + `.cpp`, `secure_frontend::win_launch`; built into `secure_frontend_engine_stdio_process` on Windows): `WinLaunchSpec { executable, command_line, environment_block, cwd, stdin_read, stdout_write, stderr_handle, HANDLE primary_token{nullptr}, std::vector<HANDLE> extra_inherited_handles, std::vector<std::uint8_t> crt_fd_block, bool limit_active_process_to_one{true}, bool restrict_ui{true} }`; `WinLaunched { process, thread, job }` (the caller owns all three; the thread is already resumed); `WinLaunchStep`; `std::variant<WinLaunched, DWORD> launch_in_job(const WinLaunchSpec&, WinLaunchStep* failed_step = nullptr)` (DWORD = GetLastError of the failing call). It is the engine's former CreateProcessW + Job code, moved unchanged: Job `KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION`; flags `CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW`; explicit `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` = the three standard handles, then the extra handles (each checked inheritable, else `ERROR_INVALID_HANDLE` at step `attributes`; each must be distinct from the three standard handles and from each other, since a duplicate makes CreateProcess fail with `ERROR_INVALID_PARAMETER`; not deduped, documented); `lpCurrentDirectory` = cwd (empty: inherit); the once-per-process error mode; assign while suspended, then resume. `primary_token` set → `CreateProcessAsUserW`. `crt_fd_block` is copied into `cbReserved2`/`lpReserved2` (≤ 65535 bytes). `ACTIVE_PROCESS = 1` and all `JOB_OBJECT_UILIMIT_*` restrictions **default ON** (ruling RF11 as amended in fix round 1: a new caller is confined by default, and SP4 Task 26's 10-field positional initialiser gets this Job). The engine's `start()` sets both to false explicitly, so the engine Job is unchanged. The engine's `start()` maps the step and code to its former messages, including 740 → `spawn_failed` "engine requires elevation; refused" (never retried via runas). The SP0 twin keeps its own CreateProcessW (no stdio redirection, `bInheritHandles` FALSE). Types follow the controller addendum (ruling): `extra_inherited_handles` and `crt_fd_block` are owning vectors, so a spec never dangles. SP4 Task 26's positional `WinLaunchSpec{...}` (10 initialisers) compiles unchanged under clang `-Werror`; the test uses exactly that shape. **SP4 must close WinLaunched::thread after launch_in_job.** New supervision-fake mode `--write-inherited=N`: writes `INHERITED <N>` to fd N (POSIX), or on Windows to the handle at CRT entry N, parsed from `STARTUPINFO.lpReserved2`; exit 3 if absent. | `secure_frontend_engine_child_tests.sp4_seam_keep_fds_lift_and_hook_order` (L; keep_fds = {a parent fd opened as 3, a parent fd > 3}: the hook sees both lifted ≥ `kLiftFloor`, close-on-exec, the same files in keep_fds order, a non-kept parent fd already swept; it `dup2`s the first to 4; the fake's DUMP `FDS` is exactly `0,1,2,4` and its write on fd 4 lands in the file that was parent fd 3; checked by mutation: hook before sweep → `'H'` + EEXIST, lift after the dup2s → `'H'` + EDOM), `secure_frontend_engine_child_tests.sp4_seam_hook_failure_is_distinct_from_execve_failure` (L; hook EPERM → exactly `'H'` + EPERM, exit 127, `pre-exec hook failed: …`; missing executable → errno only (ENOENT), `execve failed: …`; unliftable keep fd → `'H'` + EBADF; empty/malformed classification; engine launcher text unchanged), `secure_frontend_engine_child_tests.sp4_seam_launch_in_job_handle_and_crt_block` (W, windows-runtime: one extra inheritable handle + CRT block n = 5 with entry 4 = that handle; the fake writes `INHERITED 4` through it, exit 0; the same launch without the extra handle cannot write (exit ≠ 0); every Job is `KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION`; the default spec (SP4's positional shape) gets `ACTIVE_PROCESS = 1` and `kAllUiRestrictions`, and the engine's spec (both false) gets neither), `secure_frontend_engine_child_tests.sp4_seam_launch_in_job_rejects_non_inheritable_handle` (W, windows-runtime; fix round 1: a non-inheritable extra handle → `ERROR_INVALID_HANDLE` at step `attributes`); the hook-failure case also checks that `read_report` stops at 16 bytes of a 40-byte pipe (RED before fix round 1: read 32); all TIMEOUT 120 | `100% tests passed out of 308` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 168` (the Windows case is windows-runtime and excluded). In a direct wine run of it, the handle-list and CRT-block assertions and the negative control pass; it exits 1 only on the Job-query assertions (wine does not model Job Objects). After fix round 1, a direct wine run of `sp4_seam_launch_in_job_rejects_non_inheritable_handle` exits 0. Direct wine runs of the engine's Windows cases on the refactored path: `proc06_child_ids_and_cwd` and `proc01_windows_argv_round_trip` exit 0; `proc02_canary_handles_absent` (no `CompareObjectHandles` in wine) and `proc04_exit_status_is_classified` (winedbg on SEGV) fail exactly as recorded before. Cross build `-Werror` clean; pytest 13 passed — **Windows authoritative in MSYS2, pending rflores's push** |
| K4, K6 | Documentation truth pass, no behaviour change. K4: the `kSweepCap` comment states when the fallback sweep runs (no `close_range`), why it is capped, and that it is not backed by close-on-exec everywhere (the listening and accepted sockets are not `SOCK_CLOEXEC`; Known small gaps). K6: `docs/security/engine-protocol-limits.md` ("Windows stdin writes" rewritten: the engine's reader thread on `read(0)`/`_read(0)`, per-chunk and overall (R1) bounds, shared generation deadline, 1 s STOP/QUIT, POSIX `O_NONBLOCK`; new READY wait, fatal lines, exit codes, GPU selection rows with RF9 wording), all upstream citations re-pinned to `v0.1.44.1` and checked against `upstream/`; threat model "Engine process isolation" (fixed environment, restart policy and circuit, client-triggerable `ERR` lines, the D-2 bound, PROC-03 and PROC-05 residual risks, NNP default, refusal of root/elevated starts, G3 a validation-kit step); `deployment.md` release record (accepted risks) and its environment wording; `secure-frontend-ci.md` (SP2 `.exe` files, `windows-runtime` label, the two skips, G3; CI run `38540719307`); `secure_frontend/README.md` (environment sentence, `/health` `starting` → `503`); the `limits.engine.ready_timeout_s` description (schema string and README table, now "how long the supervisor waits for READY after each start"); citation re-pins in the SP2 spec (§3.8 `server.py:734-735`, `_pump` `:952-967`; §3.9 `generate.cpp:1843-1865`; §3.10 and K6 `:9433-9469`) and in the `kEngineFatalPrefixes` comment. Handoff: SP1 rows flipped to verified (CI run `38540719307`), SP2 status, gaps, run-2 record. | review (reviewer reads the diff) plus a full green run; `secure_frontend_typed_config_tests.readme_config_table_matches_schema` covers the description change | `100% tests passed out of 308` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 168` (278 registered; the 110 `windows-runtime` cases excluded); cross build `-Werror` clean, 38 `.exe`; pytest `13 passed` |
| Final review I1, I2, M1-M7 | Whole-branch final review (run 2, "With fixes"). **I1 (C4):** an idle or slow HTTP client no longer turns a clean SIGTERM/console-event shutdown into `_Exit(1)`: `HttpSocketServer::shutdown_listener()` also shuts down the in-flight client socket (POSIX `SHUT_RDWR`, Windows `SD_BOTH`; under a mutex, never closed there) and `serve_one()`'s request read waits in 100 ms `poll()`/`select()` slices that re-check `listener_closed`; the shutdown worst case stays 4.35 s + 0.1 s < 5 s. **I2 (C4):** a generation left unreaped (`abandoned_`) at the end of shutdown makes `finish()` log the fixed literal `engine supervisor stopped with an unreaped engine: exit 1` (`kEngineLeftUnreapedLine`) and `main` return 1 (`EngineSupervisor::engine_left_unreaped()`, additive). **M1 (G2):** the NNP hint keys on `classified.kind != killed_by_supervisor`, not on "no kill sent". **M3:** `g_signalled` is a lock-free `std::atomic<int>`; the comment now says a process-directed POSIX signal may run the handler on any thread not blocking it, and `release_shutdown_signals()` waits for an in-flight handler (lock-free counter) after clearing the wake. **M4:** `engine_supervisor.hpp` SP3 caveats: `wait_for_change` observes states, not transitions; the one fork/reap/kill exception (a Lease outliving the supervisor with an abandoned generation runs `terminate(250 ms)` on the destroying thread); every serving-API call must have returned before the destructor begins; a stray `begin_generation` during an active client-STOP generation erases the recorded cause (errs toward counting); a cancel that finishes with `DONE` ends the uncounted streak. **M5:** one `reap_within()` helper replaces the duplicated reap-poll loops (no behaviour change). **M6:** the startup message is `Unable to prepare the state or cache directory.` (it also covers `<roots.cache>/cuda`). **M2, M7:** docs (C4 row 4.35 s; MSYS2 watch list; SP4 note). | `secure_frontend_http_socket_server_tests.socket_server_shutdown_listener_wakes_idle_client` (B), `secure_frontend_server_tests.proc05_sigterm_with_idle_client_exits_cleanly` (L), `secure_frontend_server_tests.proc05_windows_ctrl_break_with_idle_client_exits_cleanly` (W, windows-runtime), `secure_frontend_engine_supervisor_tests.supervisor_unreaped_at_shutdown_reports_engine_left` (B unit), `secure_frontend_engine_supervisor_tests.proc04_unreaped_child_opens_circuit` (extended), `secure_frontend_engine_supervisor_tests.supervisor_shutdown_sends_eof_first_then_kills` (negative control added), `secure_frontend_engine_supervisor_tests.proc06_nnp_hint_when_exit_status_lags` (B unit). RED before each fix: exit 1 after 5.33 s and a 3007 ms wait (I1); "shutdown reports the engine left behind" (I2); "the NNP hint is logged for an engine that ended before READY" (M1). | `100% tests passed out of 312` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 171` (282 registered; the 111 `windows-runtime` cases excluded; the Windows idle-client server case is authoritative in MSYS2 — pending rflores's push); cross build `-Werror` clean, 38 `.exe`; pytest `13 passed` |

Notes on the SP2 table above:

- Shutdown follows the spec §3.7 order since Task 15 (C4, C7 row): EOF, TERM, KILL, then `killed_by_supervisor(shutdown)` is logged. A shutdown that lands while `end_generation` is reaping (up to `reap_timeout`, 30 s) cannot finish inside the 5 s bound and exits via `std::_Exit(1)` (spec-mandated).
- Documented spec §3.1 exception: on Windows, `EngineStdioProcess::read_line` waits briefly on the process handle from the serving thread (`WaitForSingleObject(..., 1)`). A Windows wait consumes no exit status, so this does not violate the single-reaper intent.

#### SP2 run-2 state (2026-10-14, recorded by Task 28)

- **Commits.** Run 2 is `5ac39bb4` through the Task 28 commit, 25 local
  commits on `sp2-portable-supervision` after the SP1 merge `9ded0a5c` (Tasks
  29a, 6b, 15, 16, 18, 19, 25, 26, 27, 29b, then the controller rulings R2, R3,
  R1, R5, R4, then Task 28), then the final-review fix wave (I1, I2, M1-M7;
  last row of the SP2 table). Nothing is pushed.
- **Final counts** (after the final-review fix wave, "Verification performed", SP2): linux-gcc
  `100% tests passed out of 312` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); wine `100% tests passed out of 171` (282 registered; the 111 `windows-runtime` cases excluded); pytest `13 passed`; cross build `-Werror`
  clean, 38 `.exe` files.
- **Proof status.** L and B rows are green locally. Every W row and every
  `windows-runtime` test is unverified until the `windows-msys2-clang` job is
  green after rflores pushes. CI run `38540719307` (MSYS2 193/193) covers SP1
  only, because it predates the SP2 merge. `proc03_other_uid_cannot_open_engine_fd`
  runs only in the GitHub Linux jobs. `proc05_cgroup_kill_when_delegated` skips
  wherever no delegated cgroup exists. G3 is a validation-kit step. Nothing ran
  on a GPU.
- **MSYS2 watch list for the first SP2 push:** Windows A2 argv[0] final-path
  form (CI run `38598235525` failed it; since the winfix branch the harness
  puts `root()` in `GetFinalPathNameByHandleW` form on Windows, so an 8.3 or
  junction `TEMP` no longer mismatches — pending the next MSYS2 run); the LUA token executing the
  harness `bin/` copy; the console handler, `CTRL_CLOSE` and `CREATE_NO_WINDOW`
  engine stdio (C6); the owner-only `--state-dir` check, the
  `make_owner_private_directory` test roots and the junction case (N3); SP1
  server cases and the two CLI checks launched through the shared
  `non_elevated_launch` (G4); G1 (`proc06_child_ids_and_cwd`); the
  `roots.cache` CUDA path (`engine_cuda_cache_follows_roots_cache`); the SP4
  seam Job limits (`sp4_seam_launch_in_job_handle_and_crt_block`);
  `GetProcessHandleCount` staying flat across restarts (V9/V10); UCRT
  `__fastfail` and WER behaviour (`proc04_windows_abort_does_not_stall`,
  `proc04_windows_crash_does_not_stall`); R2 `sudo -n -u nobody` in the Linux
  CI jobs; the Windows `shutdown_listener()` `closesocket` versus `accept()`
  race (`http_socket_server.cpp`, the `listener_closed` re-check after
  `accept()` in `serve_one()` and the `closesocket` in `shutdown_listener()`:
  a socket handle closed while `accept()` runs may be reused); the C6
  `CTRL_CLOSE` exit-code race (Windows may end the process when the console
  handler returns, before `main` returns its code); the idle-client shutdown
  (`proc05_windows_ctrl_break_with_idle_client_exits_cleanly`: whether
  `shutdown(SD_BOTH)` wakes the `select()` at once or the 100 ms slice does).
- **Owner items:**
  1. The delegated-cgroup paths (C5, and the C3 delegated branch) are verified
     by compiling and reading only. A live proof needs approval to run
     `systemd-run --user --scope -p Delegate=yes ctest --preset linux-gcc -R proc05_cgroup --output-on-failure`.
  2. SP2 spec §4.7 K4 row (`docs/superpowers/specs/2026-10-13-sp2-portable-supervision-design.md`
     ~line 381) says "all frontend fds are `O_CLOEXEC`, so the sweep is
     defence in depth". The code contradicts it: the listening and accepted
     sockets are created without `SOCK_CLOEXEC` (Known small gaps, first
     bullet). The spec text was not edited; the `kSweepCap` comment states the
     code's truth.
  3. C3 spec row versus mechanism: the spec asserts the grandchild "only when
     C5 active", but after a frontend SIGKILL nothing writes `cgroup.kill`. The
     controller ruled a membership assertion instead (the C3 row). This is the
     PROC-05 residual risk in the threat model and the release record.
  4. D-2 bound: at most `config_defaults::kMaxConsecutiveUncountedRestarts` = 3
     uncounted client-STOP restarts in a row. This is a controller ruling (SP3
     D-2 row); a `DONE` resets the streak, including one that finishes a cancel.
  5. R1: the read to `DONE` gets only what is left of the generation deadline
     the GEN write used (R1 row; judged consistent with K1/RF10 in review).
  6. SP1 security-test edits made by SP2: `auth04_no_switch_disables_auth`'s
     boolean allow-list admits `engine.allow_new_privileges` (G2, G4); SP1's
     CFG-01 case gained the "no supervisor start, no engine generation"
     assertion (V2, V11); SP1's `process_runner` launches
     `strata-secure-server` through the shared non-elevated launcher on Windows
     (G2, G4).
- **SP3 note.** SP3 spec §2.6 (lines ~317-319) and its R4 risk row (~1298)
  still describe the pre-D-2 behaviour (a client-STOP drain failure as a
  counted `drain_failed`). They were not edited. SP3's P6 cancel must call
  `stop(EngineStopCause::client_cancelled)` and derive the kill reason through
  `kill_reason_for(protocol)`.
- **SP4 note.** SP4 must close `WinLaunched::thread` after `launch_in_job`.
  SP4 must pass `keep` to `sweep_orphans` (the pids of its live downloader
  children) so a live downloader child is not swept as an orphan.
  `crt_fd_block` and `extra_inherited_handles` are `std::vector` (controller
  addendum), so SP4's locals must be vectors, not arrays or spans.
  `WinLaunchSpec` defaults to a confined Job (`ACTIVE_PROCESS = 1`, UI limits);
  the engine opts out (SP4 seam row).
- **Plan.** The merge note at the top of the plan's Task 15 is satisfied (ruling
  RF5 was applied in Task 15, C4/C7 row). The plan file is outside Task 28's
  scope and was not edited.

The native frontend enforces these in-process boundaries: configuration
validation, secret-source metadata, Linux/Windows protected-file token reading,
exact Host/Origin/CORS policy, bounded HTTP request parsing with a total request
deadline plus bearer authentication, portable child-process supervision, and a
serial native Qwen (or selected GLM-5.3) text-chat route. The server does **not**
download artifacts (since SP4 only the separate, operator-invoked `strata`
binary does), package a secure release, implement every upstream serving
profile, or replace the upstream Python service in a release. Therefore the
repository must not yet be described as privacy-hardened or as having removed
upstream network-capable behavior.

### SP3 M1 deliverables (branch `sp3-api-streaming`)

Plan: `docs/superpowers/plans/2026-10-14-sp3-m1-concurrency-hardening.md`. Spec:
`docs/superpowers/specs/2026-10-14-sp3-api-concurrency-streaming-design.md`.
Baseline before Task 1: linux-gcc N₀ = 520 (+2 allowed skips) tests, wine W₀ = 256 tests.

| Task | IDs | What changed | Tests (CTest names) | linux-gcc | wine |
| --- | --- | --- | --- | --- | --- |
| 1 | §3.9, §4.6, §5.3, §7 | api_constants.hpp, api_errors (§7.2 table), http_wire (security headers, Date), router uses the shared JSON writer | http_parser_tests.err_every_code_renders_fixed_body, …err_param_is_key_only, …wire_response_has_security_headers_and_date, api_router_tests.models_list_keeps_utf8_model_id | 100% tests passed out of 524 (+2 allowed skips) | 100% tests passed out of 260 (smoke; real Windows pending MSYS2) |
| 2 | DOS-01, §4.2 | request-head scan + parser (414/431/411/413/505/417/400); shared ASCII helpers `ascii_iequal`/`ascii_to_lower`/`trim_ows` in http_request_head.hpp (pre-flight D6; no SP4-file edits) | http_parser_tests.dos01_request_line_over_limit_is_414, …dos01_header_block_over_limit_is_431, …dos01_too_many_headers_is_431, …dos01_transfer_encoding_variants_are_411, …dos01_content_length_variants, …head_request_line_and_header_syntax | 100% tests passed out of 530 (+2 allowed skips) | 100% tests passed out of 266 (smoke; real Windows pending MSYS2) |
| 3 | WEB-01, WEB-02, WEB-03, WEB-06 (unit) | Host allowlist (bound, localhost on loopback, aliases; wildcard = aliases only; names case-folded), exact origins, preflight fixed list (204/403); `make_http_policy` replaces the old 4-field HttpPolicy in every user (mains keep their old authority as an alias, no CORS yet); `struct HttpPolicy;` forward-declared in http_request_handler.hpp (pre-flight P11); temporary handler shim until Task 6a | http_policy_tests.web01_host_matrix, …web02_host_name_case_is_folded, …web03_origin_matrix, …web06_preflight_rules_unit, …cors_and_alias_grammar | 100% tests passed out of 530 (+2 allowed skips) | 100% tests passed out of 266 (smoke; real Windows pending MSYS2) |
| 4 | WEB-05 (config), CFG-01 (SP3 rows) | listener.cors_origins/host_aliases, HTTP deadline keys (header_deadline_ms, write_stall_ms, response_write_deadline_ms, stream_keepalive_ms), logging.requests; string-array bound + grammar side table (`ConfigKeyExtension`, `find_config_key_extension`); strata-secure-server passes `listener.host_aliases`/`cors_origins` to `make_http_policy` and drops the old-authority alias (wildcard bind = aliases only, §4.3); smoke mains pass no alias (smoke-server keeps its own authority only for a wildcard bind); SP1 tests ported: `subsystem_limits_follow_config` sets header_deadline_ms with its 1500 ms request deadline, `auth04_no_switch_disables_auth` admits logging.requests; README key table regenerated | typed_config_tests.cfg01_sp3_rows_type_and_range, …cfg01_header_deadline_le_request_deadline, …cfg01_response_deadline_ge_write_stall, …cfg01_wildcard_bind_requires_host_aliases, …cfg01_host_alias_grammar_and_count, …web05_cors_origin_config_rejects_wildcard_null_path_duplicate_and_17_entries | 100% tests passed out of 536 (+2 allowed skips) | 100% tests passed out of 272 (the 6 new cases are unlabelled and run under wine; real Windows pending MSYS2) |
| 5 | CFG-01 (SP3 rows), B1, B2, B11 | concurrency rows with derived defaults (`limits.concurrency.max_concurrent_requests` 1-256 default 8; `max_queued_generations` 0-254 derived min(4, max(0, workers-2)); `queue_timeout_ms` 1000-3600000 default 300000; `max_connections_per_remote_address` 1-256 derived min(4, workers); cross-field workers=1 ⇒ queue 0, workers ≥ 2 ⇒ queue+2 ≤ workers, cap ≤ workers; a derived value applies only when the key is absent, `--check` prints it with "(derived)"), `default_max_tokens` 0-16384 default 0 = auto, `resolve_max_tokens` (auto = min(max_completion, ctx − n − kContextMarginTokens); above-limit requests clamped, not rejected) used by `ChatExecutionService::execute`; README key table regenerated (derived Default text from `ConfigKeyExtension::derived_default`). Updated per spec §9.4: typed_config_tests.typed_config_accepts_minimal_file_and_applies_defaults (8 workers, default_max_tokens 0), chat_execution_tests.rejects_context_and_output_limits_before_generation (over-limit max_tokens clamped to GEN 1), chat_generation_plan_tests.defaults_output_limit_and_rejects_unsafe_inputs (omitted max_tokens plans 0 = auto) | typed_config_tests.cfg01_sp3_concurrency_rows_and_defaults, …cfg01_queue_plus_two_le_workers, …cfg01_serial_requires_zero_queue, …cfg01_remote_cap_le_workers, …cfg01_sp1_config_with_one_worker_still_valid, …cfg01_derived_defaults_follow_worker_count, …cfg01_explicit_values_are_not_adjusted; chat_execution_tests.resolve_max_tokens_follows_decisions_1_and_2 | 100% tests passed out of 544 (+2 allowed skips) | 100% tests passed out of 280 (the 8 new cases are unlabelled and run under wine; real Windows pending MSYS2) |
| 6a | §3.11 seam, §4.1 seam | RequestRouter returning RouteResult; HttpHead/StreamSink/StreamHandler; serialize_head; in-memory handle_http_request; legacy adapter (`DispatcherRouter`, deleted in Task 9); `serialize_response` rebuilt on the head helper (Content-Length except 204, drops Transfer-Encoding); `constant_time_token_equals` kept (pre-flight P24). Updated per spec §9.4: http_request_handler_tests.rejects_malformed_and_ambiguous_messages (Transfer-Encoding → 411), http_socket_server_tests.parser_honors_configured_max_request_bytes (Content-Length over the bound → 413) | http_parser_tests.wire_head_has_no_content_length, …route_result_seam_returns_complete_response | 100% tests passed out of 546 (+2 allowed skips) | 100% tests passed out of 282 (the 2 new cases are unlabelled and run under wine; real Windows pending MSYS2) |
| 6b | AUTH-01..04 kept, DOS-01 (415/417/505), §4.1, §3.6, §3.9 | header-first RequestRouter/ApiRouter (`ApiRouterConfig`, `HealthView`, `ChatHandler`), kRouteTable routing, 401/404/405/415/413 order, ACAO + `Vary: Origin` on every response after an approved origin (401 included); /v1/models[/id] only the served model (`launch.model_id`, owned_by "local"; expert inventory no longer listed, spec E9/re-anchor 4); model id/owned_by validated as UTF-8, no C0/DEL, 1..`kMaxModelFieldBytes` (new in api_constants.hpp, pre-flight D10), else 500 internal_error; /health keeps the SP2 body, a non-literal engine/recovery or a throwing provider is 503 engine_unavailable; `is_json_content_type` compares in place (noexcept, no allocation; D9) with the shared ASCII helpers (D6); `is_valid_utf8` exported from json.hpp; `handle_authenticated_get` legacy bridge for secure_server_main and both smoke mains (smoke mains serve their first inventory model; Task 8b reworks them). Transitional (pre-flight S11): main's health lambda calls `supervisor.snapshot()` directly until Task 16 moves it onto SupervisorPort. Updated per spec §9.4: api_router_tests.* and http_request_handler_tests.* assert §7.2 bodies (no `{"error":"Not Found"}`/`Service Unavailable`) | http_parser_tests.dos01_status_matrix_415_417_505, …content_type_variants_accepted, …auth_and_route_order_follows_spec; api_router_tests.* (rewritten, names kept; auth01 iterates kRouteTable; health_carries_recovery_only_with_failed ported per T6b(a)); http_request_handler_tests.* (rewritten, names kept) | 100% tests passed out of 549 (+2 allowed skips) | 100% tests passed out of 285 (new cases unlabelled, run under wine; real Windows pending MSYS2) |
| 7 | DOS-01 (JSON), EXT-01 (schema), B6 | §3.1 schema: `parse_chat_request` → `ChatRequestResult` (`ChatRequestError{ApiError, param}`; every param a literal from the §7.2 fixed list), extensions and role tool/function first in document order, neutral no-ops (penalties 0, `logit_bias` {}, `stop` null/[], `n` 1, `logprobs` false), bounded temperature 0–2 / top_p (0,1] / seed 0–2^63−1 into `SamplingParams` (integer forms accepted), `max_tokens`/`max_completion_tokens` alias (both → invalid_request) and clamp-at-resolve (B2; parse caps at UINT32_MAX), `stream:true` → unsupported_parameter `stream` (M1), `stream_options` without stream → invalid_request; JSON depth `kChatMaxJsonDepth` 4 with decimals on; `parse_chat_completion_request` is now a nullopt wrapper. Deviation from the plan test text: `dos01_content_array_is_unsupported_parameter` uses `"content":["Hi"]` (depth 4); the OpenAI parts form `[{"type":"text",…}]` is depth 5 and is pinned as invalid_json (spec §3.1 depth ≤ 4) | http_parser_tests.dos01_json_depth_5_is_400, …dos01_json_limits, …dos01_content_array_is_unsupported_parameter, …sampling_neutral_values_are_no_ops, …sampling_bounds_rejected, …sampling_integer_forms_accepted; json_tests.json_decimals_only_when_enabled | 100% tests passed out of 556 (+2 allowed skips) | 100% tests passed out of 292 (new cases unlabelled, run under wine; real Windows pending MSYS2) |
| 8a | §2.2 polled reads, §2.7 stall rule, §9.4 SP0 gaps (EINTR, transient accept), §10 | socket_io (library `secure_frontend_socket_io`, not yet used outside its tests; Task 8b builds on it): RAII `Socket`, `set_non_blocking`/`set_no_delay`, `set_no_inherit` helper for Task 8b (pre-flight V12; binding test stays 8b's), `poll_sockets` over poll/WSAPoll bounded by `kMaxPollEntries` 128 (new in api_constants.hpp, pre-flight D10), `recv_some`/`send_some` (EINTR retried; `kInterruptedCode` = EINTR/WSAEINTR, T8a), `send_all_bounded` (every send sliced to `kMaxSendChunk` and polled for writability in `kStreamPollSlice` steps on POSIX and Windows; stall measured on progress, whole-write deadline; closes the SP2 carry-in that Windows sends to a stalled reader were not sliced), `probe_peer`/`bytes_pending` (MSG_PEEK), `half_close_and_drain` (kDrainBudget/kDrainBytes), `WinsockGuard`, `detail::accept_backoff_for` (50 ms on transient errors, nullopt on EBADF/ENOTSOCK/EINVAL and Winsock equivalents) | http_socket_server_tests.send_retries_on_eintr, …accept_backs_off_on_transient_failure, …send_some_slices_to_max_send_chunk, …send_all_bounded_stops_at_stall_on_a_stalled_reader, …send_all_bounded_meets_deadline_and_completes, …send_all_bounded_stall_restarts_on_progress, …socket_io_poll_probe_and_recv, …set_no_inherit_marks_the_socket | 100% tests passed out of 564 (+2 allowed skips) | 100% tests passed out of 300 (new cases unlabelled, run under wine; real Windows pending MSYS2) |
| 8b | DOS-01 (P1/P3 deadlines), §2.2, §2.7 complete responses, §3.11 dispatch site, §9.4, SP2 K4 (pre-flight V12) | header-first connection handler (`connection_handler.hpp`: `ConnectionLimits` with SP1 schema defaults, `WorkerSignals`, `ConnectionOutcome`, `ConnectionResult`, `serve_connection` P1–P8 polled in 20 ms slices, 414/431 as soon as known, 408 at header/request deadline, authorize before any body byte, 100 Continue only with no body byte received, stray byte after the body → 400, EOF fine), `deliver_route_result` + `SocketStreamSink` (M1 placeholder; `kNoResponseStatus` → close with nothing written; a handler that throws or writes no head → fixed 500), `HttpSocketServer` rebuilt (`bind(listener, backlog, &err)`, port 0 ephemeral, listener polled in 100 ms slices via `accept_next`, `serve_one(router, limits, &err)`, idempotent `shutdown_listener` whose stop flag is the worker's `shutting_down` (pre-flight P34), no WSAStartup — every main holds a `WinsockGuard`), `kMinimumSendBudget`/private `send_all` deleted (socket_io's `send_all_bounded`), `connection_limits(FrontendConfig)` replaces `http_socket_server_limits`, `make_dispatcher_router` (legacy adapter by value, main until Task 9), smoke mains on `ApiRouter` + new bind/serve_one (chat → 404). **K4 gap closed (listener + accepted sockets CLOEXEC/no-inherit)**: Linux `SOCK_CLOEXEC` + `accept4(SOCK_CLOEXEC\|SOCK_NONBLOCK)`, other POSIX `FD_CLOEXEC`, Windows `WSASocketW(WSA_FLAG_NO_HANDLE_INHERIT)` + `set_no_inherit` per accepted socket. Transitional: `handle_authenticated_get` stays (main's legacy dispatcher) until Task 9 | http_socket_server_tests.socket_server_rejects_oversize_header_with_431, …head_terminator_split_across_reads (Review Focus 2), …expect_continue_skipped_when_body_already_sent (Review Focus 3), …expect_continue_sent_after_authorization, …stream_handler_dispatch_writes_head_chunks_and_terminal_chunk, …no_response_status_closes_without_writing, …listener_and_accepted_sockets_are_not_inherited, …socket_server_send_times_out_on_stalled_reader, …socket_server_accept_waits_without_timeout, …socket_server_ipv6_bind_is_v6only (binds `::`), …socket_server_responds_after_client_half_close (kept green), …socket_server_shutdown_listener_wakes_accept/…wakes_idle_client ("listener stopped"), …win_send_chunks_respect_write_stall (W, pending MSYS2), the rest ported per pre-flight T8b; subsystem_limits_tests.subsystem_limits_follow_config | 100% tests passed out of 571 (+2 allowed skips) | 100% tests passed out of 307 (`win_send_chunks_respect_write_stall` is `windows-runtime`: pending MSYS2; one earlier run hit a 0.01 s wine start-up flake, clean on rerun) |
| 9 | DOS-01 (header-first over TCP), AUTH-01, §4.6, §7, EXT-01 (amended ext01 bodies), §3.8 | `strata-secure-server` serves every request through `ApiRouter` (`model_id = launch.model_id`, `owned_by = "local"`, pre-flight P26) with header-first authentication, still serial (`serve_one` in SP2's loop) until Task 12; chat parses with `parse_chat_request` and maps `ChatRequestError{ApiError, param}` to `make_error_response(err, {.param})` on the wire (P28); wrong model → 404 model_not_found; `engine_refusal` → server_shutting_down while stopping, else engine_unavailable with `engine_retry_after(recovery)` (Retry-After 5 unless `exhausted`); execution errors map to context_length_exceeded / invalid_request / engine_error / internal_error. Deleted (P23/D7): legacy `handle_http_request(…HttpPolicy…)` overload, `HttpParserLimits`, `RequestDispatcher`, `DispatcherRouter`/`make_dispatcher_router`, `handle_authenticated_get`, main's `json_error`. One Winsock guard per main. Harness: `ServerOptions::config_literals` → owner-only `<root>/config.json` + `--config`; `kGeneric503`/`kBadRequest` now the §7.2 engine_unavailable/invalid_request bodies; test_support links api_core + typed_config (P36). Transitional (pre-flight S11): `supervisor.snapshot()` in the /health and `engine_refusal` lambdas and SP2's `execute_with_lease` are called directly from `run` until Task 16 | api_server_tests.dos01_body_over_limit_is_413_before_reading, …dos01_content_length_over_request_limit_is_413_before_auth, …dos01_unauthenticated_gets_401_before_body_is_read, …dos01_expect_continue_after_auth_only, …dos01_slow_header_is_408_at_header_deadline, …dos01_slow_body_is_408_at_request_deadline, …dos01_incomplete_body_then_close_frees_worker, …err_unauthenticated_is_401_on_every_path_and_method, …security_headers_on_every_response (all `windows-runtime`, pending MSYS2); server_tests.ext01_extension_fields_spawn_nothing (amended: every extension body within the depth bound — empty and populated tools/functions/mcp_servers, tool_choice, function_call, parallel_tool_calls, role tool/function — → the fixed extension_disabled body naming the key; one depth-5 tools body → 400 + nothing spawned, per the depth-limit ruling), …proc05_sigterm_during_generation_exits_cleanly (accepts the §7.2 server_shutting_down body); http_parser_tests.dos01_content_length_variants (+ mismatch / stray bytes via the seam, S12), …err_every_code_renders_fixed_body (+ engine_retry_after) | 100% tests passed out of 580 (+2 allowed skips) | 100% tests passed out of 307 (new api_server cases are `windows-runtime`: pending MSYS2) |
| 10 | WEB-01..06, AUTH-01 (route table), NET-03 (wildcard needs aliases) | acceptance over TCP against the real server: bad/malformed/duplicate Host on every `kRouteTable` route; IPv6 `[::1]:port` authority rules on a `::1` bind (skips with 77 without ::1); bound authority, `localhost` alias (any case) and exact `listener.host_aliases`; untrusted/duplicate Origin → 403 without CORS headers; no CORS header on any of 13 statuses by default; only the exact configured origin gets `Access-Control-Allow-Origin` + `Vary: Origin`, never credentials; preflight matrix (204 without a token, refused → 403, no GEN reached the engine); foreign-origin POST with a valid token → 403, no GEN; missing/malformed/wrong/duplicate token on every route; wildcard bind without aliases exits non-zero naming `listener.host_aliases` and spawns no engine (process half; validation half is typed_config_tests, Task 4). Helpers `has_no_cors_headers`, `route_request`, `wait_health_on(ip, port, host)` (pre-flight D2, reused by Task 12). No product change: acceptance tests, passed on first run | api_server_tests.web01_bad_host_rejected_on_every_route, …web01_ipv6_bound_host_rules, …web02_bound_authority_and_localhost_alias_succeed, …web02_host_alias_from_config_succeeds, …web03_untrusted_origin_no_cors_header, …web04_default_emits_no_cors_header_anywhere, …web05_only_exact_configured_origin_allowed, …web06_preflight_matrix, …web06_cross_origin_post_without_trust_rejected, …auth01_every_route_rejects_missing_malformed_wrong_token, …cfg01_wildcard_bind_requires_host_aliases (all `windows-runtime`, pending MSYS2) | 100% tests passed out of 591 (+2 allowed skips) | 100% tests passed out of 307 (new api_server cases are `windows-runtime`: pending MSYS2) |
| 11 | DOS-01 (eviction, per-remote cap, linger list), §2.3, §2.4 | `connection_pool.hpp` (library `secure_frontend_connection_pool`, unit level; Task 12 wires it): `AdmissionState` (not thread-safe; remote over `per_remote_cap` → refuse, loopback exempt; idle worker → assign; else the worker longest in P1 → evict, which releases the evicted peer's count; else refuse; connection ids make `header_complete`/`finished` of an evicted connection stale), `LingerList` (≤ `kLingerListMax` half-closed refused sockets, oldest closed at once when full; `append_poll_entries` for the accept thread's single `poll_sockets` per slice; `service` drains non-blocking and closes on EOF, error, `kDrainBytes` or `kLingerBudget`), fixed refusal `refusal_response` (503 server_busy, `Retry-After: 1`, ≤ `kRefusalMaxBytes`) and `refuse_connection` (one non-blocking send, half-close, linger). Linger case per pre-flight T11: the 503 is read from a still-lingering client, the evicted one is only asserted closed; which socket is evicted is pinned by native handle (review fix) | concurrency_tests.dos01_oldest_header_phase_connection_is_evicted, …dos01_remote_address_cap (+ eviction releases a remote peer's count), …dos01_linger_list_overflow_closes_oldest, …dos01_linger_closes_on_peer_eof, …refusal_response_is_fixed_and_small (portable, run under wine; MSYS2 pending) | 100% tests passed out of 596 (+2 allowed skips) | 100% tests passed out of 312 (the five new cases run under wine) |
| 12 | DOS-01 (slowloris, slow body, eviction over TCP), NET-01, §2.1, §2.8 | `ConnectionPool` (concurrent server, spec §2.1-2.4, §2.8): one accept loop (`run_until`) + `max_concurrent_requests` fixed workers created at start, joined at exit; `admit`/`header_complete`/`finished` only under the single pool mutex (static proof in the task report; TSan is a controller follow-up); the accept thread polls the listener plus the linger list in ONE `poll_sockets` per 100 ms slice (1 + `kLingerListMax` = 65 ≤ `kMaxPollEntries`, static_asserted); an evicted worker sees `abort` within one 20 ms slice and closes unanswered; refused sockets get the fixed 503 + linger. `secure_server_main` replaces SP2's serial loop: stop predicate `supervisor.stop_requested()` (P33), `PoolExit::listener_failed` → supervisor shutdown + `EXIT_FAILURE` (T12b); `run_until` also exits on an invalid listener handle. Task 8b carry-ins: POSIX `shutdown(SHUT_RDWR)` before closing the listener (a blocked poll wakes), and `send_all_bounded` gains a stop flag — once set, an in-flight write ends within `kShutdownDrainBudget` (never the full write deadline), every `connection_handler` write passes the pool's `shutting_down` | api_server_tests.dos01_eviction_over_tcp_admits_new_client, …dos01_slowloris_cannot_starve_a_real_client, …dos01_slow_body_clients_cannot_starve_a_real_client, …net01_workers_add_no_listener, …net01_ipv6_loopback_listener_only (new `tests/support/connection_scan.hpp`: Linux /proc fd+net tables with a uid fallback — the non-dumpable server hides /proc/pid/fd, ruling T12-scan — Windows iphlpapi tables by pid); http_socket_server_tests.send_all_bounded_stop_flag_cuts_an_inflight_write_within_the_drain_budget | 100% tests passed out of 644 (+4 allowed skips; SP2 `proc05_*` shutdown cases stay green on the pool) | wine/MSYS2 not run: owner ruling 2026-10-20 defers Windows runtime proof to owner hardware; `windows-llvm-mingw-cross` builds 0 warnings (new api_server cases + `connection_scan` Windows branch compile) |
| 13 | §2.5, D-1, V11 | `SupervisorPort` (SP3's `snapshot`/`acquire`/`report_fatal` serialized under one port mutex — SP2 was built for one serving thread; `~Lease` and `shutdown()` bypass the port and rely on SP2's own mutex, as D-1 documents) + `GenerationGate` (FIFO tickets, one running slot: snapshot fast-fail — starting/backoff/circuit_open→`engine_unavailable`, stopping/shutting_down/stopped→`shutting_down`, never waits for READY (V11); full queue → `busy` at once; a waiter wakes on `release()`/`shutdown()` or every `kStreamPollSlice` to check `client_gone`, its deadline, and headship; the head: `ready`→`acquire()` (lease, else `release()`+`engine_unavailable`), `generating`→re-check every 20 ms until its deadline; the holder destroys its Lease before `gate.release()`). T13b: `engine_supervisor.hpp` destructor comment now covers the Windows case (a reaped generation still leased in `retired_` cleans up on the Lease-destroying thread) — comment only. Plan-fixture fix: bare `supervisor.start()` would break -Werror ([[nodiscard]]) → wrapped in expect() | concurrency_tests.gate_first_request_gets_the_slot, …gate_queue_full_is_busy, …gate_fifo_order, …gate_timeout_returns_timeout, …gate_cancelled_waiter_leaves_queue, …gate_fast_fails_when_engine_not_ready, …gate_shutdown_refuses_waiters (new library `secure_frontend_generation_gate`) | 100% tests passed out of 651 (+4 allowed skips; the two timing-sensitive gate cases repeated 10/10 clean) | wine/MSYS2 not run (owner ruling 2026-10-20); `windows-llvm-mingw-cross` 0 warnings |
| 14 | test infrastructure (spec §9.2, M1 part) | fake engine: stdin read on a detached thread (`StdinReader`) — every line hits `--record-file` the moment it arrives (STOP visible mid-generation); flags `--token-ids`, `--tokens`, `--token-interval-ms`, `--finish`, `--prefill-delay-ms`, `--stop-delay-ms`, any of which switches GEN to `run_generation` and DONE to the full six-field form; STOP mid-generation → `DONE … cancel` after `--stop-delay-ms`; `max_new` reached first → `length`; SP2 modes (`--hang-in-gen` never acts on STOP, `--abort-in-gen`, `--fatal-line`, `--stall-stdin`, `--spew`) unchanged. Exit-path fix (ruling T14-exit): with a detached reader blocked in `std::getline`, glibc `exit()` deadlocks flushing all FILEs (main stuck in futex while the reader holds the stdin lock — observed: QUIT left the fake alive, deterministic 5×); `main` now flushes cout/cerr and `_Exit`s — the plan's own detach comment promises "return/_Exit"; every protocol line is flushed at emit, so no output loss. CMake: `find_package(Threads REQUIRED)` + link for both fake targets | fake_engine_tests.fake_engine_stream_modes_selftest (six blocks: cycled ids + full DONE, length, nonfinite, STOP-cancel with delay, prefill delay, SP2 short form intact) | 100% tests passed out of 652 (+4 allowed skips; fake+supervisor+server+child sets 135/135) | wine/MSYS2 not run (owner ruling 2026-10-20); `windows-llvm-mingw-cross` 0 warnings |
| 15 | B6 (GEN keys), §2.6 P6 cancel, §3.5, §5.4 | `GEN` carries schema-bounded sampling keys: `begin_generation(…, write_deadline, sampling={})` (ruling T15-signature: re-anchored SP2 keeps `write_deadline` 3rd, sampling added 4th — the plan snippet predates the hotfix), `render_sampling_keys` (shortest round-trip via `std::to_chars`, "" = greedy, never request bytes). `run_generation` (P6): READY gate like `execute`; reads in `kStreamPollSlice` (20 ms) slices; between slices checks cancel (→ `STOP(client_cancelled)` (ruling T15-stopcause) + `stop_drain_timeout` drain → `cancelled`), shutdown — pool flag OR SP2 signal flag, ruling R-H (→ STOP + `min(stop_drain, kShutdownDrainBudget)` drain → `shutting_down`), `generation_timeout` (→ STOP + drain → `timed_out`); failed STOP write or drain timeout → `abandon()` + `engine_unavailable`/`shutting_down`; nonfinite DONE → `engine_error` idle; ERR/fatal → `engine_error` closed; more tokens than asked → abandon + `engine_error`; DONE field 6 `length` else `stop`; text via `decode_token_ids` (fail → `decode_failed`). `context_tokens()` = READY context (0 before). `render_chat_completion` = exact §3.5 OpenAI body (invalid UTF-8/over-cap refused). RESUME/REUSED branches untouched | engine_protocol_client_tests.gen_carries_bounded_sampling_keys (reuses the file's FakeTransport — ruling T15-fake, no duplicate fake); chat_execution_tests.run_generation_reports_finish_usage_and_context, …run_generation_cancel_sends_stop_and_drains, …run_generation_timeout_stops_and_reports_timed_out, …run_generation_drain_failure_abandons, …run_generation_shutdown_uses_short_drain, …run_generation_maps_engine_errors (StopAwareTransport; the four timing cases repeated 20/20 clean); chat_schema_tests.renders_openai_completion_shape | 100% tests passed out of 660 (+4 allowed skips; targeted trio 38/38) | wine/MSYS2 not run (owner ruling 2026-10-20); `windows-llvm-mingw-cross` 0 warnings |
| 16 | DOS-02 (queue/busy/timeout/FIFO/health-while-full/serial), B1, B2, B6, §3.5, §5.4, §8 log codes | `ChatRoute` (new library `secure_frontend_chat_route`): P4 = schema parse, model check, plan (profile), prompt ids, `resolve_max_tokens` against the last READY context — 400s answered before any queue place; P5 = `gate.admit(port, now+queue_timeout, client_gone)` with the refusal map (busy/timeout→503 server_busy, cancelled→`kNoResponseStatus` + log_code `client_gone`, engine_unavailable→snapshot-based Retry-After, shutting_down→503); P6 = lease: budget re-checked against THIS generation's READY (400 if no room), `run_generation` with `ExecutionControl{client_gone, pool flag, shutdown_signalled}` (R-H: `report_fatal` only when protocol closed AND not shutting), then Lease destroyed BEFORE `gate.release()`. `make_completion_id` = "chatcmpl-"+32 CSPRNG hex; the 200 body is the §3.5 shape with real usage; `timed_out` → engine_error + log_code `generation_timeout` (B4 in M2). Defect found and fixed (named per plan): `GenerationGate::admit` refused an arrival whenever `max_queued == 0` even with the slot idle (serial mode got busy at once) — the cap now bounds WAITERS only; RED: "FAILED: max_queued = 0 still admits when the slot is idle (serial mode)". Wiring: supervisor→port→gate→chat_route→router→server→pool declaration order; /health reads `port.snapshot()`; `pool.run_until(P33 predicate, [&gate]{ gate.shutdown(); })` — ruling T16-pool: the plan's `shutdown_signalled()` predicate predates P33 and misses the recovery-exhausted exit, so P33 stays and `gate.shutdown()` runs as the pool's on-shutdown hook (Task 12's run_until already takes it). SP2 transitional chat lambda + `engine_refusal` deleted from main | api_server_tests.max_tokens_above_limit_is_clamped, …max_tokens_clamped_to_context_room, …prompt_alone_over_context_is_400, …absent_max_tokens_uses_auto, …sampling_passthrough_reaches_gen, …dos01_context_rule_is_400_without_gen, …chat_response_has_openai_shape, …dos02_excess_connections_get_503_retry_after, …dos02_queue_full_is_503, …dos02_queue_timeout_is_503, …dos02_queue_is_fifo, …dos02_health_answers_while_generation_places_full, …dos02_serial_mode_one_worker (the seven timing/shape cases repeated 21/21 clean) + concurrency_tests.gate_zero_queue_admits_one_at_a_time; SP2 `proc04_client_err_lines_open_circuit_until_restart` and `proc04_abort_in_generation_is_generic_503` stay green through the port | 100% tests passed out of 674 (+4 allowed skips; targeted api/server/e2e/concurrency 112/112; budget cases passed pre-implementation — SP2 already resolves B1/B2, honest note like T9a) | wine/MSYS2 not run (owner ruling 2026-10-20); `windows-llvm-mingw-cross` 0 warnings |
| 17 | DOS-02 (cancel, release), DOS-01 (health after attacks), §2.6, §2.8 | acceptance suite for behavior built in Tasks 6a/8a/8b/12/13/15/16: queued client disconnect leaves the FIFO queue silently (only A,C reach the engine); mid-P6 disconnect sends STOP within one poll slice (record shows STOP <1 s) and the drained cancel NEVER kills the engine; after 100 abandon-and-cancel chats the server's thread and fd counts return to their idle baseline and /health answers; SIGTERM during a generation: exit 0 within SP2's 5 s bound, the in-flight chat gets 503 `server_shutting_down` or a close, and the log contains NO `drain_failed`/`protocol_failed`/`write_timeout` (R-H — no worker-side failure reported fatal during shutdown); /health 200 + chat 200 after each of 7 attacker shapes (oversize header, deep JSON, chunked, slow-then-closed body, slow header, over-limit body, TLS-garbage) | api_server_tests.dos02_queued_client_disconnect_leaves_queue, …dos02_non_stream_disconnect_cancels, …dos02_resources_return_to_idle, …shutdown_errors_never_report_fatal, …dos01_service_healthy_after_each_attack — all passed on FIRST run (no product change needed); repeats 15/15 clean | 100% tests passed out of 679 (+4 allowed skips) | wine/MSYS2 not run (owner ruling 2026-10-20); `windows-llvm-mingw-cross` 0 warnings |
| 18 | PRIV-01/DL-01 (frontend part), §6.2 static tripwire | `tests/support/binary_imports.hpp` (stdlib-only): ELF64-LE reader — undefined `.dynsym` symbols + `DT_NEEDED`; NO `SHT_DYNSYM` → `ok=false` "no dynamic section (static binary?)" (never passes vacuously); PE32+ reader — import directory (data dir 1) → DLL names, by-name and by-ordinal thunks (bit 63); no import directory → `ok=false`; `forbidden_imports`: resolver calls (`getaddrinfo`…, `_`-stripped, lowercased), `winhttp/wininet/urlmon/dnsapi.dll` (case-insensitive), and ANY ordinal-only `ws2_32.dll` import (catches gethostbyname #52). Deviations to compile under -Werror: `std::numeric_limits<…>::max()` for the plan's `UINT64_MAX`, `(void)import_size` (read but unused in plan text), `<cctype>` in the test | egress_tests.egress_server_imports_no_resolver_or_http_client (positive control: `accept`/`accept4` really in `.dynsym`; the real Linux `strata-secure-server` imports NO forbidden symbol — no egress path found), …egress_static_tripwire_fails_on_binary_without_dynamic_section (synthetic ELF/PE per controller note 10/R-I; the readers run on the images, not a mock) | 100% tests passed out of 681 (+4 allowed skips) | wine/MSYS2 not run (owner ruling 2026-10-20 — the wine ctest line of the plan NOT RUN; PE reader still COMPILES in `windows-llvm-mingw-cross`, 0 warnings) |
| 19 | PRIV-01, PRIV-03, DL-01 (frontend part), §6.2 runtime | LD_PRELOAD interposer `tests/support/egress_tripwire.cpp` (Linux test-only; never linked into product): wraps `connect`/`sendto` (address≠null)/`sendmsg` (msg_name)/`getaddrinfo`/`gethostbyname`/`socket` (AF_UNIX, AF_NETLINK, SOCK_DGRAM) — one line to `$STRATA_EGRESS_RECORD` + EACCES/EAI_FAIL/null; everything else passes through to the real symbol. `tests/support/egress_support.hpp`: `arm_egress_tripwire` (extra_env), `SocketScan` (50 ms samples of `sockets_of(server pid)` + `descendants_of` children), `run_lifecycle` (health, models, chat, mid-generation cancel, command-like values, refusal flood, 40 half-header slow clients, health; engine restart via `--fail-first=1`). DEFECT found reaching GREEN (named): the plan's SocketScan rule assumed per-pid attribution — the server is non-dumpable so its rows are only uid-attributed (ruling T12-scan) and the ambient same-uid/container sockets drowned it (first RED below). Ruling T19-scan: on Linux the scan pins the server's LISTENER set differentially (NET-01 precedent) and the engine children EXACTLY (dumpable → inode mapping); Windows keeps the plan-strict rule (per-pid iphlpapi tables — `-Wunused-private-field` adaptation: baseline members guarded to Linux). CMake: `strata_egress_tripwire` SHARED + `strata-egress-probe-helper` above the first `secure_frontend_test_paths` call, defs via `if(TARGET)` in that function; Windows registers only command-like + table_scan (windows-runtime label) + iphlpapi; egress tests link `secure_frontend_socket_io` | egress_tests.egress_interposer_self_test (probe helper under the preload: all five calls recorded AND denied), …egress_interposer_records_nothing_during_lifecycle (zero forbidden calls through the whole lifecycle, exit 0), …egress_table_scan_during_lifecycle (violation list empty; windows-runtime-labeled on Windows), …egress_command_like_values_trigger_nothing (5 remote-looking contents 400, pull-model 400, 4 acquire/update routes 404, no GEN, `active_processes` unchanged, interposer record empty) — stability repeats 20/20 clean | 100% tests passed out of 685 (+4 allowed skips; egress set 6/6) — interim honest note: one earlier "green" claim was against an un-wired build (full-suite rerun exposed the 3 not-green cases; corrected here) | wine/MSYS2 not run (owner ruling 2026-10-20; the plan's `ctest -R egress_tests` under wine NOT RUN); `windows-llvm-mingw-cross` 0 warnings (test binary compiles clean, 4 cases registered 2 on Windows) |
| 20 | EXT-01, EXT-02 (spec §6.4 amendments) | The SP2 ext cases now run under the §6.2 runtime tripwires: `ext01_extension_fields_spawn_nothing` and both `ext02_*` cases wrapped with `arm_egress_tripwire` + `SocketScan` (+ end-of-case "scan: only the listener's sockets" / "interposer recorded nothing" expects); adaptations recorded: the arm for `ext02_extension_env_never_reaches_child` sits AFTER its own `extra_env` assignment (a plain assignment would wipe the preload; replacing /nonexistent with the real tripwire strengthens the ban it asserts), and that case's `SocketScan` is optional (the case tolerates a null server). For `ext02_rejected_before_spawn` (refusal-to-start): interposer lines only, record asserted empty after `wait_exit` — no scan (no running server). New: `ext01_upstream_control_routes_are_404_after_auth` (16 upstream control targets × GET+POST all 404 with the exact `not_found` body after auth), `ext02_http_headers_cannot_enable_extensions` (4 header switches change nothing: tools still 400 `extension_disabled`/"tools", ordinary chat 200 unaffected, exactly 1 GEN, no process churn). `secure_frontend_server_tests` links iphlpapi on WIN32 | server_tests.ext01_extension_fields_spawn_nothing, …ext02_extension_env_never_reaches_child, …ext02_rejected_before_spawn (amended — interposer + scan recorded NOTHING during all three: no real finding) + api_server_tests.ext01_upstream_control_routes_are_404_after_auth, …ext02_http_headers_cannot_enable_extensions — acceptance suite, ALL passed on FIRST run (rules exist since Tasks 6b/7/9); repeats 15/15 clean | 100% tests passed out of 687 (+4 allowed skips; targeted ext0 set 5/5) | wine/MSYS2 not run (owner ruling 2026-10-20); `windows-llvm-mingw-cross` 0 warnings |
| 21 | §8 (request logging without telemetry), PRIV-02 (frontend), §7 fixed reasons | `secure_frontend_request_log` library: `format_request_line` = "req <seq> <route> <status> <code\|-\\> <ms> <bytes_out> <peer>" (route ∈ health/models/model/chat/other; peer loopback\|remote; codes §7.2 + log-only `generation_timeout`/`client_gone`/`write_stall`/`evicted` via `log_record_for` mapping pool outcomes); `RequestLogger` token bucket — burst `kLogBurst` 100, refill `kLogRatePerSecond` 20/s, drops counted and reported `log: <n> request lines suppressed` at most once per second when the bucket next has a token; off ⇒ nothing written; `stderr_sink` fixed 256 B buffer, one fwrite per line, failures dropped. Wiring: pool observer (Task 12 hook) feeds the logger; startup summary `strata: listening <authority>, workers <n>, queued generations <q>` once to stderr after bind, before supervisor.start() — the operator's own settings only | concurrency_tests.request_log_format_and_token_bucket (exact lines incl. "log: 200 request lines suppressed" and the 100+1+20 refill count); api_server_tests.log_line_format_and_rate_limit (300 health hits: burst 100, ≤ 100+20·(s+1.2)+1 lines, suppression line, startup summary present); api_server_tests.err_no_token_prompt_or_path_in_any_body_or_log (marker through content/tools/field-name/model/path/bad-token/header/Host/Origin: never reflected in any response; stderr has no marker, token or root path) — RED (compile, as plan Step 2 predicts): "fatal error: secure_frontend/request_log.hpp: No such file or directory"; all three green on FIRST build; repeats 9/9 clean | 100% tests passed out of 690 (+4 allowed skips) | wine/MSYS2 not run (owner ruling 2026-10-20); `windows-llvm-mingw-cross` 0 warnings |
| 22 | §10 Windows parity, R2 (TSan) | Three Winsock-parity cases compiled everywhere, ctest-registered on Windows only (windows-runtime label, MSYS2 authoritative), manual on Linux: `win_refusal_is_read_not_reset` (30 refused clients all READ the full 503 — lingering close, no RST), `win_eviction_wakes_worker_within_one_slice` (workers=1, 30 s half-header holder; the new client served <250 ms — oldest-P1 eviction wakes the worker within one 20 ms slice), `win_disconnect_detected_by_peek` (mid-generation vanish → STOP in the record within 1 s). CI: `linux-clang-tsan` job added after `linux` (continue-on-error, ubuntu-24.04 pinned, mmap_rnd_bits=28, `-fsanitize=thread` on the linux-clang preset, `-E egress_interposer` — interposer+TSan don't mix) + header Non-blocking line updated. Ruling T22-tsan: owner disabled Actions (2026-10-20) — definition only, agents never push; TSan absent on this host, so the job is the future vehicle | api_server_tests.win_refusal_is_read_not_reset, …win_eviction_wakes_worker_within_one_slice, …win_disconnect_detected_by_peek — all three exit=0 on Linux FIRST run (same code paths), repeats 9/9 clean; `ctest --test-dir … -N -L windows-runtime` lists 3 win_ entries (grep count 4 counting SP2's pre-existing win_send_chunks_respect_write_stall) — wine run NOT RUN (owner ruling), pending MSYS2 | 100% tests passed out of 690 (+4 allowed skips; no Linux registration change) | `windows-llvm-mingw-cross` 0 warnings; Windows execution of the three cases waits for the owner's hardware (pending MSYS2) |

#### M1 status (recorded by Task 23, 2026-10-21)

SP3 M1 done on branch `sp3-api-streaming`, merged into `main` 2026-10-21: accept thread + worker pool (default 8), FIFO generation gate (default queue 4, 300 s), header-first authentication, §4.2 parser, Host/Origin/CORS, §7.2 JSON errors, decisions B1/B2/B6/B10/B11/B12 implemented; B3/B4/B5 are M2.

- linux-gcc (Task 23 battery, this host): `100% tests passed out of 690` — 686 passed, 4 allowed env skips (`cfg03_rejects_mount_crossing`, `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`, `bundle_at_mount_root_is_read_but_never_written`); `ctest -N | grep -cE '\.(net0[123]|web0[1-6]|dos0[12]|ext0[12]|egress_|err_|cfg01_|win_)'` = 98 §9.3 M1 cases listed individually; `Total Tests: 690`. pytest 25 passed.
- wine: NOT RUN (owner ruling 2026-10-20: GitHub Actions disabled, no wine on this host; agents prove only the local `windows-llvm-mingw-cross` cross-build — clean, 0 warnings, compile-only).
- `windows-runtime` cases pending windows-msys2-clang (owner hardware): 308 registered in the cross preset — acquire 68, api_server 50, bundle 26, fetch 27, server_tests 16, server_cli 13, engine_supervisor 13, engine_arguments 12, privacy 9, token_reader 8, engine_child 8, typed_config 19, paths 6, token_store 3, fake_engine 3, subsystem_limits 3, model_inventory 4, server_e2e 9, model_index 2, egress 2, engine_process 1, http_socket_server 1, tokenizer_pack 5, plus the 2 `strata_secure_server_*` CLI smokes.
- TSan: not installed on this host — "not run on this host (controller follow-up)"; the non-blocking `linux-clang-tsan` job (Task 22, ruling T22-tsan) is the future vehicle.
- Final-grep honesty (ruling T23-grep): `grep -rn "kMinimumSendBudget\|chatcmpl-local\|text/plain; charset" src include` prints ONE line — `chat_schema.cpp:277`, the legacy `render_chat_completion_response` kept per the plan's own Task 16 rule ("stays only if a test still uses it" — `chat_schema_test.cpp` pins it; no product path calls it; the M1 response is the §3.5 `render_chat_completion`, pinned since Task 15/16). `grep -rnE "std::chrono::(milli)?seconds\([0-9]{3,}\)" src` prints 8 lines, ALL in untouched SP1/SP2-era supervision files (`engine_stdio_process.cpp`, `engine_process.cpp`, `engine_supervisor.cpp`, `models_store_windows.cpp` — verified unchanged on this branch; §5.3 governs the HTTP/API constants files, which carry every SP3 timing value). No SP3 task added a literal either grep flags.

#### SP1 addendum (recorded by SP3, spec §5.1, §5.3)

| # | Change | Task |
| --- | --- | --- |
| A1 | Rows listener.cors_origins, listener.host_aliases, limits.http.{header_deadline_ms, write_stall_ms, response_write_deadline_ms, stream_keepalive_ms}, logging.requests; string-array entry bound and per-entry grammar (ConfigKeyExtension side table); cross-field header ≤ request, response ≥ stall, wildcard ⇒ aliases. Compatibility: an SP1 file that sets request_deadline_ms below 10000 must now also set header_deadline_ms (≤ it); an SP1 wildcard-bind config must now name listener.host_aliases (spec §4.3) | 4 |
| A2 | max_concurrent_requests 1-256 default 8; max_queued_generations, queue_timeout_ms, max_connections_per_remote_address (derived defaults, `--check` marks "(derived)", init omits them); default_max_tokens 0-16384 default 0 = auto. Compatibility: an SP1 file that sets max_concurrent_requests to 1 still validates (queue 0, per-remote cap 1 derived); one that omits it now gets 8 workers | 5 |
| A3 | secure_frontend_json: opt-in `JsonLimits::allow_fractions` + `JsonKind::decimal` / `make_decimal` / `if_decimal` (RFC 8259 frac/exp via `from_chars`, finite only; config stays integer-only by default); chat schema depth 4, max_tokens clamped instead of rejected | 7 |
| A4 | SP1 spec §4 internal-constants list: the 1000 ms minimum send budget is deleted (replaced by `limits.http.write_stall_ms` and `limits.http.response_write_deadline_ms`); the 100 ms / 256 KiB half-close drain moved to `api_constants.hpp`. | 8a |

#### SP2 second-run follow-ups SP3 still depends on (Task 23)

- **D-1** (lease-release notification; documented thread-safety of `acquire`/`snapshot`/`report_fatal`): SP3 serializes its own calls through `SupervisorPort` (Task 13); `~Lease` and `EngineSupervisor::shutdown()` still bypass the port and rely on SP2's own mutex — unchanged SP2 behavior, documented there.
- **D-2** (a drain failure after a client-requested `STOP` must not count toward the circuit; risk R4): SP3 sends `STOP(EngineStopCause::client_cancelled)` from the P6 cancel path (ruling T15-stopcause) and derives the kill reason through `kill_reason_for(protocol)`; SP2's bound (≤3 uncounted client-STOP restarts in a row) still applies. Residual: R4 in the threat model.

#### Deferred to M2 (controller note 7, recorded by Task 23)

SSE/chunked streaming, `next_event`, `Utf8StreamDecoder` (and the non-streaming decode via it), decision B4 (timeout → partial text with `length`; M1 answers `503 engine_error` + log_code `generation_timeout`), B3 (U+FFFD), B5 (chunked framing), keepalive, `stream_options` acceptance, `secure_frontend_api_client`, `strata-api-probe`, `docs/validation/sp3-api-kit.md`, the streaming DOS-02/WEB-04/EXT-01 cases, fake-engine modes `--progress-records`, `--crash-mid-gen`, `--err-mid-gen` and the UTF-8 tokenizer ids.
| A6b | export `is_valid_utf8` from json.hpp (noexcept wrapper over the existing valid_utf8; behaviour unchanged) for §3.9 model-field validation | Task 6b |

### SP3 M2 deliverables (branch `sp3-api-streaming`, after the M1 merge)

Plan: `docs/superpowers/plans/2026-10-14-sp3-m2-streaming.md`. Baseline after M1 (reproduced at `f01ef654`, 2026-10-21): linux-gcc N₀ = 690 run, 100% (694 registered, the 4 allowed environment skips), pytest 25, `windows-llvm-mingw-cross` build 0 warnings; wine W₀: **not run on this host (owner ruling 2026-10-20: no wine, no CI; agents prove only the cross build)**. Every M1 name M2 consumes was found (Task 1 Step 2): all greps `OK` except three plan strings with grep-text drift whose interfaces exist exactly as consumed — `api_error_row(ApiError error) noexcept` (named parameter + noexcept), `void report_fatal(const Lease& lease, KillReason reason)` (declared in `generation_gate.hpp`, beside `SupervisorPort`), and `refuse(ApiError::unsupported_parameter, "stream")` in `chat_schema.cpp` (M1's helper is `refuse`, not `fail`; Task 10 replaces that line). Ruling recorded in the lane ledger.

| Task | Deliverable | RED | linux-gcc | wine | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | M1 interfaces verified; baseline reproduced | — | 690 run, 100% (694 reg., 4 env skips); pytest 25; cross 0 warnings | not run on this host (owner ruling 2026-10-20) | done |
| 2 | Fake engine M2 modes: STOP-aware prefill/pauses, `--progress-records`, `--crash-mid-gen`, `--err-mid-gen`, `--burst-tokens`; byte pack id 258 (1024×`a`) + `id_for_byte`/`token_ids_for` | `fake_engine_stream_modes_selftest` (extended): "FAILED: not after the 3 s prefill", "FAILED: not after the 3 s pause", "FAILED: four tokens without a pause", "FAILED: PP then the token", "FAILED: ERR after two tokens: T 7", "FAILED: --crash-mid-gen exits" | 690 run, 100% (694 reg., 4 env skips) — unchanged, no new CTest entry; cross 0 warnings | not run on this host (owner ruling 2026-10-20) | done |
| 3 | `Utf8StreamDecoder` (incremental UTF-8, decision-3 U+FFFD policy), `TokenByteDecoder` raw per-token bytes; `decode_token_ids` now delegates | `sse_test.cpp:1:10: fatal error: secure_frontend/utf8_stream_decoder.hpp: No such file or directory`; `tokenizer_pack_test.cpp:185:26: error: 'TokenByteDecoder' in namespace 'secure_frontend' does not name a type` | 695 run, 100% (699 reg., 4 env skips) = +5; cross 0 warnings | not run on this host (owner ruling 2026-10-20) | done |
| 4 | `EngineProtocolClient::next_event` (T/PP/DONE one record at a time; strict full-form DONE finish); `read_generation` rebuilt on it | `engine_protocol_client_test.cpp:368:36: error: 'GenerationEvent' in namespace 'secure_frontend' does not name a type` (+ `no member named next_event`) | 698 run, 100% (702 reg., 4 env skips) = +3; cross 0 warnings | not run on this host (owner ruling 2026-10-20) | done |
| 5 | `drive_generation` — the one generation loop (timeout→STOP→length/B4, byte cap on code points, cancel/shutdown drains); `run_generation` = `begin` + loop; `tests/support/chat_json.hpp`; route: timeout is 200 length + `generation_timeout` log code | compile: `chat_execution_test.cpp:2:10: fatal error: secure_frontend/generation_run.hpp: No such file or directory`; runtime (untouched M1): "FAILED: a max_tokens cut mid-character is a 200, not a decode failure", "FAILED: a timed-out generation is a 200 (decision 4)" | 704 run, 100% (708 reg., 4 env skips) = +6; TSan spot on the new loop 10/10 zero reports; cross 0 warnings | not run on this host (owner ruling 2026-10-20) | done |
| 6 | SSE encoder: role/content/final/usage/error events (one line, `append_json_string` escaping), 16 KiB code-point deltas under the 128 KiB event cap, chunk framing, `[DONE]`/keep-alive/terminator constants | `sse_test.cpp:2:10: fatal error: secure_frontend/sse_encoder.hpp: No such file or directory` | 707 run, 100% (711 reg., 4 env skips) = +3; cross 0 warnings | not run on this host (owner ruling 2026-10-20) | done |

## Current security behavior implemented in `secure_frontend`

Since SP1, `strata-secure-server` configuration is one typed, schema-validated
`FrontendConfig` (`frontend_config.hpp`; every key is in the README key table,
generated from `config_schema()`), read from built-in defaults, then an
optional strict JSON file (`--config`), then command-line options:

- Defaults to `127.0.0.1:8080`.
- The listener classifies its address from the parsed bytes (IPv4/IPv6
  literals) and rejects every hostname except `localhost` (ASCII
  case-insensitive), which maps to `127.0.0.1` with no resolver call.
- Requires `listener.allow_remote` for every non-loopback address, and in
  addition `listener.allow_wildcard_bind` for every spelling of the unspecified
  address (`0.0.0.0`, `::`, `::0`, `0::0`, the long form, `::ffff:0.0.0.0`, …).
- The whole configuration is validated, collecting every issue by key path
  with a fixed reason (no values echoed), before the listener binds or the
  engine starts. `--check` opens and inspects but never creates, writes,
  renames or deletes anything; only serve and `init` create the logs/cache
  roots. Config files (and their folders) writable by other users are refused.
- The engine is spawned only after the listener is bound.
- Roots and the engine executable are canonical (`CanonicalRoot`,
  `CanonicalFile`); files below a root are opened with `openat2`/a no-follow
  walk on Linux and a `READ_CONTROL` reparse-rejecting walk on Windows.
- Every listener requires a token, including on loopback. `init` generates a
  43-character CSPRNG base64url token; operator tokens must be 32–256 bytes.
  The token is held in `SecretBytes`, compared in a fixed 256-byte window
  (`TokenVerifier`), never stored in the config object and never passed to the
  child. An environment token is wiped and removed from the environment after
  it is read. The server is non-dumpable with a zero core limit (Linux).
- Rejects ports outside `1..65535`.

This is intentionally stricter than upstream. Do not weaken it to recover
legacy behavior. Add an explicit, reviewed migration path if compatibility
requires a change.

The implemented primitives and their current runtime connections are:

- `SecretSource` retains only a validated environment-variable name or
  portable relative protected-file path metadata. It rejects traversal,
  absolute/UNC/device/drive/ADS forms and Windows reserved names. It has no
  plaintext-token field or resolution operation; a later authentication layer
  must resolve beneath a canonical root and own the secret briefly and securely.
- `HttpPolicy` validates exactly one syntactically valid `Host` header against
  an exact allowlist, rejects duplicate/malformed/untrusted `Origin` headers,
  keeps CORS off by default, and only permits byte-for-byte configured CORS
  origins.
- `TokenReader` resolves an environment source or a canonical-root,
  owner-only regular protected file without symlinks/reparse points or extra
  hard links, through the canonical-path module. The Windows branch validates
  final handle paths, current-user ownership, and a protected private DACL on
  the root and every component, and unwraps a DPAPI `STRATAK1` file. It is
  fail-closed. Since SP1 `secure_frontend_token_reader_tests` builds and runs
  on every platform; its Windows file cases are `windows-runtime` and **verified in MSYS2, CI
  run `38540719307`**.
- `EngineProcess` and `EngineStdioProcess` start a child without a shell or
  inherited environment and reject embedded NUL in executable/argv/env values.
  The production engine's environment is rendered by the frontend
  (`EngineEnvironment`, spec §3.9) and is exactly: POSIX `PATH=/usr/bin:/bin`,
  `LD_LIBRARY_PATH`, `TMPDIR=<state>/engine-tmp/<gen>`,
  `CUDA_CACHE_PATH=<state>/cache/cuda` (`<roots.cache>/cuda` when `roots.cache`
  is set, since Task 29b) (plus optional `STRATA_HIPBLASLT_TUNING`,
  `STRATA_WATCHDOG_S`, `STRATA_WATCHDOG_IO_S`); Windows
  `PATH=<lib dirs>;%SystemRoot%\System32`, `TEMP`, `TMP`, `CUDA_CACHE_PATH`,
  `SystemRoot`, `WINDIR`, `SystemDrive`, `NUMBER_OF_PROCESSORS`. `<state>` is
  the required owner-only `--state-dir` (`roots.state`).
  On POSIX the child gets only stdio (argv/env prepared before `fork`,
  `O_CLOEXEC` pipes, descriptor sweep), runs in its own process group, and is
  reaped after `SIGKILL`. On Windows it is created suspended, assigned to a Job
  Object, then resumed. Both talk the documented Strata `--serve` line protocol
  over bounded private standard-I/O pipes, with a total generation deadline and
  `STOP`/drain recovery.
- `build_engine_arguments` builds the engine argv tail: for the Strata profile
  shard 1 comes from the inventory (`--native`), owned or unsupported flags
  are rejected, and `--pack` plus the other weight flags are operator-supplied
  pass-through; the GLM-5.3 profile passes arguments through.
- `RequestRouter`/`ApiRouter` (SP3 §3.6/§4.1/§4.2) route the **complete header**
  before any body byte (`kRouteTable`: `GET /health`, `GET /v1/models`,
  `GET /v1/models/<id>`, `POST /v1/chat/completions`; everything else 404/405
  after authentication). The §4.2 head scan rejects malformed, ambiguous or
  over-limit request lines and header blocks (414/431/411/413/505/417/400);
  Host/Origin policy and CORS as before; authentication is part of the header
  phase (constant-time token compare in the 256-byte window), and every error
  is the §7.2 fixed JSON body with a fixed `code` and `param`.
- `HttpSocketServer` binds only a revalidated numeric configured address
  (`::` as IPv6-only) and accepts in 100 ms slices; since SP3 it is the
  listener only — `ConnectionPool` (§2.1–2.4) runs it on one accept thread
  with `limits.concurrency.max_concurrent_requests` fixed workers (default 8):
  per-address admission cap `max_connections_per_remote_address` (derived
  min(4, workers); loopback exempt — decision B12), oldest-P1 (header-phase)
  eviction when no worker is idle, and a fixed 503 `server_busy` +
  `Retry-After: 1` read through a lingering close for refusals. Each worker
  serves P1–P8 polled in 20 ms slices under `header_deadline_ms` (default
  10 s) and `request_deadline_ms` (default 30 s) with body caps
  (`limits.http.max_request_bytes` 64 KiB; chat body 49152), §2.7 complete-
  response writes bounded by the stall rule (`write_stall_ms` 10 s measured on
  progress, `response_write_deadline_ms` 60 s); every wait sees `abort` and
  shutdown within one slice. Chat generations are serialized by
  `GenerationGate` (FIFO; `max_queued_generations` derived default 4;
  `queue_timeout_ms` default 300 s; a full queue gets the fixed refusal at
  once; a client that vanishes mid-generation gets `STOP(client_cancelled)`
  within one slice). `secure_frontend_http_socket_server_tests` +
  `secure_frontend_concurrency_tests` + `secure_frontend_api_server_tests`
  cover these on this Linux host; the server-starting api/server/egress cases
  are `windows-runtime` (MSYS2 pending).
- `RequestLogger` (§8): with `logging.requests=true`, one fixed-field stderr
  line per finished request (`req <seq> <route> <status> <code> <ms>
  <bytes_out> <peer>`) under a token bucket (burst 100, refill 20/s, counted
  suppression line at most once per second); off by default; never a token,
  prompt, configured path or payload value.
- `ApiRouter` implements authenticated `GET /health` and `GET /v1/models[/id]` over
  immutable injected providers; in `strata-secure-server` `/health` returns
  `{"status":"ok"|"unavailable","engine":"starting|ready|generating|failed"}`
  (`starting` → `200` with `engine=starting` — READY is consumed on the first
  request; eager READY is SP2 — `ready`/`generating` → `200`, `failed` → `503`). Since
  SP3 /health also answers while the generation queue is full. The smoke
  executables pass no engine-state provider and keep `{"status":"ok"}`. `ModelInventory` discovers local
  `.gguf` artifacts only; it has no download, subprocess, or network behavior.
- `secure-frontend-smoke` wires the local components into a process users can
  run with an API-key environment variable and local model directory. It is a
  test server, not an inference server: chat requests correctly remain absent.
- `strata-secure-server` starts exactly one local engine child and implements
  authenticated, non-streaming, text-only `POST /v1/chat/completions` for the
  fixed offline GPT-2-byte-BPE/Qwen-ChatML profile or, only when selected at
  startup, the fixed GLM-5.3 prompt profile (since SP3 the endpoint runs
  through the concurrent pool + FIFO generation gate — many connections, one
  generation at a time; SSE streaming is M2). GLM mode requires an independently
  built and audited LightTransport-compatible `strata-glm-decode` engine and
  accepts only its exact bounded `PP` prefill progress record in addition to
  the normal private protocol. It requires explicit local engine/model/tokenizer
  paths, uses no downloads, and rejects unsupported model/templates, tools,
  images, URLs, MCP, and streaming.

## Required architecture

```
client
  -> portable native frontend (authentication, Host/Origin policy, request limits)
  -> private authenticated IPC/loopback endpoint
  -> Strata 0.1.43 engine child process
```

The frontend owns the externally visible listener. The engine must never be
directly exposed to LAN clients. The frontend starts it without a shell,
passes only typed and validated arguments, strips secrets from child argv and
environment, and gives it only the handles/descriptors it needs.

Implement a common process-supervision interface with platform backends:

- Windows: `CreateProcessW`, explicit inherited-handle list, anonymous/named
  pipes as appropriate, and a Job Object that terminates descendants.
- Linux: `posix_spawn` or `fork`/`execve`, close-on-exec descriptors, a process
  group, bounded output capture, and `waitpid` cleanup.

Never import UnbiasedStrata's POSIX process implementation unchanged.

## Privacy contract

Normal install, startup, inference, failure handling, shutdown, and local API
use must make no outbound connection or DNS lookup. The release must contain no
analytics, telemetry, crash upload, remote configuration, advertising, or
automatic update client. Prompts, completions, images, and usage data remain
local; request logging is off by default.

The only permitted network operations are separately invoked, foreground
`strata` commands: `strata pull` (acquire), `strata update` (today the
models part, `update --models`; the program part exits 12 until SP7) and
`strata run` for a model that is not installed, after the same confirmation.
Each uses a user-visible, digest-pinned HTTPS manifest and cannot be
triggered by an API request, model content, plugin, configuration or
automatic logic; `strata-secure-server` links no acquisition code (PRIV-04).
See the threat model ("Privacy and offline operation", "Artifact
acquisition"; amended by SP4 Task 29, spec §7.4) for the full rules. The
matching product-experience-spec amendments (SP4 spec §13.3) await a PX
addendum (SP4 closing summary, "What has changed").

## Ordered implementation backlog

SP0 items are marked **Done (SP0)**. Each open item names the sub-project that
owns it (see the decisions above).

### Phase 1 — native security primitives

1. Extend `secure_frontend` with immutable typed configuration for request
   time/concurrency limits and roots for models/logs/cache. **Done (SP1)**:
   `FrontendConfig`, `--config`/`--check`/`init`; concurrency stays 1 until SP3.
2. Add canonical-path validation for Linux and Windows, including reparse
   points, UNC/device/ADS forms, and traversal prevention. **Done (SP1)**;
   Windows runtime verified in `windows-msys2-clang` (CI run `38540719307`).
3. Add secure token generation/storage: CSPRNG; DPAPI-backed file on Windows;
   user-only permissions on Linux. Tokens must never reach log output,
   environment, child command lines, or metrics. **Done (SP1)**; the Windows
   DPAPI store passed in `windows-msys2-clang` (CI run `38540719307`).
4. Implement all relevant `CFG-*` and `AUTH-*` tests from
   `tests/security/README.md` before connecting these primitives to a server.
   **Done (SP1)** for CFG-01..06 and AUTH-01..04 (plus NET-01..03); the
   `windows-runtime` cases passed in `windows-msys2-clang` (CI run
   `38540719307`).

### Phase 2 — portable child supervision

1. Define a testable `EngineProcess` abstraction and a fake engine fixture. **Done.**
2. Implement the Windows and Linux backends described above. **Done (SP0)
   for the launch path: POSIX argv-before-fork, `O_CLOEXEC`, descriptor sweep,
   reap; Windows suspended start into the Job. Windows runtime still needs the
   `windows-msys2-clang` job.**
3. Add the remaining `PROC-01` through `PROC-06`, including fake-child crash/hang, inherited
   handle/descriptor inspection, and descendant cleanup tests. **Done on
   branch `sp2-portable-supervision` for Linux (all L and B rows green
   locally); Windows (W) rows pending the `windows-msys2-clang` job.**
4. Connect the abstraction to the actual 0.1.43 engine. **Done for the
   documented serial `--serve` protocol, with SP0's deadlines, recovery and
   inventory-owned `--native`; full profile coverage remains open (SP5).**

### Phase 3 — private API boundary

1. Implement authenticated `/health`, `/v1/models`, and
   `/v1/chat/completions` with bounded HTTP/JSON parsing and streaming.
   **The non-streaming text-only Qwen and explicitly selected GLM-5.3 subsets
   are implemented; streaming and concurrency are SP3, other profiles SP5.**
2. Enforce exact Host, Origin, and CORS policies; CORS is off by default.
   **Health/models/chat routing and engine state are connected for the narrow
   serial profile; add chat streaming only after a separate review (SP3).**
3. Add all `NET-*`, `WEB-*`, `DOS-*` and `EXT-*` tests on Windows and Linux.
   **SP3.** (SP0's socket tests cover the slow-request, oversize and early-close
   parts of `DOS-01` on Linux only.)
4. Differential-test supported request/response behavior against the upstream
   service. Preserve model and backend flexibility; reject only unsafe API
   behavior. **SP5.**

### Phase 4 — verified, explicit artifact acquisition

1. Implement an offline-by-default model inventory and local-file validation.
   **Inventory done; canonical-root validation done (SP1).**
2. Implement the explicit `acquire` command with HTTPS-only sources, byte
   limits, SHA-256 verification, temporary staging, and atomic publish.
   **Done in SP4** (branches `sp4-acquire`, merged at `4b9fdd31`, and
   `sp4-acquire-part2`): `strata pull`/`import`/`run`/`update --models`
   through a confined system curl. The real-HTTPS run is the manual step in
   "Verification performed", SP4 part 2.
3. Add `DL-*` tests using only local fixture servers. Never make tests fetch
   public model files. **Done in SP4** (same branches): DL-01..05 and
   PRIV-01..04 with a fake downloader and scripted resolver; Windows runtime
   cases of Tasks 25–28 verified in CI run `38655938748` (PRIV-04 link-set
   re-run pending).

### Phase 5 — compatibility, packaging, and release

1. Port all upstream model profiles, quantizations, vision/MTP paths,
   multi-GPU, CUDA, HIP, and experimental SYCL behavior one capability at a
   time with regression coverage. **SP5; the GLM engine is SP6. Both need the
   owner's NVIDIA host.**
2. Add CMake presets and CI for Windows and Linux. **Done (SP0)**: `linux-gcc`,
   `linux-clang`, `windows-llvm-mingw-cross`, `windows-msys2-clang`, and
   informational `windows-msvc`. **CI runs and is green**: all blocking jobs
   on run `38458255140` and, after the submodule layout, on run `38478775552`
   (see owner decision 9); `windows-msvc` stays informational.
3. Generate an SBOM and release manifest listing exact engine/dependency
   revisions and enabled network-capable components. **SP7.**
4. Run the full security/privacy matrix, dependency scan, and an independent
   review before claiming a hardened release. **SP7**, including the offline
   GPU validation kit for the Linux and Windows test boxes.
   SP2 G3 (unverified in CI and wine): on the offline Windows box, from a
   NON-elevated prompt, run `secure_frontend_engine_child_tests.exe --case
   proc06_elevation_required_is_spawn_failed` and record the result; it must
   pass (error 740 → `spawn_failed`, no `runas`).
   SP2 inputs for the kit: check that `/dev/nvidia-uvm` exists before
   starting; run once with the default (`PR_SET_NO_NEW_PRIVS` on) and, only if
   CUDA init fails, once with `--allow-new-privileges`; record which works;
   confirm the SP2 environment allowlist is sufficient for CUDA and ROCm (spec
   §2, not yet verified).
5. Stage only the native deliverables, then run
   `python3 scripts/secure_distribution_check.py --package-dir STAGE --release`.
   A source checkout fails this gate by design: it rejects any path under an
   `upstream` directory (the submodule) and the quarantined names at any depth;
   do not weaken the gate to make a source archive pass. **SP7.**

## Verification performed

### SP4 part 2 (2026-10-14, branch `sp4-acquire-part2`, Tasks 25–29)

Commits on base `557a2cc7`: `06630dbd` (Task 25, Linux confined
downloader), `563dd0e9` + `a79e8b02` (Task 26, Windows downloader + fix
round 1), `ecff71dc` + `1582fba4` (Task 27, network verbs + signals fix
round 1), `68273f72` + `e7a16999` (Task 28, privacy/release proofs +
positive controls), then the Task 29 docs commit. Each task was reviewed
(spec + quality); each fix round was re-reviewed. Run at `e7a16999` (Task 29
changes docs only) on the dev host: Linux 5.15.0 x86_64, no GPU, LSMs
`lockdown,capability,landlock,yama,apparmor` (Landlock ABI 1, so the
confinement proofs ran, not skipped), cmake 4.4.3, wine 6.0.3, worktree
`.worktrees/sp4b`, `.venv-dev/bin` first on `PATH`.

| Command (in `secure_frontend/` unless noted) | Result |
| --- | --- |
| `cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc` (hooks ON) | builds clean (`-Werror`, no warning lines); `100% tests passed out of 556` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); 520 at the base + 36 |
| `ctest --preset linux-gcc -N -L 'release-only\|release-also'` | `Total Tests: 7` (the preset excludes the 3 `release-only` cases; `ctest --test-dir out/build/linux-gcc -N` lists 559) |
| `cmake --preset linux-gcc-release && cmake --build --preset linux-gcc-release && ctest --preset linux-gcc-release` (hooks OFF, `release-only\|release-also`) | builds clean (`-Werror`); `100% tests passed out of 10` (6 at the base + `privacy.priv04_secure_server_does_not_link_acquisition`, `privacy.release_binary_lacks_hook_marker`, `privacy.dl01_server_makes_no_outbound_connection`, `fetch.release_spawn_has_no_fd4`) |
| `ctest --test-dir out/build/linux-gcc-release` (full, hooks OFF) | `100% tests passed out of 523` (same 2 skipped) |
| stage `strata` + `strata-secure-server` (release) into `out/stage-release/bin`; `python3 -I ../scripts/secure_distribution_check.py --package-dir out/stage-release` | `secure distribution check: PASS`, rc 0 (without `--release` until SP7, Controller note 19) |
| `cmake --preset windows-llvm-mingw-cross && cmake --build --preset windows-llvm-mingw-cross` | builds clean (`-Werror`, no warning lines) |
| `WINEPREFIX=$PWD/out/wineprefix WINEDLLOVERRIDES=mscoree,mshtml= ctest --preset windows-llvm-mingw-cross` | `100% tests passed out of 260` (515 registered; `windows-runtime\|release-only` excluded) |
| `.venv-dev/bin/pytest -q` (worktree root) | `25 passed` |
| `.venv-dev/bin/pytest -q tools/secure/test_catalog_provenance.py` (worktree root) | `2 passed` |
| spec case-name check (Task 29 Step 1 loop, over `ctest -N` of the linux-gcc, linux-gcc-release and cross build directories, so `release-only` and `windows-runtime` cases are listed) | every `<binary>.<case>` named in spec §10.3, §4.9 and §10.5 is registered except the SP7-deferred `fetch.release_spawn_has_no_extra_handle_windows`; the other non-matches are config keys and file names, not case names |
| `grep -n SECURE_STRATA_ENGINE_VERSION .github/workflows/secure-frontend.yml` (root) | no output; both `paths:` filters list `upstream.version` |

Real Windows: CI run `38625663621` on the base `557a2cc7` is green
(`windows-msys2-clang` 488/488, `linux-gcc-release` job green); it covers
Tasks 1–24b and SP2 run 2, not Tasks 25–28. **Verified on real Windows by
CI run `38655938748` (`9044a5bc`, `windows-msys2-clang` 515/516; was
pending MSYS2)**: every new `windows-runtime` case of Tasks 25–28 —
`fetch.downloader_transfer_through_job_windows`,
`dl03_default_windows_curl_path_accepted_windows`,
`dl03_downloader_runs_at_low_integrity_windows`,
`priv04_downloader_env_is_systemroot_only_windows`; the Task 27 Windows
acquire/fetch CLI cases including the Ctrl-Break
`acquire.dl04_interrupt_during_download_never_indexed_windows` (ruling I15)
and `fetch.confinement_reduced_written_to_log_record`;
`privacy.dl01_server_makes_no_outbound_connection_windows` (TCP and UDP,
IPv4 and IPv6 tables, listener positive control) and the Windows
`windows-runtime` privacy cases (tripwire, priv03, doctor proxy hint,
record-channel strata cases, doctor positive control). Also first proven
there: the Job `ActiveProcessLimit = 1` against conhost and the
Low-integrity child's access to `.staging/.cwd`. Wine-runnable additions
(`dl03_downloader_path_normalised_windows`,
`dl03_downloader_unc_path_rejected_windows`, priv04 and the hooks marker
case) are in the wine 260. Still pending on real Windows (no case in run
`38655938748` covers it): Ctrl-C at a
pending `[y/N]` may race the console-handler thread (the handler runs on its
own thread, so the read can return EOF before the flag is set: exit 2
instead of 8). MSYS2 run id for this branch: `38655938748` (`9044a5bc`).

- CI run `38655938748` (`9044a5bc`, `windows-msys2-clang`): 515/516; every other Tasks 25–28 `windows-runtime` case passed on real Windows (rows above flipped from pending to verified). The failure, `privacy.priv04_secure_server_does_not_link_acquisition` ("the strata link set was generated" + all three positive controls), was CRLF: native-Windows CMake's `file(WRITE)` writes text mode, so `strata\r\n` never matched the test's `"strata\n"` (the server's newline-free check passed and its `\n`-suffixed negative checks were vacuous). Fix commit "sp4: PRIV-04 link sets written LF and parsed per line, CRLF-proof with path/size/entries diagnostics (SP4 merge gate; spec §7.1)": `file(CONFIGURE ... NEWLINE_STYLE UNIX)` and an exact per-line entry parse dropping `\r`, positive controls unchanged in strength. linux-gcc 560/560 (+2 skips), linux-gcc-release 526/526 (10/10), wine 260/260, pytest 25, cross 0 warnings. MSYS2 re-run: pending.

**Required manual step (spec §13.5 item 4, the only real-HTTPS proof of DL-02), not yet run:**
on the online dev machine,
1. hooks build: a third-party manifest of profile `raw` for the 9 426 880-byte
   `vision/GLM-5.3-Flash-vocab.gguf` (`peasantsmith/GLM-5.3-Flash-Maya-GGUF` @ `f16ee4ba50d8fd2bb726ea1862ca6ca14ba188da`),
   `strata --config <cfg> pull --manifest raw.json --trust-manifest sha256:<hex> --yes`;
2. release build, stock curl: `strata --config <cfg> pull <name:tag> --bundle <dir>` once a catalog
   entry exists (D5 (A)/(C)); until then, `make_bundle.py` + `strata import` of a developer bundle.
Record curl version, TLS backend, confinement label and the result here; `import`
on an offline box is recorded when the owner runs it. Also to verify on the boxes
(§3.2, §10.4): Schannel and revocation checks at Low integrity; the inherited stdout
pipe accepting a Low-integrity writer; Landlock on the offline Linux kernel (`strata doctor`);
`--resolve host:443:[v6]` on curl 7.81.0 (until then IPv6-only hops fail closed).

What this does **not** show: no real curl, no network and no real model was
used (fake downloader, scripted resolver, local fixtures only); nothing ran
on Windows or on a GPU; Landlock ABI ≥ 2 rights (`REFER`, `TRUNCATE`, the
ABI 4 TCP rule) were not exercised on this ABI 1 kernel.

### SP4 merge into `main` (2026-10-14, merge `4b9fdd31`)

Merged tree (main `863b3ff6` + `sp4-acquire` `f0b09e2e`), dev host, `.venv-dev/bin` first.

| Command | Result |
| --- | --- |
| in `secure_frontend/`: `cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc` | build: 0 warnings; `100% tests passed out of 520` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`); 312 (main) + 207 (SP4) + 1 merge case |
| `cmake --preset linux-gcc-release && cmake --build --preset linux-gcc-release`; `ctest --test-dir out/build/linux-gcc-release`; `ctest --preset linux-gcc-release` (`release-only\|release-also`) | 0 warnings; `100% tests passed out of 510` (same 2 skipped); labelled `6/6` |
| `cmake --preset windows-llvm-mingw-cross && cmake --build --preset windows-llvm-mingw-cross`; `WINEPREFIX=$PWD/out/wineprefix WINEDLLOVERRIDES=mscoree,mshtml= ctest --preset windows-llvm-mingw-cross` | `-Werror`, 0 warnings; wine `100% tests passed out of 256` (489 registered; `windows-runtime` cases excluded) |
| `.venv-dev/bin/pytest -q` (worktree root) | `23 passed` |

### SP2 final-review fix wave (2026-10-14, branch `sp2-portable-supervision`)

HEAD before the wave was `b9d707de`; each line was run after the wave's code
commits (I1, I2, M1, M3/M5/M6) and the M4 header edit.

| Command | Result |
| --- | --- |
| in `secure_frontend/`: `cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc` | build: 0 warnings; `100% tests passed out of 312` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`) |
| in `secure_frontend/`: `cmake --preset windows-llvm-mingw-cross && cmake --build --preset windows-llvm-mingw-cross` | builds with `-Werror`, 0 warnings; 38 `.exe` files |
| `WINEPREFIX=$PWD/out/wineprefix WINEDLLOVERRIDES=mscoree,mshtml= ctest --preset windows-llvm-mingw-cross` (wine 6.0.3) | `100% tests passed out of 171` (282 registered; the 111 `windows-runtime` cases excluded) |
| `.venv-dev/bin/pytest -q` (worktree root) | `13 passed` |

### SP2 (2026-10-14, Task 28 final verification, branch `sp2-portable-supervision`)

Dev host (Linux x86_64, no GPU), worktree `.worktrees/sp2`, `PATH` with
`.venv-dev/bin` first; HEAD before the Task 28 commit was `a12fa0b0`. Each
line is a command run in Task 28, after its edits.

| Command | Result |
| --- | --- |
| in `secure_frontend/`: `cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc` | build: 0 warnings; `100% tests passed out of 308` (2 skipped: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`) |
| in `secure_frontend/`: `cmake --preset windows-llvm-mingw-cross && cmake --build --preset windows-llvm-mingw-cross` | builds with `-Werror`, 0 warnings; 38 `.exe` files (SP1's 30 + `strata-supervision-fake-engine`, `strata-supervision-fake-engine-elevated`, `secure_frontend_non_elevated_run` and five test binaries) |
| `WINEPREFIX=$PWD/out/wineprefix WINEDLLOVERRIDES=mscoree,mshtml= ctest --preset windows-llvm-mingw-cross` (wine 6.0.3) | `100% tests passed out of 168` (278 registered; the 110 `windows-runtime` cases excluded) |
| `pgrep -f strata-supervision-fake-engine` after both runs | no fake engine running (the only match was the `pgrep` shell itself) |
| `.venv-dev/bin/pytest -q` (worktree root) | `13 passed` |

Windows (W) rows and every `windows-runtime` test are unverified until the
`windows-msys2-clang` job is green after rflores pushes; nothing here was run
on a GPU.

### SP1 final fix wave (2026-10-14, branch `sp1-typed-config-paths-tokens`)

Final whole-branch review fixes I1 (`9e8312b5`, chat ranges = enforced caps),
I2 (`7d59353c`, engine `--native` as UTF-8), I3 + F3 (`4ad028c0`, serve prints
the actionable reason; `--check` verdict after the token read), F1 + F2
(`c706366d`, docs). Same dev host and `PATH`; HEAD before the wave `05c9db02`.
These numbers supersede the Task 24 table below.

| Command | Result |
| --- | --- |
| `.venv-dev/bin/pytest -q` (worktree root) | `13 passed` |
| in `secure_frontend/`: `cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc` | `100% tests passed out of 215` (210 + `cfg01_chat_ranges_match_enforced_caps`, `engine_native_path_is_utf8_for_non_ascii_root`, `serve_reports_why_the_token_and_tokenizer_pack_are_unusable`, `serve_reports_symlinked_model_entry` (POSIX only), `cli_check_unreadable_token_is_not_reported_valid`) |
| `ctest --preset linux-gcc -N \| grep -cE '\.(net0[123]\|auth0[1234]\|cfg0[123456])_'` | `59` (58 + `cfg01_chat_ranges_match_enforced_caps`) |
| in `secure_frontend/`: `cmake --preset windows-llvm-mingw-cross && cmake --build --preset windows-llvm-mingw-cross` | builds with `-Werror`, no diagnostics; 30 `.exe` files |
| `ctest --preset windows-llvm-mingw-cross` (wine 6.0.3) | `100% tests passed out of 128`, 0 failed; 193 registered, the 65 `windows-runtime` cases excluded: the 61 listed below plus `secure_frontend_typed_config_tests.cfg01_chat_ranges_match_enforced_caps`, `secure_frontend_engine_arguments_tests.engine_native_path_is_utf8_for_non_ascii_root`, `secure_frontend_server_e2e_tests.serve_reports_why_the_token_and_tokenizer_pack_are_unusable`, `secure_frontend_server_cli_tests.cli_check_unreadable_token_is_not_reported_valid` (each **verified in MSYS2, CI run `38540719307`**) |
| direct wine runs (smoke, not evidence) | `engine_native_path_is_utf8_for_non_ascii_root`: RED before I2 (`--native` not UTF-8 under ACP 1252), pass after; `serve_reports_why_the_token_and_tokenizer_pack_are_unusable`, `cli_check_unreadable_token_is_not_reported_valid`, `cli_check_prints_no_token`: pass |

### SP1 (2026-10-14, Task 24 final verification, branch `sp1-typed-config-paths-tokens`)

Dev host (Linux x86_64, no GPU), worktree `.worktrees/sp1`, `PATH` with
`.venv-dev/bin` first; HEAD before the Task 24 commit was `1904f827`.

| Command | Result |
| --- | --- |
| `.venv-dev/bin/pytest -q` (worktree root) | `13 passed` |
| in `secure_frontend/`: `cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc` | `100% tests passed out of 210` (`ctest -N`: `Total Tests: 210`; 209 before Task 24, plus `readme_config_table_matches_schema`) |
| `ctest --preset linux-gcc -N \| grep -cE '\.(net0[123]\|auth0[1234]\|cfg0[123456])_'` | `58`; every `net0*`, `auth0*` and `cfg0*` case is listed individually as `<binary>.<case>` |
| in `secure_frontend/`: `cmake --preset windows-llvm-mingw-cross && cmake --build --preset windows-llvm-mingw-cross` | builds with `-Werror` (incremental, 18 Ninja steps, no diagnostics); 30 `.exe` files in the build directory |
| `ctest --preset windows-llvm-mingw-cross` (wine 6.0.3, `WINEPREFIX=secure_frontend/out/wineprefix`) | `100% tests passed out of 128`, 0 failed; 189 registered (`ctest -N`), the 61 `windows-runtime` cases excluded (list below). `readme_config_table_matches_schema` runs unlabelled under wine with the Linux-absolute README path and passes, so no label was needed (ruling R9) |
| `wine …/strata-secure-server.exe --help` | `help exit=0` |
| `wine …/strata-secure-server.exe --check --port 0 --models-root 'C:\x' --tokenizer-pack 'C:\y' --engine 'C:\e.exe' --model-id m --token-env X` | prints `Configuration error: listener.port: must be between 1 and 65535`, `roots.models: the root does not exist or cannot be opened`, `roots.tokenizer_pack: …`, `engine.executable: the engine executable does not exist`; `check exit=1` (spec §9.2) |
| D4 probe: a scratch copy of `bootstrap-llvm-mingw.sh` under `secure_frontend/out/d4-*` with a corrupt archive in its own `.toolchains/downloads` (no network; the real `.toolchains` untouched) | before the fix `exit=1` and the archive kept; after `exit=1`, "digest mismatch; the downloaded archive was deleted", `downloads` empty |

`windows-runtime` tests not run locally (61; each was **pending
windows-msys2-clang** at Task 24 and is now **verified in MSYS2, CI run
`38540719307`**; some were run directly under wine as recorded in the
SP1 deliverables table, which is not evidence): `secure_frontend_paths_tests.paths_handle_non_ascii_and_long_names`, `secure_frontend_paths_tests.cfg02_create_within_root_writes_nothing_outside`, `secure_frontend_paths_tests.auth02_windows_token_file_reads_with_private_dacl`, `secure_frontend_paths_tests.cfg03_rejects_junction_below_root`, `secure_frontend_paths_tests.cfg03_rejects_symlink_below_root`, `secure_frontend_token_store_tests.token_store_windows_round_trips_through_dpapi`, `secure_frontend_token_store_tests.token_store_windows_file_has_private_dacl`, `secure_frontend_token_store_tests.token_reader_windows_accepts_plaintext_under_private_dacl`, `secure_frontend_token_reader_tests.reads_an_owner_only_regular_file_below_the_root`, `secure_frontend_token_reader_tests.rejects_control_characters_in_file_token`, `secure_frontend_token_reader_tests.auth02_token_file_with_trailing_lf_accepted`, `secure_frontend_token_reader_tests.auth02_token_file_with_trailing_crlf_accepted`, `secure_frontend_token_reader_tests.auth02_token_file_with_two_newlines_rejected`, `secure_frontend_token_reader_tests.auth02_token_file_with_bom_rejected`, `secure_frontend_token_reader_tests.auth02_token_file_over_4k_rejected`, `secure_frontend_token_reader_tests.auth02_notepad_edits_rejected_with_reason`, `secure_frontend_model_inventory_tests.inventories_only_local_gguf_artifacts`, `secure_frontend_model_inventory_tests.rejects_duplicate_ids`, `secure_frontend_model_inventory_tests.cfg03_inventory_rejects_junction_entry`, `secure_frontend_engine_arguments_tests.engine_receives_model_path_from_inventory`, `secure_frontend_engine_arguments_tests.engine_args_reject_owned_and_network_flags`, `secure_frontend_engine_arguments_tests.strata_profile_passes_pack_and_weight_flags_through`, `secure_frontend_engine_arguments_tests.rejects_invalid_relative_artifact_path`, `secure_frontend_engine_arguments_tests.glm_profile_passes_arguments_through_without_native`, `secure_frontend_typed_config_tests.typed_config_accepts_minimal_file_and_applies_defaults`, `secure_frontend_typed_config_tests.cfg01_unknown_key_rejected`, `secure_frontend_typed_config_tests.cfg01_duplicate_key_rejected`, `secure_frontend_typed_config_tests.cfg01_type_confusion_rejected`, `secure_frontend_typed_config_tests.cfg01_missing_required_rejected`, `secure_frontend_typed_config_tests.cfg01_out_of_range_rejected`, `secure_frontend_typed_config_tests.typed_config_cross_field_rules`, `secure_frontend_typed_config_tests.typed_config_errors_never_contain_values`, `secure_frontend_typed_config_tests.cfg02_logs_and_cache_roots_are_created_private`, `secure_frontend_typed_config_tests.cfg06_validated_config_bytes_do_not_contain_token`, `secure_frontend_typed_config_tests.cfg01_config_with_everyone_write_ace_rejected`, `secure_frontend_tokenizer_pack_tests.loads_validates_and_decodes_offline_pack`, `secure_frontend_tokenizer_pack_tests.rejects_ambiguous_or_incompatible_pack_assets`, `secure_frontend_tokenizer_pack_tests.rejects_malformed_json_and_special_literals_for_decode`, `secure_frontend_tokenizer_pack_tests.encoding_fails_closed_for_special_invalid_and_missing_tokens`, `secure_frontend_tokenizer_pack_tests.cfg03_tokenizer_file_swapped_to_junction_rejected`, `secure_frontend_subsystem_limits_tests.ready_timeout_defaults_to_900_seconds`, `secure_frontend_subsystem_limits_tests.subsystem_limits_follow_config`, `secure_frontend_server_cli_tests.cli_config_file_and_flags_share_validator`, `secure_frontend_server_cli_tests.cli_flag_overrides_file_and_is_reported`, `secure_frontend_server_cli_tests.cli_check_prints_no_token`, `secure_frontend_server_cli_tests.cli_unknown_option_does_not_echo_value`, `secure_frontend_server_cli_tests.auth04_empty_token_rejected_on_loopback`, `secure_frontend_server_cli_tests.auth04_no_switch_disables_auth`, `secure_frontend_server_cli_tests.cli_check_has_no_side_effects`, `secure_frontend_server_cli_tests.init_writes_config_and_token_then_server_starts`, `secure_frontend_server_cli_tests.init_refuses_to_overwrite_without_force`, `secure_frontend_server_cli_tests.init_force_refuses_a_non_regular_config_target`, `secure_frontend_server_cli_tests.init_failure_creates_nothing`, `secure_frontend_server_e2e_tests.cfg01_invalid_config_fails_before_listener_and_child`, `secure_frontend_server_e2e_tests.net02_remote_addresses_need_opt_in`, `secure_frontend_server_e2e_tests.net02_error_is_non_secret_and_exits_before_bind`, `secure_frontend_server_e2e_tests.ready_timeout_is_configurable`, `secure_frontend_server_e2e_tests.cfg05_token_absent_from_child_argv_env_and_outputs`, `secure_frontend_server_e2e_tests.auth01_socket_rejects_missing_and_wrong_token_on_every_route`, `secure_frontend_server_e2e_tests.auth02_valid_token_succeeds_and_is_not_echoed`, `secure_frontend_server_e2e_tests.net01_default_listener_is_loopback_only`.

Update (2026-10-14, SP2 Task 28): CI run `38540719307` ran the
`windows-msys2-clang` job on SP1, 193/193, so the `windows-runtime` cases
listed above are now verified there; the paragraph below records the state
at Task 24.

What this does **not** show: nothing in SP1 is Windows-runtime-verified. The
`windows-msys2-clang` job (authoritative) has not run on any SP1 commit; wine
does not model DACLs (`D:P` is stored as `D:`), junctions, long final paths or
Job Objects faithfully. `linux-clang`, `windows-msvc` and the root build were
not run for SP1. Nothing ran on a GPU or a real engine (fake engine only).

### Submodule layout (2026-10-13, branch `layout/upstream-submodule`)

Dev host (Linux x86_64, no GPU), `PATH` with `.venv-dev/bin` first.

| Command (repository root unless noted) | Result |
| --- | --- |
| `git submodule status` | ` 7695859aa13afb248bdb4d36f9b2e95707db079d upstream (v0.1.43)`; `git -C upstream status --short` empty after every gate below |
| `git ls-files \| sed 's#/.*##' \| sort -u` | `.gitattributes .github .gitignore .gitmodules CMakeLists.txt LICENSE README.md conftest.py docs pytest.ini scripts secure_frontend tests tools upstream` |
| `pytest -q` | `12 passed` in Task 7; `13 passed` after the final fix wave (new `extract()` guard test) (`tools/secure/` only); with `upstream/` empty it exits 4 with "run `git submodule update --init`". A fresh venv from `bootstrap-linux.sh` (no numpy) passes too (from Task 3 report, same date) |
| in `secure_frontend/`: `ctest --preset linux-gcc` | `100% tests passed out of 20` (also from a fresh build directory: 78 steps, 0 warnings) |
| in `secure_frontend/`: `windows-llvm-mingw-cross` build, then `ctest --preset windows-llvm-mingw-cross` (wine) | 20 `.exe` with `-Werror`; `100% tests passed out of 19` (also from a fresh build directory: 76 steps, 0 warnings) |
| `cmake -S . -B out/root -G Ninja && cmake --build out/root && ctest --test-dir out/root` (from clean) | 94 steps, 0 warnings; `strata-plan`, `strata-gguf`, `strata-dequant`, `strata-secure-server` built; `100% tests passed out of 20`; no `out/root/_deps` |
| root configure with `-DCMAKE_BUILD_TYPE=Debug -DSTRATA_WERROR=OFF` / `-DSTRATA_ENABLE_CUDA=ON` / empty `upstream/` / `-DSECURE_STRATA_BUILD_ENGINE=OFF` (from Task 2 report, same date) | `Debug` kept and `SECURE_FRONTEND_WERROR=ON`; fails at `CMAKE_CUDA_COMPILER` (override reached upstream); fails with "run `git submodule update --init`"; configures and builds the frontend |
| fresh scratch clone (`git clone`, then `git submodule update --init --depth 1`) | plain clone: configure (exit 1) and pytest (exit 4) stop with the init instruction; after init: root build 94 steps, 0 warnings, ctest 20/20, no `_deps`, pytest 12 passed; `git rm -r upstream && ls -A` shows only our paths. With `--depth 1` the tag is not fetched, so `git submodule status` there shows `(7695859)` instead of `(v0.1.43)` |
| `pytest upstream/tools` (with the recorded `--ignore`/`--deselect`), separate venv from `scripts/dev/requirements-dev.txt` + `upstream/requirements.txt` | from the repository root: `4 failed, 612 passed, 2 skipped, 3 deselected, 214 subtests passed` — the four (`test_conversation_cache_disabled.py` and `test_conversation_cache_growth.py`, two each) run `tools/<script>.py` and import `tools.test_…` relative to the working directory; from `upstream/` (`pytest -q tools --ignore=tools/… --deselect=upstream/tools/…`, node ids stay relative to our root `pytest.ini`): `616 passed, 2 skipped, 3 deselected, 214 subtests passed` |
| `pytest upstream/serve` (same venv, repository root) | `695 passed, 11 skipped, 5532 subtests passed`, exit 0 |
| offline bundle (`git -C upstream bundle create … v0.1.43`, init a scratch clone from it) (from Task 6 report, same date) | bundle okay; `refs/tags/v0.1.43` → submodule checked out at `7695859a` with no network |

Final fix wave (same date, after `45487311`):

| Command | Result |
| --- | --- |
| `pytest -q` (repo root) | `13 passed` (new: `extract()` raises "upstream layout changed; re-verify the wrapper" when `tokenizer/tokenizer.json` is missing) |
| in `secure_frontend/`: `ctest --preset linux-gcc` | `100% tests passed out of 20` |
| `cmake -S . -B out/root-fixwave -G Ninja && cmake --build out/root-fixwave && ctest --test-dir out/root-fixwave` (fresh dir) | 94 steps, 0 warnings, `100% tests passed out of 20`, no `_deps` |
| root defaults, no `-D` flags (`cmake -S . -B out/root-defaults-fixwave -G Ninja`, the CI step's greps) | `STRATA_NATIVE_EXPERTS:BOOL=OFF`, `STRATA_ENABLE_CUDA:BOOL=OFF`, `STRATA_ENABLE_HIP:BOOL=OFF`, `CMAKE_BUILD_TYPE:STRING=Release`, no `_deps` |
| upstream suites, the exact `PROVENANCE.md` step-2 commands (`python3 -m venv --without-pip out/venv-upstream-fixwave`, dev pip `--python … install`, then from `upstream/`) | `tools`: `616 passed, 2 skipped, 3 deselected, 214 subtests passed`; `serve`: `695 passed, 11 skipped, 5532 subtests passed` (4 min 14 s); `git -C upstream status --porcelain` empty |

Not shown here: `linux-clang`, `windows-msys2-clang`, `windows-msvc`. CI on
GitHub: run `38478775552` on `4aa742c9` (U10 row above); no CI run since
`4aa742c9` (docs/comment-only commits until the final fix wave, which adds
the root-defaults CI step and the `extract()` guard).

### SP0 (before the submodule layout)

Run on the dev host (Linux x86_64, no GPU) on 2026-10-13, after the SP0 final fix
wave (`--pack` pass-through, `/health` engine state, portable socket tests). Always put the venv first:
`export PATH=/opt/projects/ai/.venv-dev/bin:$PATH`.

| Command (from the repository root unless noted) | Result |
| --- | --- |
| `scripts/dev/bootstrap-linux.sh` | `bootstrap-linux: ready` (idempotent on the existing venv; also exit 0 in a fresh scratch checkout with network, and offline from a `STRATA_WHEEL_DIR` holding pip + all pinned wheels with the network blocked; cmake 4.4.3, ninja 1.13.2, pytest 9.1.1) |
| `.venv-dev/bin/pytest -q` | `620 passed, 2 skipped, 3 deselected, 214 subtests passed in 20.60s` |
| in `secure_frontend/`: `cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc` | `100% tests passed out of 20` (the socket-server binary runs 10 cases, binding loopback and `::` on this host; `strata_secure_server_glm_requires_engine_arg` is new) |
| `scripts/dev/bootstrap-llvm-mingw.sh` | llvm-mingw `20261006` (clang 23.1.3) present, sha256 checked when fetched |
| in `secure_frontend/`: `cmake --preset windows-llvm-mingw-cross && cmake --build --preset windows-llvm-mingw-cross` | Builds with `-Werror`; 20 `.exe` files (3 executables, 17 test binaries) |
| in `secure_frontend/`: `ctest --preset windows-llvm-mingw-cross` (wine 6.0.3, `WINEPREFIX=secure_frontend/out/wineprefix`) | `100% tests passed out of 19`: config, secret_source, engine_stdio_process (round trip, invalid record, `read_line_rejects_oversize_on_all_platforms`, `read_line_waits_for_a_record_split_across_writes`, `job_object_terminates_grandchild`), http_policy, http_request_handler, http_socket_server (all 10 cases; S3 1.6 s, S2 1.0 s), api_router, engine_process, engine_protocol_client, model_inventory, engine_arguments, chat_schema, tokenizer_pack, qwen_prompt_renderer, glm_profile, chat_generation_plan, chat_execution, strata_secure_server_help, strata_secure_server_glm_requires_engine_arg. wine is not authoritative for the Job Object grandchild case or native Winsock RST behavior. |
| `wine out/build/windows-llvm-mingw-cross/strata-secure-server.exe --help` | exit 0 |

What this does **not** show:

- `linux-clang`, `windows-msys2-clang` and `windows-msvc` were not built on
  this host (no clang; they need Windows); see the CI table below.
- wine is a smoke test. It does not implement Job Objects or protected-file
  DACLs faithfully, and it passed all three tests that failed on real Windows.
  `secure_frontend_token_reader_tests` is the only UNIX-only target, so the
  Windows token reader has no runtime test anywhere yet, including the MSYS2
  job.
- Nothing has been run on a GPU or against a real Strata engine; every engine
  test uses the fake engine.
- `pytest upstream/serve` (the upstream service suite; `pytest serve` before
  the submodule layout) was not run for SP0; nothing in `upstream/serve/`
  changed.

#### GitHub Actions (`secure-frontend` workflow, `shift-f10/multi-strata`)

| Run | Branch / head | Result |
| --- | --- | --- |
| `38456682352` (first real run) | `main` | `windows-msys2-clang` 16/19. Failed: `engine_stdio_process_tests` (`READY must parse`, 0.02 s), `engine_process_tests` (argv/env case), `http_socket_server_tests` (S2: `/big` reported sent in 132 ms to a peer that never reads; S3 passed, 1136 ms). |
| `38457597307` (diagnostics) | `ci/windows-runtime-fixes` `1a7d3b9d` | Same three failures. Both engine tests: the re-executed fake engine exited `0xC0000135` (`STATUS_DLL_NOT_FOUND`), message `engine closed before READY` for the stdio one. Loopback probe: 64 KiB blocking sends into a non-reading peer stop at 128 KiB (the default `SO_SNDBUF`) and fail with `WSAETIMEDOUT` (10060) after the 500 ms `SO_SNDTIMEO`, for client `SO_RCVBUF` default, 1 or 0; with server `SO_SNDBUF` 0 nothing is accepted. |
| `38458255140` (fixed) | `ci/windows-runtime-fixes` `9576d03b` | All blocking jobs green: `linux-gcc`, `linux-clang`, `windows-llvm-mingw-cross`, `windows-msys2-clang` (19/19), `top-level-integration`. `windows-msvc` (non-blocking) fails at configure: the `windows-latest` image now ships Visual Studio 2026 and the preset names the `Visual Studio 17 2022` generator. |

Fixes on `ci/windows-runtime-fixes`:

1. **Engine launch (`engine_process_tests`, `engine_stdio_process_tests`).**
   Both launchers pass only the allowlisted environment, so the child has no
   `PATH`. A CLANG64 build links `libc++.dll`/`libunwind.dll` from
   `/clang64/bin`, which the Windows loader finds only through `PATH`, so the
   child failed to load. The `windows-msys2-clang` preset now links with
   `-static`, as the llvm-mingw cross preset already did. Launchers and test
   assertions are unchanged; the `HOME`-absent check stays meaningful because
   the child gets an explicit environment block.
2. **S2 (`socket_server_send_times_out_on_stalled_reader`).** One 32 MiB blocking
   `send()` was accepted whole by Winsock, so `send_deadline` never applied.
   `send_all` now caps each `send()` at 64 KiB on every platform, and the
   unchanged S2 test passes on Windows. Not gated.

The Python GLM tokenizer tests also ran under `pytest -q` above (then
`tools/test_glm_tokenizer.py`; now `tools/secure/test_glm_tokenizer.py`, with
the pinned `regex` from the venv). The two skips were hardware/platform skips
in upstream tests (`upstream/tools/test_dll_closure.py`: HIP zip absent;
`upstream/tools/test_setup_oldcpu.py`: Windows only). Run
`tools/secure/test_glm_tokenizer.py` and `tools/secure/test_secure_tokenizer.py`
again in the release Python environment before accepting a GLM tokenizer
release.

### Known small gaps

Deferred from the SP0 task reviews; none blocks SP0, each is worth a look in the
sub-project named.

- `strata`'s Windows UTF-8 argv (shared `secure_frontend_utf8_argv`, SP4 merge
  `4b9fdd31`) builds and runs under wine only. CI run `38625663621` did not
  cover it: the CLI cases there call `run_strata` in-process. The first cases
  that start the `strata` binary on Windows are Task 27's DL-04 Ctrl-Break
  case and Task 28's privacy cases (passed in CI run `38655938748`), all with ASCII arguments;
  a non-ASCII path through a `strata` verb on real Windows has no case yet
  (nor has Task 26's downloader argv, built with `path_to_utf8`).
- The fallback descriptor sweep (used only where `close_range(2)` is missing
  or fails) stops at `kSweepCap` = 65536 (documented at the constant, SP2
  Task 28). The listening and accepted sockets are created without
  `SOCK_CLOEXEC`, so on that fallback path, with `RLIMIT_NOFILE` above the
  cap, such a socket numbered at or above 65536 would reach the engine. Linux
  5.9+ (`close_range`) has no such gap. Creating the sockets close-on-exec
  would remove it. SP3 (owns the listener).
  **K4 gap closed (listener + accepted sockets CLOEXEC/no-inherit)** — SP3
  Task 8b (branch `sp3-api-streaming`); Windows proof pending MSYS2.
- S4 (oversize `413`) relies on the half-close + 100 ms drain to beat an RST
  on Windows; it passed in the MSYS2 job (run `38458255140`). SP3 if it flakes.
- `windows-msvc` (non-blocking) fails at configure on the current
  `windows-latest` image (Visual Studio 2026; preset asks for 2022). SP1 tooling.
- The `send_all`-on-`EINTR`, S6 port-range and transient-accept-backoff SP0
  bullets in this list were fixed in SP3 (`send_retries_on_eintr`, the S6 test
  binding port 0, `accept_backs_off_on_transient_failure` — Task 8a; §9.4).
- Since SP3 the per-request log and every error are fixed literals; `--check`
  still prints the operator's own configured values, as SP1 designed.
- Submodule layout: closed in the final fix wave. `top-level-integration`
  now first configures our root with no `-D` flags (`out/root-defaults`) and
  asserts `STRATA_NATIVE_EXPERTS`, `STRATA_ENABLE_CUDA`, `STRATA_ENABLE_HIP`
  `OFF`, `CMAKE_BUILD_TYPE=Release` and no `_deps`; not yet run on GitHub.
- Submodule layout: `scripts/secure_distribution_check.py` does not split
  backslash separators on Linux, so a staged name such as
  `upstream\requirements.txt` is one path component there and passes (a
  `.py` name would still be caught by the Python-source rule).
- Submodule layout: `tools/secure/secure_tokenizer.py` couples to upstream
  internals (`Tokenizer._re`, the `__init__` argument order, the `extract()`
  output path `tokenizer/tokenizer.json`); re-verify it on every upstream
  pointer bump ("Update upstream"). Since the final fix wave `extract()`
  raises ("upstream layout changed; re-verify the wrapper") when upstream did
  not write that file, instead of creating it.

SP4 part 2 (Tasks 25–29, branch `sp4-acquire-part2`). Removed from the list
above: the threat-model "`acquire` is the sole networked operation" bullet
(amended in Task 29). Added (each a deferred review minor or a ruling's
residue; none blocks the merge):

- `acquire.log` has one record per **transferred** file (ruling R12):
  files reused from a prior version, copied from a bundle or already staged
  get no record, although spec §7.3 says "one record per file". Task 22's
  `fetch_file` is the only writer.
- `LoggingProgress` reopens the logs root per record and its
  exists-then-create step can race and drop a record; logging never fails a
  pull (I14).
- A declined pull leaves the empty `roots.models/.staging/.cwd` (B1 creates
  it before the `[y/N]`); a lazy creation in the downloader would remove it.
- Interrupts: `InterruptScope` does not honour an inherited `SIG_IGN` for
  SIGINT; a SIGINT during `doctor` is swallowed (exit 0); the
  prompt-flush/`read()` race above; the Windows console handler returns TRUE
  at once for `CTRL_CLOSE`/logoff/shutdown.
- Downloader: the executable is validated, then executed by path (no
  `fexecve`; same-user race, as for the engine); `probe_result_` is not
  cleared by a later failed probe; a failed record-file open is silently
  ignored (hooks builds only); Windows maps every `launch_in_job` failure
  by DWORD, ignoring `WinLaunchStep` (Job/attribute failures should be
  `downloader_confinement_failed`); an empty `cwd` inherits the parent's on
  Windows (POSIX fails closed; every caller passes `.staging/.cwd`); the
  stdin write precedes the interrupt-aware loop. (The POSIX-worded Windows
  `untrusted_owner` text and SP1 `windows_security.cpp`'s include of SP4's
  `confinement_plan.hpp` were fixed in the final fix wave.)
- Tests: no negative Windows validator case (writable file/parent, NULL
  DACL) and no non-ASCII downloader-argv case; the DL-04 Windows case leaks
  `strata` on timeout; the Linux prompt test re-sends SIGINT every 200 ms;
  the fd census stops at fd 1024 and has no committed negative control;
  priv02's `127.0.0.1`/`93.184.216.34` sentinels are weak (the proxy
  sentinel is the real check); the crash case needs
  `CONFIG_PROC_CHILDREN`; the Windows DL-01 case fails hard on a host
  without IPv6 tables; the link-set check matches `strata\n` as a
  substring; the shim reads `sa_family` without checking `msg_namelen`.
- The interrupted error detail names the file twice (Task 22 text).

SP2 (2026-10-14, Task 28). Removed from the list above: the undocumented
sweep cap (now documented at `kSweepCap`; the remaining socket gap is the
first bullet), the Windows stdin pipe bullet (N6, R1, K2 and R1 rows; limits
doc updated) and the missing Windows `SystemRoot` (N1 renders `SystemRoot`,
`WINDIR`, `SystemDrive`; not yet tried with a real engine on Windows).

SP1 (2026-10-14, Task 24). Fixed and removed from this list: the wildcard-bind
spelling bypass (Task 1, defect a), the corrupt-archive bootstrap gap (Task 24,
D4) and the stale "MSVC/Windows runtime coverage" CMake comment (Task 18).

1. The engine opens model files by path after validation: a swap below a
   user-owned, non-shared-writable root is a same-user race (SP1 spec §3.4).
   SP2 did not take up handle passing: its spec does not mention it, and SP2
   changed only what the engine inherits (N5 descriptors/handles, N6 the
   stdin pipe). Still an accepted same-user risk; open, no sub-project named
   yet (owner/controller to assign).
2. Fixed on the winfix branch (pending the next MSYS2 run): on Windows
   `strata-secure-server` now reads its command line as UTF-8 through
   `CommandLineToArgvW(GetCommandLineW())` (invalid UTF-16 exits 1 with a
   fixed message) and `--config` goes through `path_from_utf8`, so a
   non-ASCII value (A2's `✓`, a non-ASCII root) is no longer turned into `?`
   by the ANSI code page; CI run `38601830802` showed exactly that in
   `proc01_server_passes_literal_argv`. Before: `char** argv` in the ANSI code
   page, so non-ASCII paths belonged in the config file. The engine's argv is UTF-8 end to end since the SP1 final fix
   wave: `--native` is built with `path_to_utf8` (not `path::string()`, which
   narrowed through the ANSI code page and failed the launcher's strict UTF-8
   decode for a root such as `C:\Users\José\models`), and the executable's NUL
   check reads `path::native()`. `engine_native_path_is_utf8_for_non_ascii_root`
   was RED under wine before the fix and GREEN after; it is `windows-runtime`
   on Windows CI and passed there (CI run `38540719307`).
3. Windows environment-token scrub — accepted deviation from spec §3.6,
   owner-ruled: Windows has no `/proc/<pid>/environ` exposure, so the scrub
   wipes the CRT copies in place (narrow through `getenv`'s pointer, wide
   through `_wgetenv`'s), removes the CRT entry with `_putenv_s(name, "")` and
   removes the Win32 environment-block entry with
   `SetEnvironmentVariableW(name, nullptr)`; the block entry is removed, not
   overwritten in place (no Win32 API overwrites it). No ctest case covers it
   (wine probe only), so CI run `38540719307` does not verify it.
4. The `docs/security/deployment.md` Windows token caveat ("treat the Windows
   file path as unverified and prefer `--token-env` there") is removed in a
   follow-up commit once the owner's push shows the `windows-msys2-clang` job
   green for the `windows-runtime` token tests. The condition is met (CI run
   `38540719307`, 193/193); the caveat is still in `deployment.md` (not
   removed in SP2 Task 28, which only records proof). Open for the owner.
5. `cfg03_rejects_mount_crossing` skips where unprivileged user namespaces are
   disabled (GitHub's ubuntu-24.04 images may skip it).
6. Naming: the product-experience spec §4 sketches `listen.*`, flat `limits.*`
   keys and `token_source`; SP1 supersedes those names with `listener.*`,
   `limits.<section>.*` (`limits.http.*`, `limits.chat.*`, `limits.engine.*`,
   `limits.concurrency.*`) and `token.source`, and the future `strata` CLI
   follows SP1's names (the product spec §4 text is updated when that CLI is
   planned).
7. Closed in the SP1 final fix wave: the configuration ranges now match the
   enforced caps — `limits.chat.max_messages` 1–128 (renderer
   `kMaximumMessages`), `limits.chat.max_message_bytes` 1–65536 (renderer
   `kMaximumMessageBytes`), `limits.chat.max_prompt_tokens` 1–262144
   (`EngineProtocolLimits`), pinned by `cfg01_chat_ranges_match_enforced_caps`.
   `EngineProtocolLimits` and the renderers' 512 KiB rendered-prompt cap stay
   internal constants, not configuration keys; details in
   `docs/security/engine-protocol-limits.md`.
8. Windows `create_directory_within` does not check the DACL, owner or volume
   of components that already exist (POSIX does). No SP1 caller reaches that
   path with untrusted components (every caller ends in `open_existing_root`);
   revisit if a caller is added.
9. Windows token store (Task 17): the holding directory is pinned without
   `FILE_SHARE_DELETE`, but the temp file is created and moved by path
   (handle-relative `NtCreateFile` deferred); protection against renaming an
   ancestor relies on NTFS refusing to rename directories with open handles
   below them — unverified on real Windows.
10. A plaintext Windows token file that starts with the bytes `STRATAK1` is
    treated as DPAPI-wrapped and rejected as undecryptable (documented in
    `deployment.md`).
11. `ModelInventoryErrorCode::artifact_path_escapes_root` is unused since Task 13
    (kept for API stability).
12. The chat `model` field is bounded at 256 bytes (`chat_schema.cpp`
    `kMaximumModelBytes`) while model IDs are at most 128; consistent (a longer
    field is a model mismatch), noted in `engine-protocol-limits.md`.
13. Socket-server tests still use fixed ports 20000–20099; they collide under
    `ctest -j` and across concurrent worktrees (presets run serially). Parked
    (SP3).
14. The C3 bind-before-spawn guard's RED was shown on Linux only; on Windows the
    guard (`cfg01_invalid_config_fails_before_listener_and_child`) is
    `windows-runtime` and passed in `windows-msys2-clang` (CI run
    `38540719307`; GREEN only, its RED was never shown on Windows).

## Collaboration and change rules

- Keep security changes small and add a regression test before the fix.
- Never edit anything under `upstream/`. A compatibility need is met by a
  wrapper in our tree or by an upstream pull request; record it in
  `docs/PROVENANCE.md`. `git -C upstream status --short` stays empty.
- Do not copy UnbiasedStrata code without recording source, revision, license,
  rationale, and Windows/Linux test coverage.
- Do not enable MCP, tools, plugins, arbitrary command execution, telemetry,
  update checks, or automatic downloads. Those require a new threat-model
  review and an explicit user decision.
- Gates before every hand-off and after every submodule bump: `pytest -q`;
  `ctest --preset linux-gcc`; the `windows-llvm-mingw-cross` build; the root
  build and root `ctest`; after a bump also `pytest upstream/tools` and
  `pytest upstream/serve` ("Update upstream").
- Commit locally; the owner pushes.
- Before handing off, update this document's **What has changed** and
  **Verification performed** sections, then report `git status --short`.

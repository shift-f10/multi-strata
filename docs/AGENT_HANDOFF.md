# Secure Strata agent handoff

## Purpose

This repository is a Windows-and-Linux, security- and privacy-first successor
to Strata. It must retain the model/backend flexibility of upstream Strata
`v0.1.44.1` while replacing its public service boundary with a small portable
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
   - SP1 — typed configuration, canonical paths, CSPRNG tokens. **Done on
     branch `sp1-typed-config-paths-tokens`** (local commits, not pushed or
     merged; no CI run yet, so every `windows-runtime` case is pending the
     `windows-msys2-clang` job).
   - SP2 — child supervision (`PROC-*` tests).
   - SP3 — API concurrency, streaming, and `NET-*`/`WEB-*`/`DOS-*`/`EXT-*` tests.
   - SP4 — the explicit `acquire` command.
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
   `296b59d2f73c8f04a805df29c2fa97655adace78` (tag `v0.1.44.1`) and never
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
   SP1 has not been pushed; no CI run covers it.

### Owner decisions, 2026-10-14

Approved by rflores ("approve all"); binding for plans and implementation.

- Upstream bump to `Niko1221/Strata` v0.1.44.1 merged (main `c07f2429`).
- SP2 Task 22 = bound: engine-stdin writes get an overall bound (the request's
  remaining deadline) in SP2's second run; Task 28 documents it.
- SP3 and SP4 specs APPROVED, all recommendations (see the specs' "Decisions
  taken"). SP3 plans: two, M1 (concurrency and hardening) and M2 (streaming).
  SP4 D5 stays open between (A) and (C); (D) ships meanwhile.
- SP6: A1-A11 recorded in the research doc, section 6.
- Details: `docs/superpowers/specs/2026-10-14-sp3-api-concurrency-streaming-design.md`
  (section 11), `docs/superpowers/specs/2026-10-14-sp4-acquire-design.md`
  (section 12), `docs/superpowers/research/2026-10-14-sp6-glm-engine-sources.md`
  (section 6).

## Current baseline

- Upstream baseline: the `upstream` submodule gitlink, `Niko1221/Strata` tag
  `v0.1.44.1`, commit `296b59d2f73c8f04a805df29c2fa97655adace78`
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

| Ours, at the root | Pristine, under `upstream/` (submodule @ `296b59d2`, tag `v0.1.44.1`) |
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

- Task 1: `SECURE_FRONTEND_TEST_HOOKS` option (ON in test presets), `linux-gcc-release` preset (hooks OFF; runs `release-only|release-also`), in-tree FIPS 180-4 SHA-256; `secure_frontend_sha256_tests` (7 cases; 2 `release-also`).
- Task 2: §8 reasons, exit classes and error text in `secure_frontend_manifest_core`; `acquire.exit_classes_match_spec_table`, `reason_table_is_complete_and_ordered`, `error_text_states_resumable`.
- Task 3: URL/host/wildcard/proxy grammar (spec §2.2, §3.4, §3.8); manifest.source_url_grammar_matrix, dns_names_and_wildcards, proxy_grammar; fetch.dl03_location_with_glob_characters_rejected, location_resolution_and_host_normalization, location_query_characters.
- Task 4: §3.5 address policy (`secure_frontend_acquire_core`); fetch.address_policy_* (5 cases).
- Task 5: §3.3 argv/stdin, probe parsing, C3 floors, §3.4 curl exit map; fetch.transfer_argv_exact_order, config_line_is_single_quoted_url, probe_argv_is_version_only, probe_output_parsing_and_floor, curl_exit_codes_map_to_reasons.
- Task 6: §3.4 header-block parser and status table; fetch.informational_header_blocks_skipped, header_block_limits_enforced, split_feed_reports_exact_body_offset, status_table_decisions.
- Task 7: §3.6 retry schedule, run budget, clock seam; fetch.retry_backoff_follows_schedule, non_transient_moves_to_next_source, exhausted_class_follows_last_source_reason, run_budget_remaining_seconds.
- Task 8: manifest model and §2 struct rules, engine version grammar; manifest.* (13 cases, 1 release-only, 1 hooks-only).

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
- Open item for the controller (pre-existing since `v0.1.43`, not fixed here):
  the engine emits `PP <done> <total> <ms> <tok/s>` during batched prompt
  reads, and `engine_protocol_client.cpp` rejects `PP` outside the GLM
  profile, so such a Strata-profile request would fail. Not observed at run
  time (no GPU).

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
Every test with the CTest label `windows-runtime` is **pending
windows-msys2-clang**: that job is authoritative for Windows and has not run any
SP1 commit; wine is a smoke test only (see "Verification performed", SP1).

| Task / commit | Items | What changed | Regression tests / check |
| --- | --- | --- | --- |
| 2 — `17d2452d` (on `main`) | §3.10 | `secure_frontend_add_cases(<binary> <case>... [ARGS] [LABELS] [TIMEOUT])` registers one CTest test per case (`<binary>.<case>`), dispatched through `secure_frontend_test::run_cases` (`--case`, `--list`); label `windows-runtime` (empty off Windows), excluded by the `windows-llvm-mingw-cross` test preset; scratch directories via `mkdtemp` (0700) under `<build>/test-tmp` (Windows: explicit protected DACL), removed on every exit path. Helper names, `<binary>.<case>`, the label and the preset exclusion are frozen for SP2. | Linux 111/111, wine 102/102 at that commit |
| 1 — `6be5042e` | N1, N2; defect a | Listener addresses are classified from the parsed bytes (`parse_listener_address`): every spelling of the unspecified address needs `--allow-wildcard-bind`; `::ffff:127.0.0.1` and the long loopback form are loopback; `localhost` (ASCII case-insensitive) maps to `127.0.0.1` without a resolver call; every other hostname is rejected; `bind()` uses the canonical text. `inet_ntop` runs during validation, before `WSAStartup` on Windows (wine passed; **pending windows-msys2-clang**). | `net03_wildcard_spellings_need_wildcard_opt_in`, `net03_remote_opt_in_alone_rejects_wildcard`, `net01_loopback_spellings_classified_from_bytes`, `net02_hostname_rejected_before_bind`, `net01_localhost_maps_to_ipv4_loopback` |
| 3 — `828daac8` | C1 | One strict bounded JSON reader (`json.hpp`: duplicate keys, depth, size, integers only, BOM, trailing data) shared by the chat schema and the tokenizer pack. | `json_rejects_duplicate_keys`, `json_rejects_depth_over_limit`, `json_rejects_non_integer_numbers` (+ BOM/trailing/size cases) |
| 4 — `95ca08ad`, fix `67634f81` | C2 | Typed `FrontendConfig`, the schema table `config_schema()` (one row per key: type, range, default, option, description) and `validate()` collecting every issue by key path with a fixed reason; `ready_timeout` 900 s; `limits.chat.max_body_bytes` default 49152. Fix: member names that are empty or contain `.` are unknown keys (no aliasing of nested keys); a duplicate path on insert is an error. | `cfg01_unknown_key_rejected`, `cfg01_duplicate_key_rejected`, `cfg01_type_confusion_rejected`, `cfg01_missing_required_rejected`, `cfg01_out_of_range_rejected`, `typed_config_cross_field_rules`, `typed_config_errors_never_contain_values` (all `windows-runtime` from Task 9: **pending windows-msys2-clang**) |
| 5 — `67ac645a` | C6, C8 | `strata-secure-server --config FILE` and `--check` go through the one validator; an option wins over the file and `--check` reports each overridden key; option values are never echoed. End-to-end harness (process runner, HTTP client, server fixture, fake engine). | `cli_config_file_and_flags_share_validator`, `cli_flag_overrides_file_and_is_reported`, `cli_check_prints_no_token`, `cli_unknown_option_does_not_echo_value` (`windows-runtime` from Task 9: **pending windows-msys2-clang**) |
| 6 — `2b0f83b4`, fix `e6e82aa1` | C3, N3, N4 | The server binds before it spawns the engine; process-level NET tests. Fix: the C3 guard is deterministic (an unstartable engine plus an unbindable address must report the bind error). | `cfg01_invalid_config_fails_before_listener_and_child`; acceptance `net01_default_listener_is_loopback_only` (`GetExtendedTcpTable`), `net02_remote_addresses_need_opt_in`, `net02_error_is_non_secret_and_exits_before_bind` — all four `windows-runtime` from Task 9: **pending windows-msys2-clang** (the C3 guard's RED was never shown on Windows) |
| 7 — `d9613548` | C4, C5; defect d | Listener, parser, chat schema and chat execution take their limits from `FrontendConfig`; defaults live only in `config_defaults.hpp`. Accepted deviation: an over-bound declared `Content-Length` is answered `400` from the headers alone (`413` is for bytes actually received past the bound). | `parser_honors_configured_max_request_bytes`, `ready_timeout_is_configurable`, `ready_timeout_defaults_to_900_seconds`, `subsystem_limits_follow_config` (`windows-runtime` from Task 9: **pending windows-msys2-clang**) |
| 8 — `51059af4` | P1 | One relative-path grammar (`RelativePath`) for secret sources and model artifacts; the two disagreeing grammars are deleted. | `cfg02_rejects_traversal_and_absolute`, `cfg02_rejects_nul_and_control_bytes`, `cfg04_rejects_reserved_and_device_names`, `cfg04_rejects_trailing_dot_space_and_8dot3`, `cfg04_rejects_ads_and_drive_forms`, `relative_path_accepts_portable_forms` |
| 9 — `b36dd17a`, fix `5d6232e5` | P2, P3, P7; defect e | `CanonicalRoot`/`CanonicalFile` (`open_root`, `open_executable`); the engine receives the canonical models root; Windows root forms (UNC, device, `\\?\`) rejected and network/redirected final paths reported actionably. Fix: `roots.secret` defaults to the config file's folder only for a `file:` token source; an `env:` source never opens it. From here 24 cases that open real roots are `windows-runtime` (engine_arguments, typed_config, subsystem_limits, server_cli, server_e2e): **pending windows-msys2-clang**. | `cfg03_engine_receives_canonical_models_root`, `cfg02_rejects_relative_root`, `cfg02_rejects_shared_writable_root`, `cfg02_root_may_traverse_symlink`, `cfg02_sibling_prefix_root_rejected`, `cfg02_engine_executable_must_be_private_regular_file`, `cfg04_rejects_unc_device_and_extended_roots`, `cfg04_final_path_on_network_share_is_actionable`; fix: `cfg02_env_token_ignores_config_folder_permissions`, `cfg02_file_token_default_secret_root_reports_one_issue` (POSIX) |
| 10 — `e07b0601` | P4 | Linux: `openat2(RESOLVE_BENEATH\|NO_SYMLINKS\|NO_MAGICLINKS\|NO_XDEV)` below a root, with an `openat(O_NOFOLLOW)` walk on `ENOSYS`/`EPERM`; the Linux token reader uses it; hard-linked token files rejected. | `cfg03_rejects_hardlinked_token_file`, `cfg03_rejects_symlinked_intermediate_directory`, `cfg03_rejects_symlinked_final_file`, `cfg03_fallback_walk_matches_openat2`, `cfg03_rejects_mount_crossing` |
| 11 — `9d9b1fba` | P5; defect b | Windows: `READ_CONTROL` handle walk below the root with reparse-point and hard-link rejection; the Windows token reader uses it (the old reader is deleted). The defect-b fix (handles that can read the DACL) is verified by reading only. | `auth02_windows_token_file_reads_with_private_dacl`, `cfg03_rejects_junction_below_root`, `cfg03_rejects_symlink_below_root`, `paths_handle_non_ascii_and_long_names` (Review Focus 4; passes on Linux) — the Windows four are **pending windows-msys2-clang** (wine 0/4: `GetFinalPathNameByHandleW` beyond `MAX_PATH`, `D:P` dropped, no junctions, symlink seen as not-found) |
| 12 — `ccd7c63b` | C7 | Config files and their folders are opened through the path module and refused when other users can write them (or when owned by neither euid nor root). | `cfg01_group_writable_config_rejected` (Linux), `cfg01_config_with_everyone_write_ace_rejected` (`windows-runtime`; wine passes but does not model DACLs: **pending windows-msys2-clang**) |
| 13 — `96aaf699`, fix `56a60c5d` | P6 | Inventory and tokenizer pack enumerate (`list_directory`) and open through the canonical-path module; symlinks/junctions and case-folded duplicate IDs fail naming the entry; non-portable `.gguf` names and non-portable directory names fail; other non-portable non-model files are ignored. | `inventory_symlink_error_names_entry` (Review Focus 1), `inventory_duplicate_detection_is_case_insensitive` (Review Focus 5), `inventory_ignores_non_portable_non_model_names`, `inventory_rejects_non_portable_directory`, `cfg03_inventory_rejects_symlink_entry`, `cfg03_tokenizer_file_swapped_to_symlink_rejected`; Windows junction variants `cfg03_inventory_rejects_junction_entry`, `cfg03_tokenizer_file_swapped_to_junction_rejected` and the root-opening inventory/tokenizer cases: **pending windows-msys2-clang** (wine cannot create junctions) |
| 14 — `264edde1` | P8, P9 | `create_directory_within` a root (symlinked components rejected); `roots.logs`/`roots.cache` are checked by `validate()` (absent-but-creatable under a private parent) and created 0700 only by serve and `init`; `--check` creates nothing; duplicate path checks outside the module removed (P9 grep). | `cfg02_create_within_root_writes_nothing_outside`, `cfg02_logs_and_cache_roots_are_created_private`, `cli_check_has_no_side_effects` (all `windows-runtime`: **pending windows-msys2-clang**; wine: the junction case fails, the other two pass) |
| 15 — `5cc8a91f` | K1, K6 (type) | `SecretBytes` (fixed capacity, wiped on destroy and move), CSPRNG token generator (`getrandom`, fails closed; `BCryptGenRandom` on Windows), base64url; tokens are 43 characters. | `base64url_known_vectors`, `token_generate_is_43_base64url_chars`, `token_generate_differs_across_calls`, `secret_bytes_wiped_on_destroy_and_move`, `secret_bytes_rejects_over_capacity` (wine 5/5; BCryptGenRandom/SecureZeroMemory **pending windows-msys2-clang**) |
| 16 — `e0f4294c`, fix `510617b5` | K2 | Linux token store: `O_EXCL\|O_NOFOLLOW` temp, `fsync`, `renameat2(RENAME_NOREPLACE)` (or replace with `--force`), 0600 file in a 0700 directory. Fix: rotate asserted; a target that cannot be inspected fails closed. | `token_store_creates_0600_file_in_0700_dir`, `token_store_rotate_is_atomic`, `token_store_refuses_symlinked_target` |
| 17 — `25ba2270`, fix `013f540a` | K3 | Windows token store: DPAPI (user scope) `STRATAK1` + blob, protected DACL `O:<user>D:P(A;;FA;;;<user>)(A;;FA;;;SY)`, `CREATE_NEW` temp, `FlushFileBuffers`, `MoveFileExW(WRITE_THROUGH)`; the reader unwraps DPAPI and still reads plaintext operator files. Fix: the holding directory is opened with `open_beneath` and pinned (no `FILE_SHARE_DELETE`) across create and move; creation and move are still by path (handle-relative `NtCreateFile` deferred); protection against renaming an ancestor relies on NTFS refusing to rename directories with open handles below them — unverified. | `token_store_windows_round_trips_through_dpapi`, `token_store_windows_file_has_private_dacl`, `token_reader_windows_accepts_plaintext_under_private_dacl` — **pending windows-msys2-clang** (wine 0/3 at the `D:P` gate; a DPAPI probe round-trips under wine) |
| 18 — `f9f146ac` | K4, K5, K6; defect c | `secure_frontend_token_reader_tests` runs on every platform; one trailing LF or CRLF; result is `SecretBytes`; 32-byte floor, 256-byte cap, 4 KiB file cap; quoted tokens rejected with a reason; read buffers wiped. | `auth02_token_file_with_trailing_lf_accepted`, `auth02_token_file_with_trailing_crlf_accepted`, `auth02_short_operator_token_rejected`, `auth02_token_file_over_4k_rejected`, `token_store_round_trips_through_reader`, `auth02_token_file_with_two_newlines_rejected`, `auth02_token_file_with_bom_rejected`, `auth02_notepad_edits_rejected_with_reason` (Review Focus 3); the 8 Windows file cases are **pending windows-msys2-clang** (wine fails on the DACL) |
| 19 — `137f2b4a` | K6, K7 (AUTH-03, A3) | One `TokenVerifier` in the library; `detail::fixed_window_equals` compares zero-padded 256-byte windows, folds the length difference in, never matches an empty stored value. Reviewer disassembly: at `-O2` the compare is branch-free and both `explicit_bzero` calls survive. | `auth03_compare_touches_fixed_window`, `auth03_prefix_and_suffix_variants_rejected`, `auth03_router_uses_verifier` |
| 20 — `2b480430` | K8, K9 | Environment token wiped and unset after reading; `install_process_defaults()` sets `RLIMIT_CORE` 0 and `PR_SET_DUMPABLE` 0 (Linux) or `SetErrorMode` (Windows) for every binary that calls it. Windows scrub: accepted deviation (gaps below). | `cfg05_env_token_absent_from_proc_environ`, `server_process_is_not_dumpable` (POSIX). Windows scrub has no ctest case (wine probe only: `getenv`/`_wgetenv` null, Win32 entry absent): **pending windows-msys2-clang** |
| 21 — `92a8419a`, fix `dae07073` | K10 | `strata-secure-server init --config FILE [--force]` writes the token first, then an owner-only config, atomically; refuses to replace either without `--force`; never prints the token. Fix: one JSON tree renderer shared with the tests; a non-regular config target is refused before anything is written; nothing is created on bad input. | `init_writes_config_and_token_then_server_starts`, `init_refuses_to_overwrite_without_force`, `init_force_refuses_a_non_regular_config_target`, `init_failure_creates_nothing` (`windows-runtime`: **pending windows-msys2-clang**; wine fails three on the `D:P` gap) |
| 22 — `792b7651` | K11, K12 | CFG-05 end to end; CFG-06 at the type level. | `cfg05_token_absent_from_child_argv_env_and_outputs`, `cfg06_config_has_no_secret_typed_member`, `cfg06_validated_config_bytes_do_not_contain_token` (the first and third `windows-runtime`: **pending windows-msys2-clang**) |
| 23 — `3810a67b`, fix `1904f827` | A1, A2, A4 | AUTH acceptance. Fix: the AUTH-04 sweep derives flags and `STRATA_*` names from the schema and usage text; AUTH-01 also sends a tab separator and a duplicate `Authorization` header over TCP. | `auth01_every_route_rejects_missing_malformed_wrong_token`, `auth01_socket_rejects_missing_and_wrong_token_on_every_route`, `auth02_valid_token_succeeds_and_is_not_echoed`, `auth04_empty_token_rejected_on_loopback`, `auth04_no_switch_disables_auth` (the four socket/process cases `windows-runtime`, pass under direct wine: **pending windows-msys2-clang**) |
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

The native frontend enforces these in-process boundaries: configuration
validation, secret-source metadata, Linux/Windows protected-file token reading,
exact Host/Origin/CORS policy, bounded HTTP request parsing with a total request
deadline plus bearer authentication, portable child-process supervision, and a
serial native Qwen (or selected GLM-5.3) text-chat route. It does **not**
download artifacts, package a secure release, implement every upstream serving
profile, or replace the upstream Python service in a release. Therefore the
repository must not yet be described as privacy-hardened or as having removed
upstream network-capable behavior.

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
  on every platform; its Windows file cases are `windows-runtime` and **pending
  windows-msys2-clang**.
- `EngineProcess` and `EngineStdioProcess` start a child without a shell or
  inherited environment and reject embedded NUL in executable/argv/env values.
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
- `HttpRequestHandler` is bounded in-memory HTTP/1.1 parsing with Host/Origin
  policy, bearer validation, strict CORS/preflight behavior, and a synchronous,
  bounded request-body dispatcher seam.
- `HttpSocketServer` binds only a revalidated numeric configured address
  (`::` as IPv6-only), reads one request under the configured total deadline
  and size cap (`limits.http.*`; defaults 30 s and 64 KiB), sends with a timeout, and survives clients that
  close or reset early, and half-closes plus briefly drains before closing.
  `secure_frontend_http_socket_server_tests` (10 cases) runs on this Linux host
  and under wine; it is portable, so the MSYS2 job runs it on Windows.
- `ApiRouter` implements authenticated `GET /health` and `GET /v1/models` over
  immutable injected providers; in `strata-secure-server` `/health` returns
  `{"status":"ok"|"unavailable","engine":"starting|ready|generating|failed"}`
  (`starting` → `200` with `engine=starting` — READY is consumed on the first
  request; eager READY is SP2 — `ready`/`generating` → `200`, `failed` → `503`). The smoke
  executables pass no engine-state provider and keep `{"status":"ok"}`. `ModelInventory` discovers local
  `.gguf` artifacts only; it has no download, subprocess, or network behavior.
- `secure-frontend-smoke` wires the local components into a process users can
  run with an API-key environment variable and local model directory. It is a
  test server, not an inference server: chat requests correctly remain absent.
- `strata-secure-server` starts exactly one local engine child and implements
  authenticated, non-streaming, text-only `POST /v1/chat/completions` for the
  fixed offline GPT-2-byte-BPE/Qwen-ChatML profile or, only when selected at
  startup, the fixed GLM-5.3 prompt profile. GLM mode requires an independently
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

The only permitted future network operations are separately invoked,
foreground commands: `acquire` (the product name may become `strata pull`) and
the explicit `strata update` in the owner's north star. Each must use a
user-visible, digest-pinned HTTPS manifest and cannot be triggered by an API
request, model content, plugin, or automatic updater. See the threat model for
the full rules. `threat-model.md` currently lists `acquire` as the sole
networked operation; it must be amended under review, together with the
product-experience spec, before `strata update` is designed.

## Ordered implementation backlog

SP0 items are marked **Done (SP0)**. Each open item names the sub-project that
owns it (see the decisions above).

### Phase 1 — native security primitives

1. Extend `secure_frontend` with immutable typed configuration for request
   time/concurrency limits and roots for models/logs/cache. **Done (SP1)**:
   `FrontendConfig`, `--config`/`--check`/`init`; concurrency stays 1 until SP3.
2. Add canonical-path validation for Linux and Windows, including reparse
   points, UNC/device/ADS forms, and traversal prevention. **Done (SP1)**;
   Windows runtime pending the `windows-msys2-clang` job.
3. Add secure token generation/storage: CSPRNG; DPAPI-backed file on Windows;
   user-only permissions on Linux. Tokens must never reach log output,
   environment, child command lines, or metrics. **Done (SP1)**; the Windows
   DPAPI store is pending the `windows-msys2-clang` job.
4. Implement all relevant `CFG-*` and `AUTH-*` tests from
   `tests/security/README.md` before connecting these primitives to a server.
   **Done (SP1)** for CFG-01..06 and AUTH-01..04 (plus NET-01..03); the
   `windows-runtime` cases are pending the `windows-msys2-clang` job.

### Phase 2 — portable child supervision

1. Define a testable `EngineProcess` abstraction and a fake engine fixture. **Done.**
2. Implement the Windows and Linux backends described above. **Done (SP0)
   for the launch path: POSIX argv-before-fork, `O_CLOEXEC`, descriptor sweep,
   reap; Windows suspended start into the Job. Windows runtime still needs the
   `windows-msys2-clang` job.**
3. Add the remaining `PROC-01` through `PROC-06`, including fake-child crash/hang, inherited
   handle/descriptor inspection, and descendant cleanup tests. **SP2.** (SP0's
   fake engine `DUMP` mode and `child_inherits_only_stdio_descriptors` are the
   starting point.)
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
   limits, SHA-256 verification, temporary staging, and atomic publish. **SP4.**
3. Add `DL-*` tests using only local fixture servers. Never make tests fetch
   public model files. **SP4.**

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
5. Stage only the native deliverables, then run
   `python3 scripts/secure_distribution_check.py --package-dir STAGE --release`.
   A source checkout fails this gate by design: it rejects any path under an
   `upstream` directory (the submodule) and the quarantined names at any depth;
   do not weaken the gate to make a source archive pass. **SP7.**

## Verification performed

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
| `ctest --preset windows-llvm-mingw-cross` (wine 6.0.3) | `100% tests passed out of 128`, 0 failed; 193 registered, the 65 `windows-runtime` cases excluded: the 61 listed below plus `secure_frontend_typed_config_tests.cfg01_chat_ranges_match_enforced_caps`, `secure_frontend_engine_arguments_tests.engine_native_path_is_utf8_for_non_ascii_root`, `secure_frontend_server_e2e_tests.serve_reports_why_the_token_and_tokenizer_pack_are_unusable`, `secure_frontend_server_cli_tests.cli_check_unreadable_token_is_not_reported_valid` (each **pending windows-msys2-clang**) |
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

`windows-runtime` tests not run locally (61; each **pending
windows-msys2-clang**; some were run directly under wine as recorded in the
SP1 deliverables table, which is not evidence): `secure_frontend_paths_tests.paths_handle_non_ascii_and_long_names`, `secure_frontend_paths_tests.cfg02_create_within_root_writes_nothing_outside`, `secure_frontend_paths_tests.auth02_windows_token_file_reads_with_private_dacl`, `secure_frontend_paths_tests.cfg03_rejects_junction_below_root`, `secure_frontend_paths_tests.cfg03_rejects_symlink_below_root`, `secure_frontend_token_store_tests.token_store_windows_round_trips_through_dpapi`, `secure_frontend_token_store_tests.token_store_windows_file_has_private_dacl`, `secure_frontend_token_store_tests.token_reader_windows_accepts_plaintext_under_private_dacl`, `secure_frontend_token_reader_tests.reads_an_owner_only_regular_file_below_the_root`, `secure_frontend_token_reader_tests.rejects_control_characters_in_file_token`, `secure_frontend_token_reader_tests.auth02_token_file_with_trailing_lf_accepted`, `secure_frontend_token_reader_tests.auth02_token_file_with_trailing_crlf_accepted`, `secure_frontend_token_reader_tests.auth02_token_file_with_two_newlines_rejected`, `secure_frontend_token_reader_tests.auth02_token_file_with_bom_rejected`, `secure_frontend_token_reader_tests.auth02_token_file_over_4k_rejected`, `secure_frontend_token_reader_tests.auth02_notepad_edits_rejected_with_reason`, `secure_frontend_model_inventory_tests.inventories_only_local_gguf_artifacts`, `secure_frontend_model_inventory_tests.rejects_duplicate_ids`, `secure_frontend_model_inventory_tests.cfg03_inventory_rejects_junction_entry`, `secure_frontend_engine_arguments_tests.engine_receives_model_path_from_inventory`, `secure_frontend_engine_arguments_tests.engine_args_reject_owned_and_network_flags`, `secure_frontend_engine_arguments_tests.strata_profile_passes_pack_and_weight_flags_through`, `secure_frontend_engine_arguments_tests.rejects_invalid_relative_artifact_path`, `secure_frontend_engine_arguments_tests.glm_profile_passes_arguments_through_without_native`, `secure_frontend_typed_config_tests.typed_config_accepts_minimal_file_and_applies_defaults`, `secure_frontend_typed_config_tests.cfg01_unknown_key_rejected`, `secure_frontend_typed_config_tests.cfg01_duplicate_key_rejected`, `secure_frontend_typed_config_tests.cfg01_type_confusion_rejected`, `secure_frontend_typed_config_tests.cfg01_missing_required_rejected`, `secure_frontend_typed_config_tests.cfg01_out_of_range_rejected`, `secure_frontend_typed_config_tests.typed_config_cross_field_rules`, `secure_frontend_typed_config_tests.typed_config_errors_never_contain_values`, `secure_frontend_typed_config_tests.cfg02_logs_and_cache_roots_are_created_private`, `secure_frontend_typed_config_tests.cfg06_validated_config_bytes_do_not_contain_token`, `secure_frontend_typed_config_tests.cfg01_config_with_everyone_write_ace_rejected`, `secure_frontend_tokenizer_pack_tests.loads_validates_and_decodes_offline_pack`, `secure_frontend_tokenizer_pack_tests.rejects_ambiguous_or_incompatible_pack_assets`, `secure_frontend_tokenizer_pack_tests.rejects_malformed_json_and_special_literals_for_decode`, `secure_frontend_tokenizer_pack_tests.encoding_fails_closed_for_special_invalid_and_missing_tokens`, `secure_frontend_tokenizer_pack_tests.cfg03_tokenizer_file_swapped_to_junction_rejected`, `secure_frontend_subsystem_limits_tests.ready_timeout_defaults_to_900_seconds`, `secure_frontend_subsystem_limits_tests.subsystem_limits_follow_config`, `secure_frontend_server_cli_tests.cli_config_file_and_flags_share_validator`, `secure_frontend_server_cli_tests.cli_flag_overrides_file_and_is_reported`, `secure_frontend_server_cli_tests.cli_check_prints_no_token`, `secure_frontend_server_cli_tests.cli_unknown_option_does_not_echo_value`, `secure_frontend_server_cli_tests.auth04_empty_token_rejected_on_loopback`, `secure_frontend_server_cli_tests.auth04_no_switch_disables_auth`, `secure_frontend_server_cli_tests.cli_check_has_no_side_effects`, `secure_frontend_server_cli_tests.init_writes_config_and_token_then_server_starts`, `secure_frontend_server_cli_tests.init_refuses_to_overwrite_without_force`, `secure_frontend_server_cli_tests.init_force_refuses_a_non_regular_config_target`, `secure_frontend_server_cli_tests.init_failure_creates_nothing`, `secure_frontend_server_e2e_tests.cfg01_invalid_config_fails_before_listener_and_child`, `secure_frontend_server_e2e_tests.net02_remote_addresses_need_opt_in`, `secure_frontend_server_e2e_tests.net02_error_is_non_secret_and_exits_before_bind`, `secure_frontend_server_e2e_tests.ready_timeout_is_configurable`, `secure_frontend_server_e2e_tests.cfg05_token_absent_from_child_argv_env_and_outputs`, `secure_frontend_server_e2e_tests.auth01_socket_rejects_missing_and_wrong_token_on_every_route`, `secure_frontend_server_e2e_tests.auth02_valid_token_succeeds_and_is_not_echoed`, `secure_frontend_server_e2e_tests.net01_default_listener_is_loopback_only`.

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

- READY is awaited lazily on the first chat request; `/health` cannot
  distinguish "loading" from "idle before first request"; SP2's supervisor
  consumes READY eagerly and then `starting` becomes `503`. SP2.
- `await_ready` and `read_generation` duplicate their deadline loops and treat
  `timeout == 0` differently. SP2.
- The default DACL of the Windows stdin named pipe is used; make it owner-only.
  SP2.
- `terminate` may now return `false`; the header does not state that contract.
  SP2.
- The fallback descriptor sweep's 65536 cap is undocumented. SP2.
- The `current_executable()` test helper does not check `readlink`'s result.
  SP2.
- S4 (oversize `413`) relies on the half-close + 100 ms drain to beat an RST
  on Windows; it passed in the MSYS2 job (run `38458255140`). SP3 if it flakes.
- The Windows launchers pass no `SystemRoot` to the child. A real engine that
  uses Winsock, crypto or other system DLLs that read it may need it on the
  allowlist; decide when the real engine is launched on Windows. SP2.
- `windows-msvc` (non-blocking) fails at configure on the current
  `windows-latest` image (Visual Studio 2026; preset asks for 2022). SP1 tooling.
- `send_all` returns `false` on `EINTR` instead of retrying. SP3.
- The S6 skip condition is broad, and its port range 20000–20099 could collide
  with an unrelated IPv4 listener. SP3.
- A small general backoff on any transient accept failure (not only resource
  exhaustion) is worth considering. SP3.
- `docs/security/threat-model.md` lists `acquire` as the sole future networked
  operation; it must be amended under review before `strata update` is
  designed. Product-experience spec / SP4.
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

SP1 (2026-10-14, Task 24). Fixed and removed from this list: the wildcard-bind
spelling bypass (Task 1, defect a), the corrupt-archive bootstrap gap (Task 24,
D4) and the stale "MSVC/Windows runtime coverage" CMake comment (Task 18).

1. The engine opens model files by path after validation: a swap below a
   user-owned, non-shared-writable root is a same-user race, accepted until
   SP2 decides on handle passing (spec §3.4).
2. On Windows `strata-secure-server` takes `char** argv` in the ANSI code page,
   so non-ASCII paths belong in the config file until the product `strata` CLI
   uses `wmain`. The engine's argv is UTF-8 end to end since the SP1 final fix
   wave: `--native` is built with `path_to_utf8` (not `path::string()`, which
   narrowed through the ANSI code page and failed the launcher's strict UTF-8
   decode for a root such as `C:\Users\José\models`), and the executable's NUL
   check reads `path::native()`. `engine_native_path_is_utf8_for_non_ascii_root`
   was RED under wine before the fix and GREEN after; it is `windows-runtime`
   on Windows CI, so pending windows-msys2-clang.
3. Windows environment-token scrub — accepted deviation from spec §3.6,
   owner-ruled: Windows has no `/proc/<pid>/environ` exposure, so the scrub
   wipes the CRT copies in place (narrow through `getenv`'s pointer, wide
   through `_wgetenv`'s), removes the CRT entry with `_putenv_s(name, "")` and
   removes the Win32 environment-block entry with
   `SetEnvironmentVariableW(name, nullptr)`; the block entry is removed, not
   overwritten in place (no Win32 API overwrites it). No ctest case covers it
   (wine probe only); pending windows-msys2-clang.
4. The `docs/security/deployment.md` Windows token caveat ("treat the Windows
   file path as unverified and prefer `--token-env` there") is removed in a
   follow-up commit once the owner's push shows the `windows-msys2-clang` job
   green for the `windows-runtime` token tests. Open.
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
    `windows-runtime` and pending windows-msys2-clang.

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

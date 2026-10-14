# Secure Strata agent handoff

## Purpose

This repository is a Windows-and-Linux, security- and privacy-first successor
to Strata. It must retain the model/backend flexibility of upstream Strata
`v0.1.43` while replacing its public service boundary with a small portable
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
   - SP1 — typed configuration, canonical paths, CSPRNG tokens.
   - SP2 — child supervision (`PROC-*` tests).
   - SP3 — API concurrency, streaming, and `NET-*`/`WEB-*`/`DOS-*`/`EXT-*` tests.
   - SP4 — the explicit `acquire` command.
   - SP5 — frontend parity with the upstream service.
   - SP6 — GLM engine port, in its own directory, tracking
     `lighttransport/Strata` branch `glm53f`.
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
   `7695859aa13afb248bdb4d36f9b2e95707db079d` (tag `v0.1.43`) and never
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
   commands are in "Update upstream" below.
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

## Current baseline

- Upstream baseline: the `upstream` submodule gitlink, `Niko1221/Strata` tag
  `v0.1.43`, commit `7695859aa13afb248bdb4d36f9b2e95707db079d`
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
- Supported target platforms: native Windows 10/11 and Linux. The intended
  compatibility target is every upstream-supported model profile, model
  quantization, vision option, context option, GPU backend, and multi-GPU
  configuration. Do not silently reduce that scope to one model or NVIDIA.

## Repository layout

Upstream Strata is the git submodule `upstream/`; the repository root holds
only our code. Deleting `upstream/` leaves exactly our code.

| Ours, at the root | Pristine, under `upstream/` (submodule @ `7695859a`, tag `v0.1.43`) |
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
means the `upstream/` checkout is behind the recorded gitlink. The presets need no submodule;
`pytest -q` and the root build do, and both say so when it is missing.

Root build (GPU backends off, nothing fetched): `cmake -S . -B out/root -G
Ninja && cmake --build out/root && ctest --test-dir out/root`.
`-DSECURE_STRATA_BUILD_ENGINE=OFF` builds the frontend alone. Details:
[`secure-frontend-ci.md`](secure-frontend-ci.md), "Root build".

### Update upstream

The order matches [`PROVENANCE.md`](PROVENANCE.md), "Updating the baseline"
(the single source of truth; the exact commands are there).

1. `git -C upstream fetch --tags origin`, then `git -C upstream checkout
   --detach <tag>`.
2. Gates, each with its working directory: `pytest -q` (repo root);
   `ctest --preset linux-gcc` (in `secure_frontend/`) and the
   `windows-llvm-mingw-cross` build and wine `ctest` (in `secure_frontend/`);
   the root configure, build and `ctest` from a fresh build directory (repo
   root), plus `test ! -e out/root/_deps`. Then upstream's own suites in a
   separate venv created with `python3 -m venv --without-pip
   out/venv-upstream` and filled with `.venv-dev/bin/pip --python
   out/venv-upstream/bin/python install -r scripts/dev/requirements-dev.txt -r
   upstream/requirements.txt`, run **from `upstream/`**: `cd upstream &&
   ../out/venv-upstream/bin/pytest -q tools
   --ignore=tools/test_iq_pack.py --ignore=tools/test_setup_engine_hash.py`
   with `--deselect upstream/tools/test_setup_choices.py::…` for the three
   recorded drift cases (the ids keep the `upstream/tools/` prefix because our
   root `pytest.ini` stays the rootdir), `&& ../out/venv-upstream/bin/pytest -q
   serve`. At `v0.1.43`: 616 passed / 2 skipped / 3 deselected, and 695
   passed. Re-audit upstream's top-level CMake assumptions (layout spec §3
   table): new `FetchContent`, option defaults, a `tests/CMakeLists.txt` that
   would flip `STRATA_BUILD_TESTS`. Re-check the SP5 pass-through table
   against the new engine's flags and protocol, and the upstream internals
   `tools/secure/secure_tokenizer.py` relies on (listed in its module
   docstring).
3. `git -C upstream status --porcelain` is empty and `git submodule status`
   is clean (no `-`/`U`; `+` is expected until the pointer is staged).
4. Update `PROVENANCE.md` "Baseline", then run `git grep -n '<old tag>\|<old
   short sha>' -- ':!docs/superpowers' ':!upstream'` and update every hit.
   Known pin sites: `README.md` (revision column and the pinned
   `github.com/Niko1221/Strata/blob/<tag>/…` links),
   `.github/workflows/secure-frontend.yml` (header comment), this file (owner
   decision 6, the "Repository layout" table header, "Current baseline"),
   `secure-frontend-ci.md` (the "Root build" note and the offline-bundle
   commands), `PROVENANCE.md` (the `[strata]` reference and the pinned
   license links), and the `docs/security/` pages that name the version.
5. `git add upstream docs/PROVENANCE.md` plus every file touched in step 4;
   one commit: `upstream: bump to <tag>`.

## What has changed

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

### SP2 deliverables (branch `sp2-portable-supervision`, in progress)

Item IDs are from §4 of the SP2 spec. W rows are verified only by the
`windows-msys2-clang` CI job (pending rflores's push); the wine column is a smoke result.

| Item | What changed | Regression test | Local result (linux-gcc; wine) |
| --- | --- | --- | --- |
| F1 | Standalone test-only `strata-supervision-fake-engine` with the SP2 failure modes (crash modes never wait on WER); SP2 tests registered by acceptance ID through SP1's `secure_frontend_add_cases` (`<binary>.<case>`); baseline after SP1 Task 2: N₀ = 111, W₀ = 102. Naming deviation (ruling PF5): spec F1 says `strata-fake-engine`; the target is `strata-supervision-fake-engine` because SP1 owns `secure_frontend_fake_engine` — behaviour matches spec F1. `engine_stdio_process_tests` now launch the standalone fake (the in-binary `--fake-engine`/`--fake-sleeper` self-exec is gone). | `secure_frontend_fake_engine_tests.fake_engine_modes_selftest` | `100% tests passed out of 112`; wine `100% tests passed out of 102` (label `windows-runtime` excluded; a direct wine run of the case exits 0, with winedbg noise from the SEGV mode — authoritative in MSYS2, pending rflores's push) |
| F2 | DUMP reports FDS/HANDLES, ARGV (Windows via `CommandLineToArgvW`), sorted ENV, SIG masks, CWD, IDS (uid/gid/NoNewPrivs/CapEff; Windows SID/elevation/integrity), END; `--dump-file`; parser `tests/support/fake_engine_dump.hpp`. `child_inherits_only_stdio_descriptors` and `child_receives_exact_argv_and_env` read the report through the parser. | `secure_frontend_fake_engine_tests.fake_engine_dump_is_parseable` | `100% tests passed out of 113`; wine `100% tests passed out of 102` (label `windows-runtime` excluded); a direct wine run of the case exits 1 with only `FAILED: ENV is the sorted child environment` (wine's loader adds its own variables to the exact environment block the launcher passes; ARGV, HANDLES, CWD, IDS and `--dump-file` pass) — authoritative in MSYS2, pending rflores's push |
| F3 | `tests/support/server_harness.{hpp,cpp}` starts `strata-secure-server` with the fake engine (0700 fixture dirs, 0600 files, 43-character token, free port); on Windows always with a LUA-restricted non-elevated token (Safer `NORMALUSER` fallback; no override flag) and asserts it; stops it by signal / `CTRL_BREAK_EVENT` / kill; the destructor kills every descendant it has seen (Linux subreaper reaps orphans; Windows Job); counts descendants; reads stderr; `test_tokenizer.hpp` (byte tokenizer pack, real GPT-2 byte alphabet per ruling PF6). Runs against the current SP0 server, whose `/health` answers `200 {"status":"ok","engine":"starting"}`, so the self-test keeps the tolerant 200-or-503 assertion. | `secure_frontend_server_tests.harness_server_lifecycle_selftest` | `100% tests passed out of 114`; no fake engine left running afterwards; wine `100% tests passed out of 102` (label `windows-runtime` excluded); a direct wine run of the case exits 1 with `harness: no non-elevated token for strata-secure-server (LUA and Safer NORMALUSER both elevated)` (wine has no UAC; its token answers are not authoritative); Windows token path authoritative in MSYS2, pending rflores's push |
| K1, K3, K5 | `deadline.hpp`: one `deadline_after`/`remaining_until` rule in `await_ready`, `read_generation`, `read_line`; a zero budget is an immediate timeout everywhere. `terminate` contract documented (false only when still unreaped = abandoned). `current_executable()` checks `readlink`/`GetModuleFileNameW`. | `deadline_zero_timeout_is_immediate_everywhere` | `100% tests passed out of 115`; wine `100% tests passed out of 103` (the new deadline case is portable and unlabeled and passes under wine) |
| V1 | `EngineStdioProcess::try_reap()` keeps the raw `waitpid` / `GetExitCodeProcess` status; `classify_exit` maps it to `clean_exit`/`error_exit`/`spawn_failed`/`abort`/`killed_external`/`killed_by_supervisor(reason)`/`crashed` (log only); Windows Job kill code `0x20000001`, and Windows `terminate()` records it through `try_reap()`. | `secure_frontend_engine_child_tests.proc04_exit_status_is_classified` (B) | `100% tests passed out of 116`; wine `100% tests passed out of 103` (label `windows-runtime` excluded); a direct wine run of the case exits 1 with only `FAILED: the child must end: --crash-after-ready=SEGV` (wine starts winedbg on the page fault, so the child does not end in 10 s); the table, exit-1, ABRT and supervisor-kill (`0x20000001` via `try_reap()`) checks pass under wine; Windows authoritative in MSYS2, pending rflores's push |
| V2, V11 (core) | `EngineSupervisor` library: one supervisor thread spawns, consumes READY eagerly, watches and kills; the serving thread borrows the generation via `Lease`. `health_for`: `starting` → 503, `ready`/`generating` → 200; router's optional `recovery` literal (`restarting`/`exhausted`) only with `engine=failed`. Fresh `EngineInstance` per spawn. Until the restart policy lands every end opens the circuit. SP1-bound values in `supervision_defaults.hpp`. Not yet wired into the server (Task 6b, after the SP1 merge). A spawn failure is logged by the supervisor as `engine generation <n> ended: spawn_failed`. Interface members not yet read in this run are kept for later tasks: `SupervisorConfig::shutdown_stdin_wait`, `SupervisedProcess::close_stdin`/`signal_group_terminate`, `kShutdownStdinWait` (Task 15); `SupervisorConfig::no_new_privileges_hint`, `kNoNewPrivilegesDefault` (Task 26). | `secure_frontend_engine_supervisor_tests.supervisor_health_literals_per_state`, `secure_frontend_api_router_tests.health_samples_status_before_state_once_each` (updated), `secure_frontend_api_router_tests.health_carries_recovery_only_with_failed`, `secure_frontend_chat_execution_tests.chat_uses_adopted_ready_without_waiting` | `100% tests passed out of 119`; wine `100% tests passed out of 106` (all three new cases are unit cases and unlabeled, and pass under wine) |
| V3 | `RestartTracker`: 3 consecutive failures open the circuit; backoff 1 s → 2 s → … ≤ 60 s; 300 s healthy window resets the count; spawn failures count. Injectable `SupervisorClock` (`ManualClock` in tests; `tests/support/fake_supervised_process.hpp`). Three client-triggerable ERR lines in a row open the circuit until a restart (Review Focus 6, accepted). Spec §3.1: an ended generation still held by a `Lease` waits in the supervisor's `retired_` list and is destroyed by the supervisor thread once the Lease lets go (never on the serving thread); an unreaped generation at shutdown goes to `abandoned_`. | `secure_frontend_engine_supervisor_tests.proc04_restart_backoff_then_circuit_open`, `secure_frontend_engine_supervisor_tests.proc04_healthy_window_resets_failure_count`, `secure_frontend_engine_supervisor_tests.proc04_recovers_after_transient_crash`, `secure_frontend_engine_supervisor_tests.proc04_missing_engine_opens_circuit_without_spinning` (Review Focus 2), `secure_frontend_engine_supervisor_tests.proc04_client_err_lines_open_circuit_until_restart` (Review Focus 6), `secure_frontend_engine_supervisor_tests.supervisor_retires_ended_generation_on_its_own_thread` | `100% tests passed out of 125`; wine `100% tests passed out of 111` (five new unit cases pass under wine; `proc04_recovers_after_transient_crash` is a process case, labeled windows-runtime — authoritative in MSYS2, pending rflores's push) |
| V4 | The supervisor waits on the child: pidfd (Linux 5.3+; the test asserts `monitor_handle() != kNoMonitorHandle` on Linux, so the pidfd path is proven, not just the fallback), process handle (Windows), else a 100 ms `waitpid(WNOHANG)` poll. Spec V4's "`/health` leaves ready within 1 s" is proven at supervisor level here (`wait_for_state`, ruling PF11); the `/health` form arrives with Task 6b. Spec §3.3 (carried from the V3 review): a wake that is not shutdown — a released Lease, a stale `report_fatal` notify — no longer cuts the backoff short: `schedule_restart` sleeps out the remainder to the deadline and sweeps on each wake; `release()` of a retired generation wakes the supervisor so it is swept promptly, also in `circuit_open`. | `secure_frontend_engine_supervisor_tests.proc04_monitor_detects_idle_crash`, `secure_frontend_engine_supervisor_tests.proc04_monitor_fallback_without_pidfd`, `secure_frontend_engine_supervisor_tests.proc04_backoff_survives_stale_wake` (§3.3) | `100% tests passed out of 128`; wine `100% tests passed out of 113` (`proc04_monitor_fallback_without_pidfd` and `proc04_backoff_survives_stale_wake` pass under wine; `proc04_monitor_detects_idle_crash` is a process case, labeled windows-runtime — authoritative in MSYS2, pending rflores's push) |
| V5 | The four upstream `FATAL_PREFIXES` (`kEngineFatalPrefixes`, verbatim from `upstream/serve/server.py:587-588`) fail the protocol (`fatal_engine_line`, fixed message, trailing `DONE` not accepted), checked in both `await_ready` and `read_generation` right after `validate_incoming`; `kill_reason_for` maps it to `KillReason::fatal_line`, so the supervisor kills the group and restarts (`killed_by_supervisor(fatal_line)`). Correction (Task 10, spec §3.8): until Task 10 a fatal line before READY was logged `killed_by_supervisor(protocol_failed)`, because the supervisor's `await_ready` hard-mapped every non-timeout READY failure; it now maps them through `kill_reason_for`, so a pre-READY fatal line is `fatal_line` too (`proc04_fatal_line_before_ready_kills_as_fatal_line`, V6/V7 row). Other `ERR` lines keep SP0's per-request behavior; the failed generation is replaced. | `secure_frontend_engine_supervisor_tests.proc04_fatal_prefix_kills_engine` (protocol level for each prefix, then supervisor level with `--fatal-line=0..3`) | `100% tests passed out of 129`; wine `100% tests passed out of 113` (process case, labeled windows-runtime — authoritative in MSYS2, pending rflores's push; a direct wine run of the case also passes) |
| V6, V7 | READY deadline `ready_timeout` (900 s default) kills and counts (`killed_by_supervisor(ready_timeout)`); an engine that ignores STOP is killed and replaced (`drain_failed`): `abandon()` records `EngineProtocolErrorCode::abandoned` when no earlier failure was recorded, and `kill_reason_for` maps it to `KillReason::drain_failed`. Spec §3.8: non-timeout READY failures are mapped through `kill_reason_for` (a fatal line before READY is `fatal_line`, not `protocol_failed`). (V8: Task 6b.) | `secure_frontend_engine_supervisor_tests.proc04_ready_timeout_kills_and_counts`, `secure_frontend_engine_supervisor_tests.proc04_drain_failure_kills_and_restarts`, `secure_frontend_engine_supervisor_tests.proc04_fatal_line_before_ready_kills_as_fatal_line` (§3.8) | `100% tests passed out of 132`; wine `100% tests passed out of 114` (`proc04_fatal_line_before_ready_kills_as_fatal_line` is a unit case and passes under wine; the V6 and V7 cases are process cases, labeled windows-runtime — authoritative in MSYS2, pending rflores's push; a direct wine run of each also passes) |
| V9, V10 | Ten forced restarts leave one live engine, no zombie, a stable descriptor/handle count and an empty stdout buffer in each new generation. A killed child that cannot be reaped within `reap_timeout` (30 s) is abandoned and opens the circuit; nothing respawns while it lives. | `secure_frontend_engine_supervisor_tests.proc04_no_leak_across_restarts`, `secure_frontend_engine_supervisor_tests.proc04_unreaped_child_opens_circuit` | `100% tests passed out of 134`; wine `100% tests passed out of 115` (`proc04_unreaped_child_opens_circuit` is a unit case and passes under wine; `proc04_no_leak_across_restarts` is a process case, labeled windows-runtime — authoritative in MSYS2, pending rflores's push; a direct wine run of it also passes) |
| C1 | POSIX `terminate()` always ends with `kill(-pgid, SIGKILL)`, also after the leader was reaped; the group id is forgotten only after success. | `secure_frontend_engine_child_tests.proc05_group_killed_after_leader_reaped` (L) | `100% tests passed out of 135`; wine unchanged, `100% tests passed out of 115` (Linux-only case, not registered in the cross build; cross build `-Werror` clean) |
| C2 | The frontend is the child subreaper (`PR_SET_CHILD_SUBREAPER`). When a generation ends and its leader is reaped (restart path, 1 s bound) and at shutdown (250 ms bound, inside the shutdown budget), it SIGKILLs and reaps every child that is not a live engine, so `setsid`/`setpgid`/double-fork escapes die and leave no zombie. If the leader stays unreaped, the circuit opens without a sweep. | `secure_frontend_engine_supervisor_tests.proc05_setsid_grandchild_is_reaped` (L), `secure_frontend_engine_supervisor_tests.proc05_setsid_grandchild_is_reaped_at_shutdown` (L) | `100% tests passed out of 137`; wine unchanged, `100% tests passed out of 115` (Linux-only cases, not registered in the cross build; cross build `-Werror` clean) |
| C3 | Pre-exec `PR_SET_PDEATHSIG(SIGKILL)` + `getppid()` recheck against the pid `prepare` records before fork (mismatch → `_exit(127)`); forks only from the supervisor thread (the SP0 server forks from its serial main thread). Residual risk (spec §3.7): without a delegated cgroup, the engine's own descendants survive a frontend SIGKILL — logged by the test as "residual risk (spec 3.7): grandchild survived after a frontend SIGKILL without a delegated cgroup". The test runs against the current SP0 server and waits for the grandchild pidfile, not `/health`. | `secure_frontend_server_tests.proc05_frontend_sigkill_kills_engine` (L) | `100% tests passed out of 138`; wine unchanged, `100% tests passed out of 115` (Linux-only case, not registered in the cross build; cross build `-Werror` clean) |
| C6 (PARTIAL) | **Partial: launch flags only; console handler + server cases pending Task 15 (after the SP1 merge).** Windows launch (`engine_stdio_process.cpp` and its SP0 twin `engine_process.cpp`): `CREATE_NEW_PROCESS_GROUP` (Ctrl-C is disabled in the engine's group; group-targeted Ctrl-Break reaches only the frontend; a console-wide Ctrl-Break still reaches the engine (open item for Task 15: `CREATE_NO_WINDOW` or accept the race); the console handler that runs the orderly shutdown is not written yet); the Job adds `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION` to `KILL_ON_JOB_CLOSE`; `SetErrorMode(GetErrorMode() \| SEM_NOGPFAULTERRORBOX \| SEM_FAILCRITICALERRORS)` once per process before spawn, inherited by the engine. New fake flag `--default-error-mode` (the fake skips its own `SetErrorMode` and runs with the mode it inherited). | `secure_frontend_engine_supervisor_tests.proc04_windows_abort_does_not_stall` (W; `--abort-in-gen --default-error-mode`: abort / fastfail path, error mode only), `secure_frontend_engine_supervisor_tests.proc04_windows_crash_does_not_stall` (W; `--crash-after-ready=SEGV --default-error-mode`: a real unhandled exception, so the Job's `DIE_ON_UNHANDLED_EXCEPTION` is on the path; end classified `crashed` within 5 s) — supervisor-level smokes of the launch settings, **not C6 proof**: spec C6's named tests are the two server-level cases, still to be written in Task 15 | `100% tests passed out of 138` (unchanged; Windows-only case); wine unchanged, `100% tests passed out of 115` (process case, labeled windows-runtime, excluded); cross build `-Werror` clean; a direct wine run of `proc04_windows_abort_does_not_stall` exits 0 both before and after the change (wine has no WER dialog, so it cannot show the stall); a direct wine run of `proc04_windows_crash_does_not_stall` exits 1 with `FAILED: the crash is observed and classified crashed, not stalled on WER` and `FAILED: within 5 s` (wine prints `Unhandled page fault ... starting debugger...` and starts winedbg on the access violation, ignoring the error mode and the Job limit, as in the V1 row) — **authoritative in MSYS2, pending rflores's push** |
| N4 | Fork with every signal blocked (`posix_launch::BlockAllSignals` around `fork()` in `engine_stdio_process.cpp` and its SP0 twin `engine_process.cpp`); the child (`posix_launch::reset_signal_state()`, called in `exec_child` immediately before `execve`) resets every disposition but SIGKILL/SIGSTOP to `SIG_DFL` and clears the mask before `execve`. | `secure_frontend_engine_child_tests.proc02_child_signal_state_is_default` (L) | `100% tests passed out of 139`; wine unchanged, `100% tests passed out of 115` (Linux-only case, not registered in the cross build; cross build `-Werror` clean) |
| N5 | Canaries: a non-CLOEXEC fd, a listening socket and an open token file never reach the engine (Linux: `FDS 0,1,2`); Windows: an inheritable file, event and socket are absent from the engine's handle table (parent-side `NtQueryInformationProcess(ProcessHandleInformation)` + `CompareObjectHandles`, both resolved via `GetProcAddress`; the snapshot must list at least 3 handles and at least one must duplicate, and a positive control plants the event in the engine with `DuplicateHandle` and requires the same inspection to find it, so a failed inspection cannot pass as "absent"). No production change (existing sweep / handle list); both passed on their first run where runnable. | `secure_frontend_engine_child_tests.proc02_canary_descriptors_absent` (L), `secure_frontend_engine_child_tests.proc02_canary_handles_absent` (W) | `100% tests passed out of 140`; wine unchanged, `100% tests passed out of 115` (W case labeled windows-runtime, excluded); cross build `-Werror` clean; a direct wine run of `proc02_canary_handles_absent` exits 1 with `FAILED: inspection APIs are available (Windows 10 1607+)` (wine 6.0.3's kernelbase does not export `CompareObjectHandles`; not a leak finding) — **W authoritative in MSYS2, pending rflores's push** |
| N6, R1, K2 | Windows stdin pipe: protected DACL with one ACE for the current user, `\\.\pipe\secure_frontend-<pid>-<128-bit random>` (`BCryptGenRandom`; Task 29 switches to SP1's `fill_random()`), single instance, remote clients rejected, `GetNamedPipeClientProcessId` must be our pid (a mismatch fails start with ERROR_ACCESS_DENIED; that path is untested, it cannot be provoked without racing our own client open); frontend end `FILE_FLAG_OVERLAPPED`, 64 KiB buffer and chunks, 1 s no-progress deadline per 64 KiB chunk (not an overall bound on the write) then `CancelIoEx` → write failure → `killed_by_supervisor(write_timeout)`. Limits doc update pending Task 28 (`docs/security/engine-protocol-limits.md` "Windows stdin writes" still describes synchronous writes). | `secure_frontend_engine_child_tests.proc02_stdin_pipe_dacl_is_owner_only`, `secure_frontend_engine_child_tests.proc03_windows_pipe_second_open_fails` (a `GENERIC_READ` client open must fail with exactly `ERROR_PIPE_BUSY`, and a rival `CreateNamedPipeW` on the name must be refused), `secure_frontend_engine_supervisor_tests.proc04_windows_write_timeout_kills_engine` (all W; K2: 60,000-token prompt, ~240 KB GEN line, 2 s generation timeout, CTest timeout 300 s) | Linux unchanged, `100% tests passed out of 140`; wine unchanged, `100% tests passed out of 115` (W cases labeled windows-runtime, excluded); cross build `-Werror` clean; direct wine runs: all three exit 0 (K2 in ~1.5 s), also after fix round 1; RED under wine before the fix: K2 failed `the blocked write is cancelled at its deadline` / `killed as write_timeout` (the write fit the old 16 MiB buffer) — **W authoritative in MSYS2, pending rflores's push** |
| A1, A2 | Windows argv twin: quotes, backslashes (incl. trailing), `%PATH%`, `^&\|<>()`, newline, UTF-8, empty string round-trip through the frontend's quoting and `CommandLineToArgvW`. End to end: `--engine-arg` values with shell metacharacters and the inventory `--native` reach the engine as literal argv entries with no shell (Task 19 adds the typed `--gpu` to this case). No production change; both passed on their first run where runnable (A2 runs against the current SP0 server, which writes `--dump-file` before READY). | `secure_frontend_engine_child_tests.proc01_windows_argv_round_trip` (W), `secure_frontend_server_tests.proc01_server_passes_literal_argv` (B) | `100% tests passed out of 141`; wine unchanged, `100% tests passed out of 115` (both cases labeled windows-runtime, excluded); cross build `-Werror` clean; direct wine run of `proc01_windows_argv_round_trip` exits 0; direct wine run of `proc01_server_passes_literal_argv` exits 1 with `harness: no non-elevated token for strata-secure-server` / `FAILED: the server must listen` (known wine limit: no UAC, the restricted-token harness cannot launch the server; not an argv finding) — **W and the Windows run of B authoritative in MSYS2, pending rflores's push** |
| R2, R3 | Linux PROC-03 = other user context: `nobody` cannot open `/proc/<engine>/fd/0` (CI via `sudo -n -u nobody`, env `STRATA_TEST_SECOND_UID_SUDO=1`, set on the Linux ctest step for both linux-gcc and linux-clang; skipped locally with its reason printed, never run with the variable set outside CI). Same-uid reopen and injection is the recorded accepted risk (threat model "Engine process isolation"; release record). No production change; R3 passed on its first run. | `secure_frontend_engine_child_tests.proc03_other_uid_cannot_open_engine_fd` (L, CI only, `SKIP_RETURN_CODE 77`), `secure_frontend_engine_child_tests.proc03_same_uid_reopen_is_accepted_risk` (L) | `100% tests passed out of 143` (1 skipped: `proc03_other_uid_cannot_open_engine_fd`, printing `SKIP: needs a second uid: CI sets STRATA_TEST_SECOND_UID_SUDO=1 where` … `is allowed`); wine unchanged, `100% tests passed out of 115` (Linux-only cases compiled out); cross build `-Werror` clean — **R2 authoritative in the GitHub Linux jobs, pending rflores's push** |

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

`secure_frontend::validate_config()` is the initial enforced boundary:

- Defaults to `127.0.0.1:8080`.
- Requires a supplied, non-blank API key for every listener, including
  loopback.
- Requires `allow_remote=true` in addition to the API key for every
  non-loopback literal or hostname.
- Requires a separate `allow_wildcard_bind=true` for `0.0.0.0` or `::`; a
  remote-listening opt-in alone cannot expose every interface.
- Discards the plaintext key after validation; the validated configuration
  retains only a boolean indicating that a non-blank key was supplied.
- Rejects invalid hosts and ports outside `1..65535`.

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
  owner-only regular protected file without symlinks/reparse points. The
  Windows branch validates final handle paths, current-user ownership, and a
  protected private DACL on the root and every component (see the comment in
  `token_reader.hpp`). It is fail-closed, compiles in the cross build, and has
  **no Windows runtime test**: `secure_frontend_token_reader_tests` is a
  UNIX-only target.
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
  (`::` as IPv6-only), reads one request under a 30 s total deadline and a
  64 KiB cap (`413` above it), sends with a timeout, and survives clients that
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
   time/concurrency limits and roots for models/logs/cache. **SP1.** (SP0 added
   `HttpSocketServerLimits` as a defaulted parameter to be promoted.)
2. Add canonical-path validation for Linux and Windows, including reparse
   points, UNC/device/ADS forms, and traversal prevention. **SP1.**
3. Add secure token generation/storage: CSPRNG; DPAPI-backed file on Windows;
   user-only permissions on Linux. Tokens must never reach log output,
   environment, child command lines, or metrics. **SP1.**
4. Implement all relevant `CFG-*` and `AUTH-*` tests from
   `tests/security/README.md` before connecting these primitives to a server.
   **SP1.**

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
   **Inventory done; canonical-root validation is SP1.**
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
- The fallback descriptor sweep's 65536 cap is undocumented. SP2.
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
- **SP1 (first task):** `is_wildcard_host` matches only the literal strings
  `0.0.0.0` and `::`; alternate IPv6 spellings of the unspecified address
  (`::0`, `0::0`, `0:0:0:0:0:0:0:0`, `::0.0.0.0`) parse as wildcard binds but
  pass with `--allow-remote` alone, bypassing the dedicated
  `--allow-wildcard-bind` opt-in (NET-03). Loopback detection has the mirror
  issue in the safe direction (`0:0:0:0:0:0:0:1`, `::ffff:127.0.0.1` treated as
  non-loopback). Fix by classifying from the parsed address bytes
  (`IN6_IS_ADDR_UNSPECIFIED` / `LOOPBACK` / `V4MAPPED`). Low exposure today:
  still requires `--allow-remote` and a token.
- A small general backoff on any transient accept failure (not only resource
  exhaustion) is worth considering. SP3.
- `bootstrap-llvm-mingw.sh` keeps a corrupt archive after a digest mismatch;
  delete it by hand before re-running. Tooling / SP1.
- `docs/security/threat-model.md` lists `acquire` as the sole future networked
  operation; it must be amended under review before `strata update` is
  designed. Product-experience spec / SP4.
- The comment in `secure_frontend/CMakeLists.txt` above the UNIX-only
  `token_reader_tests` still says "MSVC/Windows runtime coverage"; the plan for
  that coverage is now the MSYS2 job. SP1.
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

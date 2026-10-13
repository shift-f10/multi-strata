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
6. **Upstream-trackability.** Our code lives only in our own directories.
   Upstream-owned files are touched only from an allowlist (the root
   `CMakeLists.txt` frontend hunk, `.gitignore`, `requirements.txt` if ever
   needed). The allowlist is defined in
   [`PROVENANCE.md`](PROVENANCE.md), which records each touch (including one
   pre-allowlist baseline edit to `tools/strata_tokenizer.py`). The upstream Python
   service stays in-tree, untouched (quarantined at package time). Merge
   runbook: `git fetch upstream && git merge upstream/main`, then run every gate
   below. An upstream-delta script plus a CI gate for it are still to be added.
   The SP6 engine is never woven into `src/`.
7. **pytest exclusions to keep visible** (all in `pytest.ini`, each with its
   reason):
   - deselected, upstream drift against `setup.py` (fail with
     `FileNotFoundError` on the mocked `build/strata`):
     `tools/test_setup_choices.py::HipVision::test_the_cpu_encoder_is_built_once`,
     `tools/test_setup_choices.py::HipVision::test_without_images_nothing_changes`,
     `tools/test_setup_choices.py::CudaVision::test_the_encoder_is_built_native`;
   - ignored: `tools/test_iq_pack.py` (needs llama.cpp's `gguf` module) and
     `tools/test_setup_engine_hash.py` (reaches GitHub; tests must be hermetic).
8. **Pre-push hook.** The owner's pre-push hook runs `pytest -q`. With
   `pytest.ini` it collects `tools/` only and passes in about 20.6 s on the dev host.
   `pytest serve` is the explicit run of the upstream service suite (about
   4.5 minutes) after an upstream merge.
   `conftest.py` skips numpy-dependent upstream tests when the interpreter running pytest lacks numpy, so the pre-push hook passes with a system pytest; the full set runs in `.venv-dev`.
9. **CI status: all blocking jobs green on Windows and Linux** (run
   `38458255140`, branch `ci/windows-runtime-fixes`, 2026-10-13). The first
   real run (`38456682352`) failed three tests on `windows-msys2-clang`; the
   fixes are listed under "Verification performed". The wine results below
   remain a smoke test only.

## Current baseline

- Upstream baseline: `Niko1221/Strata` tag `v0.1.43`, checked-out commit
  `7695859aa13afb248bdb4d36f9b2e95707db079d`.
- Git remotes: `upstream` points at `https://github.com/Niko1221/Strata.git`;
  `origin` is the owner's repository. Only the owner pushes.
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

## What has changed

### Secure baseline (commit `7de35b0c` on `main`)

| Area | Files | Status |
| --- | --- | --- |
| Provenance | `docs/PROVENANCE.md` | Complete baseline/attribution record. SP0 added the upstream-touch allowlist and the record of every touch to an upstream-owned file. |
| Security/privacy contract | `docs/security/threat-model.md`, `tests/security/README.md`, `docs/security/privacy-migration.md`, `docs/security/deployment.md` | Complete specification, legacy-network inventory, platform deployment prerequisites, and package-readiness procedure; most acceptance tests are not implemented yet. |
| Secure package gate | `scripts/secure_distribution_check.py` | Checks a selected staging directory (never this source tree) for quarantined Python installer/service/MCP/update artifacts and symlinks; `--release` additionally requires a privacy declaration manifest and SBOM. |
| Native frontend foundation | `secure_frontend/` | C++20 configuration, secret/token-reader, HTTP policy/request-handler/socket adapter, API router, local model inventory, and process-supervision libraries with unit tests. |
| Runnable smoke executables | `secure-frontend-smoke`, `strata-secure-smoke-server` | Authenticated local `/health` and `/v1/models`; no engine inference. |
| Native serial chat executable | `strata-secure-server` | Starts one supervised local `--serve` engine child and offers authenticated text-only, non-streaming Qwen or explicitly selected GLM-5.3 `/v1/chat/completions` plus health/models. It is intentionally not a claim of universal upstream model/template/vision compatibility. |
| GLM tokenizer tooling | `tools/strata_tokenizer.py`, `tools/test_glm_tokenizer.py` | Offline support for the `glm4` and `chatglm-bpe` byte-BPE pre-tokenizer aliases, preserving GLM's 1–3-digit segmentation, with emitted pack metadata. `secure_frontend` does not yet consume tokenizer-pack metadata, so native GLM execution still needs matching-pack validation. |
| Top-level integration | `CMakeLists.txt` | Builds `secure_frontend` through `STRATA_BUILD_SECURE_FRONTEND=ON` (default `OFF` since SP0). |

### SP0 deliverables (branch `sp0-foundation-hardening` on `4dce6f79`, including the docs commits and the final fix wave)

Item IDs are from §4 of the SP0 spec. Each row names its regression test, or
says why it has none.

| Item | What changed | Regression test / check |
| --- | --- | --- |
| Tooling (T1, T5) | `scripts/dev/bootstrap-linux.sh` creates `.venv-dev` (no root) with `-r requirements.txt -r scripts/dev/requirements-dev.txt`: cmake/ninja pinned in `requirements.txt`; pytest 9.1.1 and its dependencies pinned in `scripts/dev/requirements-dev.txt`. Offline (`STRATA_WHEEL_DIR` set) needs every wheel both files name **plus** a pip wheel, which the pip-bootstrap step now takes from `STRATA_WHEEL_DIR` too; nothing is fetched from the network then. `pytest.ini` collects `tools/test_*.py` only, with the exclusions listed above. | Bootstrap is idempotent (re-run on the existing venv: exit 0); a fresh scratch checkout bootstraps with network (exit 0) and offline from a wheel directory with the network blocked (exit 0); `pytest -q` passes from the repository root. |
| CMake hygiene (T3, T4) | Top-level `STRATA_BUILD_SECURE_FRONTEND` defaults `OFF` (opt-in). `SECURE_FRONTEND_WERROR` (default `ON`, follows `STRATA_WERROR` from the root). One `secure_frontend_set_warnings()` helper replaces the per-target flag blocks; dead `if(MSVC)`-inside-`if(UNIX)` blocks removed. | Configure with each setting. |
| llvm-mingw (T2, P5) | `scripts/dev/bootstrap-llvm-mingw.sh` (llvm-mingw `20261006`, sha256 pinned), toolchain file, `windows-llvm-mingw-cross` preset. `win32_prelude.hpp` (`NOMINMAX`, `WIN32_LEAN_AND_MEAN`); paths converted with `path::wstring()`. Two further Windows fixes found by the cross build: unused POSIX helpers in `engine_process.cpp` guarded; `token_reader.cpp` uses `std::next(it) == end()` (libc++ `path::iterator` is an input iterator). | Cross build with `-Werror`; `wine strata-secure-server.exe --help` exits 0. |
| Early close (S1) | `install_process_defaults()` ignores `SIGPIPE` in all three mains; `send()` uses `MSG_NOSIGNAL` (`SO_NOSIGPIPE` where that is the only option). | `socket_server_survives_client_early_close` |
| Request deadline, send timeout (S2, S3) | `HttpSocketServerLimits{request_deadline = 30 s, max_request_bytes = 64 KiB}`, a defaulted `bind()` parameter until SP1's typed configuration. Total monotonic deadline for header and body; send timeout, with each `send()` capped at 64 KiB (Winsock accepted one 32 MiB blocking `send()` whole, bypassing the deadline; found by the first MSYS2 run). | `socket_server_rejects_slow_request_past_deadline`, `socket_server_send_times_out_on_stalled_reader` |
| Listener robustness (S4–S7) | Oversize request answered `413`; accept blocks without a timeout (smoke server no longer exits after 5 s idle); `IPV6_V6ONLY` on IPv6 binds; `SO_REUSEADDR` (`SO_EXCLUSIVEADDRUSE` on Windows); complete responses. `listener_failed()` is set only for a broken listener (`EBADF`/`ENOTSOCK`/`EINVAL` and the Winsock equivalents); peer and network errors are transient; 50 ms backoff on descriptor/buffer exhaustion. The mains stop only on listener failure. | `socket_server_rejects_oversize_request_over_tcp`, `socket_server_accept_waits_without_timeout`, `socket_server_ipv6_bind_is_v6only` (binds `::`), `socket_server_response_is_complete`, `socket_server_survives_reset_before_accept`, `socket_server_responds_after_client_half_close`. After the last response byte (normal, `408`, `413`) the server half-closes its send side and drains the peer for at most 100 ms / 256 KiB before closing, so a Windows client reads the `413` rather than an RST. The socket tests are portable (run under wine and in the MSYS2 job). |
| Generation deadline and recovery (E1, E2) | Total generation deadline; on timeout the client sends `STOP` and drains to `DONE` within `ChatExecutionLimits::stop_drain_timeout` (5 s), returning to idle (`idle()`), or marks the engine failed (`abandon()`). The request gets the `generation_timed_out` error; a `nonfinite` result is a `503` for that request only and the engine stays ready. | `generation_total_deadline_is_enforced`, `chat_recovers_after_generation_timeout`, `chat_marks_engine_failed_when_drain_fails`, `chat_rejects_nonfinite_done_and_stays_ready` |
| Health (E3) | `EngineHealth` / `health()`; `ApiRouter` takes an optional `EngineStateProvider` and `/health` returns `{"status":"ok"|"unavailable","engine":"<state>"}` with the state one of four fixed literals (anything else fails closed). `starting` → `200` with `engine=starting` (READY is consumed on the first request; eager READY is SP2), `ready`/`generating` → `200`, `failed` or a stopped child → `503`. The server samples the child and protocol state once per request and derives both fields from that snapshot. No secrets or paths. | `health_reflects_protocol_state`, `health_is_failed_after_engine_closed_mid_generation`, `health_is_failed_when_engine_closes_before_ready`, `health_includes_engine_state_when_provided`, `health_is_503_with_engine_state_when_unavailable`, `health_samples_status_before_state_once_each` |
| Protocol limits (E4, D4) | Limits derived from `READY`: `max_line_bytes = 0` means `min(32 + 11 × ctx, 16 MiB kProtocolMaxLineBytes)` for the outbound `GEN` line; inbound records capped at `kMaxReadLineBytes = 8192`; `kMaxWriteLineBytes = kProtocolMaxLineBytes`. The engine's `+8` context rule is applied before `GEN` (`400`). Facts in `docs/security/engine-protocol-limits.md`. | `gen_line_fits_max_prompt_tokens`, `chat_applies_engine_context_rule_with_eight_token_margin`, 100 KB `GEN` write in `engine_stdio_process_tests`, 16 MiB clamp case in `engine_protocol_client_tests` |
| POSIX launch (P1–P3) | `src/posix_child_launch.hpp`: argv/env built before `fork`, `pipe2(O_CLOEXEC)`, descriptor sweep (`close_range`, bounded fallback), reap after `SIGKILL`. | `child_inherits_only_stdio_descriptors`, `child_receives_exact_argv_and_env`, `terminate_reaps_killed_child` (asserts pid `-1` and `ECHILD`) |
| Windows launch (P4, P6, P7) | `CREATE_SUSPENDED` → Job Object → `ResumeThread`. Iterative bounded `read_line` shared with POSIX through `take_pending_line()`. Stdin pipe created with `CreateNamedPipeW`, buffer **requested** at `kMaxWriteLineBytes + 4096` (advisory per Win32; overlapped writes deferred to SP2). `engine_stdio_process_tests` is now portable. `read_line` keeps one deadline across chunks (POSIX polls with the remaining budget) and treats `WAIT_FAILED` as a failure on Windows. | `read_line_rejects_oversize_on_all_platforms`, `read_line_waits_for_a_record_split_across_writes` (both pass under wine); P4: `job_object_terminates_grandchild` (Windows only: the fake engine spawns a 30 s sleeper grandchild, which must be gone after `terminate()`; passes under wine, authoritative only in the MSYS2 job). |
| Engine arguments (M1, M2) | `secure_frontend_engine_arguments` library, profile-aware (`EngineArgumentsProfile`). Strata profile: the frontend supplies shard 1 by appending `--native <models_root/artifact>` (last) from the inventory entry for `--model-id` and rejects `--native`, `--serve`, `--batch`, `--slots`, `--vision` in `--flag` and `--flag=value` forms; the expert pack (`--pack`, loaded unconditionally, default cwd-relative `pack/full`) and other weight sources (`--ple-gguf`, `--embd-gguf`, `--native-head-gguf`, `--native-dense-gguf`, `--mtp`) pass through and are operator-supplied until SP1/SP5 model the whole launch. An invalid manifest artifact path (`../x.gguf`, `/abs.gguf`) is `invalid_value`. GLM-5.3 profile: arguments pass through (only NUL and `--serve` rejected), no model path is supplied; `strata-secure-server --profile glm53` requires at least one `--engine-arg`. | `engine_receives_model_path_from_inventory`, `engine_args_reject_owned_and_network_flags`, `strata_profile_passes_pack_and_weight_flags_through`, `rejects_invalid_relative_artifact_path`, `glm_profile_passes_arguments_through_without_native`, ctest `strata_secure_server_glm_requires_engine_arg` |
| CI (T6) | `.github/workflows/secure-frontend.yml`: blocking `linux-gcc` (+ `pytest -q`), `linux-clang`, `windows-llvm-mingw-cross`, `windows-msys2-clang`, `top-level-integration` (root CMake, `STRATA_NATIVE_EXPERTS=OFF`, no llama.cpp clone); non-blocking `windows-msvc`. Green on run `38458255140` (all blocking jobs; `windows-msys2-clang` 19/19). `windows-msys2-clang` links with `-static` (preset) so a child launched with the allowlisted environment, which has no `PATH`, needs no runtime DLL. See [`secure-frontend-ci.md`](secure-frontend-ci.md). |
| Docs (D1–D4) | `secure_frontend/README.md` build section and current behavior; `token_reader.hpp` comment describes the Windows checks that run, unreachable `protected_file_unsupported_on_platform` removed; this handoff; `secure-frontend-ci.md`; `engine-protocol-limits.md`. | Builds and tests re-run after the header change (below). |

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
   informational `windows-msvc`. **CI has not run yet.**
3. Generate an SBOM and release manifest listing exact engine/dependency
   revisions and enabled network-capable components. **SP7.**
4. Run the full security/privacy matrix, dependency scan, and an independent
   review before claiming a hardened release. **SP7**, including the offline
   GPU validation kit for the Linux and Windows test boxes.
5. Stage only the native deliverables, then run
   `python3 scripts/secure_distribution_check.py --package-dir STAGE --release`.
   The repository source tree intentionally fails this gate because it retains
   quarantined upstream files for provenance; do not weaken the gate to make a
   source archive pass. **SP7.**

## Verification performed

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
- `pytest serve` (the upstream service suite) was not run for SP0; nothing in
  `serve/` changed.

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

The Python GLM tokenizer module also runs under `pytest -q` above
(`tools/test_glm_tokenizer.py`, with the pinned `regex` from the venv). The two
skips are hardware/platform skips in upstream tests
(`tools/test_dll_closure.py`: HIP zip absent; `tools/test_setup_oldcpu.py`:
Windows only). Run `tools/test_glm_tokenizer.py` again in the release Python
environment before accepting a GLM tokenizer release.

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

## Collaboration and change rules

- Keep security changes small and add a regression test before the fix.
- Do not modify upstream engine/model code while developing the frontend unless
  a compatibility defect proves it necessary; record every such change in
  `docs/PROVENANCE.md`. Upstream-owned files outside the allowlist in the owner
  decisions are not touched at all.
- Do not copy UnbiasedStrata code without recording source, revision, license,
  rationale, and Windows/Linux test coverage.
- Do not enable MCP, tools, plugins, arbitrary command execution, telemetry,
  update checks, or automatic downloads. Those require a new threat-model
  review and an explicit user decision.
- Gates before every hand-off and after every upstream merge: `pytest -q`;
  `ctest --preset linux-gcc`; the `windows-llvm-mingw-cross` build; after an
  upstream merge also `pytest serve`.
- Commit locally; the owner pushes.
- Before handing off, update this document's **What has changed** and
  **Verification performed** sections, then report `git status --short`.

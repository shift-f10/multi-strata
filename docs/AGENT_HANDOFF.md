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

## Current baseline

- Upstream baseline: `Niko1221/Strata` tag `v0.1.43`, checked-out commit
  `7695859aa13afb248bdb4d36f9b2e95707db079d`.
- Git remote: `upstream` points at `https://github.com/Niko1221/Strata.git`.
- UnbiasedStrata reference: commit
  `46c46ecfc11d2315512f21f7549b0a7792ccd2ae`; no code has been copied from it.
- GLM-5.3 reference: `lighttransport/Strata` branch `glm53f`, commit
  `4894c9967f5754a2052d7b05f10a01b6071bb6e4`; the fixed native serving profile
  and Python `glm4`/`chatglm-bpe` tokenizer handling were implemented against
  its observable contracts. The separate GLM engine, CUDA/HIP kernels, and
  remote tensor-parallel worker are not yet ported.
- Supported target platforms: native Windows 10/11 and Linux. The intended
  compatibility target is every upstream-supported model profile, model
  quantization, vision option, context option, GPU backend, and multi-GPU
  configuration. Do not silently reduce that scope to one model or NVIDIA.

## What has changed in this working tree

The following files are new or edited and remain uncommitted deliberately:

| Area | Files | Status |
| --- | --- | --- |
| Provenance | `docs/PROVENANCE.md` | Complete baseline/attribution record. |
| Security/privacy contract | `docs/security/threat-model.md`, `tests/security/README.md`, `docs/security/privacy-migration.md`, `docs/security/deployment.md` | Complete specification, legacy-network inventory, platform deployment prerequisites, and package-readiness procedure; acceptance tests are not fully implemented yet. |
| Secure package gate | `scripts/secure_distribution_check.py` | Checks a selected staging directory (never this source tree) for quarantined Python installer/service/MCP/update artifacts and symlinks; `--release` additionally requires a privacy declaration manifest and SBOM. |
| Native frontend foundation | `secure_frontend/` | C++20 configuration, secret/token-reader, HTTP policy/request-handler/socket adapter, API router, local model inventory, and process-supervision libraries with unit tests. |
| GLM tokenizer tooling | `tools/strata_tokenizer.py`, `tools/test_glm_tokenizer.py` | Offline `glm4` / `chatglm-bpe` byte-BPE pre-tokenizer support, including GLM's 1--3 digit boundary and emitted pack metadata. Python runtime verification requires the pinned third-party `regex` package, unavailable in this sandbox. |
| Portable CI | `secure_frontend/CMakePresets.json`, `.github/workflows/secure-frontend.yml` | Linux GCC/Clang and Windows MSVC matrix; not run from this host. |
| Runnable smoke executable | `secure-frontend-smoke`, `strata-secure-smoke-server` | Authenticated local `/health` and `/v1/models`; no engine inference. |
| Native serial chat executable | `strata-secure-server` | Starts one supervised local `--serve` engine child and offers authenticated text-only, non-streaming Qwen or explicitly selected GLM-5.3 `/v1/chat/completions` plus health/models. It is intentionally not a claim of universal upstream model/template/vision compatibility. |
| GLM tokenizer tooling | `tools/strata_tokenizer.py`, `tools/test_glm_tokenizer.py` | Recognizes the `glm4` and `chatglm-bpe` pre-tokenizer aliases and preserves GLM's 1–3-digit segmentation; secure_frontend does not yet consume tokenizer-pack metadata, so native GLM execution still needs matching-pack validation. |
| Top-level integration | `CMakeLists.txt` | Builds `secure_frontend` through `STRATA_BUILD_SECURE_FRONTEND=ON`. |

The native frontend currently enforces several in-process security boundaries:
configuration validation, secret-source metadata, Linux/Windows protected-file token
reading, exact Host/Origin/CORS policy, bounded HTTP request parsing plus bearer
authentication, portable child-process supervision, and a serial native Qwen
text-chat route. It can start a local listener in a permitted runtime, but this
sandbox prohibits socket binds. It does **not** download artifacts, package a
secure release, implement every upstream serving profile, or replace the
upstream Python service in a release. Therefore the repository must not yet be
described as privacy-hardened or as having removed upstream network-capable
behavior.

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
  protected private DACL. It remains fail-closed pending MSVC/Windows runtime
  validation.
- `EngineProcess` and `EngineStdioProcess` start a child without a shell or
  inherited environment,
  rejects embedded NUL truncation in executable/argv/env values, supervises a
  POSIX process group, and has a Windows `CreateProcessW`/Job Object path. It
  connects to the documented Strata `--serve` line protocol using bounded
  private standard-I/O pipes.
- `HttpRequestHandler` is bounded in-memory HTTP/1.1 parsing with Host/Origin
  policy, bearer validation, strict CORS/preflight behavior, and a synchronous,
  bounded request-body dispatcher seam.
- `HttpSocketServer` binds only a revalidated numeric configured address, reads
  one bounded request, and passes it to the request gate. Linux runtime binding
  is blocked by this sandbox, so it needs CI validation.
- `ApiRouter` implements authenticated `GET /health` and `GET /v1/models` over
  immutable injected providers. `ModelInventory` discovers local `.gguf`
  artifacts only; it has no download, subprocess, or network behavior.
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

The only permitted future network operation is a separately invoked,
foreground `acquire` command. It must use a user-visible, digest-pinned HTTPS
manifest and cannot be triggered by an API request, model content, plugin, or
automatic updater. See the threat model for the full rules.

## Ordered implementation backlog

### Phase 1 — native security primitives

1. Extend `secure_frontend` with immutable typed configuration for request
   time/concurrency limits and roots for models/logs/cache.
2. Add canonical-path validation for Linux and Windows, including reparse
   points, UNC/device/ADS forms, and traversal prevention.
3. Add secure token generation/storage: CSPRNG; DPAPI-backed file on Windows;
   user-only permissions on Linux. Tokens must never reach log output,
   environment, child command lines, or metrics.
4. Implement all relevant `CFG-*` and `AUTH-*` tests from
   `tests/security/README.md` before connecting these primitives to a server.

### Phase 2 — portable child supervision

1. Define a testable `EngineProcess` abstraction and a fake engine fixture. **Done.**
2. Implement the Windows and Linux backends described above. **Implemented; Windows requires CI runtime validation.**
3. Add the remaining `PROC-01` through `PROC-06`, including fake-child crash/hang, inherited
   handle/descriptor inspection, and descendant cleanup tests.
4. Connect the abstraction to the actual 0.1.43 engine. **Done for the
   documented serial `--serve` protocol; full profile coverage remains open.**

### Phase 3 — private API boundary

1. Implement authenticated `/health`, `/v1/models`, and
   `/v1/chat/completions` with bounded HTTP/JSON parsing and streaming.
   **The non-streaming text-only Qwen and explicitly selected GLM-5.3 subsets
   are implemented; streaming and other profiles remain open.**
2. Enforce exact Host, Origin, and CORS policies; CORS is off by default.
   **Health/models/chat routing and engine state are connected for the narrow
   serial profile; add chat streaming only after a separate review.**
3. Add all `NET-*`, `WEB-*`, and `DOS-*` tests on Windows and Linux.
4. Differential-test supported request/response behavior against the upstream
   service. Preserve model and backend flexibility; reject only unsafe API
   behavior.

### Phase 4 — verified, explicit artifact acquisition

1. Implement an offline-by-default model inventory and local-file validation.
2. Implement the explicit `acquire` command with HTTPS-only sources, byte
   limits, SHA-256 verification, temporary staging, and atomic publish.
3. Add `DL-*` tests using only local fixture servers. Never make tests fetch
   public model files.

### Phase 5 — compatibility, packaging, and release

1. Port all upstream model profiles, quantizations, vision/MTP paths,
   multi-GPU, CUDA, HIP, and experimental SYCL behavior one capability at a
   time with regression coverage.
2. Add CMake presets and CI for Windows/MSVC and Linux/GCC-or-Clang.
3. Generate an SBOM and release manifest listing exact engine/dependency
   revisions and enabled network-capable components.
4. Run the full security/privacy matrix, dependency scan, and an independent
   review before claiming a hardened release.
5. Stage only the native deliverables, then run
   `python3 scripts/secure_distribution_check.py --package-dir STAGE --release`.
   The repository source tree intentionally fails this gate because it retains
   quarantined upstream files for provenance; do not weaken the gate to make a
   source archive pass.

## Verification performed so far

The secure frontend tests were compiled and passed on Linux with strict
compiler warnings:

```sh
g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror ...
```

Passed binaries:

- `secure_frontend_config_tests`
- `secure_frontend_secret_source_tests`
- `secure_frontend_token_reader_tests`
- `secure_frontend_http_policy_tests`
- `secure_frontend_http_request_handler_tests`
- `secure_frontend_engine_process_tests`
- `secure_frontend_engine_protocol_client_tests`
- `secure_frontend_engine_stdio_process_tests`
- `secure_frontend_model_inventory_tests`
- `secure_frontend_chat_schema_tests`
- `secure_frontend_tokenizer_pack_tests`
- `secure_frontend_qwen_prompt_renderer_tests`
- `secure_frontend_glm_profile_tests`
- `secure_frontend_chat_generation_plan_tests`
- `secure_frontend_chat_execution_tests`
- strict standalone builds of `secure-frontend-smoke`,
  `strata-secure-smoke-server`, and `strata-secure-server`

The socket-server test compiles but cannot complete in this sandbox because
the runtime denies a loopback bind (`Operation not permitted`). The same path
must run in Linux CI and on Windows before release.

`cmake` and `ninja` are not installed in this execution environment, so the
CMake/CTest path has not yet run here. A successor should run:

```sh
cmake -S . -B build -DSTRATA_BUILD_SECURE_FRONTEND=ON -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Then repeat on Windows using an MSVC developer environment. Do not mistake the
Linux direct-compiler result for cross-platform validation.

The new Python GLM tokenizer test module passed locally after installing the
repository-pinned `regex==2026.9.10` dependency:

```sh
python3 -m unittest tools/test_glm_tokenizer.py
```

Run it again in the project Python environment before accepting a GLM tokenizer
release.

## Collaboration and change rules

- Keep security changes small and add a regression test before the fix.
- Do not modify upstream engine/model code while developing the frontend unless
  a compatibility defect proves it necessary; record every such change in
  `docs/PROVENANCE.md`.
- Do not copy UnbiasedStrata code without recording source, revision, license,
  rationale, and Windows/Linux test coverage.
- Do not enable MCP, tools, plugins, arbitrary command execution, telemetry,
  update checks, or automatic downloads. Those require a new threat-model
  review and an explicit user decision.
- Before handing off, update this document's **What has changed** and
  **Verification performed** sections, then report `git status --short`.

# Portable frontend threat model

## Status and scope

This document defines the release gate for the Strata-compatible portable
frontend. It applies to the code that starts and supervises the inference
engine, exposes HTTP APIs, reads configuration, and acquires model artifacts on
Windows and Linux. It does **not** change the upstream inference engine or make
claims about the safety of untrusted model weights.

The default deployment is one user running a local service on a workstation.
Remote or shared-network operation is a deliberate opt-in and has a separate
acceptance gate below.

## Assets and trust boundaries

Assets requiring protection:

- API tokens and credentials supplied to the process.
- Prompts, responses, uploaded images, model-selection data, and usage data.
- The host filesystem, including model directories and configuration files.
- GPU/CPU, memory, and the availability of the local inference service.
- Integrity of executable, engine, and model artifacts.
- Requests from clients, browsers, LAN peers, and child-process output.

Trust boundaries:

1. HTTP clients and browser-originated requests are untrusted.
2. Config files, environment variables, CLI values, and model manifests are
   untrusted input until validated.
3. Download servers and downloaded bytes are untrusted until their expected
   digest is verified.
4. The inference engine is a child process with a constrained, explicit
   argument and environment contract.
5. A model file is data, not executable code; loading untrusted weights is not
   a security boundary and must be disclosed to the operator.

## Security contract

### Network and authentication

- Default bind addresses are loopback only (`127.0.0.1` and `::1` where
  available). Wildcard, LAN, and public binding require an explicit
  `--listen`/configuration opt-in.
- Wildcard addresses (`0.0.0.0` and `::`) require a second, distinct opt-in;
  selecting a remote listener alone must never expose every interface.
- Every API route, including health and model discovery, requires a non-empty
  bearer token by default. A token must be generated with a cryptographically
  secure RNG, never logged, and compared in constant time.
- An unauthenticated mode is permitted only with an explicit development-only
  switch; it must refuse non-loopback binds and emit a high-severity warning.
- Rate/size/concurrency limits are configured with safe finite defaults.
  Streaming requests must be cancellable on client disconnect and shutdown.

### Privacy and offline operation

- The distributed binary has no analytics, telemetry, crash-report upload,
  update check, remote configuration, advertising, or usage-reporting client.
  It must not contact an external service during installation, startup,
  inference, shutdown, or failure handling.
- Prompts, completions, images, API metadata, and local model information stay
  on the operator's machine. Request logging is disabled by default; any
  operator-enabled diagnostic log must redact credentials and use a bounded,
  documented local retention policy.
- The networked operations are the explicit, foreground `strata pull` (acquire),
  `strata update`, and — only for a model that is not installed and only after
  the same confirmation — `strata run`. Each runs only after the operator
  confirms the manifest-pinned hosts and digests it displays. `strata import`,
  `export` and `verify` are local. None can be invoked by the HTTP API, a model,
  a plugin, configuration or automatic logic.
- Privacy-relevant behavior is build-time auditable: the release manifest lists
  enabled network-capable components, and CI tests prove that a normal service
  lifecycle makes no outbound network connection.

### Browser and HTTP boundary

- Reject `Host` headers not matching the configured loopback host/port or an
  explicit allowlist. Reject ambiguous, malformed, duplicate, or control-byte
  host values.
- Reject browser `Origin` values unless the origin is same-origin or exactly in
  an explicit allowlist. Missing `Origin` is allowed for non-browser API
  clients after token authentication.
- CORS is disabled by default: no `Access-Control-Allow-Origin` header is
  emitted. When configured, emit only exact allowed origins; never reflect an
  arbitrary origin and never combine `*` with credentials.
- State-changing routes reject cross-origin browser requests even if a token is
  present, unless the origin is explicitly trusted. Preflight responses are
  restricted to allowed methods/headers and do not disclose credentials.
- Parse HTTP and JSON with bounded headers, body size, nesting, request time,
  and streaming buffer limits. Return generic client errors; details belong in
  protected server logs.
- (SP3) Authentication happens when the header is complete, before any body
  byte: an unauthenticated client never has a body read and can hold a worker
  only in the header phase (`limits.http.header_deadline_ms`, oldest-first
  eviction of the connection longest in that phase). Bodies are read only from
  token holders.
- (SP3) One accept thread plus a fixed worker pool (`max_concurrent_requests`,
  default 8) with a per-address cap for non-loopback peers; over-admission and
  an over-full generation queue (`max_queued_generations`, default 4) get one
  fixed 503 `server_busy` + `Retry-After: 1` read through a lingering close
  (never an RST the client's stack could cache as an attack signature).
- (SP3) Every error body and the optional per-request log line are fixed
  literals — never a token, prompt, configured path or client payload
  (`err_no_token_prompt_or_path_in_any_body_or_log`).
- (SP3 M2) Streaming responses are SSE under HTTP/1.1 chunked framing. A stream
  cut before its end carries neither the terminal chunk nor `data: [DONE]`: the
  truncation is visible to SDKs and to `curl -N` rather than silently accepted,
  and `[DONE]` is never a success marker — an in-stream error event is followed
  by `[DONE]` after the text already sent has been flushed
  (`stream_cut_has_no_terminal_chunk`, `err_mid_stream_is_error_event_then_done`).
- (SP3 M2) No bytes while queued (R6): a request waiting on the generation slot
  has written nothing to its socket, and a full queue is refused with a plain
  503 `server_busy` before any SSE header (`dos02_queue_full_with_streams_is_503_before_headers`).
- (SP3 M2) Slow-reader bound: a non-reading client never backpressures the
  engine (the pump reads at engine speed); unread decoded text is bounded per
  streaming worker by `limits.chat.max_generated_bytes` plus one pending SSE
  event of at most 128 KiB in the socket sink, and after
  `limits.http.write_stall_ms` without progress the stream is cancelled with
  `STOP` (`dos02_slow_reader_never_backpressures_engine`,
  `dos02_slow_stream_reader_hits_write_stall`).
- (SP3 M2) R4's real numbers are only measurable on the owner's GPU boxes:
  `docs/validation/sp3-api-kit.md` with the `cancel-during-prefill` probe mode
  is a release-record step, not a CI proof (see R4 under residual risks).
- (SP5 M1) Image input exists only for a vision-capable model (`vision.enabled`
  plus the manifest `mmproj` artifact): the OpenAI content-parts grammar opens
  only for that model, an image URL must be a `data:` URL — an http(s) image
  URL is refused by name and never fetched, so no image path reaches any
  resolver or socket — and every cap (images per request, base64 length, 32 MiB
  decoded, the side-length probe) is answered before any scratch file is
  written; the refusal is the fixed 400 naming `image_url`.

### Configuration and filesystem

- Configuration is schema-validated before start. Unknown keys are errors;
  security-sensitive values cannot be silently ignored or coerced.
- Paths are converted to canonical/absolute paths and must remain below an
  explicitly configured root after symlink/reparse-point resolution. Traversal,
  NUL/control characters, device paths, and paths outside the root are rejected.
- On Windows, apply the same policy to drive-relative, UNC, extended-length,
  alternate-data-stream, and junction/reparse-point paths. On Linux, cover
  symlinks, bind mounts where observable, and `/proc`/device paths.
- Secrets come from a protected file or environment at startup and are never
  copied into logs, command lines, telemetry, crash reports, or child arguments.
  A Windows implementation may use DPAPI for at-rest local token storage.
- Long-lived parsed configuration stores only secret-source metadata and
  validation state, never a plaintext API token. The authentication component
  owns its short-lived secret representation.
- The service creates data files with user-only permissions where the platform
  supports them and rejects configuration files writable by untrusted users.
- (SP5 M1) Upstream-style environment configuration knobs (`STRATA_*`,
  `MAYA_*`) never configure the frontend — the typed config file is the only
  source — and `strata doctor` warns when such variables sit in the
  environment, so a user who expects the pinned server's behaviour sees that
  they are ignored.
- (SP5 M1) `strata serve` is foreground-only: it never daemonizes and never
  writes a lifecycle file (no pidfile, no `server.json`, no lock). The pin has
  none of these, and our lifecycle writer has never existed.
- (SP5 M1) Vision staging and encoded scratch files are 0600 regular files
  under `<state_dir>/vision` (0700), and every request deletes its own files
  when its generation ends, by success or failure. The pin's
  `session.keep_files` LRU has no consumer in M1 (recorded gap); the
  per-request cleanup bounds what the directory holds. Boot with
  `vision.enabled` fails when the state path contains whitespace — the
  encoder's positional argv cannot carry it safely (pin issue #480).

### Artifact acquisition

- Runtime networking is off by default. No model, executable, dependency, or
  plugin is downloaded implicitly on startup or request handling.
- An explicit acquire command accepts a manifest containing HTTPS source,
  artifact name/version, byte limit, and SHA-256 digest. The artifact is written
  to a temporary file, size-checked, hashed, then atomically moved into the
  configured model root.
- Redirects must remain HTTPS and obey an allowlist/policy. Archive extraction,
  if introduced, must defend against traversal, links, decompression bombs, and
  unexpected file types. Initial releases should distribute verified files, not
  arbitrary archives.
- Build dependencies and release artifacts are pinned, provenance recorded, and
  accompanied by an SBOM. Verification failure leaves no accepted artifact.
- Every file is SHA-256-pinned by a manifest that is compiled into the release
  or pinned by an operator-typed digest; redirects are followed only by the
  frontend, only over HTTPS and only to hosts the manifest names. The
  downloader runs confined (on Linux with Landlock: no file writes and reads
  only below system directories; on Windows: Low integrity, which blocks writes
  but not reads of the user's files). Confinement limits but does not remove
  what a compromised downloader can do: it can open network connections to any
  host, including LAN and loopback services (Landlock restricts only ports and
  only from ABI 4; Low integrity restricts no network), read and send the
  user's files on Windows, and on Linux change modes, owners and timestamps and
  — below Landlock ABI 3 — truncate files. Digest verification still prevents
  it from planting a model.

### Engine process isolation

- The frontend starts the engine without a shell. It passes a fixed executable
  path and an argument vector built from validated typed values; user strings
  never form shell syntax.
- The child gets a fixed, frontend-rendered environment and nothing from the
  parent: POSIX `PATH=/usr/bin:/bin`, `LD_LIBRARY_PATH` (the engine library
  directories), `TMPDIR`, `CUDA_CACHE_PATH`; Windows `PATH`, `TEMP`, `TMP`,
  `CUDA_CACHE_PATH`, `SystemRoot`, `WINDIR`, `SystemDrive`,
  `NUMBER_OF_PROCESSORS`. The renderer also supports optional
  `STRATA_HIPBLASLT_TUNING`, `STRATA_WATCHDOG_S` and `STRATA_WATCHDOG_IO_S`
  rows, but no configuration key sets them yet. Never the token variable,
  `STRATA_API_KEY` or other `STRATA_*`, `LD_PRELOAD`, `LD_AUDIT`,
  `CUDA_LAUNCH_BLOCKING`, `HOME`/`USERPROFILE`/`APPDATA`, proxies, or
  GPU-selection variables (strata family: GPUs are the typed `--gpu` argv; the
  SP6 `glm` family will render `CUDA_DEVICE_ORDER`/`CUDA_VISIBLE_DEVICES` from
  typed configuration, a mechanism that no configuration reaches today). Not
  yet verified with a real CUDA/ROCm engine. The child inherits no listening
  socket, credential descriptor/handle or token. On POSIX it starts with
  default signal dispositions and an empty signal mask; on both platforms its
  cwd is `<state_dir>/engine`; on Linux `PR_SET_NO_NEW_PRIVS` is set by default
  (`engine.allow_new_privileges` turns it off for a GPU stack that needs it).
  Its stdout is the bounded strict protocol pipe; stderr is discarded to the
  platform null device so diagnostics cannot corrupt protocol framing or leak
  prompts into logs.
- The child is reached only by private stdio in the current profile; clients
  never receive an engine address. Any future private loopback/IPC bridge must
  be authenticated and blocked from non-frontend peers.
- PROC-03 on Linux means "other user context": another uid cannot open the
  engine's stdio (`proc03_other_uid_cannot_open_engine_fd`; it runs only in CI,
  which has not yet run SP2 — pending rflores's push). The
  **same** uid can reopen the engine's stdin through `/proc/<pid>/fd/0` and
  inject protocol lines; the upstream engine cannot be made non-dumpable after
  exec and its protocol carries no nonce without engine changes. This is an
  **accepted risk** for SP2 and must appear in the release record
  (`proc03_same_uid_reopen_is_accepted_risk` pins today's behavior). On Windows
  the stdin pipe is owner-only, single-instance and client-verified (N6, R1)
  (implemented; authoritative in the MSYS2 CI job — pending rflores's push).
- Windows uses restricted handle inheritance plus a Job Object so all child
  processes terminate with the service. Linux uses close-on-exec descriptors
  plus a descriptor sweep before `execve`; the listening and accepted sockets
  are not close-on-exec (no `SOCK_CLOEXEC`), so the sweep is what closes them
  in the engine child (the fallback sweep's 65536 cap is a recorded gap,
  `docs/AGENT_HANDOFF.md`, Known small gaps), a dedicated process group, and
  reliable `waitpid`/signal cleanup. A single supervisor thread owns the
  engine: it restarts a failed engine after 1 s, 2 s, … (at most 60 s), opens
  a circuit on the third consecutive failure (closed only by restarting the
  frontend), and resets the count after 300 s of healthy running. Because an
  `ERR` answer leaves the generation unusable, three requests in a row whose
  input makes the engine answer `ERR` open the circuit until the frontend is
  restarted; this is accepted (Review Focus 6,
  `proc04_client_err_lines_open_circuit_until_restart`). A drain failure after
  a client-requested `STOP` (SP3) restarts the engine without counting, at most
  3 times in a row with no `DONE` in between; after that it counts. Linux
  cleanup is process-group SIGKILL, a child-subreaper sweep after every reaped
  generation, `PR_SET_PDEATHSIG`, and `cgroup.kill` when a delegated cgroup v2
  is detected (the delegated path is verified by reading only, not run).
  **Residual risk (PROC-05):** a frontend killed with SIGKILL on Linux takes
  the engine leader with it (`PR_SET_PDEATHSIG`), but the engine's own
  descendants survive. Without a delegated cgroup nothing reaches them; with
  one they stay in the generation's cgroup until the operator's scope is
  killed, because nothing writes `cgroup.kill` once the frontend is dead. The
  upstream engine is not known to spawn any. This must appear in the release
  record.
- Privilege elevation is forbidden. The service and child run as the invoking
  user (or a documented dedicated low-privilege account); writable roots are
  narrowly scoped. The frontend refuses to start as root or with an elevated
  Windows token; an engine that requires elevation is a spawn failure and is
  never started via `runas` (G3 is verified only on a non-elevated Windows
  prompt, a validation-kit step; CI runners are elevated).
- (SP5 M1) The vision encoder is a second supervised child (`strata-vision`, a
  sibling of the engine executable): the same fixed environment allowlist, cwd
  `<state_dir>/vision`, private stdio only, READY/ENC/QUIT role protocol with
  typed ready/encode timeouts, and a resident encoder that fails the boot if it
  cannot reach READY. **Recorded gap:** in M1 the encoder role receives no
  per-generation cgroup delegation (the PROC-05 residual above applies to it
  too, one role smaller). Lifecycle timers are typed frontend decisions —
  `engine.lazy_load` defers the engine start, `engine.idle_unload_s` reaps an
  idle engine child, the MTP rows compose argv — they hand no control to the
  engine.

### Extensions and MCP

- MCP, tool execution, arbitrary plugins, and remote command execution are
  disabled and absent from the default build/runtime configuration.
- Enabling an extension requires a future, separately reviewed capability model;
  it cannot be enabled through a model manifest, HTTP request, or unrecognized
  configuration key.

## Out of scope and residual risks

- A valid token grants the API permissions implemented by the service. Operators
  must treat it as a password.
- Local users with the same OS account can generally read that account's files
  and are outside this service's isolation boundary.
- Model outputs can be harmful or unreliable. Prompt injection is not solved by
  transport security; the initial release has no tool execution surface.
- GPU drivers, inference libraries, and upstream engine vulnerabilities remain
  supply-chain and patch-management risks. Releases must document versions and
  security updates.
- **Decision 12 residual (accepted, SP3 B12):** loopback peers are exempt from
  the per-address cap; another local user's connection flood can cause
  eviction churn that delays a local client's header by up to its own send
  time, and an authenticated local client can occupy every worker. A token
  holder is trusted with the API's capacity.
- **R4 (SP3):** a client that disconnects during a long real prefill may make
  `STOP` miss `limits.engine.stop_drain_timeout_s`; SP2 then kills the engine
  and counts a failure, so three such disconnects within 300 s can open the
  circuit. Mitigation: SP2 follow-up D-2 (a client-requested `STOP` drain
  failure does not count; bounded at 3 uncounted restarts in a row); GPU-box
  measurement (M2 kit); the operator may raise the drain timeout.
- **R5 (SP3):** SDK retries amplify engine errors; `engine_error` carries
  `x-should-retry: false`, clients that ignore it remain a residual risk.
- **R8 (SP3) — egress checks are tripwires, not proofs:** the import check
  misses `dlopen`/`GetProcAddress` and raw syscalls; the `LD_PRELOAD`
  interposer misses raw `syscall(2)` and static binaries (which the import
  check then fails on); the 50 ms connection-table scan misses sockets that
  live less than 50 ms, and on Windows it is the only runtime check.
  Whole-machine monitoring is the SP7 validation-kit part of `PRIV-01`.

## Release decision

No release may claim the portable frontend is security-hardened unless every
MUST test in `tests/security/README.md` passes on supported Windows and Linux
targets, dependencies have been scanned, and a reviewer has assessed changes
to this document or the security boundary.

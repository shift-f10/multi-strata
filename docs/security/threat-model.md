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
- The sole future networked operation is an explicit, foreground `acquire`
  command initiated by the operator. It must display its source and expected
  digest before transfer and cannot be invoked by the HTTP API, a model, a
  plugin, or automatic update logic.
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

### Engine process isolation

- The frontend starts the engine without a shell. It passes a fixed executable
  path and an argument vector built from validated typed values; user strings
  never form shell syntax.
- The child inherits an empty environment allowlist and no listening socket,
  credential file descriptor/handle, or token. Its stdout is the bounded strict
  protocol pipe; stderr is discarded to the platform null device in the
  privacy-preserving profile so diagnostics cannot corrupt protocol framing or
  leak prompts into logs.
- The child is reached only by private stdio in the current profile; clients
  never receive an engine address. Any future private loopback/IPC bridge must
  be authenticated and blocked from non-frontend peers.
- PROC-03 on Linux means "other user context": another uid cannot open the
  engine's stdio (`proc03_other_uid_cannot_open_engine_fd`, run in CI). The
  **same** uid can reopen the engine's stdin through `/proc/<pid>/fd/0` and
  inject protocol lines; the upstream engine cannot be made non-dumpable after
  exec and its protocol carries no nonce without engine changes. This is an
  **accepted risk** for SP2 and must appear in the release record
  (`proc03_same_uid_reopen_is_accepted_risk` pins today's behavior). On Windows
  the stdin pipe is owner-only, single-instance and client-verified (N6, R1).
- Windows uses restricted handle inheritance plus a Job Object so all child
  processes terminate with the service. Linux uses close-on-exec descriptors,
  a dedicated process group, and reliable `waitpid`/signal cleanup. Restart
  loops are bounded with backoff.
- Privilege elevation is forbidden. The service and child run as the invoking
  user (or a documented dedicated low-privilege account); writable roots are
  narrowly scoped.

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

## Release decision

No release may claim the portable frontend is security-hardened unless every
MUST test in `tests/security/README.md` passes on supported Windows and Linux
targets, dependencies have been scanned, and a reviewer has assessed changes
to this document or the security boundary.

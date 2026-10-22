# Secure frontend scaffold

This is a dependency-free C++20 foundation for the portable Strata frontend.
It currently provides configuration validation, secret-source metadata,
protected-file token reading on Linux and Windows, exact Host/Origin/CORS policy checks, a
bounded in-memory HTTP request gate, and a portable engine-process supervisor.
It includes a deliberately limited socket-listener executable for smoke testing
and a native, serial inference listener. It does not connect to the legacy
service, download artifacts, or open outbound sockets.

## Token-source metadata

`SecretSource` represents only an explicit environment-variable name or a
protected-file path. It deliberately cannot contain a resolved API token, so
long-lived configuration never retains plaintext credentials.

`read_token()` resolves a source only when required and returns the token as
`SecretBytes` (wiped on destruction). On Linux it opens the file below the
canonical secret root with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV)`
(or an `openat(O_NOFOLLOW)` walk where `openat2` is unavailable) and accepts
only a current-user-owned regular file with no group/world permissions. On
Windows it opens every component with `READ_CONTROL` without following reparse
points, checks the final path stays beneath the root, and requires a
current-user-owned protected DACL; a `STRATAK1` file is unwrapped with DPAPI,
anything else is read as a plaintext token under the same rules. The token may
end in one LF or CRLF and must be at least 32 bytes. `secure_frontend_token_reader_tests`
now builds and runs on every platform; its Windows file cases carry the
`windows-runtime` label and are validated only by the `windows-msys2-clang` CI
job (CI run `38540719307`: `windows-msys2-clang` 193/193 on SP1, before
the SP2 merge).

## Security contract

- The default bind is the IPv4 loopback literal `127.0.0.1:8080`.
- Every listener requires a bearer token, including on loopback — with one
  owner-approved exception: `listener.loopback_without_key = true` (config file
  only; no flag, no environment variable) runs a loopback listener with no key.
  It is refused for a remote or wildcard bind, at load and again at bind, and
  refused next to a `token.source`; see "Built-in chat page and the keyless
  loopback mode" below. `init`
  generates it from the OS random generator (CSPRNG, base64url, 43
  characters). An operator-made token must be at least 32 bytes (at most 256);
  a token file may end in one LF or CRLF. Tokens are compared in a fixed
  256-byte window, so the comparison time does not reveal the length.
- Ports must be TCP ports in the inclusive range 1–65535.
- The listener address is classified from its bytes: it must be an IPv4/IPv6
  literal or `localhost` (ASCII case-insensitive), which maps to `127.0.0.1`
  without a resolver call. Every other hostname is rejected, never resolved.
  CIDR notation, bracketed IPv6 literals and whitespace are rejected.
- A non-loopback bind additionally requires `listener.allow_remote = true`
  (`--allow-remote`); it defaults to `false` and cannot be enabled implicitly
  by selecting a remote host.
- Wildcard binds (`0.0.0.0`, `::` and every other spelling of the unspecified
  address) additionally require `listener.allow_wildcard_bind = true`
  (`--allow-wildcard-bind`); a regular remote-listening opt-in is not enough.
  A wildcard listener also needs a non-empty `listener.host_aliases` (config
  file): those are the only `Host` values it accepts.
- The whole configuration is schema-validated before the listener binds or the
  engine starts; `--check` opens and inspects but never creates, writes,
  renames or deletes anything. The server binds before it spawns the engine.
- An environment token (`token.source = env:NAME`) is wiped and removed from
  the process environment after it is read (on Windows the CRT copies are
  wiped and the Win32 environment entry is removed). The server is
  non-dumpable with a zero core-file limit on Linux.
- Protected-file token sources are portable relative paths only; traversal,
  absolute/UNC/device/drive/ADS forms and Windows reserved device names are
  rejected before a platform reader resolves the path below its canonical root.
- HTTP messages are bounded, require exactly one trusted `Host`, reject
  untrusted or ambiguous browser `Origin`, keep CORS off by default, and require
  exactly one bearer token before reaching route dispatch.
- Since SP3 the server is concurrent: one accept thread plus
  `limits.concurrency.max_concurrent_requests` workers (default 8). Each
  connection gets a header deadline (`limits.http.header_deadline_ms`, 10 s)
  before authentication completes and a total request deadline
  (`limits.http.request_deadline_ms`, 30 s) with a body cap
  (`limits.http.max_request_bytes`, 64 KiB); chat bodies are capped at 49152
  bytes. Unauthenticated clients can hold a worker only in the header phase
  (oldest-P1 eviction); bodies are read only after the bearer token checks.
  Over-admission (per-remote cap `max_connections_per_remote_address`, derived
  min(4, workers), loopback exempt) and an over-full generation queue
  (`limits.concurrency.max_queued_generations`, derived default 4,
  `queue_timeout_ms` default 300 s) answer one fixed 503 `server_busy` +
  `Retry-After: 1` read through a lingering close. Response writes are bounded
  by the stall rule (`limits.http.write_stall_ms` 10 s measured on progress,
  `limits.http.response_write_deadline_ms` 60 s). `::` binds IPv6-only, and
  the listener stops only when the socket itself fails.
- Engine children are started directly without a shell, with a minimal
  allowlisted environment. Embedded NUL bytes in the executable path, argv, or
  environment are rejected before the platform process API can truncate them.
  On Linux, argv/env are built before `fork`, pipes are `O_CLOEXEC`, every
  descriptor above stdio is closed in the child, the child runs in its own
  process group, and a killed child is reaped. On Windows the child starts
  suspended, is assigned to a Job Object, and only then resumes.
- The engine protocol has a total generation deadline, recovers from a timed-out
  generation with `STOP` and a bounded drain (or marks the engine failed),
  sizes the outbound `GEN` cap from the engine's `READY` context, and reports
  its state through `/health` as `{"status":"ok"|"unavailable","engine":"<state>"}`:
  `starting` → `503` (since SP2 a supervisor thread reads READY as soon as
  the engine starts), `ready`/`generating` → `200`, `failed` → `503` with an
  optional `recovery` of `restarting` or `exhausted`. The supervisor restarts
  a failed engine with backoff and opens a circuit after three consecutive
  failures. The engine
  facts these limits rely on are in
  [`docs/security/engine-protocol-limits.md`](../docs/security/engine-protocol-limits.md).

## Build

No packages are fetched during CMake configuration or testing. On Linux, create
the tool environment once (no root needed). It installs `-r
scripts/dev/requirements-dev.txt` into `.venv-dev`: cmake, ninja, regex, pytest
and pytest's dependencies are pinned there. Offline use (`STRATA_WHEEL_DIR`
set) needs every wheel that file names **plus** a pip wheel (`pip-*.whl`): on a
fresh venv the pip bootstrap takes pip from `STRATA_WHEEL_DIR` as well.

```sh
scripts/dev/bootstrap-linux.sh                # from the repository root
export PATH=$PWD/.venv-dev/bin:$PATH
cd secure_frontend
cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc
```

`CMakePresets.json` has five presets:

| Preset | Where it runs |
| --- | --- |
| `linux-gcc` | Linux, GCC, Ninja |
| `linux-clang` | Linux, Clang, Ninja |
| `windows-llvm-mingw-cross` | Linux host, cross-compiles Windows x86_64 `.exe` files with llvm-mingw (`scripts/dev/bootstrap-llvm-mingw.sh` fetches the pinned, sha256-checked toolchain); `ctest` runs them under wine |
| `windows-msys2-clang` | Windows, MSYS2 CLANG64 clang |
| `windows-msvc` | Windows, Visual Studio 2022 (informational only) |

Warnings are errors by default (`SECURE_FRONTEND_WERROR`, which follows
`STRATA_WERROR` when the parent project sets it). The top-level Strata build
includes this directory only when configured with
`-DSTRATA_BUILD_SECURE_FRONTEND=ON` (default `OFF`). `ws2_32` is linked
automatically on Windows. See [`docs/secure-frontend-ci.md`](../docs/secure-frontend-ci.md)
for the CI jobs.

Windows binaries are cross-compiled with llvm-mingw and smoke-tested under
wine on Linux. wine does not implement Job Objects or protected-file DACLs
faithfully; Windows runtime behavior is validated only by the `windows-msys2-clang`
CI job on a real Windows runner. The `windows-msvc` job is informational.

Each test case is its own CTest test (`<binary>.<case>`). Cases that need real
Windows semantics (DACLs, junctions, DPAPI, Job Objects, private roots) carry
the label `windows-runtime`: the `windows-llvm-mingw-cross` test preset
excludes them under wine, and `windows-msys2-clang` runs everything. Every test
binary, including `secure_frontend_token_reader_tests`, is built on Windows;
the socket-server tests run on Windows too. `engine_process_tests` and `engine_stdio_process_tests` start and
terminate through the Job on MSYS2; the grandchild assertion
(`job_object_terminates_grandchild`) runs only there (wine passes it but is not
authoritative for Job Objects). Both Windows presets link with `-static`: the
engine launchers give the child only the allowlisted environment, with no
`PATH`, so a dynamically linked MSYS2 binary could not find its runtime DLLs
when it is started as an engine.

## Runnable smoke server

`secure-frontend-smoke` is a local, privacy-preserving test server. It serves
authenticated `GET /health` and `GET /v1/models` only; it does not start the
inference engine and intentionally does not implement chat completion yet.

```sh
export STRATA_SMOKE_API_KEY='choose-a-long-random-value-of-32-bytes-or-more'
./secure-frontend-smoke --api-key-env STRATA_SMOKE_API_KEY --models-root /path/to/local/models
curl -H "Authorization: Bearer $STRATA_SMOKE_API_KEY" http://127.0.0.1:8080/health
curl -H "Authorization: Bearer $STRATA_SMOKE_API_KEY" http://127.0.0.1:8080/v1/models
```

## Run the secure smoke server

`strata-secure-smoke-server` is an authenticated, offline-only smoke-test
server. It inventories pre-existing local `.gguf` files and exposes only
`GET /health` and `GET /v1/models`. It does **not** perform inference; chat
routes deliberately return `404` until the engine integration is complete.

Build it with the commands above, then set a token only in the process
environment and run it on loopback:

```sh
export STRATA_SMOKE_TOKEN='replace-with-a-long-random-token'
./out/build/linux-gcc/strata-secure-smoke-server \
  --models-root /absolute/path/to/local/models \
  --token-env STRATA_SMOKE_TOKEN
```

In another terminal, use the exact configured `Host` value and bearer token:

```sh
curl --fail --header 'Host: 127.0.0.1:8080' \
  --header "Authorization: Bearer $STRATA_SMOKE_TOKEN" \
  http://127.0.0.1:8080/health
curl --fail --header 'Host: 127.0.0.1:8080' \
  --header "Authorization: Bearer $STRATA_SMOKE_TOKEN" \
  http://127.0.0.1:8080/v1/models
```

For Linux protected-file tokens, create an owner-only file below a dedicated
secret root and pass `--token-file token.txt --secret-root /path/to/root`.
The relative token-file name is validated before the secure reader opens it.
Windows protected-file tokens require an explicitly protected owner-only DACL;
the implementation is fail-closed, and its runtime tests (`windows-runtime`)
passed in the `windows-msys2-clang` CI job (run `38540719307`). Tokens shorter than 32 bytes are
rejected.

Remote/wildcard binds are rejected unless the corresponding explicit flags are
provided. CORS remains disabled, and the executable neither sends outbound
traffic nor starts MCP, telemetry, analytics, update checks, or downloads.

## Configuration

`strata-secure-server` reads one strict JSON file (`--config FILE`) and the
command-line options; an option wins over the file, and `--check` reports every
key where that happened. Built-in defaults fill the rest. The file is UTF-8
without BOM, no comments, no trailing commas, no duplicate keys, nesting at most
4 levels, at most 64 KiB, integers only where a number is expected, and
`schema_version: 1` is required. It must be owned by you and not writable by
other users (its directory too). It never holds the token: `token.source` names
an environment variable (`env:NAME`) or a file below `roots.secret`
(`file:token`).

    strata-secure-server init --config ~/.config/strata/config.json \
        --models-root ~/models --engine ~/strata/strata --model-id NAME:TAG
    strata-secure-server --check --config ~/.config/strata/config.json
    strata-secure-server --config ~/.config/strata/config.json

`engine.model_id` names a model installed in `roots.models` (`strata pull` or
`strata import`; `strata list` shows them). Its manifest supplies the engine
profile, `--native`, `--pack`, `--ple-gguf` and the tokenizer, so
`engine.profile`, `roots.tokenizer_pack` and those weight flags in
`engine.args` are configuration errors that `--check` and serve both report. A
model this release cannot run stops serve with exit 11. `--expert` (below)
is the operator bring-up path instead.

`init` writes the config (owner-only, atomic). For a file token source
(`file:…`, the default) it also writes a 43-character token generated from the
OS random generator (`0600` on Linux; DPAPI-wrapped with a private ACL on
Windows); for an `env:NAME` source it writes no token, and you set that variable
yourself (at least 32 bytes). It refuses to replace an existing file without
`--force`. Where the files live by
default and the `strata` command are defined by the product-experience spec, not
here. On Windows, give non-ASCII paths in the config file: command-line arguments
arrive in the ANSI code page.

Every key (generated from the schema; `readme_config_table_matches_schema` keeps it current):

<!-- config-keys:begin -->
| Key | Type | Default | Range | Option | Meaning |
| --- | --- | --- | --- | --- | --- |
| `schema_version` | integer | `1` | 1-1 | - | Config format version; must be 1. Required in a config file. |
| `listener.host` | string | `127.0.0.1` | - | `--host` | Bind address: an IPv4/IPv6 literal or localhost. Other hostnames are rejected (never resolved). |
| `listener.port` | integer | `8080` | 1-65535 | `--port` | TCP port. |
| `listener.allow_remote` | boolean | `false` | - | `--allow-remote` | Required for every non-loopback address. |
| `listener.allow_wildcard_bind` | boolean | `false` | - | `--allow-wildcard-bind` | Also required for 0.0.0.0, :: and every other spelling of the unspecified address. |
| `listener.backlog` | integer | `16` | 1-4096 | - | listen() backlog. |
| `listener.cors_origins` | string array | `[]` | - | - | Exact browser origins allowed CORS: http:// or https://, a lower-case host, an optional port, no path; never * or null; at most 16. |
| `listener.host_aliases` | string array | `[]` | - | - | Extra exact Host values (host or host:port) clients use; required when the bind is a wildcard; at most 16. |
| `listener.web_ui` | boolean | `false` | - | - | Serve the built-in chat page at / (bundled files only). The page asks for the API key and keeps it in that tab; every API route still needs the key. |
| `listener.loopback_without_key` | boolean | `false` | - | - | Answer the API and the page without the API key: only with a loopback listener.host, and with no token.source; Host and Origin checks still apply. |
| `limits.http.request_deadline_ms` | integer | `30000` | 1-3600000 | - | Total time to read one request, header and body. |
| `limits.http.max_request_bytes` | integer | `65536` | 4096-16777216 | - | Largest request (header and body) the listener and parser accept. |
| `limits.http.max_header_bytes` | integer | `16384` | 1024-65536 | - | Largest header block; at most limits.http.max_request_bytes. |
| `limits.http.max_headers` | integer | `64` | 8-256 | - | Most header fields. |
| `limits.http.max_request_line_bytes` | integer | `4096` | 256-16384 | - | Longest request line; at most limits.http.max_header_bytes. |
| `limits.http.header_deadline_ms` | integer | `10000` | 1-3600000 | - | Time from accept to the end of the request header; at most limits.http.request_deadline_ms. |
| `limits.http.write_stall_ms` | integer | `10000` | 100-300000 | - | Longest send without progress before the client is treated as gone. |
| `limits.http.response_write_deadline_ms` | integer | `60000` | 1000-3600000 | - | Time to send a whole complete response, or a stream's tail after DONE; at least limits.http.write_stall_ms. |
| `limits.http.stream_keepalive_ms` | integer | `15000` | 1000-300000 | - | SSE comment interval while no content flows (streaming). |
| `limits.chat.max_body_bytes` | integer | `49152` | 1-16777216 | - | Largest chat request body; at most max_request_bytes minus max_header_bytes. |
| `limits.chat.max_messages` | integer | `128` | 1-128 | - | Most messages in one chat request. |
| `limits.chat.max_message_bytes` | integer | `65536` | 1-65536 | - | Largest single message content. |
| `limits.chat.max_prompt_tokens` | integer | `32768` | 1-262144 | - | Largest tokenized prompt sent to the engine. |
| `limits.chat.max_completion_tokens` | integer | `4096` | 1-16384 | - | Largest max_tokens a request may ask for. |
| `limits.chat.default_max_tokens` | integer | `0` | 0-16384 | - | max_tokens when a request omits it; 0 = auto: min(max_completion_tokens, context - prompt - 8); at most limits.chat.max_completion_tokens. |
| `limits.chat.max_generated_bytes` | integer | `1048576` | 1-16777216 | - | Largest generated text returned. |
| `limits.engine.ready_timeout_s` | integer | `900` | 1-86400 | - | How long the supervisor waits for the engine's READY after each start; a miss kills and restarts it (upstream STRATA_ENGINE_READY_S). |
| `limits.engine.generation_timeout_s` | integer | `120` | 1-86400 | - | Total time for one generation before STOP. |
| `limits.engine.stop_drain_timeout_s` | integer | `5` | 1-600 | - | Time to drain to DONE after STOP before the engine is marked failed. |
| `limits.concurrency.max_concurrent_requests` | integer | `8` | 1-256 | - | Worker threads: connections read or answered at once; 1 = serial. |
| `limits.concurrency.max_queued_generations` | integer | `derived: min(4, max(0, workers-2))` | 0-254 | - | Chats waiting behind the running generation; 0 when max_concurrent_requests is 1, otherwise at most max_concurrent_requests - 2. |
| `limits.concurrency.queue_timeout_ms` | integer | `300000` | 1000-3600000 | - | Longest wait for the engine before 503 server_busy. |
| `limits.concurrency.max_connections_per_remote_address` | integer | `derived: min(4, workers)` | 1-256 | - | Workers one non-loopback address may hold; at most max_concurrent_requests. Loopback is exempt. |
| `roots.models` | string | required | - | `--models-root` | Absolute directory of .gguf files. The root itself may be a symlink; nothing below it may be. |
| `roots.tokenizer_pack` | string | unset | - | `--tokenizer-pack` | Absolute tokenizer directory; only with strata-secure-server --expert (a managed model brings its own). |
| `roots.secret` | string | unset | - | `--secret-root` | Absolute directory holding the token file. Default: the config file's directory. |
| `roots.logs` | string | unset | - | - | Absolute log directory (created 0700; unused in SP1). |
| `roots.cache` | string | unset | - | - | Absolute cache directory (created 0700); when set, it holds the engine's CUDA cache in its cuda subdirectory. |
| `roots.state` | string | unset | - | `--state-dir` | Absolute, existing owner-only directory for engine state: the engine's cwd, per-generation temp and (without roots.cache) the CUDA cache. Required to serve. |
| `token.source` | string | `file:token` | - | `--token-file, --token-env` | file:<relative path below roots.secret> or env:<NAME>. Metadata only; the token is never in the config. |
| `engine.profile` | string | unset | - | `--profile` | qwen or glm53; only with --expert (a managed model's manifest sets it). |
| `engine.executable` | string | required | - | `--engine` | Absolute path of the engine; a regular file not writable by group or others. |
| `engine.model_id` | string | required | - | `--model-id` | Default model reference name[:tag] from the model index (or, with --expert, an inventory ID). |
| `engine.args` | string array | `[]` | - | `--engine-arg (repeatable)` | Extra engine arguments; frontend-owned and unsupported flags are rejected. |
| `engine.lib_dirs` | string array | `[]` | - | `--engine-lib-dir (repeatable)` | Absolute library directories for the engine (default: the engine executable's directory). |
| `engine.gpu` | string | unset | - | `--gpu` | GPU device indices for the engine, e.g. 0 or 0,1 (distinct, 0-255, at most 16); rendered as the engine's --gpu argument (strata family: no GPU variable). Not supported with engine.profile glm53. |
| `engine.allow_new_privileges` | boolean | `false` | - | `--allow-new-privileges` | Linux: do not set PR_SET_NO_NEW_PRIVS on the engine (default: set). Only for hosts whose NVIDIA driver must run setuid nvidia-modprobe to create /dev/nvidia-uvm on first use. |
| `pull.downloader` | string | unset | - | - | Absolute path of curl for pull/update. Default /usr/bin/curl (Windows: System32\curl.exe). Validated when a transfer or doctor --downloader runs, never at serve start. |
| `pull.proxy` | string | unset | - | - | http://host:port or https://host:port; absent = --noproxy *. No credentials. Environment proxies are never read. |
| `pull.allow_private_addresses` | boolean | `false` | - | - | Allow sources that resolve to private or special-use addresses. |
| `pull.max_total_bytes` | integer | `1099511627776` | 1048576-17592186044416 | - | Largest manifest total a pull accepts (bytes). |
| `pull.max_duration_s` | integer | `172800` | 60-604800 | - | Time budget for a whole pull run. |
| `pull.stall_timeout_s` | integer | `120` | 10-3600 | - | Abort a transfer slower than 1024 B/s for this long. |
| `pull.connect_timeout_s` | integer | `30` | 1-300 | - | TCP/TLS connect timeout per request. |
| `update.source` | string array | `[]` | - | - | HTTPS release-mirror URLs that 'strata update' fetches the signed release envelope from. |
| `logging.requests` | boolean | `false` | - | - | One line per request to stderr: route, status, code, time, bytes, loopback or remote; never paths, headers, tokens or text. |
| `defaults.sampling.temperature` | number | unset | 0-2 | - | Request default temperature (pin: 0..2); unset keeps the engine default. |
| `defaults.sampling.top_p` | number | unset | >0-1 | - | Request default top_p (pin: 0 < top_p <= 1); unset keeps the engine default. |
| `defaults.sampling.top_k` | integer | unset | 1-64 | - | Request default top_k candidates (pin: an integer 1..64); unset keeps the engine default. |
| `defaults.sampling.min_p` | number | unset | 0-1 | - | Request default min_p (pin wire: only 0 < min_p <= 1 is sent; 0 stays off). |
| `defaults.sampling.presence_penalty` | number | unset | 0-2 | - | Request default presence penalty (0 off; cap 2 added, C-1). |
| `defaults.sampling.repetition_penalty` | number | unset | >0-2 | - | Request default repetition penalty (pin wire: only != 1.0 is sent; cap 2 added, C-1). |
| `defaults.sampling.frequency_penalty` | number | unset | 0-2 | - | Request default frequency penalty (0 off; cap 2 added, C-1). |
| `defaults.sampling.penalty_last_n` | integer | unset | 0-8192 | - | Penalty window; unset means the pin default of 64 when any penalty is on (cap added, C-1). |
| `defaults.sampling.seed` | integer | unset | 1-4294967295 | - | Request default sampling seed (pin: a positive integer; 32-bit cap added, C-1). |
| `reasoning.effort` | string | unset | - | - | Thinking level for requests that name none: none, low, medium or high (pin levels); unset names none. Qwen packs with <think>: none closes the think block, any other value or unset thinks. |
| `reasoning.budget_tokens` | integer | `0` | 0-4294967295 | - | Default thinking budget in tokens (0 = none, the pin default); bounds added, C-1. |
| `reasoning.close_retry` | boolean | `false` | - | - | Close an unfinished thinking block once when the reply ends inside it (pin opt-in, off). |
| `reasoning.loop_recovery` | string | `off` | - | - | A reasoning loop ends the reply (off, the pin default), stops (stop) or continues once (recover). |
| `reasoning.effort_position` | string | `start` | - | - | Where a non-default effort sits in the prompt: start (the pin default) or end; end adds the engine's --tail-role-token. |
| `reasoning.anthropic_thinking` | string | `model` | - | - | Thinking default for /v1/messages-shaped clients: model (the pin default) or on_request. |
| `engine.fit_max_tokens` | boolean | `true` | - | - | Fit an over-room max_tokens to the context room (true, the pin default); false answers the §7.2 400 instead. |
| `engine.lazy_load` | boolean | `false` | - | - | Start with the engine unloaded; the first request loads it (the pin's lazy_load, text only). |
| `engine.idle_unload_s` | integer | `0` | 0-86400 | - | Seconds without a request before the engine is unloaded (0: never, the pin default); cap added, C-1. |
| `engine.mtp` | boolean | `true` | - | - | Draft layer (MTP): on unless explicitly false; false drops --mtp/--spec-min-p/--batch-mtp at every start. |
| `engine.vram_reserve_mib` | integer | unset | 0-1048576 | - | VRAM MiB the engine leaves free (renders --vram-reserve-mib; unset: the engine's own 700). |
| `engine.min_free_vram_mib` | integer | `0` | 0-1048576 | - | Refuse to load when free VRAM is below this (0: never; the driver check runs on the owner's GPU box). |
| `engine.vram_elastic` | boolean | `false` | - | - | Segment the expert cache so VRAM can be given back and taken back (renders --vram-elastic, #533). |
| `engine.vram_segment_mib` | integer | unset | 1-1048576 | - | Segment size for vram_elastic (renders --vram-segment-mib; unset: the engine's own 512). |
| `engine.elastic` | boolean | `false` | - | - | The image encoder starts with the first picture and stops when idle (needs vram_elastic; the vision turn). |
| `engine.elastic_idle_s` | integer | `120` | 1-86400 | - | Seconds without a picture before the elastic encoder stops (pin default 120); whole seconds, cap added. |
| `engine.elastic_mib` | integer | `2048` | 1-1048576 | - | VRAM MiB the expert cache keeps free while the encoder runs (pin default 2048). |
| `engine.gpu_order` | string | `auto` | - | - | GPU order: auto (reorder by card speed, where the driver can tell) or as_given (keep the configured order). |
| `engine.gpu_policy` | string | `auto` | - | - | GPU turn for a picture: auto, keep, shrink or unload the engine's VRAM first (the POLICIES set). |
| `engine.layer_split` | string | `auto` | - | - | First layer of each later GPU (rising numbers from 2), or auto; renders --layer-split with several GPUs. |
| `engine.split_skip_if_fits` | boolean | `false` | - | - | Let an auto split run on the first card alone when it holds every expert and the KV (renders --split-skip-if-fits). |
| `engine.hip_ordinal` | integer | unset | 0-127 | - | The HIP number of the discrete card (setup-recorded); wins over one (or zero) configured GPUs. |
| `engine.uma` | boolean | `false` | - | - | An APU: engine and image turn share the RAM either way, so a picture never needs the engine moved. |
| `engine.silence_s` | integer | `300` | 0-86400 | - | End a request when the engine says nothing valid for this long (pin default 300 s; 0: wait, still bounded by the total generation timeout). |
| `engine.answer_room` | boolean | `true` | - | - | Close a long un-budgeted thinking reply early enough to leave the answer room (true, the pin default). |
| `engine.repeat_stop_tokens` | integer | `256` | 0-65536 | - | One token this many times in a row ends a reply as length (pin default 256; 0: off). Cap added, C-1. |
| `engine.max_tokens` | integer | unset | 1-1048576 | - | Ceiling on a request's output budget (unset: the completion cap; an added frontend bound, C-1). |
| `engine.min_tokens` | integer | unset | 1-1048576 | - | Floor on a request's output budget (unset: none; an added frontend bound, C-1). |
| `model.aliases` | string array | `[]` | - | - | Other model names the server lists and answers to (exact match only, like the pin's set_aliases). |
| `session.slot_save_path` | string | unset | - | - | Directory for engine slot session save/restore files (absolute; the /slots route is not served today). |
| `session.expert_profile_save` | string | unset | - | - | Where the engine re-saves its learned expert profile (absolute path; --expert-profile-save). |
| `session.expert_profile_save_every` | integer | `10` | 0-1440 | - | Re-save the learned expert profile every N minutes (pin default 10; 0: at engine exit only). Cap added, C-1. |
| `session.tool_call_recovery` | boolean | `false` | - | - | Attempt to recover malformed tool-call output (the pin's opt-in; stored for parity today). |
| `session.env_to_user` | boolean | `false` | - | - | Pass configured environment hints to the user prompt path (the pin's opt-in; stored for parity today). |
| `session.codex_thread_titles` | boolean | `false` | - | - | Codex thread titles (#923; the pin's opt-in; the route is not served here). |
| `session.codex_compaction_cache` | boolean | `false` | - | - | Codex compaction cache (#924; the pin's opt-in; the route is not served here). |
| `session.keep_files` | integer | `64` | 1-1024 | - | How many image-scratch files to retain (pin default 64; bounds added, C-1; the consumer is out per D-9). |
| `replicas.parallel` | integer | `1` | 1-1024 | - | Decode up to N requests together inside the one engine (1: one at a time; the N-child scheduler is not implemented). |
| `vision.enabled` | boolean | `false` | - | - | Read images: a supervised strata-vision child encodes image_url parts for the engine. |
| `vision.max_side` | integer | `2048` | 1-16384 | - | Largest image side accepted before decoding (pin default 2048; cap added, C-1). |
| `vision.max_n` | integer | `4` | 1-64 | - | Most images one request may carry (pin default 4; cap added, C-1). |
| `vision.need_mib` | integer | unset | 1-1048576 | - | Override the free-VRAM figure the encoder is checked against (unset: computed; bounds added, C-1). |
| `vision.no_flash_attn` | boolean | `false` | - | - | Run the encoder without flash attention (added, spec §5.1; the encoder's --no-flash-attn). |
| `vision.resident` | boolean | `true` | - | - | Keep the encoder running from boot (the pin's eager resident encoder; false: the first image starts it). |
| `vision.threads` | integer | `0` | 0-256 | - | Encoder CPU threads (0: the tool's own default; cap added, C-1). |
| `vision.ready_timeout_s` | integer | `300` | 0-86400 | - | Seconds the encoder gets to print READY (0: wait for ever, as at the pin). |
| `vision.encode_timeout_s` | integer | `300` | 0-86400 | - | Seconds one image encoding may take (0: wait for ever, as at the pin). |
| `glm.thinking_budget` | integer | `32768` | 0-1000000000 | - | Thinking-token budget when a request names none (Maya's default 32768; 0 disables the budget). |
| `glm.reasoning_effort` | string | unset | - | - | Thinking level when a request names none: none, low, high or max (Maya's canonical levels; Maya's aliases such as "medium" are not accepted here). |
| `glm.fit_max_tokens` | boolean | `false` | - | - | Fit a request's output budget to the context room on the GLM side (Maya's default: false). |
| `glm.experimental_speed_projection` | boolean | `false` | - | - | GLM speed projection (Maya's default: false). |
| `glm.gpu` | string | unset | - | - | GPU device indices for the GLM engine, e.g. 0 or 0,1 (distinct, 0-255, at most 16). |
| `glm.layer_split` | string | `auto` | - | - | First layer of each later GPU's share (rising numbers, e.g. 18 or 16,32), or auto; the GLM engine's --layer-split. |
| `glm.tokenizer` | string | unset | - | - | Absolute tokenizer-pack path for the GLM engine (default: the pack named by the model). |
| `glm.model_name` | string | unset | - | - | Served model id for the GLM engine (1-256 characters; a managed model takes its identity from the manifest). |
| `glm.max_context` | integer | `32768` | 1-1048576 | - | GLM context length in tokens the engine is started with (Maya's default 32768). |
<!-- config-keys:end -->

`roots.secret` defaults to the config file's directory only for a `file:` token
source; an `env:` source never opens it. `roots.logs` and `roots.cache` may be
absent if their parent is a private directory; only serving and `init` create
them. `--check` creates nothing.

**Replicas (SP5 narrowing, spec C-4).** N-child replica scheduling is not
implemented in SP5; `--parallel` within one engine is. The pinned scheduler's
`replicas` entry and its `replica_*` members are rejected at load, naming the
key; what stands is engine-internal parallelism: `replicas.parallel` decodes up
to N requests together inside the one engine child (rendered to the engine as
`--batch N`, exactly like the pinned server; 1, the default, is one request at
a time, and the engine's batch window is 8).

**Vision (SP5 M1, spec D-9).** Image *input* is typed and plumbed; image
*generation* stays out (its routes answer 404, parity table). `vision.enabled`
needs the manifest artifact `launch.mmproj` — the files[] role `mmproj` is
listed like any other file, at most one — and the engine then receives
`--vision`, like the pinned server's section gate (serve/server.py:2926-2931).
The encoder is a supervised `strata-vision` child, a sibling of the engine
executable (the pin's config-named vision exe stays rejected, spec §4); it
must print READY within `vision.ready_timeout_s` (300 s, the pin's
VISION_READY_S; 0 waits for ever), and a resident encoder that cannot start
fails the boot — `vision.enabled` promises images. `vision.resident` false
waits for the first picture (the pin's laziness, :2646). On the request path
images arrive as `data:` URLs only — an http(s) image URL is refused 400 by
name, never fetched — `vision.max_side` and `vision.max_n` cap them before
any decode, `vision.encode_timeout_s` (the pin's VISION_ENCODE_S, :328)
bounds one ENC round trip, and every staged or encoded scratch file lives
under `<state>/vision` (owner-private) and is deleted when the request ends.
`engine.max_tokens`/
`engine.min_tokens` also reach the child as `--max-tokens`/`--min-tokens`
exactly as at the pin (:2564-2567), and `vision.no_flash_attn` is the added
spec §5.1 family flag. Real encode behaviour on real images is proven only by
the owner-box acceptance kit.

**Constants.** Internal constants live in
`include/secure_frontend/api_constants.hpp` (SP3) and `config_defaults.hpp`
(SP1). SP3 removed SP1's 1000 ms minimum send budget (SP1 addendum A4); the
half-close drain (100 ms / 256 KiB) moved to `api_constants.hpp`; M2 adds the
streaming bounds `kMaxDeltaTextBytes` (16 KiB of text per content delta) and
`kMaxSseEventBytes` (128 KiB per SSE event).

## Strata option-surface parity (SP5 M1)

The pinned upstream Strata (`upstream.version`, tag `v0.2.2`) reads 88 config
keys and 32 environment knobs (the verbatim grep in
`secure_frontend/tests/parity_keys_upstream.hpp`); the parity table
(`secure_frontend/src/parity_table.cpp`) gives each one — plus a few rule rows
the flat grep cannot see — exactly one disposition, cited to the governing
read site. The three tables below mirror that table for humans, one block per
disposition; the C++ table stays the authority and the pytest gate
`tools/secure/test_parity_readme_coverage.py` re-checks these blocks against
it. Typed options live in the config table above (each note names the wiring
task); rejected options are refused **at config load, by name**, and
`strata doctor` warns about ignored `STRATA_*`/`MAYA_*` environment variables.
Narrowings: `replicas.parallel` is typed but renders `--batch N` inside the
one child (C-4: the pin's N-child replica scheduler is not implemented);
`session.answer_room` is typed only (the pin's formula sits in its thinking
parser, not in our §7.2 room rule); `lazy_load` is typed but has no flag (the
pin has none either); the vision encoder gets no per-generation cgroup in M1
(recorded gap); `session.keep_files` keeps the pin's default but its LRU
consumer is out of M1 — every request cleans up after itself instead.

### Kept as typed options

<!-- parity-typed:begin -->
| Upstream option | Destination | Disposition note and the pin read site |
| --- | --- | --- |
| `aliases` | frontend behaviour | serve/server.py:8263, set_aliases :3951-3964; runconfig.py:34 (M1 Task 8: model.aliases — /v1/models lists them, chat matches exactly) |
| `allowed_hosts` | frontend behaviour | already typed (SP1/SP3 listen); serve/server.py:8283 |
| `answer_room` | typed config | serve/server.py:8231 (`is not False`), formula :4893-4905; typed only: the pin's formula sits in its thinking parser, not in our §7.2 room rule (Ruling T8-d, Task 15) |
| `anthropic_thinking` | typed config | serve/server.py:8319 (M1 Task 5: reasoning.anthropic_thinking) |
| `codex_compaction_cache` | typed config | serve/server.py:8261 (M1 Task 9: session.codex_compaction_cache) |
| `codex_thread_titles` | typed config | serve/server.py:8260 (M1 Task 9: session.codex_thread_titles) |
| `cors_origins` | frontend behaviour | already typed (SP3 B12: listener.cors_origins); serve/server.py:8280 |
| `effort_position` | engine argv | serve/server.py:2880 (M1 Task 5: reasoning.effort_position composes the engine's --tail-role-token) |
| `elastic` | frontend behaviour | serve/server.py:2557, :8138 (M1 Task 7: engine.elastic; Tasks 11-12 consume it) |
| `elastic_idle_s` | frontend behaviour | serve/server.py:2559, :4041 (M1 Task 7: engine.elastic_idle_s) |
| `elastic_mib` | frontend behaviour | serve/server.py:2558, :4019 (M1 Task 7: engine.elastic_mib; /v1/vram headroom) |
| `engine_silence_s` | frontend behaviour | serve/server.py:942, default 300 at :277, engine_silence_s() :2905-2912; runconfig.py:39 (M1 Task 8: the pump's silence watchdog) |
| `env_to_user` | typed config | serve/server.py:8327 (M1 Task 9: session.env_to_user) |
| `expert_profile_save` | engine argv | serve/server.py:3071-3076 (M1 Task 9: --expert-profile-save; an operator-owned flag wins, :3072) |
| `expert_profile_save_every` | engine argv | serve/server.py:3075-3076, default 10 at :3067 (M1 Task 9: --expert-profile-save-every; rides the save, :3072) |
| `fit_max_tokens` | frontend behaviour | serve/server.py:8213 (M1 Task 5: engine.fit_max_tokens) |
| `gpu` | engine argv | already typed (SP2 engine.gpu; compose renders --gpu); serve/server.py:2826 (gpu_list :2819-2826: a set `gpu` wins; unset, a saved `gpu_roles` picks the cards, Main last, :2822-2825 — see the gpu_roles row) |
| `gpu_order` | engine argv | serve/server.py:3224 (M1 Task 7: `as_given` keeps the order; at v0.2.2 active `gpu_roles` keep it too and a HIP built-in Radeon goes first before the speed sort, :3230-3247 — the typed auto or as_given vocabulary is unchanged) |
| `gpu_policy` | typed config | serve/images.py:174 (M1 Task 7: engine.gpu_policy, re-scoped to the vision child's GPU turn; the pin's use is the image-generation turn) |
| `hip_ordinal` | engine argv | serve/server.py:3094 (M1 Task 7) |
| `host` | frontend behaviour | already typed (SP1 listen.host); serve/server.py:8071 |
| `idle_unload_s` | frontend behaviour | serve/server.py:4287-4296, :8298 (M1 Task 6: supervisor idle timer) |
| `keep_files` | typed config | serve/images.py:189 (`or 64`); typed only: the consumer is the pin's ImageService and D-9 keeps image generation out (Ruling T9-e, M1 Task 9) |
| `layer_split` | engine argv | serve/server.py:2921 (M1 Task 7) |
| `lazy_load` | frontend behaviour | serve/server.py:8134, :967-994 (M1 Task 6: the first request spawns the same composed launch) |
| `max_n` | frontend behaviour | serve/images.py:103 (M1 Tasks 11-12: vision.max_n; the pin's cap lives on the images block) |
| `max_side` | frontend behaviour | serve/images.py:102 (M1 Task 12: vision.max_side pre-decode cap) |
| `max_tokens` | request rule | serve/server.py:2571 (vision encoder at the pin); engine.max_tokens re-scoped as the request output ceiling (added, C-1; Ruling T8-e: caps at the §7.2 resolve site) |
| `min_free_vram_mib` | frontend behaviour | serve/server.py:8300 (M1 Task 7: engine.min_free_vram_mib) |
| `min_tokens` | request rule | serve/server.py:2573 (vision encoder at the pin); engine.min_tokens re-scoped as the request output floor (added, C-1; Ruling T8-e: lifts at the §7.2 resolve site) |
| `mtp` | engine argv | strata_control/draft_layer.py is_off; serve/server.py:2966-2969 (M1 Task 6: engine.mtp drops --mtp/--spec-min-p/--batch-mtp at every start) |
| `need_mib` | frontend behaviour | serve/images.py:157 (M1 Task 11: vision.need_mib; added security bound) |
| `parallel` | engine argv | serve/server.py:3000-3020 (replicas.parallel renders --batch N, :3020; window PARALLEL_MAX 8 at :2999; cap 1024 from the pin's own bound :8054, M1 Task 10) |
| `reasoning_budget_tokens` | typed config | serve/server.py:8337 (M1 Task 5: reasoning.budget_tokens) |
| `reasoning_close_retry` | typed config | serve/server.py:8232 (M1 Task 5: reasoning.close_retry) |
| `reasoning_effort` | frontend behaviour | serve/server.py:7642 (M1 Task 5: reasoning.effort; the qwen think tail, issue 19: none writes the closed block, unset/low/medium/high open it, the levels are not told apart) |
| `reasoning_loop_recovery` | typed config | serve/server.py:8346 (M1 Task 5: reasoning.loop_recovery) |
| `repeat_stop_tokens` | frontend behaviour | serve/server.py:198 (REPEAT_STOP_TOKENS 256), the pin's detector is frontend-side at :5098, notice :5278, 0 = off :8332 (Ruling T8-f: no GEN key) |
| `sampling` | typed config | serve/server.py:7691 (M1 Task 4: defaults.sampling.*) |
| `slot_save_path` | typed config | serve/server.py:8311 + slot_save_dir :3656-3668; the pin uses it FRONTEND-side for its /slots file store (:3885-3902) — no argv append (Ruling T9-a, M1 Task 9) |
| `split_skip_if_fits` | engine argv | serve/server.py:2985 (M1 Task 7) |
| `threads` | engine argv | serve/server.py:2569 (M1 Task 11: vision.threads; the only pin read of `threads`, inside the vision reader_args — the flag lands on the encoder child's argv) |
| `tool_call_recovery` | typed config | serve/server.py:8323 (M1 Task 9: session.tool_call_recovery) |
| `trusted_origins` | frontend behaviour | already typed (SP3 origins family); serve/server.py:8281 |
| `uma` | frontend behaviour | serve/images.py:23, :335 (M1 Task 7: engine.uma; Tasks 11-12 consume it) |
| `update.source` | typed config | our key (PX §4 reserved; SP7 M2 D-10): the HTTPS mirror list read only by 'strata update' (SP7 M2 Task 3) |
| `vision` | typed config | serve/server.py:2974 (M1 Task 11: the vision.* block) |
| `vram_elastic` | engine argv | serve/server.py:2989 (M1 Task 7) |
| `vram_segment_mib` | engine argv | serve/server.py:2991 (M1 Task 7) |
| `STRATA_ALLOWED_HOSTS` | frontend behaviour | same semantics as allowed_hosts, already typed; serve/server.py:3703 |
| `STRATA_BATCH_MTP` | engine argv | serve/server.py:3017; engine.mtp (M1 Task 6) |
| `STRATA_ENGINE_READY_S` | frontend behaviour | already typed: ready_timeout (SP1); serve/server.py:292 |
| `STRATA_ENGINE_STALL_S` | frontend behaviour | serve/server.py:308; engine.silence_s (M1 Task 8) |
| `STRATA_MAX_BODY_MIB` | frontend behaviour | already typed: limits.chat.max_body_bytes (SP1); serve/server.py:5869 |
| `STRATA_VISION_ENCODE_S` | frontend behaviour | serve/server.py:329 (M1 Task 12: vision encode-timeout row) |
| `STRATA_VISION_READY_S` | frontend behaviour | serve/server.py:328 (M1 Task 11: vision.ready_timeout_s; 0 = wait for ever, :292) |
| `vram_reserve_mib` | engine argv | serve/runconfig.py:42 renders --vram-reserve-mib (M1 Task 7) |
<!-- parity-typed:end -->

### Mapped to a Strata mechanism instead

<!-- parity-mapped:begin -->
| Upstream option | Where it lives in Strata instead (and the pin read site) |
| --- | --- |
| `api_key` | SP1 token store is the only auth source (CFG-06: no secret in config); serve/server.py:8078 |
| `arch` | model identity comes from the SP4 manifest/GGUF inventory; serve/server.py:7857 |
| `backend` | engine identity: SP4 manifest + engine gate; serve/server.py:7889 |
| `gpu_none` | strata_control/gpu_roles.py saved_roles :399; serve/server.py:2841 (gpu_all_off), :3353-3355 (every card Off: empty CUDA/HIP_VISIBLE_DEVICES), :2854-2859 (refused at start for a GPU engine); card choice is the typed engine.gpu (SP2 §3.9: rendered as --gpu, never a GPU variable), so the all-Off run has no counterpart |
| `gpu_roles` | strata_control/gpu_roles.py saved_roles :386-405 (:390); serve/server.py:2822-2825 (gpu_list: the cards, Main last, when `gpu` is unset), :3224 (keeps the given order); card choice and order are the typed engine.gpu (SP2 §3.9: rendered as --gpu), the Main/Helper/Off roles have no typed form |
| `images` | spec D-9: image generation is out, the route answers 404 like an unknown route; serve/server.py:8233 |
| `max_queue` | the SP3 row limits.concurrency.max_queued_generations already carries queue admission (pin bound 0..4096 at serve/server.py:8044, derived default :3789-3791; Ruling T8-a) |
| `model_name` | served-model identity comes from the SP4 manifest; serve/images.py:184 |
| `native` | the SP4 manifest composes --native (engine_arguments); serve/images.py:126 |
| `out_dir` | spec D-9 image generation is out; serve/images.py:186 |
| `pool_cores` | the operator's engine.args carries the engine's own --pool-cores LIST (not frontend-owned and not a mode: engine_arguments.cpp passes it through; no typed row); serve/server.py:3031, pool_cores_args :3026-3046 (experimental, off by default; a --pool-cores already in the args wins, :3034), composed after parallel at :2995 |
| `quant` | quant identity comes from the SP4 manifest; serve/images.py:283 |
| `queue_timeout` | the SP3 row limits.concurrency.queue_timeout_ms already carries admission waiting (pin bound 0.1..600 at serve/server.py:8048; Ruling T8-a) |
| `reload` | image-generation card reload mode (spec D-9); the vision child's lifecycle follows the vision/elastic rows; serve/images.py:177 |
| `sigmas` | spec D-9 image generation is out; serve/images.py:120 |
| `steps` | spec D-9 image generation is out; serve/images.py:104 |
| `timeout_s` | the SP3 row limits.engine.generation_timeout_s already carries the generation deadline (pin: generation job timeout at serve/images.py:227; Ruling T8-b) |
| `tokenizer` | the SP4 manifest carries the tokenizer; serve/server.py:8092 |
| `STRATA_ADMIT_MAX_WAIT_S` | serve/server.py:312; admission waiting is already carried by limits.concurrency.queue_timeout_ms (Ruling T8-a) |
| `STRATA_ADMIT_SHORT_FIRST` | SP3 admission ordering is the pool policy (B8); serve/server.py:315 |
| `STRATA_API_KEY` | SP1 token store is the only auth source; serve/server.py:7425 |
| `STRATA_DROP_CACHE_ON_EXIT` | the SP2 shutdown order (§3.7) is fixed by the supervisor; serve/cache_drop.py:1 |
| `STRATA_ENGINE_NICE` | the SP2 child pre-exec state (§3.12) is fixed by the supervisor, which sets no engine priority; serve/server.py:3161 (engine_nice :3154-3168: Linux only, +5 by default beside a built-in Radeon), applied at spawn :1017-1022 |
| `STRATA_HTTP_BACKLOG` | the listener backlog is fixed by the SP3 poll design (128 entries); serve/server.py:7230 |
| `STRATA_KEEP_EMPTY_TURNS` | the frontend serves stateless requests; conversation history is the client's; serve/frontend.py:60 |
| `STRATA_KEEP_LEFTOVERS` | lifecycle is teardown + respawn (M1 Task 6); serve/server.py:129 |
| `STRATA_LIFELINE` | SP2 supervision replaces the lifeline watcher (pdeathsig, monitor handle); serve/lifeline.py:33 |
| `STRATA_NO_PRESET` | launch is SP4 manifest-composed; serve/server.py:7657 |
| `STRATA_OFFLINE` | PRIV-01: the frontend never reaches the network; enforced by design and the DL-01 proof; serve/server.py:3373 |
| `STRATA_REQUEST_LINES` | the wire record is fixed by docs/security/engine-protocol-limits.md; serve/server.py:640 |
| `STRATA_RELEASE_PUBKEY_HEX` | our compile-definition pin of the Ed25519 release public key (SP7 M2 D-2), not an upstream knob: it is read by the release-manifest verifier and reported by 'strata update'; empty refuses every update (SP7 M2 Task 2/3) |
| `STRATA_START_RETRIES` | respawn retries belong to the SP2 RestartTracker (restart_policy.hpp); serve/server.py:610 |
| `STRATA_TOKENIZER` | the SP4 manifest carries the tokenizer; serve/test_detok.py:21 |
<!-- parity-mapped:end -->

### Excluded keys — refused at config load

<!-- parity-rejected:begin -->
| Upstream option | Excluded by (and the pin read site) |
| --- | --- |
| `api_monitor` | spec §4 web/desktop/telemetry; serve/server.py:8289 |
| `args` | spec §4 free-form process control; serve/server.py:3226 |
| `batch_telemetry` | spec §4 telemetry endpoints; serve/server.py:898 |
| `before_load` | spec §4 command execution; serve/server.py:8108 |
| `before_load_ignore_failure` | spec §4 command execution; serve/server.py:8307 |
| `before_load_strict` | spec §4 command execution; serve/server.py:8308 |
| `before_load_timeout_s` | spec §4 command execution; serve/server.py:8303 |
| `command` | spec §4 MCP command; serve/mcp.py:610 |
| `cwd` | spec §4 free-form process control; serve/mcp.py:106 |
| `env` | spec §4 raw env dict; serve/server.py:3361 |
| `exe` | spec §4 free-form process control (engine identity comes from the SP4 manifest); serve/server.py:7883 |
| `headers` | spec §4 MCP headers; serve/mcp.py:257 |
| `lib_dirs` | spec §4 free-form process control; serve/images.py:135 |
| `log` | spec §4 free-form process control; serve/replicas.py:99 |
| `mcp` | spec §4 MCP; serve/mcp.py:632 |
| `mcp_servers` | spec §4 MCP; serve/mcp.py:651 |
| `open_browser` | spec §4 web/desktop; serve/server.py:8408 |
| `prevent_sleep` | spec §4 desktop; serve/server.py:8248 |
| `replica_cpus` | spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7758 |
| `replica_load_tokens` | spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7792 |
| `replicas` | spec C-4: N-child replica scheduling is the accepted narrowing; serve/replicas.py:44 |
| `telemetry_read_key` | spec §4 telemetry endpoints; serve/server.py:8270 |
| `type` | spec §4 MCP entry type; serve/mcp.py:604 |
| `url` | spec §4 MCP url; serve/mcp.py:384 |
| `user_args` | spec §4 free-form process control; serve/server.py:2962 |
| `STRATA_BATCH_TELEMETRY` | spec §4 telemetry endpoints; serve/server.py:900 |
| `STRATA_BATCH_TRACE` | spec §4 no new web/diagnostics surface; serve/server.py:822 |
| `STRATA_DEBUG` | spec §4 no new web/diagnostics surface; serve/mcp.py:130 |
| `STRATA_FAIL_ONCE` | spec §4 free-form process control (fault-injection knob); serve/test_server.py:4722 |
| `STRATA_OWNER_ATTEST_KEY` | spec §4 signing material, deferred to SP7; serve/server.py:8029 |
| `STRATA_PARALLEL_SOLO` | spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:1734 |
| `STRATA_REPLICA_START` | spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7774 |
| `STRATA_RUNTIME_PROFILE` | spec §4 no new web/diagnostics surface; serve/lifeline.py:265 |
| `STRATA_SYCL_BIN` | spec §4 free-form process control (external binary path); serve/server.py:2868 |
| `STRATA_TELEMETRY_KEY` | spec §4 telemetry endpoints; serve/server.py:8270 |
| `STRATA_VERIFY_TRACE` | spec §4 no new web/diagnostics surface; serve/server.py:1220 |
| `mcpServers` | spec §4 MCP (Claude Desktop block); serve/mcp.py:648 |
<!-- parity-rejected:end -->

## MAYA v1.1.21 option-surface parity (SP5 M2)

The vendored MAYA reference (`engines/maya-ref/`, tag `v1.1.21`, read-only —
nothing of it is compiled by our presets; `docs/PROVENANCE.md`) is the
`glm53` profile's reference surface. Its parity table
(`secure_frontend/src/parity_table.cpp`, `kMayaRows`) gives all 178 options —
138 typed, 30 rejected, 10 mapped — exactly one disposition, cited to the
read site. The option inventory is the set generated at `v1.1.8`
(`tests/parity_keys_maya.hpp`; regenerating it at `v1.1.21` is open), while
the citations follow `v1.1.21`. That tag's `docs/SETTINGS.md` spells every
setting `MAYA_*`; the rows keep the `STRATA_*` names the engine reads (the
older spelling still works, its lines 6-8). The blocks below mirror that
table for humans; the pytest gate
`tools/secure/test_parity_readme_coverage.py` re-checks them against it. The
typed **child-env** rows form a closed 100-name allowlist for the glm-family
child (`kFamilyForcibleEnvironment`): no other `STRATA_*`/`MAYA_*` name can
reach that child at all (D-7). Free-form launch is retired: a `glm53`
manifest refuses any `engine.args` (D-8) — the launch is composed from the
manifest and this table. Declared gaps the acceptance kit runs without, on
both sides: `--expert-profile`, `--expert-profile-save(-every)`,
`--kv-resident` and `--spec*` have no typed value source yet, and
`--parallel` is bounded 1..8 at composition (`docs/validation/sp5-parity-kit.md` §0).

### Kept as typed options

<!-- maya-typed:begin -->
| Maya option | Destination | Disposition note and the MAYA v1.1.21 read site |
| --- | --- | --- |
| `cors_origins` | frontend behaviour | already typed (SP3 B12: listener.cors_origins); serve/server.py:4096 |
| `experimental_speed_projection` | typed config | serve/server.py:3819 (shared settings, bool); Task 3: glm.experimental_speed_projection |
| `fit_max_tokens` | typed config | serve/server.py:4077; Task 3: glm.fit_max_tokens (M1 engine.fit_max_tokens pattern) |
| `gpu` | engine argv | already typed (SP2 engine.gpu renders --gpu); serve/server.py:1264, child_env :1280-1288, maya.py:2429; Task 7 |
| `host` | frontend behaviour | already typed (SP1 listen.host); serve/server.py:3983, maya.py:2790 |
| `layer_split` | engine argv | serve/server.py:1274-1277 renders --layer-split; docs/SETTINGS.md:44; Task 7 |
| `max_tokens` | request rule | serve/server.py:1053, :1213 (the vision block), shared settings :3815; engine.max_tokens stays the request output ceiling (M1 Ruling T8-e pattern) |
| `min_p` | typed config | serve/server.py:3808 (shared settings: 0 <= min_p < 1), sampling-block validator :3848; defaults.sampling.min_p |
| `model_name` | typed config | serve/server.py:4075, maya.py:2805; Task 3: glm.model_name (Ruling T2-c: managed launches still take served identity from the SP4 manifest) |
| `no_flash_attn` | frontend behaviour | serve/server.py:1055, :1222 (--no-flash-attn on the encoder child); Task 8: vision.no_flash_attn |
| `port` | frontend behaviour | already typed (SP1 listen port); maya.py:2789, :3132 |
| `reasoning_effort` | typed config | serve/server.py:4081, shared settings :3798 (none|low|high|max); Task 3: glm.reasoning_effort |
| `resident` | typed config | serve/server.py:4015 (on-demand vs resident encoder); Task 8: vision.resident |
| `sampling` | typed config | serve/server.py:3829-3836 (supported keys, validators from :3840); maya.py:106 (SAMPLING defaults); defaults.sampling.* (M1 Task 4) |
| `seed` | typed config | serve/server.py:3815 (shared settings: positive integer), :265; defaults.sampling.seed (SP3 B9 neutral seed) |
| `temperature` | typed config | serve/server.py:3802 (shared settings: 0..2), config-block validator :3840 (>= 0, 0 = greedy); defaults.sampling.temperature |
| `thinking_budget` | typed config | serve/server.py:4090 (default 32768); C-3 keeps Maya's name: Task 3 glm.thinking_budget; STRATA_GLM_THINK_RESERVE rides it (docs/SETTINGS.md:141) |
| `threads` | engine argv | serve/server.py:1051 (the vision block; the flag lands on the encoder child :1221-1222); Task 8 (M1 Task 11 vision.threads pattern) |
| `top_k` | typed config | serve/server.py:3811 (shared settings: integer 1..64), validator :3852; defaults.sampling.top_k |
| `top_p` | typed config | serve/server.py:3805 (shared settings: 0 < top_p <= 1), validator :3844; defaults.sampling.top_p |
| `tokenizer` | typed config | serve/server.py:3989, maya.py:2758, :3144; Task 3: glm.tokenizer — managed launches still compose the tokenizer from the SP4 manifest (Ruling T2-c) |
| `vision` | typed config | serve/server.py:4008, :4011, :4015; the vision.* block (M1 Task 11); Task 8 the GLM side |
| `mmproj` | manifest artifact | serve/server.py:1221 (the vision child's --mmproj); M1 Task 11: manifest files[] role mmproj (at most one entry) |
| `model` | manifest artifact | serve/server.py:1221 (the vision child's --model file); the SP4 manifest composes the vision model artifact (Task 8) |
| `presence_penalty` | typed config | serve/server.py:263-265 (supported sampling fields), block docstring :3829-3834, validator from :3856; defaults.sampling.presence_penalty |
| `repetition_penalty` | typed config | serve/server.py:263-265, :274-279 (llama.cpp repeat_penalty is taken as this one); defaults.sampling.repetition_penalty |
| `frequency_penalty` | typed config | serve/server.py:263-265, :3829-3834; defaults.sampling.frequency_penalty |
| `penalty_last_n` | typed config | serve/server.py:263-265, :280-283, :305-306 (repeat_last_n maps; 0 = no penalties, -1 = the whole context up to PENALTY_WINDOW_MAX 4096 :260, below -1 refused); defaults.sampling.penalty_last_n |
| `STRATA_ENGINE_STALL_S` | frontend behaviour | serve/server.py:343, docs/SETTINGS.md:142 (the pump's silence watchdog — M1 engine.silence_s pattern) |
| `STRATA_GLM_AHEAD` | typed child env | docs/SETTINGS.md:87 |
| `STRATA_GLM_CKPT_EVERY` | typed child env | docs/SETTINGS.md:69 |
| `STRATA_GLM_CKPTS` | typed child env | docs/SETTINGS.md:69 |
| `STRATA_GLM_CPU_1T` | typed child env | docs/SETTINGS.md:104 |
| `STRATA_GLM_CPU_LANE` | typed child env | docs/SETTINGS.md:46 |
| `STRATA_GLM_CPU_LANE0` | typed child env | docs/SETTINGS.md:47 |
| `STRATA_GLM_CPU_LANE1` | typed child env | docs/SETTINGS.md:47 |
| `STRATA_GLM_CPU_MT` | typed child env | docs/SETTINGS.md:104 |
| `STRATA_GLM_CPU_PIN` | typed child env | docs/SETTINGS.md:48 |
| `STRATA_GLM_CPU_PLAN` | typed child env | docs/SETTINGS.md:54 |
| `STRATA_GLM_CPU_RETIME` | typed child env | docs/SETTINGS.md:55 |
| `STRATA_GLM_CPU_SHARED` | typed child env | docs/SETTINGS.md:48 |
| `STRATA_GLM_CPU_SPLIT` | typed child env | docs/SETTINGS.md:53 |
| `STRATA_GLM_DISK_QD` | typed child env | docs/SETTINGS.md:97 |
| `STRATA_GLM_DISK_READERS` | typed child env | docs/SETTINGS.md:97 |
| `STRATA_GLM_DISK_SKIP_FROM` | typed child env | docs/SETTINGS.md:87 |
| `STRATA_GLM_DISK_SKIP_W` | typed child env | docs/SETTINGS.md:87 |
| `STRATA_GLM_DROP_CACHE` | typed child env | docs/SETTINGS.md:119 |
| `STRATA_GLM_DSA_SCORE` | typed child env | docs/SETTINGS.md:109 |
| `STRATA_GLM_EXL3_MMA_ROWS` | typed child env | docs/SETTINGS.md:115 |
| `STRATA_GLM_KDA_GRAPH` | typed child env | docs/SETTINGS.md:52 |
| `STRATA_GLM_KQ` | typed child env | docs/SETTINGS.md:103 |
| `STRATA_GLM_KV_INT8` | typed child env | docs/SETTINGS.md:107 |
| `STRATA_GLM_KV_PREFETCH` | typed child env | docs/SETTINGS.md:108 |
| `STRATA_GLM_KV_RESIDENT` | typed child env | docs/SETTINGS.md:108 |
| `STRATA_GLM_LOOP_ANSWER` | typed child env | docs/SETTINGS.md:121 (the loop guard: SP6 §4.9 keeps the guards a forced default the table may move; Task 4) |
| `STRATA_GLM_LOOP_THINK` | typed child env | docs/SETTINGS.md:121 (the loop guard: SP6 §4.9 keeps the guards a forced default the table may move; Task 4) |
| `STRATA_GLM_MMQ_GLU` | typed child env | docs/SETTINGS.md:118 |
| `STRATA_GLM_MTP_KEEP` | typed child env | docs/SETTINGS.md:84 |
| `STRATA_GLM_MTP_MISS` | typed child env | docs/SETTINGS.md:84 |
| `STRATA_GLM_MULTI_BENCH` | typed child env | docs/SETTINGS.md:140 |
| `STRATA_GLM_MULTI_BOUNDARY` | typed child env | docs/SETTINGS.md:77 |
| `STRATA_GLM_MULTI_ROOM` | typed child env | docs/SETTINGS.md:77 |
| `STRATA_GLM_MULTI_SPEC` | typed child env | docs/SETTINGS.md:77 |
| `STRATA_GLM_MV_RDNA` | typed child env | docs/SETTINGS.md:82 |
| `STRATA_GLM_NO_MTP` | typed child env | docs/SETTINGS.md:83 |
| `STRATA_GLM_NO_SPEC` | typed child env | docs/SETTINGS.md:89 |
| `STRATA_GLM_NUMA` | typed child env | docs/SETTINGS.md:59 |
| `STRATA_GLM_PARALLEL_LOAD` | typed child env | docs/SETTINGS.md:45 |
| `STRATA_GLM_PCIE_SHARE` | typed child env | docs/SETTINGS.md:54 |
| `STRATA_GLM_POOL_STATS` | typed child env | docs/SETTINGS.md:137 |
| `STRATA_GLM_PREFETCH_AT` | typed child env | docs/SETTINGS.md:58 |
| `STRATA_GLM_PREFETCH_BLOCKS` | typed child env | docs/SETTINGS.md:58 |
| `STRATA_GLM_PREFETCH_N` | typed child env | docs/SETTINGS.md:58 |
| `STRATA_GLM_PREFETCH_RANK` | typed child env | docs/SETTINGS.md:58 |
| `STRATA_GLM_PREFILL_ATTN` | typed child env | docs/SETTINGS.md:114 |
| `STRATA_GLM_PREFILL_ATTN_CHECK` | typed child env | docs/SETTINGS.md:114 |
| `STRATA_GLM_PREFILL_CHUNK` | typed child env | docs/SETTINGS.md:61 |
| `STRATA_GLM_PREFILL_CPU` | typed child env | docs/SETTINGS.md:95 |
| `STRATA_GLM_PREFILL_CPU_ROW_MS` | typed child env | docs/SETTINGS.md:95 |
| `STRATA_GLM_PREFILL_MB` | typed child env | docs/SETTINGS.md:62 |
| `STRATA_GLM_PREFILL_SUB` | typed child env | docs/SETTINGS.md:106 |
| `STRATA_GLM_PREFILL_TAIL_SKIP` | typed child env | docs/SETTINGS.md:63 |
| `STRATA_GLM_PREFILL_TRACE` | typed child env | docs/SETTINGS.md:98 |
| `STRATA_GLM_PREFILL_WINDOW` | typed child env | docs/SETTINGS.md:64 |
| `STRATA_GLM_PRESTAGE` | typed child env | docs/SETTINGS.md:96 |
| `STRATA_GLM_PRESTAGE_ADAPT` | typed child env | docs/SETTINGS.md:96 |
| `STRATA_GLM_PROFILE_WEIGHT` | typed child env | docs/SETTINGS.md:120 |
| `STRATA_GLM_PROMOTE` | typed child env | docs/SETTINGS.md:78 |
| `STRATA_GLM_PROMOTE_FILL` | typed child env | docs/SETTINGS.md:80 |
| `STRATA_GLM_PROMOTE_MIN` | typed child env | docs/SETTINGS.md:79 |
| `STRATA_GLM_RAM_GB` | typed child env | docs/SETTINGS.md:39 |
| `STRATA_GLM_RAM_HEADROOM_GB` | typed child env | docs/SETTINGS.md:38 |
| `STRATA_GLM_RAM_RESIDENT` | typed child env | docs/SETTINGS.md:43 |
| `STRATA_GLM_RAM_SLACK` | typed child env | docs/SETTINGS.md:43 |
| `STRATA_GLM_READ_CHUNKS` | typed child env | docs/SETTINGS.md:60 |
| `STRATA_GLM_RESERVE_MB` | typed child env | maya.py:2241 (value from hip_reserve_mib, :642-648; the HIP calibration writes it into the config env); docs/SETTINGS.md:190-193 now documents MAYA_GLM_RESERVE_MB; the calibration flow is docs/SETTINGS.md:29 |
| `STRATA_GLM_SCORE` | typed child env | docs/SETTINGS.md:139 |
| `STRATA_GLM_SCORE_PREFILL` | typed child env | docs/SETTINGS.md:139 |
| `STRATA_GLM_SEQ_CTX` | typed child env | docs/SETTINGS.md:72 |
| `STRATA_GLM_SEQS` | typed child env | docs/SETTINGS.md:72 |
| `STRATA_GLM_SERVICE_IDLE_MS` | typed child env | docs/SETTINGS.md:94 |
| `STRATA_GLM_SLOT_DAYS` | typed child env | docs/SETTINGS.md:71 |
| `STRATA_GLM_SLOT_GB` | typed child env | docs/SETTINGS.md:70 |
| `STRATA_GLM_SLOT_KEEP` | typed child env | docs/SETTINGS.md:71 |
| `STRATA_GLM_SLOT_MIN` | typed child env | docs/SETTINGS.md:70 |
| `STRATA_GLM_SLOTS` | typed child env | docs/SETTINGS.md:68 (SP6 §4.9: slots off is the forced default — the table may move it, nothing unknown is ever sent; Task 4) |
| `STRATA_GLM_SPEC_CANCEL` | typed child env | docs/SETTINGS.md:90 |
| `STRATA_GLM_SPEC_HEAD` | typed child env | docs/SETTINGS.md:89 |
| `STRATA_GLM_SPEC_SAMPLE` | typed child env | docs/SETTINGS.md:90 |
| `STRATA_GLM_SPLIT` | typed child env | docs/SETTINGS.md:44 (SP6 §4.9: the forced split; glm.layer_split also renders --layer-split, serve/server.py:1274-1277; Task 4/7) |
| `STRATA_GLM_SPLIT_LAYER_MS` | typed child env | docs/SETTINGS.md:44 |
| `STRATA_GLM_SPLIT_LOG` | typed child env | docs/SETTINGS.md:44 |
| `STRATA_GLM_THINK_RESERVE` | typed config | docs/SETTINGS.md:141, serve/server.py:2279 (server-side reserve; rides glm.thinking_budget — C-3; Task 3) |
| `STRATA_GLM_TIMING` | typed child env | docs/SETTINGS.md:137 |
| `STRATA_GLM_TRUNK_KEEP` | typed child env | docs/SETTINGS.md:86 |
| `STRATA_GLM_TRUNK_KEEP_MAP` | typed child env | docs/SETTINGS.md:86 |
| `STRATA_GLM_VISION_LEND_MB` | typed child env | serve/server.py:4026 (the vision turn lends MB from the expert pool; the flow is docs/SETTINGS.md:29) |
| `STRATA_GLM_VRAM_EVICT` | typed child env | docs/SETTINGS.md:81 |
| `STRATA_GLM_WIN_ALLCPU` | typed child env | docs/SETTINGS.md:130 |
| `STRATA_GLM_WIN_CPU` | typed child env | docs/SETTINGS.md:130 |
| `STRATA_GLM_WIN_LANES` | typed child env | docs/SETTINGS.md:130 |
| `STRATA_GLM_WIN_PIPE` | typed child env | docs/SETTINGS.md:122 |
| `STRATA_GLM_WIN_SKIP` | typed child env | docs/SETTINGS.md:123 |
| `STRATA_GLM_WIN_STAGGER` | typed child env | docs/SETTINGS.md:130 |
| `STRATA_GLM_WIN_THREADS` | typed child env | docs/SETTINGS.md:123 |
| `STRATA_GLM_WIN_X3` | typed child env | docs/SETTINGS.md:133 |
| `STRATA_GLM_WIN_X3_POOLS` | typed child env | docs/SETTINGS.md:133 |
| `STRATA_MAX_BODY_MIB` | frontend behaviour | already typed: limits.chat.max_body_bytes (SP1); serve/server.py:2922, docs/SETTINGS.md:144 |
| `STRATA_WATCHDOG_S` | typed child env | docs/SETTINGS.md:143, src/program/generate.cpp:747 (engine-side watchdog; SP6 §4.9/M5 forces 0 pending the owner's sheet; Task 4) |
| `--max-context` | engine argv | maya.py:3148 (default 32768 when unset), :2228; Task 7 types glm.max_context at the pin default |
| `--prefill` | engine argv | maya.py:2229 (auto), :2284 keeps an operator's value; docs/SETTINGS.md:178-182; Task 7 |
| `--kv-streaming` | engine argv | maya.py:2229 (the KV_STREAMING constant :104), :2285; docs/SETTINGS.md:108; Task 7 |
| `--kv-resident` | engine argv | maya.py:2286; docs/SETTINGS.md:108 (the window stays at least 20480); Task 7 |
| `--parallel` | engine argv | maya.py:3885 (choices 1..8), :2291; replicas.parallel renders --parallel N inside the one child (C-4, M1 Task 10 pattern); Task 7 |
| `--expert-profile-save` | engine argv | docs/SETTINGS.md:164, maya.py:2285 (rides the save; M1 session.expert_profile_save pattern); Task 7 |
| `--expert-profile-save-every` | engine argv | docs/SETTINGS.md:164 (default 10 minutes), maya.py:2285; Task 7 |
| `--spec` | engine argv | docs/SETTINGS.md:323 (the verify window's tokens; MTP drafting, the DFlash2 drafter itself stays out per C-5); Task 7 |
| `--spec-min-p` | engine argv | docs/SETTINGS.md:324 (the confidence cut); Task 7 |
<!-- maya-typed:end -->

### Mapped to a Strata mechanism instead

<!-- maya-mapped:begin -->
| Maya option | Destination | Disposition note and the MAYA v1.1.21 read site |
| --- | --- | --- |
| `api_key` | — | SP1 token store is the only auth source (CFG-06); serve/server.py:4094, maya.py:2791 |
| `backend` | — | engine identity: the SP4 manifest + engine gate; serve/server.py:1284, maya.py:2752 |
| `STRATA_API_KEY` | — | SP1 token store is the only auth source (CFG-06); serve/server.py:3967 |
| `STRATA_ENGINE_QUIT_S` | — | the SP2 shutdown order (§3.7) is fixed by the supervisor; serve/server.py:1010, docs/SETTINGS.md:145 |
| `STRATA_ENGINE_WRAP_S` | — | the SP3 shutdown drain is fixed in the frontend (no per-request wrap-up); serve/server.py:4172, docs/SETTINGS.md:146 |
| `STRATA_FAIR_SLICE_S` | — | SP3 admission/pool scheduling (B8/B9) is the frontend's policy; serve/server.py:234, docs/SETTINGS.md:147 |
| `STRATA_HTTP_BACKLOG` | — | the listener backlog is fixed by the SP3 poll design (128 entries); serve/server.py:2913, docs/SETTINGS.md:144 |
| `--serve` | — | the supervision composes the engine's serve mode at every start; serve/server.py:437, maya.py:3158 |
| `--glm-pack` | manifest artifact | the SP4 manifest composes the pack role (Task 7); maya.py:2228 (the launcher's form) |
| `--expert-profile` | manifest artifact | the expert profile is an install/manifest artifact, not an operator path (Task 7); maya.py:2280, :2372-2374 |
<!-- maya-mapped:end -->

### Excluded keys — refused at config load

<!-- maya-rejected:begin -->
| Maya option | Excluded by (and the MAYA v1.1.21 read site) |
| --- | --- |
| `args` | spec §4 free-form process control (raw engine argv); serve/server.py:4106, engine_args :1274-1277 (Task 7 retires the glm53 pass-through) |
| `command` | spec §4 MCP command; serve/mcp.py:604 |
| `cwd` | spec §4 free-form process control; serve/server.py:4035, serve/mcp.py:104 |
| `env` | spec §4 raw env dict (Maya carries engine settings as raw env with no allowlist — the closed typed table replaces it); serve/server.py:1289, :3729 |
| `exe` | spec §4 free-form process control (engine identity from the SP4 manifest); serve/server.py:4035, maya.py:2757 |
| `headers` | spec §4 MCP headers; serve/mcp.py:251, :601 |
| `installer` | spec §4 PRIV-01 forbids update checks and self-update (the Maya updater block, serve/update.py); maya.py:2298, :2541, :2560; the block's sub-keys (models_dir, quant, gguf, draft, data_dir, speed_calibration) ride the parent reject |
| `lib_dirs` | spec §4 free-form process control (library search paths); serve/server.py:1291 |
| `log` | spec §4 free-form process control (the child's log path); serve/server.py:4009, :4035, maya.py:2503 |
| `mcp` | spec §4 MCP; serve/mcp.py:626 |
| `mcp_servers` | spec §4 MCP; serve/mcp.py:645 |
| `type` | spec §4 MCP entry type; serve/mcp.py:598 |
| `url` | spec §4 MCP url; serve/mcp.py:378, :597 |
| `mcpServers` | spec §4 MCP (Claude Desktop block); serve/mcp.py:646, serve/server.py:3970 (--mcp-config) |
| `MAYA_RESTART_ON_UPDATE` | spec §4 PRIV-01 forbids the self-updater restart; maya.py:2809 |
| `MAYA_UPDATE_CHECK` | spec §4 PRIV-01 forbids update checks (the Maya self-updater block); serve/update.py:75 |
| `STRATA_DEBUG` | spec §4 no new diagnostics surface (debug logging switch); serve/server.py:2430, :2465 |
| `STRATA_GLM_CPU_CAL` | spec §4 free-form process control (the `log` rule: a timing cache in an operator-named file); docs/SETTINGS.md:51 |
| `STRATA_GLM_DFLASH` | spec C-5: the DFlash2 drafter and its knobs stay rejected on the A7 licence ground (the drafter weights are CC BY-NC-ND 4.0, docs/SETTINGS.md:293) — not a knob-visibility call; docs/SETTINGS.md:322 |
| `STRATA_GLM_DFLASH_MIN` | spec C-5: the DFlash2 drafter and its knobs stay rejected on the A7 licence ground (the drafter weights are CC BY-NC-ND 4.0, docs/SETTINGS.md:293) — not a knob-visibility call; docs/SETTINGS.md:328 |
| `STRATA_GLM_DFLASH_PROF` | spec C-5: the DFlash2 drafter and its knobs stay rejected on the A7 licence ground (the drafter weights are CC BY-NC-ND 4.0, docs/SETTINGS.md:293) — not a knob-visibility call; docs/SETTINGS.md:134 |
| `STRATA_GLM_DFLASH_STATS` | spec C-5: the DFlash2 drafter and its knobs stay rejected on the A7 licence ground (the drafter weights are CC BY-NC-ND 4.0, docs/SETTINGS.md:293) — not a knob-visibility call; docs/SETTINGS.md:134 |
| `STRATA_GLM_MTP_GGUF` | spec §4 model files come from the SP4 manifest (a draft GGUF picked by free path); docs/SETTINGS.md:83 |
| `STRATA_GLM_ROUTE_LOG` | spec §4 free-form process control (the `log` rule: every route written to an operator-named prefix); docs/SETTINGS.md:138 |
| `STRATA_GLM_SLOT_DIR` | spec §4 free-form process control (the `cwd` rule: the slot folder moves off the pack root); docs/SETTINGS.md:70 |
| `STRATA_GLM_USAGE` | spec §4 free-form process control (the `log` rule: an operator-named file the engine writes after every request); docs/SETTINGS.md:67 |
| `STRATA_MOCK_RELOAD_S` | spec §4 the mock engine is excluded (serve/server.py:3945 --engine mock); serve/server.py:1587 |
| `--dflash` | spec C-5: DFlash2 drafter rejected on the A7 licence ground (CC BY-NC-ND weights, docs/SETTINGS.md:293); maya.py:2301 |
| `--dump-routing` | spec §4 free-form process control (the trace dump writes an operator-named file); docs/SETTINGS.md:165 |
| `--engine` | spec §4 free-form process control (server-mode select; the mock engine is excluded, serve/server.py:3945); maya.py:2792 |
<!-- maya-rejected:end -->

## Run the native inference server

`strata-secure-server` is the first runnable native chat path. It starts one
local Strata engine as a direct child (never through a shell), communicates
only through private stdio, and exposes authenticated `GET /health`, `GET
/v1/models`, `GET /v1/models/<id>`, and text-only `POST /v1/chat/completions`
— complete JSON or streamed SSE (`"stream": true`, SP3 M2). Its
default fixed native profile uses the local GPT-2-byte-BPE tokenizer pack and
the fixed Qwen ChatML renderer; the separately selected GLM-5.3 profile is
documented below. It deliberately rejects tools, MCP and downloads, and a
request whose `model` is not the one model selected at startup. Images are an
input path only for a vision-capable model (`vision.enabled` plus the
manifest `mmproj` artifact, SP5 M1) and only as `data:` URLs — an http(s)
image URL is refused by name, never fetched.

`strata serve` (SP5 M1) runs exactly this boot in the foreground from the
config file alone — no daemonization, no `server.json`, no lock (the pin has
none, and the PX lifecycle writer has never existed); it serves the installed
managed model, and `--expert` stays a `strata-secure-server` flag. `strata
version` prints the frontend and pin versions — the tag version governs, and
the engine's own self-version is informational only. `strata key show [--env]`
prints the locally generated API token (only when the store is readable by
this uid — the SP1 store rules), and `strata key rotate` replaces it atomically;
after a rotate, restart the server and reconfigure every app that used the old
token.

### Built-in chat page and the keyless loopback mode (owner decisions 2026-10-21)

`listener.web_ui = true` serves a small chat page at `/` (with `/ui/app.js`
and `/ui/app.css`). It is three bundled files from `secure_frontend/web/`,
embedded in the binary at configure time (`cmake/EmbedWebUi.cmake`: ASCII, LF,
nothing read from disk at run time). It loads nothing from any other server,
and every model reply is rendered as text, never as HTML. Only these exact
`GET` targets are public, and only after the `Host` and `Origin` checks: the
files hold no secret and reach no route.

- **The login is the API key.** The page asks for it, checks it against
  `/v1/models` and keeps it in that browser tab only (`sessionStorage`). It
  sends it only as `Authorization: Bearer` to this server, with cookies off.
  Every API route still requires the key; the key field has no form name, so
  no submission can put it in a URL.
- **Its own policy:** the page's responses carry `Content-Security-Policy:
  default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';
  img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
  (no inline script, style or handler) and `Cross-Origin-Opener-Policy:
  same-origin`. Every other response keeps `default-src 'none'`.
- **Streaming chat** through `/v1/chat/completions` (`stream: true`, with usage),
  with the reasoning shown apart from the answer, Stop (which disconnects, so the
  server sends STOP), a model picker and an optional `max_tokens`.

`listener.loopback_without_key = true` answers the API and the page with no key
at all. On the page, the login is skipped. It is accepted only with a loopback
`listener.host` (`127.0.0.1`, `::1`, `localhost`), and refused next to a
`token.source` (a key that would never be read). `--check` reports `token: not
used`, and the boot prints a warning line on stderr. `Host` and `Origin` are
still checked, and chat still needs `Content-Type: application/json`. So
another web site cannot use it from a browser: DNS rebinding fails the Host
check, a page on another origin fails the Origin check, and a plain form post
fails the Content-Type check. Any program or user on the same machine can
use it.

### Routes, errors, headers (SP3)

Every route requires `Authorization: Bearer <token>` (except the built-in
page's files and the keyless loopback mode, above); authentication happens
when the request header is complete, before any body byte. Unknown paths are
404 `not_found` and wrong methods 405 `method_not_allowed` (with `Allow`) only
after authentication — unauthenticated requests get 401 on every path, so the
route table is not observable without a token. Errors are fixed JSON bodies
`{"error":{"message","type","param","code"}}` — the message is a compile-time
literal, `param` names at most a fixed-list key, never request bytes:

| Status | `code` | Message |
| --- | --- | --- |
| 400 | `invalid_request` | The request is malformed or not supported. |
| 400 | `invalid_json` | The request body is not valid JSON within the allowed limits. |
| 400 | `unsupported_parameter` | This parameter is not supported by this server. |
| 400 | `extension_disabled` | Tools, functions and extensions are disabled on this server. |
| 400 | `context_length_exceeded` | The prompt exceeds the model context or the configured prompt limit. |
| 401 | `invalid_api_key` | Missing or invalid API key. (`WWW-Authenticate: Bearer`) |
| 403 | `forbidden` | The request origin or host is not allowed. |
| 404 | `not_found` / `model_not_found` | Not found. / The requested model is not served here. |
| 405 | `method_not_allowed` | Method not allowed. (`Allow`) |
| 408 | `request_timeout` | The request was not received in time. |
| 411 | `length_required` | A Content-Length body is required; chunked bodies are not accepted. |
| 413 | `request_too_large` | The request body is too large. |
| 414 | `request_line_too_long` | The request line is too long. |
| 415 | `unsupported_media_type` | Send application/json. |
| 417 | `expectation_failed` | Unsupported Expect header. |
| 431 | `header_too_large` | The request header is too large. |
| 500 | `internal_error` | Internal error. |
| 503 | `server_busy` | The server is busy; retry later. (`Retry-After: 1`) |
| 503 | `engine_unavailable` | The local engine is not available. (`Retry-After: 5` or none) |
| 503 | `engine_error` | The local engine could not complete the request. (`x-should-retry: false`) |
| 503 | `server_shutting_down` | The server is shutting down. |
| 505 | `http_version_not_supported` | Only HTTP/1.1 is supported. |

Every response carries `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff`,
`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` (the
built-in page's files carry their own, above),
`Referrer-Policy: no-referrer` and `Date`. `Vary: Origin` and (only for
configured origins) `Access-Control-Allow-Origin` appear as per §4.4.

`POST /v1/chat/completions` with `"stream": true` (SP3 M2) is served as SSE:
`Content-Type: text/event-stream` under HTTP/1.1 chunked framing,
`Cache-Control: no-store`, no `Content-Length`. The event sequence is a role
chunk, content chunks coalesced to at most 16 KiB of text each
(`api_constants::kMaxDeltaTextBytes`) with no SSE event above
`api_constants::kMaxSseEventBytes` (128 KiB), a `: keep-alive` comment every
`limits.http.stream_keepalive_ms` while no content flows, an optional usage
chunk when `stream_options.include_usage` is true, a final chunk with
`finish_reason` (`stop` or `length`), `data: [DONE]`, then the terminal chunk.
Headers go out only after the engine lease, the context re-check and `GEN`.
After the headers, engine failures arrive as in-stream error events with the
§7.2 codes (`engine_error`, `engine_unavailable`, `internal_error`,
`server_shutting_down`), each followed by `data: [DONE]` and the terminal
chunk. A stream cancelled by the client, by `limits.http.write_stall_ms` or by
a missed shutdown budget gets neither `data: [DONE]` nor the terminal chunk, so
SDKs see the truncation. Keys that govern streams:
`limits.http.write_stall_ms` (no progress → cancel + `STOP`),
`limits.http.response_write_deadline_ms` (the tail once the generation ended),
`limits.http.stream_keepalive_ms`, and `limits.chat.max_generated_bytes` (the
pump's held-text bound). The loopback-only client library used by the tests
(spec §6.1, the only `connect()` in the frontend) also serves the future
`strata run`; its command-line form, `strata-api-probe`, is test-only and
never installed.

Default limits (all config keys; see the table below): 8 workers, 4 queued
generations (queue timeout 300 s), 4 connections per remote address (loopback
exempt), 10 s header / 30 s request deadlines, 64 KiB request cap (49152-byte
chat body), 10 s write stall / 60 s response-write deadline, `logging.requests`
off (when on: one fixed-field stderr line per request under a token bucket —
never tokens, prompts, paths or payload text; a reply cut by a token the
frontend refuses to output answers the generic `500 internal_error` and logs
the log-only code `undecodable_token`).

The launch described in this section is the `--expert` bring-up mode: the
operator supplies `engine.profile`, `roots.tokenizer_pack` (required) and the
weight flags other than `--native` in `engine.args`, and `engine.model_id`
names a `.gguf` in the local inventory (no managed model; `/v1/models` lists
only `engine.model_id` and its `model.aliases`, as for a managed model — SP3
E9). Pass `--expert` when serving and with `--check` (which
then validates this mode); `init` accepts it and ignores it.

The model directory must already contain the selected `.gguf`; the tokenizer
pack must already contain `vocab.json`, `merges.txt`, and `token_type.json`.
The server adds `--serve` and, for this default profile, supplies shard 1 via
`--native <model>` built from the local inventory entry named by `--model-id`
(appended last); never pass `--native` yourself. The expert pack (`--pack DIR`)
and the other weight sources (`--ple-gguf`, `--embd-gguf`, `--native-head-gguf`,
`--native-dense-gguf`, `--mtp`) are operator-supplied with `--engine-arg`
(`engine.args` in the config file) until SP5 models the whole launch. With
`engine.mtp` set to `false` the draft layer's own options (`--mtp`,
`--spec-min-p`, `--batch-mtp`) are dropped from the engine's argv at every
start — the pinned `mtp: false` behaviour (`strata_control/draft_layer.py`);
prompt-lookup `--spec` stays. The
engine loads `--pack` unconditionally and its default is the cwd-relative
`pack/full`, so a real run must pass it. Give every engine switch and value as
its own `--engine-arg` (its own array element in `engine.args`). With the
`qwen` profile, `--native`, `--serve`, `--batch`, `--slots` and `--vision` are
rejected there, in both `--flag value` and `--flag=value` forms, and
`--check` names `engine.args` as the key at fault.
The engine child receives a fixed environment rendered by the frontend (see
`docs/security/threat-model.md`, Engine process isolation); nothing is
inherited from the server's environment, so pass every engine setting as a
typed option or `--engine-arg`. The engine path (`engine.executable`)
must be absolute and name a regular file not writable by group or others; the
engine receives the canonical models root, never the configured spelling.

The flags below can equally live in the config file (see
[Configuration](#configuration)); the token must be at least 32 bytes.

```sh
export STRATA_API_TOKEN='replace-with-a-long-random-token-of-32-bytes-or-more'
./out/build/linux-gcc/strata-secure-server --expert \
  --models-root /absolute/path/to/models \
  --model-id local-model-name \
  --tokenizer-pack /absolute/path/to/tokenizer-pack \
  --engine /absolute/path/to/strata-engine \
  --engine-arg --pack --engine-arg /absolute/path/to/pack \
  --state-dir /absolute/path/to/owner-only-state-dir \
  --token-env STRATA_API_TOKEN
```

For example, make a request without putting the token into a URL or request
body:

```sh
curl --fail --header 'Host: 127.0.0.1:8080' \
  --header "Authorization: Bearer $STRATA_API_TOKEN" \
  --header 'Content-Type: application/json' \
  --data '{"model":"local-model-name","messages":[{"role":"user","content":"Hello"}],"max_tokens":64}' \
  http://127.0.0.1:8080/v1/chat/completions
```

This is not yet a release claim for every upstream model/template or vision
profile. The native server fails closed for profiles it cannot represent; do
not substitute the legacy Python service to bypass that boundary.

### GLM-5.3 Flash profile

Select `--profile glm53` to use the native, fixed GLM-5.3 text profile. It is
text-only, non-streaming, and greedy through the private `GEN`/`T`/`DONE`
stdio protocol. The only additional engine record accepted in this mode is its
strictly validated `PP` prefill-progress heartbeat. Tools, images, remote URLs,
templates, downloads, analytics, and MCP remain disabled.

This profile emits fixed GLM framing
`[gMASK]<sop>...<|assistant|><think>` and rejects message text that contains
any framing literal. It does not build, download, or embed the LightTransport
fork. Build and audit a compatible `strata-glm-decode` executable separately,
then pass that build's required positional engine arguments unchanged with
repeated `--engine-arg`. The server adds only `--serve` immediately after the
executable; it does not reinterpret or synthesize positional arguments, does
not add `--native`, and rejects only `--serve` and NUL bytes in them. With
`glm53`, `engine.args` must not be empty (`--check --expert` reports it as required). The
tokenizer pack must match that exact engine/model build and provide the fixed
GLM framing markers as CONTROL tokens.

```sh
./out/build/linux-gcc/strata-secure-server --expert \
  --profile glm53 \
  --models-root /absolute/path/to/models \
  --model-id glm53-local \
  --tokenizer-pack /absolute/path/to/glm53-tokenizer-pack \
  --engine /absolute/path/to/strata-glm-decode \
  --engine-arg /absolute/path/to/models/glm53-local.gguf \
  --engine-arg /absolute/path/to/fork-required-config \
  --token-env STRATA_API_TOKEN
```

The positional-argument example is illustrative. Use the separately audited
engine's local documentation for its exact required order and values; do not
expose its own listener or run its network-facing service beside this server.

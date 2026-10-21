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
- Every listener requires a bearer token, including on loopback. `init`
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
| `reasoning.effort` | string | unset | - | - | Thinking level for requests that name none: none, low, medium or high (pin levels); unset names none. |
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

The pinned upstream Strata (`upstream.version`, tag `v0.2.1.3`) reads 87 config
keys and 31 environment knobs (the verbatim grep in
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
| `aliases` | frontend behaviour | serve/server.py:8046, set_aliases :3764-3777; runconfig.py:34 (M1 Task 8: model.aliases — /v1/models lists them, chat matches exactly) |
| `allowed_hosts` | frontend behaviour | already typed (SP1/SP3 listen); serve/server.py:8066 |
| `answer_room` | typed config | serve/server.py:8014 (`is not False`), formula :4704-4716; typed only: the pin's formula sits in its thinking parser, not in our §7.2 room rule (Ruling T8-d, Task 15) |
| `anthropic_thinking` | typed config | serve/server.py:8102 (M1 Task 5: reasoning.anthropic_thinking) |
| `codex_compaction_cache` | typed config | serve/server.py:8044 (M1 Task 9: session.codex_compaction_cache) |
| `codex_thread_titles` | typed config | serve/server.py:8043 (M1 Task 9: session.codex_thread_titles) |
| `cors_origins` | frontend behaviour | already typed (SP3 B12: listener.cors_origins); serve/server.py:8063 |
| `effort_position` | engine argv | serve/server.py:2836 (M1 Task 5: reasoning.effort_position composes the engine's --tail-role-token) |
| `elastic` | frontend behaviour | serve/server.py:2550, :7927 (M1 Task 7: engine.elastic; Tasks 11-12 consume it) |
| `elastic_idle_s` | frontend behaviour | serve/server.py:2552, :3854 (M1 Task 7: engine.elastic_idle_s) |
| `elastic_mib` | frontend behaviour | serve/server.py:2551, :3832 (M1 Task 7: engine.elastic_mib; /v1/vram headroom) |
| `engine_silence_s` | frontend behaviour | serve/server.py:941, default 300 at :276, engine_silence_s() :2861-2868; runconfig.py:39 (M1 Task 8: the pump's silence watchdog) |
| `env_to_user` | typed config | serve/server.py:8110 (M1 Task 9: session.env_to_user) |
| `expert_profile_save` | engine argv | serve/server.py:3000-3005 (M1 Task 9: --expert-profile-save; an operator-owned flag wins, :3001) |
| `expert_profile_save_every` | engine argv | serve/server.py:3004-3005, default 10 at :2996 (M1 Task 9: --expert-profile-save-every; rides the save, :3001) |
| `fit_max_tokens` | frontend behaviour | serve/server.py:7996 (M1 Task 5: engine.fit_max_tokens) |
| `gpu` | engine argv | already typed (SP2 engine.gpu; compose renders --gpu); serve/server.py:2815 |
| `gpu_order` | engine argv | serve/server.py:3112 (M1 Task 7) |
| `gpu_policy` | typed config | serve/images.py:173 (M1 Task 7: engine.gpu_policy, re-scoped to the vision child's GPU turn; the pin's use is the image-generation turn) |
| `hip_ordinal` | engine argv | serve/server.py:3023 (M1 Task 7) |
| `host` | frontend behaviour | already typed (SP1 listen.host); serve/server.py:7862 |
| `idle_unload_s` | frontend behaviour | serve/server.py:4100-4109, :8081 (M1 Task 6: supervisor idle timer) |
| `keep_files` | typed config | serve/images.py:188 (`or 64`); typed only: the consumer is the pin's ImageService and D-9 keeps image generation out (Ruling T9-e, M1 Task 9) |
| `layer_split` | engine argv | serve/server.py:2877 (M1 Task 7) |
| `lazy_load` | frontend behaviour | serve/server.py:7925, :966-993 (M1 Task 6: the first request spawns the same composed launch) |
| `max_n` | frontend behaviour | serve/images.py:103 (M1 Tasks 11-12: vision.max_n; the pin's cap lives on the images block) |
| `max_side` | frontend behaviour | serve/images.py:102 (M1 Task 12: vision.max_side pre-decode cap) |
| `max_tokens` | request rule | serve/server.py:2564 (vision encoder at the pin); engine.max_tokens re-scoped as the request output ceiling (added, C-1; Ruling T8-e: caps at the §7.2 resolve site) |
| `min_free_vram_mib` | frontend behaviour | serve/server.py:8083 (M1 Task 7: engine.min_free_vram_mib) |
| `min_tokens` | request rule | serve/server.py:2566 (vision encoder at the pin); engine.min_tokens re-scoped as the request output floor (added, C-1; Ruling T8-e: lifts at the §7.2 resolve site) |
| `mtp` | engine argv | strata_control/draft_layer.py is_off; serve/server.py:2922-2925 (M1 Task 6: engine.mtp drops --mtp/--spec-min-p/--batch-mtp at every start) |
| `need_mib` | frontend behaviour | serve/images.py:156 (M1 Task 11: vision.need_mib; added security bound) |
| `parallel` | engine argv | serve/server.py:2955-2975 (replicas.parallel renders --batch N, :2975; window PARALLEL_MAX 8 at :2954; cap 1024 from the pin's own bound :7845, M1 Task 10) |
| `reasoning_budget_tokens` | typed config | serve/server.py:8120 (M1 Task 5: reasoning.budget_tokens) |
| `reasoning_close_retry` | typed config | serve/server.py:8015 (M1 Task 5: reasoning.close_retry) |
| `reasoning_effort` | typed config | serve/server.py:7433 (M1 Task 5: reasoning.effort) |
| `reasoning_loop_recovery` | typed config | serve/server.py:8129 (M1 Task 5: reasoning.loop_recovery) |
| `repeat_stop_tokens` | frontend behaviour | serve/server.py:197 (REPEAT_STOP_TOKENS 256), the pin's detector is frontend-side at :4908, notice :5088, 0 = off :8115 (Ruling T8-f: no GEN key) |
| `sampling` | typed config | serve/server.py:7482 (M1 Task 4: defaults.sampling.*) |
| `slot_save_path` | typed config | serve/server.py:8094 + slot_save_dir :3469-3481; the pin uses it FRONTEND-side for its /slots file store (:3698-3715) — no argv append (Ruling T9-a, M1 Task 9) |
| `split_skip_if_fits` | engine argv | serve/server.py:2941 (M1 Task 7) |
| `threads` | engine argv | serve/server.py:2562 (M1 Task 11: vision.threads; the only pin read of `threads`, inside the vision reader_args — the flag lands on the encoder child's argv) |
| `tool_call_recovery` | typed config | serve/server.py:8106 (M1 Task 9: session.tool_call_recovery) |
| `trusted_origins` | frontend behaviour | already typed (SP3 origins family); serve/server.py:8064 |
| `uma` | frontend behaviour | serve/images.py:23, :334 (M1 Task 7: engine.uma; Tasks 11-12 consume it) |
| `vision` | typed config | serve/server.py:2930 (M1 Task 11: the vision.* block) |
| `vram_elastic` | engine argv | serve/server.py:2945 (M1 Task 7) |
| `vram_segment_mib` | engine argv | serve/server.py:2947 (M1 Task 7) |
| `STRATA_ALLOWED_HOSTS` | frontend behaviour | same semantics as allowed_hosts, already typed; serve/server.py:3516 |
| `STRATA_BATCH_MTP` | engine argv | serve/server.py:2972; engine.mtp (M1 Task 6) |
| `STRATA_ENGINE_READY_S` | frontend behaviour | already typed: ready_timeout (SP1); serve/server.py:291 |
| `STRATA_ENGINE_STALL_S` | frontend behaviour | serve/server.py:307; engine.silence_s (M1 Task 8) |
| `STRATA_MAX_BODY_MIB` | frontend behaviour | already typed: limits.chat.max_body_bytes (SP1); serve/server.py:5660 |
| `STRATA_VISION_ENCODE_S` | frontend behaviour | serve/server.py:328 (M1 Task 12: vision encode-timeout row) |
| `STRATA_VISION_READY_S` | frontend behaviour | serve/server.py:327 (M1 Task 11: vision.ready_timeout_s; 0 = wait for ever, :291) |
| `vram_reserve_mib` | engine argv | serve/runconfig.py:42 renders --vram-reserve-mib (M1 Task 7) |
<!-- parity-typed:end -->

### Mapped to a Strata mechanism instead

<!-- parity-mapped:begin -->
| Upstream option | Where it lives in Strata instead (and the pin read site) |
| --- | --- |
| `api_key` | SP1 token store is the only auth source (CFG-06: no secret in config); serve/server.py:7869 |
| `arch` | model identity comes from the SP4 manifest/GGUF inventory; serve/server.py:7648 |
| `backend` | engine identity: SP4 manifest + engine gate; serve/server.py:7680 |
| `images` | spec D-9: image generation is out, the route answers 404 like an unknown route; serve/server.py:8016 |
| `max_queue` | the SP3 row limits.concurrency.max_queued_generations already carries queue admission (pin bound 0..4096 at serve/server.py:7835, derived default :3602-3604; Ruling T8-a) |
| `model_name` | served-model identity comes from the SP4 manifest; serve/images.py:183 |
| `native` | the SP4 manifest composes --native (engine_arguments); serve/images.py:126 |
| `out_dir` | spec D-9 image generation is out; serve/images.py:185 |
| `quant` | quant identity comes from the SP4 manifest; serve/images.py:282 |
| `queue_timeout` | the SP3 row limits.concurrency.queue_timeout_ms already carries admission waiting (pin bound 0.1..600 at serve/server.py:7839; Ruling T8-a) |
| `reload` | image-generation card reload mode (spec D-9); the vision child's lifecycle follows the vision/elastic rows; serve/images.py:176 |
| `sigmas` | spec D-9 image generation is out; serve/images.py:120 |
| `steps` | spec D-9 image generation is out; serve/images.py:104 |
| `timeout_s` | the SP3 row limits.engine.generation_timeout_s already carries the generation deadline (pin: generation job timeout at serve/images.py:226; Ruling T8-b) |
| `tokenizer` | the SP4 manifest carries the tokenizer; serve/server.py:7883 |
| `STRATA_ADMIT_MAX_WAIT_S` | serve/server.py:311; admission waiting is already carried by limits.concurrency.queue_timeout_ms (Ruling T8-a) |
| `STRATA_ADMIT_SHORT_FIRST` | SP3 admission ordering is the pool policy (B8); serve/server.py:314 |
| `STRATA_API_KEY` | SP1 token store is the only auth source; serve/server.py:7216 |
| `STRATA_DROP_CACHE_ON_EXIT` | the SP2 shutdown order (§3.7) is fixed by the supervisor; serve/cache_drop.py:1 |
| `STRATA_HTTP_BACKLOG` | the listener backlog is fixed by the SP3 poll design (128 entries); serve/server.py:7021 |
| `STRATA_KEEP_EMPTY_TURNS` | the frontend serves stateless requests; conversation history is the client's; serve/frontend.py:60 |
| `STRATA_KEEP_LEFTOVERS` | lifecycle is teardown + respawn (M1 Task 6); serve/server.py:128 |
| `STRATA_LIFELINE` | SP2 supervision replaces the lifeline watcher (pdeathsig, monitor handle); serve/lifeline.py:33 |
| `STRATA_NO_PRESET` | launch is SP4 manifest-composed; serve/server.py:7448 |
| `STRATA_OFFLINE` | PRIV-01: the frontend never reaches the network; enforced by design and the DL-01 proof; serve/server.py:3240 |
| `STRATA_REQUEST_LINES` | the wire record is fixed by docs/security/engine-protocol-limits.md; serve/server.py:639 |
| `STRATA_START_RETRIES` | respawn retries belong to the SP2 RestartTracker (restart_policy.hpp); serve/server.py:609 |
| `STRATA_TOKENIZER` | the SP4 manifest carries the tokenizer; serve/test_detok.py:21 |
<!-- parity-mapped:end -->

### Excluded keys — refused at config load

<!-- parity-rejected:begin -->
| Upstream option | Excluded by (and the pin read site) |
| --- | --- |
| `api_monitor` | spec §4 web/desktop/telemetry; serve/server.py:8072 |
| `args` | spec §4 free-form process control; serve/server.py:3114 |
| `batch_telemetry` | spec §4 telemetry endpoints; serve/server.py:897 |
| `before_load` | spec §4 command execution; serve/server.py:7899 |
| `before_load_ignore_failure` | spec §4 command execution; serve/server.py:8090 |
| `before_load_strict` | spec §4 command execution; serve/server.py:8091 |
| `before_load_timeout_s` | spec §4 command execution; serve/server.py:8086 |
| `command` | spec §4 MCP command; serve/mcp.py:610 |
| `cwd` | spec §4 free-form process control; serve/mcp.py:106 |
| `env` | spec §4 raw env dict; serve/server.py:3228 |
| `exe` | spec §4 free-form process control (engine identity comes from the SP4 manifest); serve/server.py:7674 |
| `headers` | spec §4 MCP headers; serve/mcp.py:257 |
| `lib_dirs` | spec §4 free-form process control; serve/images.py:135 |
| `log` | spec §4 free-form process control; serve/replicas.py:99 |
| `mcp` | spec §4 MCP; serve/mcp.py:632 |
| `mcp_servers` | spec §4 MCP; serve/mcp.py:651 |
| `open_browser` | spec §4 web/desktop; serve/server.py:8191 |
| `prevent_sleep` | spec §4 desktop; serve/server.py:8031 |
| `replica_cpus` | spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7549 |
| `replica_load_tokens` | spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7583 |
| `replicas` | spec C-4: N-child replica scheduling is the accepted narrowing; serve/replicas.py:44 |
| `telemetry_read_key` | spec §4 telemetry endpoints; serve/server.py:8053 |
| `type` | spec §4 MCP entry type; serve/mcp.py:604 |
| `url` | spec §4 MCP url; serve/mcp.py:384 |
| `user_args` | spec §4 free-form process control; serve/server.py:2918 |
| `STRATA_BATCH_TELEMETRY` | spec §4 telemetry endpoints; serve/server.py:899 |
| `STRATA_BATCH_TRACE` | spec §4 no new web/diagnostics surface; serve/server.py:821 |
| `STRATA_DEBUG` | spec §4 no new web/diagnostics surface; serve/mcp.py:130 |
| `STRATA_FAIL_ONCE` | spec §4 free-form process control (fault-injection knob); serve/test_server.py:4610 |
| `STRATA_OWNER_ATTEST_KEY` | spec §4 signing material, deferred to SP7; serve/server.py:7820 |
| `STRATA_PARALLEL_SOLO` | spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:1727 |
| `STRATA_REPLICA_START` | spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7565 |
| `STRATA_RUNTIME_PROFILE` | spec §4 no new web/diagnostics surface; serve/lifeline.py:265 |
| `STRATA_SYCL_BIN` | spec §4 free-form process control (external binary path); serve/server.py:2824 |
| `STRATA_TELEMETRY_KEY` | spec §4 telemetry endpoints; serve/server.py:8053 |
| `STRATA_VERIFY_TRACE` | spec §4 no new web/diagnostics surface; serve/server.py:1213 |
| `mcpServers` | spec §4 MCP (Claude Desktop block); serve/mcp.py:648 |
<!-- parity-rejected:end -->

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

### Routes, errors, headers (SP3)

Every route requires `Authorization: Bearer <token>`; authentication happens
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
`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
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
never tokens, prompts, paths or payload text).

The launch described in this section is the `--expert` bring-up mode: the
operator supplies `engine.profile`, `roots.tokenizer_pack` (required) and the
weight flags other than `--native` in `engine.args`, and `engine.model_id`
names a `.gguf` in the local inventory (no managed model; `/v1/models` lists
the whole inventory). Pass `--expert` when serving and with `--check` (which
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

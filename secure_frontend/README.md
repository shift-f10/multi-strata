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
job (pending: that job has not yet run them).

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
- The socket listener (`HttpSocketServerLimits`, from `limits.http.*`) gives
  each connection a total deadline for the whole request (default 30 s) and a
  send timeout, rejects a request over `limits.http.max_request_bytes`
  (default 64 KiB), binds `::` as IPv6-only, survives clients that close or
  reset early, and stops only when the listening socket itself fails.
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
  `starting` → `200` with `engine=starting` (READY is consumed on the first
  request; eager READY is SP2), `ready`/`generating` → `200`, `failed` (or a
  stopped child) → `503`. The engine
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
are pending the `windows-msys2-clang` CI job. Tokens shorter than 32 bytes are
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
        --models-root ~/models --tokenizer-pack ~/tok --engine ~/strata/strata --model-id qwen-local
    strata-secure-server --check --config ~/.config/strata/config.json
    strata-secure-server --config ~/.config/strata/config.json

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
| `limits.http.request_deadline_ms` | integer | `30000` | 1-3600000 | - | Total time to read one request, header and body. |
| `limits.http.max_request_bytes` | integer | `65536` | 4096-16777216 | - | Largest request (header and body) the listener and parser accept. |
| `limits.http.max_header_bytes` | integer | `16384` | 1024-65536 | - | Largest header block; at most limits.http.max_request_bytes. |
| `limits.http.max_headers` | integer | `64` | 8-256 | - | Most header fields. |
| `limits.http.max_request_line_bytes` | integer | `4096` | 256-16384 | - | Longest request line; at most limits.http.max_header_bytes. |
| `limits.chat.max_body_bytes` | integer | `49152` | 1-16777216 | - | Largest chat request body; at most max_request_bytes minus max_header_bytes. |
| `limits.chat.max_messages` | integer | `128` | 1-128 | - | Most messages in one chat request. |
| `limits.chat.max_message_bytes` | integer | `65536` | 1-65536 | - | Largest single message content. |
| `limits.chat.max_prompt_tokens` | integer | `32768` | 1-262144 | - | Largest tokenized prompt sent to the engine. |
| `limits.chat.max_completion_tokens` | integer | `4096` | 1-16384 | - | Largest max_tokens a request may ask for. |
| `limits.chat.default_max_tokens` | integer | `256` | 1-16384 | - | max_tokens when a request omits it; at most limits.chat.max_completion_tokens. |
| `limits.chat.max_generated_bytes` | integer | `1048576` | 1-16777216 | - | Largest generated text returned. |
| `limits.engine.ready_timeout_s` | integer | `900` | 1-86400 | - | How long the first request waits for the engine's READY (upstream STRATA_ENGINE_READY_S). |
| `limits.engine.generation_timeout_s` | integer | `120` | 1-86400 | - | Total time for one generation before STOP. |
| `limits.engine.stop_drain_timeout_s` | integer | `5` | 1-600 | - | Time to drain to DONE after STOP before the engine is marked failed. |
| `limits.concurrency.max_concurrent_requests` | integer | `1` | 1-1 | - | Requests served at once; only 1 until SP3. |
| `roots.models` | string | required | - | `--models-root` | Absolute directory of .gguf files. The root itself may be a symlink; nothing below it may be. |
| `roots.tokenizer_pack` | string | required | - | `--tokenizer-pack` | Absolute directory with vocab.json, merges.txt, token_type.json. |
| `roots.secret` | string | unset | - | `--secret-root` | Absolute directory holding the token file. Default: the config file's directory. |
| `roots.logs` | string | unset | - | - | Absolute log directory (created 0700; unused in SP1). |
| `roots.cache` | string | unset | - | - | Absolute cache directory (created 0700; unused in SP1). |
| `token.source` | string | `file:token` | - | `--token-file, --token-env` | file:<relative path below roots.secret> or env:<NAME>. Metadata only; the token is never in the config. |
| `engine.profile` | string | `qwen` | - | `--profile` | qwen or glm53. |
| `engine.executable` | string | required | - | `--engine` | Absolute path of the engine; a regular file not writable by group or others. |
| `engine.model_id` | string | required | - | `--model-id` | Model ID from the local inventory. |
| `engine.args` | string array | `[]` | - | `--engine-arg (repeatable)` | Extra engine arguments; frontend-owned and unsupported flags are rejected. |
<!-- config-keys:end -->

`roots.secret` defaults to the config file's directory only for a `file:` token
source; an `env:` source never opens it. `roots.logs` and `roots.cache` may be
absent if their parent is a private directory; only serving and `init` create
them. `--check` creates nothing.

## Run the native inference server

`strata-secure-server` is the first runnable native chat path. It starts one
local Strata engine as a direct child (never through a shell), communicates
only through private stdio, and exposes authenticated `GET /health`, `GET
/v1/models`, and non-streaming, text-only `POST /v1/chat/completions`. Its
default fixed native profile uses the local GPT-2-byte-BPE tokenizer pack and
the fixed Qwen ChatML renderer; the separately selected GLM-5.3 profile is
documented below. It deliberately rejects streaming, tools, images, URLs, MCP,
downloads, and a request whose `model` is not the one model selected at startup.

The model directory must already contain the selected `.gguf`; the tokenizer
pack must already contain `vocab.json`, `merges.txt`, and `token_type.json`.
The server adds `--serve` and, for this default profile, supplies shard 1 via
`--native <model>` built from the local inventory entry named by `--model-id`
(appended last); never pass `--native` yourself. The expert pack (`--pack DIR`)
and the other weight sources (`--ple-gguf`, `--embd-gguf`, `--native-head-gguf`,
`--native-dense-gguf`, `--mtp`) are operator-supplied with `--engine-arg`
(`engine.args` in the config file) until SP5 models the whole launch. The
engine loads `--pack` unconditionally and its default is the cwd-relative
`pack/full`, so a real run must pass it. Give every engine switch and value as
its own `--engine-arg` (its own array element in `engine.args`). With the
`qwen` profile, `--native`, `--serve`, `--batch`, `--slots` and `--vision` are
rejected there, in both `--flag value` and `--flag=value` forms, and
`--check` names `engine.args` as the key at fault.
The engine child receives an empty environment allowlist, so encode all
required engine options explicitly. The engine path (`engine.executable`)
must be absolute and name a regular file not writable by group or others; the
engine receives the canonical models root, never the configured spelling.

The flags below can equally live in the config file (see
[Configuration](#configuration)); the token must be at least 32 bytes.

```sh
export STRATA_API_TOKEN='replace-with-a-long-random-token-of-32-bytes-or-more'
./out/build/linux-gcc/strata-secure-server \
  --models-root /absolute/path/to/models \
  --model-id local-model-name \
  --tokenizer-pack /absolute/path/to/tokenizer-pack \
  --engine /absolute/path/to/strata-engine \
  --engine-arg --pack --engine-arg /absolute/path/to/pack \
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
`glm53`, `engine.args` must not be empty (`--check` reports it as required). The
tokenizer pack must match that exact engine/model build and provide the fixed
GLM framing markers as CONTROL tokens.

```sh
./out/build/linux-gcc/strata-secure-server \
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

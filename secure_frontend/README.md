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

`read_token()` resolves a source only when required. On Linux it canonicalizes
the configured root and target, opens every protected-file component with
`O_NOFOLLOW`, and accepts only a current-user-owned regular file with no
group/world permissions. On Windows it opens each component without following
reparse points, verifies final paths remain beneath the root, and requires a
current-user-owned protected DACL. The Windows branch is fail-closed and
compiles in the llvm-mingw cross build, but it has no runtime test yet:
`secure_frontend_token_reader_tests` is built only on UNIX, so not even the
`windows-msys2-clang` CI job exercises it.

## Security contract

- The default bind is the IPv4 loopback literal `127.0.0.1:8080`.
- Every listener requires an explicitly supplied, non-blank API key, including
  literal loopback addresses. Hostnames, including `localhost`, are treated as
  non-loopback because their address resolution is outside this module's
  control.
- Ports must be TCP ports in the inclusive range 1–65535.
- Hosts must be an IP literal or a syntactically valid DNS hostname. Wildcards,
  CIDR notation, bracketed IPv6 literals, whitespace, and malformed labels are
  rejected.
- A non-loopback bind additionally requires `allow_remote = true`; it defaults
  to `false` and cannot be enabled implicitly by selecting a remote host.
- Wildcard binds (`0.0.0.0` and `::`) additionally require
  `allow_wildcard_bind = true`; a regular remote-listening opt-in is not enough.
- Protected-file token sources are portable relative paths only; traversal,
  absolute/UNC/device/drive/ADS forms and Windows reserved device names are
  rejected before a platform reader resolves the path below its canonical root.
- HTTP messages are bounded, require exactly one trusted `Host`, reject
  untrusted or ambiguous browser `Origin`, keep CORS off by default, and require
  exactly one bearer token before reaching route dispatch.
- The socket listener (`HttpSocketServerLimits`) gives each connection a 30 s
  total deadline for the whole request and a send timeout, answers a request
  over 64 KiB with `413`, binds `::` as IPv6-only, survives clients that close
  or reset early, and stops only when the listening socket itself fails.
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
  `ready` and `generating` are `200`; `starting` (still loading) and `failed`
  (or a stopped child) are `503`. The engine
  facts these limits rely on are in
  [`docs/security/engine-protocol-limits.md`](../docs/security/engine-protocol-limits.md).

## Build

No packages are fetched during CMake configuration or testing. On Linux, create
the tool environment once (no root needed). It installs `-r requirements.txt
-r scripts/dev/requirements-dev.txt` into `.venv-dev`: cmake/ninja are pinned in
`requirements.txt`; pytest and its dependencies are pinned in
`scripts/dev/requirements-dev.txt`. Offline use (`STRATA_WHEEL_DIR` set) needs
every wheel those two files name **plus** a pip wheel (`pip-*.whl`): on a fresh
venv the pip bootstrap takes pip from `STRATA_WHEEL_DIR` as well.

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

On Windows (wine or CI) `ctest` runs 19 entries. Only
`secure_frontend_token_reader_tests` is built on UNIX alone, so the Windows
protected-file reader has no runtime test yet; the socket-server tests run on
Windows too. `engine_process_tests` and `engine_stdio_process_tests` start and
terminate through the Job on MSYS2; the grandchild assertion
(`job_object_terminates_grandchild`) runs only there (wine passes it but is not
authoritative for Job Objects).

## Runnable smoke server

`secure-frontend-smoke` is a local, privacy-preserving test server. It serves
authenticated `GET /health` and `GET /v1/models` only; it does not start the
inference engine and intentionally does not implement chat completion yet.

```sh
export STRATA_SMOKE_API_KEY='choose-a-long-random-value'
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
the implementation is fail-closed and has no Windows runtime test yet.

Remote/wildcard binds are rejected unless the corresponding explicit flags are
provided. CORS remains disabled, and the executable neither sends outbound
traffic nor starts MCP, telemetry, analytics, update checks, or downloads.

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
`--native-dense-gguf`, `--mtp`) are operator-supplied with `--engine-arg` until
SP1/SP5 model the whole launch. The engine loads `--pack` unconditionally and
its default is the cwd-relative `pack/full`, so a real run must pass it. Give
every engine switch and value as its own `--engine-arg`. `--native`, `--serve`,
`--batch`, `--slots` and `--vision` are rejected there, in both `--flag value`
and `--flag=value` forms.
The engine child receives an empty environment allowlist, so encode all
required engine options explicitly.

```sh
export STRATA_API_TOKEN='replace-with-a-long-random-token'
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
not add `--native`, and rejects only `--serve` and NUL bytes in them. The
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

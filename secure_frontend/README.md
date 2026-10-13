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
current-user-owned protected DACL. The Windows branch is fail-closed and still
needs MSVC/Windows runtime validation before a release claim.

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
  exactly one bearer token before reaching route dispatch. The current success
  body is a placeholder until real routes are connected.
- Engine children are started directly without a shell, with a minimal
  allowlisted environment. Embedded NUL bytes in the executable path, argv, or
  environment are rejected before the platform process API can truncate them.
  Linux uses a process group for cleanup; Windows uses a Job Object.

## Build and test

No packages are fetched during configuration or testing.

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

On Windows, use a Visual Studio developer shell or a CMake preset supplied by
the parent project. `ws2_32` is linked automatically for IP-literal parsing.

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
./build/strata-secure-smoke-server \
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
the implementation is fail-closed pending Windows CI/runtime validation.

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
Give each engine switch and value as its own `--engine-arg`; `--serve` is added
by the server and must not be supplied. The engine child receives an empty
environment allowlist, so encode all required engine options explicitly.

```sh
export STRATA_API_TOKEN='replace-with-a-long-random-token'
./build/strata-secure-server \
  --models-root /absolute/path/to/models \
  --model-id local-model-name \
  --tokenizer-pack /absolute/path/to/tokenizer-pack \
  --engine /absolute/path/to/strata-engine \
  --engine-arg --model --engine-arg /absolute/path/to/models/local-model-name.gguf \
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
executable; it does not reinterpret or synthesize positional arguments. The
tokenizer pack must match that exact engine/model build and provide the fixed
GLM framing markers as CONTROL tokens.

```sh
./build/strata-secure-server \
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

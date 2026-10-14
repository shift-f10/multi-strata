# Engine protocol limits (Strata v0.1.43, `upstream/src/program/generate.cpp`)

Facts the frontend relies on; verified against the engine source on 2026-10-13.

| Fact | Engine behavior | Frontend consequence |
| --- | --- | --- |
| stdin line length | Unbounded `std::string`; no truncation, no error | Frontend caps its own GEN line at min(32 + 11 × ctx, 16 MiB `kProtocolMaxLineBytes`) bytes and never relies on the engine to reject |
| Prompt form | One line: `GEN <max_new> [k=v ...] <id,id,...>`; no multi-line form | Non-streaming prompt only; one request in flight |
| Context rule | `n + max_new + 8 <= --max-context` else `ERR ...` and the engine stays alive | Frontend rejects with 400 before GEN using the same rule |
| READY | `READY <max_context> stop` | ctx parsed from READY sizes the outbound GEN cap (min(32 + 11 × ctx, 16 MiB)); the inbound record cap is a fixed 8192 bytes (`kMaxReadLineBytes`); a fixed 32768 context is never advertised |
| STOP | Honored only after the GEN has been picked up; always followed by `DONE ... cancel` | Frontend sends STOP only after a generation has started; drains to DONE |
| `nonfinite` | `DONE ... nonfinite`; next request restarts from token 0 | 503 for that request; protocol stays idle |
| Model path | `--pack DIR` is the expert/weight directory, loaded unconditionally, default cwd-relative `pack/full`; `--native <shard1.gguf>` is a separate shard source; other weight flags: `--ple-gguf`, `--embd-gguf`, `--native-head-gguf`, `--native-dense-gguf`, `--mtp`; no positional args. Upstream (`setup.py`) launches `--pack <pack> --native <shard1> [--ple-gguf <ple>] ...` | Strata profile only: the frontend supplies shard 1 as `--native <models_root/artifact>` from the inventory (`engine_arguments`, appended last) and rejects `--native` from `--engine-arg`. The operator MUST pass `--pack` for a real run (otherwise the engine resolves `pack/full` against its cwd); `--pack` and the other weight flags pass through (as `engine.args` since SP1) until SP5 models the whole launch. The GLM-5.3 profile passes arguments through (next row) |
| GLM-5.3 profile | Engine CLI not characterized | Frontend passes arguments through unchanged (NUL/--serve rejected) and does not supply the model path; model-id linkage is Strata-only until SP5/SP6 |
| Network | None in the engine; no host/port/bind/http flags | Deny-list covers only frontend-owned flags |
| Unsupported modes | `--batch` and its alias `--slots` (BT/BDONE), `--vision` (GENI) | Rejected in `--engine-arg` until the frontend implements their protocol |
| Windows stdin writes | Engine reads stdin with blocking `getline` | The stdin pipe buffer is requested at kMaxWriteLineBytes + 4096 so one GEN record should not block; Win32 treats the size as advisory, and only the `windows-msys2-clang` CI job can confirm it; overlapped writes are SP2 work |

## Configuration keys and internal constants (SP1)

Tunable limits are configuration keys (`secure_frontend/README.md` key table;
defaults in `include/secure_frontend/config_defaults.hpp`): listener backlog,
request deadline, request/header/request-line sizes and header count, chat body
/ message / prompt / completion / generated-text limits, `ready_timeout_s`
(default 900 s, upstream `STRATA_ENGINE_READY_S`), generation and STOP-drain
timeouts, and `max_concurrent_requests` (only 1 until SP3).

These stay internal because they are format or protocol facts, not tuning:
`kProtocolMaxLineBytes` 16 MiB and the 8192-byte inbound record cap; the
`EngineStdioProcess` buffers; process timings (10 ms poll, 1 s post-kill, 250 ms
grace — SP2); POSIX launch `kReportFd`/`kLiftFloor`/`kSweepCap`; the 1000 ms
minimum send budget; 50 ms EMFILE backoff; the 100 ms / 256 KiB half-close drain;
tokenizer-pack caps (64 MiB file, 1 Mi entries, 16 KiB token, 8 MiB decoded);
model ID ≤ 128 bytes; chat `model` field ≤ 256 bytes; token ≤ 256 bytes; token
file ≤ 4 KiB; the frontend-owned and unsupported engine flags.

The chat `model` field bound (256 bytes, `chat_schema.cpp` `kMaximumModelBytes`)
is a parsing bound, not a second model-ID rule: the field must still equal the
configured `engine.model_id`, whose grammar caps it at 128 bytes, so a 129–256
byte value parses and is then rejected as a model mismatch.

### `EngineProtocolLimits`: internal backstops, and a recorded range gap

`EngineProtocolLimits` (`include/secure_frontend/engine_protocol_client.hpp`)
holds `max_prompt_tokens`, `max_generated_tokens` and `max_new_tokens`, each
262144, and `secure_server_main.cpp` builds the client with `{}` (these
defaults). They are classified as **internal protocol backstops**, not
configuration keys: they bound what the protocol client will put on the GEN
line or accumulate from `T` records no matter what the layers above decide, and
they are not in spec §4's list of keys. The operator-facing limits are the
`limits.chat.*` keys, enforced before `begin_generation` is called.

Recorded gap (not fixed in SP1): two configuration ranges are wider than an
internal cap below them, so the effective limit is the smaller of the two and a
configured value above the cap has no effect.

- `limits.chat.max_prompt_tokens` accepts up to 1048576, but the protocol
  client refuses a prompt over 262144 tokens ("generation request exceeds
  protocol limits"). With a configured value above 262144 and an engine
  context large enough to pass the context check, a prompt between the two is
  still refused (the chat route answers `503`, as it does for every execution
  error). `max_completion_tokens` (≤ 16384) is always below `max_new_tokens`,
  so that pair cannot diverge.
- `limits.chat.max_messages` accepts up to 1024, but the Qwen and GLM renderers
  (`kMaximumMessages` 128 in `qwen_prompt_renderer.cpp` and
  `glm_prompt_renderer.cpp`) refuse more than 128 messages, so a request with
  129 or more messages is refused even when the configured limit allows it.

Either the ranges are narrowed to the internal caps or the caps are derived from
the validated configuration; the choice is left to the task that next touches
chat limits (recorded in `docs/AGENT_HANDOFF.md`). The defaults (32768 prompt
tokens, 128 messages) are within both caps.

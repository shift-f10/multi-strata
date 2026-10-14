# Engine protocol limits (Strata v0.1.44.1, `upstream/src/program/generate.cpp`)

Facts the frontend relies on; verified against the engine source on 2026-10-13
(`v0.1.43`) and re-verified for `v0.1.44.1` on 2026-10-14. The `qwen35moe` and
`strata_kq` rows are new at `v0.1.44.1`. The SP2 rows (Windows stdin writes,
rewritten; READY wait, fatal lines, exit codes, GPU selection, added) were
checked against the `v0.1.44.1` submodule on 2026-10-14 (SP2 Task 28); line
numbers are for that tag.

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
| Windows stdin writes | The engine reads stdin on its own reader thread with `read(0)` / `_read(0)` (`generate.cpp:9433-9469`), which normally drains the pipe | Every engine-stdin write has two bounds. Per chunk: on Windows the frontend's end of the stdin pipe is overlapped and writes go in 64 KiB chunks, each allowed 1 s (cancelled with `CancelIoEx` when it makes no progress); on POSIX the stdin write end is `O_NONBLOCK` and each `poll` wait for writability is at most 1 s (a limit per wait, not strictly per 64 KiB). Overall (R1, owner ruling 2026-10-14): every chunk wait is also capped by the request's remaining deadline. A GEN write and the read to `DONE` share one generation deadline: the read gets only what is left of it. `STOP` and `QUIT` are each bounded by 1 s. A GEN write that misses either bound fails the request and the supervisor kills the engine (`killed_by_supervisor(write_timeout)`, counted). Windows behavior is confirmed only by the `windows-msys2-clang` job (pending) |
| `qwen35moe` family switch (new at `v0.1.44.1`, CUDA/HIP builds only) | When the GGUF named by `--native`/`--model` declares `general.architecture = qwen35moe`, `main` hands the whole argv to a separate engine (`upstream/src/qwen35/q36_engine.cu`, `strata::qwen35::run`) before normal parsing. Its serve loop differs: context rule `n + max_new > ctx` (no `+ 8`), only `GEN` (no `GENI`/batch), no `nonfinite` finish, no `QUIT` handling (exits on stdin EOF), no `--pack`, and unknown `--flags` are skipped instead of fatal | Our `+ 8` check is stricter, so still safe. Not yet modeled: the frontend must not assume a `qwen35moe` model behaves as above (QUIT alone does not end it; deny-listed flags would be ignored rather than rejected by the engine). Open until SP5 |
| `strata_kq` shared library (new at `v0.1.44.1`, CUDA builds only) | With `STRATA_MMQ_KQ=1` (set by default by the `qwen35moe` path unless already set) the engine opens `strata_kq.dll` / `libstrata_kq.so` by full path from its own executable's folder (`LoadLibraryA` / `dlopen`, `upstream/src/prefill/mmq_kq_loader.cpp`); missing file falls back to FP16. Its own DLL dependencies use the default Windows search order | Packaging/inventory must ship or exclude it explicitly and verify it like the engine binary; the engine folder must not be writable by the service user |
| READY wait (SP2) | Upstream's service waits `STRATA_ENGINE_READY_S`, default 900 s (`serve/server.py:268`) | The supervisor reads READY as soon as the engine starts, within `limits.engine.ready_timeout_s` (default 900 s). `/health` is `503` `engine=starting` until then. A miss kills the engine (`killed_by_supervisor(ready_timeout)`) and counts a failure |
| Fatal lines (SP2) | `ERR verify: timed out at layer `, `ERR verify batch: timed out at layer `, `ERR verify: an earlier window never finished`, `ERR verify batch: an earlier window never finished` (upstream `FATAL_PREFIXES`, `serve/server.py:734-735`; upstream's `_pump` stops at such a line and never publishes the trailing `DONE`, `:952-967`). The engine lives on but is unusable | A prefix match, before or after READY, fails the request with a generic `503`, kills the engine (`killed_by_supervisor(fatal_line)`) and restarts it. A trailing `DONE` is never accepted |
| Exit codes (SP2) | `QUIT` ends the serve loop (`generate.cpp:10368`); a CUDA fault after an `ERR` leaves at once with `_Exit(1)` (`:11796-11805`); the no-progress watchdog calls `abort()` (`:9658-9667`; SIGABRT on POSIX, exit 3 or `0xC0000409` on Windows). Exit codes are not part of the protocol | Classified only for the frontend's own log line (`engine generation <n> ended: <kind>`). Every end before shutdown counts as a failure, except, at most 3 times in a row with no `DONE` in between, a drain failure after a client-requested `STOP` (`client_stop_drain_failed`, SP3 D-2; nothing issues a client `STOP` before SP3) |
| GPU selection (SP2) | `--gpu LIST` makes the engine set `CUDA_DEVICE_ORDER`/`CUDA_VISIBLE_DEVICES` (or `HIP_VISIBLE_DEVICES`) itself (`generate.cpp:1843-1865`; usage `:706-708`) | The frontend renders `--gpu` from its typed `engine.gpu` option and refuses `--gpu` in `--engine-arg`. Strata family: no GPU variable is ever in the engine's environment. The SP6 `glm` family will render `CUDA_DEVICE_ORDER`/`CUDA_VISIBLE_DEVICES` from typed configuration (mechanism only today; not reachable from configuration). Not GPU-verified |

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

### `EngineProtocolLimits` and the renderer caps: internal backstops

`EngineProtocolLimits` (`include/secure_frontend/engine_protocol_client.hpp`)
holds `max_prompt_tokens`, `max_generated_tokens` and `max_new_tokens`, each
262144, and `secure_server_main.cpp` builds the client with `{}` (these
defaults). They are classified as **internal protocol backstops**, not
configuration keys: they bound what the protocol client will put on the GEN
line or accumulate from `T` records no matter what the layers above decide, and
they are not in spec §4's list of keys. The operator-facing limits are the
`limits.chat.*` keys, enforced before `begin_generation` is called.

The Qwen and GLM prompt renderers (`qwen_prompt_renderer.cpp`,
`glm_prompt_renderer.cpp`) carry three more internal constants:
`kMaximumMessages` 128, `kMaximumMessageBytes` 64 KiB (65536) and
`kMaximumPromptBytes` 512 KiB, the cap on the rendered prompt text (template
markup plus every message) before tokenization. The rendered-prompt cap is an
internal constant, not a configuration key (controller ruling, SP1 final fix
wave): with the defaults a chat body is at most 49152 bytes, far below it. An
operator who raises `limits.http.max_request_bytes` and
`limits.chat.max_body_bytes` above roughly 512 KiB can send messages that pass
the per-message and message-count limits but whose rendered prompt exceeds
512 KiB; such a request is refused at planning (`503`), as before.

Since the SP1 final fix wave the configuration ranges match the enforced caps
(spec §9.5: every value the schema accepts is one the server can honour):

| Key | Range | Enforced cap it matches |
| --- | --- | --- |
| `limits.chat.max_messages` | 1–128 | renderer `kMaximumMessages` 128 |
| `limits.chat.max_message_bytes` | 1–65536 | renderer `kMaximumMessageBytes` 64 KiB |
| `limits.chat.max_prompt_tokens` | 1–262144 | `EngineProtocolLimits::max_prompt_tokens` 262144 |

`max_completion_tokens` (≤ 16384) is always below `max_new_tokens`, so that
pair cannot diverge. The defaults (128 messages, 65536 message bytes, 32768
prompt tokens) are inside these ranges. `cfg01_chat_ranges_match_enforced_caps`
pins each cap (the cap is accepted, one above it is `out_of_range`).

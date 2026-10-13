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
| Model path | `--pack DIR` is the expert/weight directory, loaded unconditionally, default cwd-relative `pack/full`; `--native <shard1.gguf>` is a separate shard source; other weight flags: `--ple-gguf`, `--embd-gguf`, `--native-head-gguf`, `--native-dense-gguf`, `--mtp`; no positional args. Upstream (`setup.py`) launches `--pack <pack> --native <shard1> [--ple-gguf <ple>] ...` | Strata profile only: the frontend supplies shard 1 as `--native <models_root/artifact>` from the inventory (`engine_arguments`, appended last) and rejects `--native` from `--engine-arg`. The operator MUST pass `--pack` for a real run (otherwise the engine resolves `pack/full` against its cwd); `--pack` and the other weight flags pass through until SP1/SP5 model the whole launch. The GLM-5.3 profile passes arguments through (next row) |
| GLM-5.3 profile | Engine CLI not characterized | Frontend passes arguments through unchanged (NUL/--serve rejected) and does not supply the model path; model-id linkage is Strata-only until SP5/SP6 |
| Network | None in the engine; no host/port/bind/http flags | Deny-list covers only frontend-owned flags |
| Unsupported modes | `--batch` and its alias `--slots` (BT/BDONE), `--vision` (GENI) | Rejected in `--engine-arg` until the frontend implements their protocol |
| Windows stdin writes | Engine reads stdin with blocking `getline` | The stdin pipe buffer is requested at kMaxWriteLineBytes + 4096 so one GEN record should not block; Win32 treats the size as advisory, and only the `windows-msys2-clang` CI job can confirm it; overlapped writes are SP2 work |

# Engine protocol limits (Strata v0.1.43, `src/program/generate.cpp`)

Facts the frontend relies on; verified against the engine source on 2026-10-13.

| Fact | Engine behavior | Frontend consequence |
| --- | --- | --- |
| stdin line length | Unbounded `std::string`; no truncation, no error | Frontend caps its own GEN line at min(32 + 11 × ctx, 16 MiB `kProtocolMaxLineBytes`) bytes and never relies on the engine to reject |
| Prompt form | One line: `GEN <max_new> [k=v ...] <id,id,...>`; no multi-line form | Non-streaming prompt only; one request in flight |
| Context rule | `n + max_new + 8 <= --max-context` else `ERR ...` and the engine stays alive | Frontend rejects with 400 before GEN using the same rule |
| READY | `READY <max_context> stop` | ctx parsed from READY sizes every limit; a fixed 32768 is never advertised |
| STOP | Honored only after the GEN has been picked up; always followed by `DONE ... cancel` | Frontend sends STOP only after a generation has started; drains to DONE |
| `nonfinite` | `DONE ... nonfinite`; next request restarts from token 0 | 503 for that request; protocol stays idle |
| Model path | `--native <shard1.gguf>` or `--pack DIR`; no positional args | Frontend owns `--native` (engine_arguments, next task) |
| Network | None in the engine; no host/port/bind/http flags | Deny-list covers only frontend-owned flags |
| Unsupported modes | `--batch` (BT/BDONE), `--vision` (GENI) | Rejected in `--engine-arg` until the frontend implements their protocol |
| Windows stdin writes | Engine reads stdin with blocking `getline` | Windows stdin writes: pipe buffer ≥ kMaxWriteLineBytes + 4096 so one GEN record never blocks; overlapped writes are SP2 work |

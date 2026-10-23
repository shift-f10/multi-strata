# strata-gemma4-engine

Our own engine for Gemma 4 26B-A4B (spec `docs/superpowers/specs/2026-10-22-gemma4-engine-design.md`,
plan `docs/superpowers/plans/2026-10-22-gemma4-plan2-3-engine.md`). It is a supervised child of
`strata-secure-server` and speaks the same stdio protocol as upstream's engine (`strata_0143`), so the
frontend's `gemma4` profile drives it like the Qwen engine. NVIDIA only; nothing of `upstream/` is
compiled or linked.

## Build (the owner's box)

```
engines\gemma4\build-windows.bat
```

MSVC v143 + CUDA 13.0 (`sm_89`), Ninja, Release, into `out\gemma4-engine`. Host code builds with
`/W4 /WX`, device code with `-Werror=all-warnings`. Tests: `ctest --test-dir out\gemma4-engine`
(label `gpu` needs the GPU; label `model` needs the GGUF named by `G4_MODEL_FILE` at configure time).

## Model

Exactly the Gemma 4 26B-A4B text shape (30 layers, 2816 wide, 128 experts top-8), in Q8_0, BF16 and
F32 tensors — the owner's `gemma-4-26B-A4B-it-UD-Q8_K_XL.gguf`. The loader refuses any other
architecture, shape, quant type or unknown tensor with a fixed message (`src/g4_model.cpp`).

## Flags

| Flag | Meaning |
| --- | --- |
| `--native GGUF` | the model file (frontend-owned: the server composes it) |
| `--serve` | the stdio protocol (inserted by the server) |
| `--gpu i[,j]` | CUDA devices in PCI order (the first is used) |
| `--max-context N` | 1-262144 (default 32768); the full layers' f16 KV costs 20 KiB a token |
| `--chunk N` | prompt tokens per forward pass, 1-8192 (used up to 1024; default 512) |
| `--kv f16` | the cache precision (`f32` is refused in v1) |
| `--expert-vram GiB` | the VRAM given to expert slots (default: the free VRAM less 640 MiB) |
| `--expert-slots N` | slots per layer instead of the budget |
| `--no-graph`, `--hybrid-rows N`, `--cpu-threads N` | accepted, no effect in v1 |

Test-only (refused with `--serve`): `--tokens ids [--n N] [--force ids] [--dump-full-logits F]
[--dump-layers F]`, `--bench-pp N`, `--bench-tg N`, `--check`.

## How it runs

- Dense weights, attention and the tied embedding/head in VRAM (Q8_0 repacked into int8 and fp16
  scale planes); every expert in pinned host RAM (23.5 GiB for the Q8 file); as many experts per layer
  as fit in VRAM slots, moved toward the most-routed experts after each prompt chunk and every 32
  decoded tokens. The GPU reads the other experts from pinned RAM over PCIe.
- Decode: matvec kernels, split-K attention over the f16 caches (sliding layers: a 2,048-row ring).
  Prompts: dequantised weights through cuBLAS SGEMM, attention as cuBLAS batched GEMMs with a masked
  softmax, experts grouped by expert.
- Protocol: `INFO …`, `READY <ctx> stop`; `GEN <max_new> [k=v …] <ids>` → `PP`, `T <id>`, `DONE …`
  (stops by itself on `<eos>` and `<turn|>`); `STOP`; `QUIT`. A new prompt reuses the held tokens'
  common prefix when the held tail past it fits the ring's spare rows.

## Validation

`docs/validation/gemma4/2026-10-22-engine-parity-and-speed.md`: llama.cpp parity at its own
backend-to-backend floor, 47-80 tok/s decode, 860-1,100 tok/s prompts on the RTX 4080 SUPER.
Tools: `tools/g4_llama_dump.cpp` (test-only llama.cpp side), `tools/g4_parity.py`,
`tools/g4_paths_agree.py`, `tools/g4_serve_smoke.py`.

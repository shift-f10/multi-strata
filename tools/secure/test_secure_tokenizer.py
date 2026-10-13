"""extract() through tools/secure/secure_tokenizer.py ships the declared pre-tokenizer's pattern.

Upstream's extract() always writes the Qwen35 pattern; the wrapper must rewrite it for GLM packs.
The GGUF here is a tiny metadata-only v3 file written with struct: no weights, no numpy, no network.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from secure_tokenizer import GLM4_PATTERN, QWEN35_PATTERN, bytes_to_unicode, extract, main  # noqa: E402

GGUF_STRING, GGUF_ARRAY = 8, 9


def _string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack("<Q", len(raw)) + raw


def _strings(values: list[str]) -> bytes:
    return struct.pack("<IQ", GGUF_STRING, len(values)) + b"".join(_string(v) for v in values)


def write_tiny_gguf(path: Path, pre: str) -> Path:
    tokens = list(bytes_to_unicode().values()) + ["12", "123"]
    entries = [
        ("tokenizer.ggml.model", GGUF_STRING, _string("gpt2")),
        ("tokenizer.ggml.pre", GGUF_STRING, _string(pre)),
        ("tokenizer.ggml.tokens", GGUF_ARRAY, _strings(tokens)),
        ("tokenizer.ggml.merges", GGUF_ARRAY, _strings(["1 2", "12 3"])),
    ]
    blob = struct.pack("<IIQQ", 0x46554747, 3, 0, len(entries))  # "GGUF", v3, 0 tensors
    for key, type_id, payload in entries:
        blob += _string(key) + struct.pack("<I", type_id) + payload
    path.write_bytes(blob)
    return path


def shipped(out_dir: Path) -> dict:
    return json.loads((out_dir / "tokenizer" / "tokenizer.json").read_text(encoding="utf-8"))


def test_extract_ships_the_glm_pattern_for_a_glm_pack(tmp_path):
    out_dir = tmp_path / "pack"
    cfg = extract(write_tiny_gguf(tmp_path / "glm.gguf", "chatglm-bpe"), out_dir)
    assert cfg["pre"] == "chatglm-bpe"
    assert shipped(out_dir)["pre_pattern"] == GLM4_PATTERN
    assert "CHATGLM4" in shipped(out_dir)["pre_pattern_source"]
    assert shipped(out_dir) == cfg


def test_cli_keeps_the_qwen_pattern_for_a_qwen35_pack(tmp_path):
    out_dir = tmp_path / "pack"
    assert main(["--gguf", str(write_tiny_gguf(tmp_path / "qwen.gguf", "qwen35")), "--out", str(out_dir)]) == 0
    assert shipped(out_dir)["pre_pattern"] == QWEN35_PATTERN
    assert "QWEN35" in shipped(out_dir)["pre_pattern_source"]

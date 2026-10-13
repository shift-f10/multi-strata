"""tools/secure/secure_tokenizer.py - GLM pre-tokenizer aliases over upstream's tokenizer, without editing it.

Upstream's `upstream/tools/strata_tokenizer.py` (the git submodule, never edited) knows only the `qwen35`
pre-tokenizer.  GLM-5.3 tokenizer packs declare `glm4` or the older `chatglm-bpe` alias, whose regex caps
numeric runs at three digits.  This module imports upstream's tokenizer and adds:

  * GLM4_PATTERN and pre_tokenizer_pattern(pre) -> (regex, provenance);
  * Tokenizer, a subclass that recompiles `_re` from the declared `pre`;
  * extract(), which calls upstream's extract() and rewrites `pre_pattern`/`pre_pattern_source` in the
    pack's tokenizer.json, because upstream ships the Qwen35 pattern for every pack.

The GLM regex was transcribed from lighttransport/Strata `glm53f` @ 4894c996 `tools/strata_tokenizer.py`
(see docs/PROVENANCE.md).  Upstream's module inserts its own directory into sys.path for gguf_reader, so it
is imported here as a top-level module from upstream/tools.

Coupling to upstream internals (not a public API; re-verify on every upstream pointer bump, see
docs/AGENT_HANDOFF.md "Update upstream"):

  * `strata_tokenizer.Tokenizer._re` - the compiled pre-tokenizer regex this subclass replaces;
  * `strata_tokenizer.Tokenizer.__init__` positional argument order
    `(tokens, merges, token_types, pre, special_ids)` and its `self.pre` attribute;
  * `strata_tokenizer.extract(gguf_path, out_dir)` returning the config dict (with `pre`, `vocab_size`,
    `n_merges`) and writing it to `<out_dir>/tokenizer/tokenizer.json`, the file rewritten here (extract()
    raises if that file is missing rather than creating it);
  * the module-level `QWEN35_PATTERN` and `bytes_to_unicode`.
"""
from __future__ import annotations

import json
import pathlib
import sys

import regex

_UPSTREAM_TOOLS = pathlib.Path(__file__).resolve().parents[2] / "upstream" / "tools"
if not (_UPSTREAM_TOOLS / "strata_tokenizer.py").is_file():
    raise ImportError("upstream/tools/strata_tokenizer.py is missing: run `git submodule update --init` "
                      "from the repository root")
if str(_UPSTREAM_TOOLS) not in sys.path:
    sys.path.insert(0, str(_UPSTREAM_TOOLS))
import strata_tokenizer as _upstream  # noqa: E402

QWEN35_PATTERN = _upstream.QWEN35_PATTERN
bytes_to_unicode = _upstream.bytes_to_unicode

# llama.cpp's LLAMA_VOCAB_PRE_TYPE_CHATGLM4.  GLM-5.3 tokenizer packs identify
# this as either `glm4` or the older `chatglm-bpe` alias.  The three-digit cap
# is semantic: using the Qwen pattern here tokenizes every digit separately,
# while accepting arbitrarily long numeric runs changes BPE merge boundaries.
GLM4_PATTERN = (
    r"(?:'[sS]|'[tT]|'[rR][eE]|'[vV][eE]|'[mM]|'[lL][lL]|'[dD])"
    r"|[^\r\n\p{L}\p{N}]?\p{L}+"
    r"|\p{N}{1,3}"
    r"| ?[^\s\p{L}\p{N}]+[\r\n]*"
    r"|\s*[\r\n]+|\s+(?!\S)|\s+"
)
GLM4_PRE_NAMES = ("glm4", "chatglm-bpe")


def pre_tokenizer_pattern(pre: str) -> tuple[str, str]:
    """Return the fixed regex and provenance for a declared GGUF pre-tokenizer.

    Unknown pre-tokenizers retain the historic Qwen35 fallback so this utility
    remains usable for existing Strata packs.  A caller that needs exact
    compatibility must validate `pre` against its model profile before use.
    """
    if pre in GLM4_PRE_NAMES:
        return (GLM4_PATTERN,
                ".ref/llama.cpp src/llama-vocab.cpp (LLAMA_VOCAB_PRE_TYPE_CHATGLM4)")
    return (QWEN35_PATTERN,
            ".ref/llama.cpp src/llama-vocab.cpp L396 (LLAMA_VOCAB_PRE_TYPE_QWEN35)")


class Tokenizer(_upstream.Tokenizer):
    """Upstream's tokenizer with the pre-tokenizer regex chosen by the declared `pre`."""

    def __init__(self, tokens: list[str], merges: list[str], token_types: list[int] | None = None,
                 pre: str = "qwen35", special_ids: dict[str, int] | None = None):
        super().__init__(tokens, merges, token_types, pre, special_ids)
        self._re = regex.compile(pre_tokenizer_pattern(self.pre)[0])


def extract(gguf_path, out_dir) -> dict:
    """Upstream's extract(), then ship the declared pre-tokenizer's pattern in tokenizer.json."""
    cfg = _upstream.extract(gguf_path, out_dir)
    cfg["pre_pattern"], cfg["pre_pattern_source"] = pre_tokenizer_pattern(cfg["pre"])
    path = pathlib.Path(out_dir) / "tokenizer" / "tokenizer.json"
    if not path.is_file():
        raise RuntimeError("upstream extract() did not write %s: upstream layout changed; re-verify the wrapper "
                           "(tools/secure/secure_tokenizer.py, see its module docstring)" % path)
    path.write_text(json.dumps(cfg, ensure_ascii=False, indent=1), encoding="utf-8")
    return cfg


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Write a pack's tokenizer/ with the declared pre-tokenizer's pattern")
    ap.add_argument("--gguf", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    cfg = extract(args.gguf, args.out)
    print("tokenizer: pre=%s vocab=%d merges=%d" % (cfg["pre"], cfg["vocab_size"], cfg["n_merges"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

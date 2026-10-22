"""Dev-only generator for SP6 §5.5: the GLM tokenizer fixtures and the C++ Unicode class tables.

Run from anywhere (nothing here runs MAYA's or llama.cpp's code, R-1):

    .venv-dev/bin/python tools/secure/gen_glm_tokenizer_fixtures.py

It writes exactly two files, both committed:

  * `secure_frontend/tests/fixtures/glm-tokenize.txt` - one self-describing pack
    (vocabulary, token types, merge ranks) plus 200 cases: the text, the pre-tokenizer
    pieces and the ids, produced by the FIXED `tools/secure/secure_tokenizer.py`
    (SP6 §5.5: `ignore_merges` for the GLM pre-tokenizer names).  The C++ case
    `secure_frontend_tokenizer_pack_tests.glm5_pretokenizer_matches_committed_fixtures`
    compares piece by piece and id by id.
  * `secure_frontend/src/glm_pretokenizer_tables.hpp` - the codepoint ranges for
    `\\p{L}`, `\\p{N}` and `\\s` that the C++ GLM split needs.

Both outputs are byte-stable: every classification comes from the venv's `regex`
module, which is the classifier the fixture texts were tokenized with, so the C++
port and the fixtures agree by construction.  The `regex` and `unicodedata` versions
are recorded in each header, and the pytest guard
`tools/secure/test_glm_tokenizer_fixtures.py` regenerates both files and fails on any
drift: a `regex` upgrade cannot silently change what the frontend accepts.

Surrogates (U+D800-DFFF) are in no range: not `\\p{L}`, not `\\p{N}`, not `\\s`, and
the C++ never sees one because it is not valid UTF-8.
"""
from __future__ import annotations

import argparse
import random
import sys
import unicodedata
from pathlib import Path

import regex

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secure_tokenizer as wrapper  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "secure_frontend" / "tests" / "fixtures" / "glm-tokenize.txt"
TABLES_PATH = ROOT / "secure_frontend" / "src" / "glm_pretokenizer_tables.hpp"

# 200 generated strings: digit runs 1-12, CJK, emoji, mixed whitespace, punctuation and
# combining marks (§5.5), from a fixed seed plus the fixed edge-case list below.
CASE_COUNT = 200


def byte_symbols() -> dict[int, str]:
    return wrapper.bytes_to_unicode()


def mapped(text: str) -> str:
    """`text` in the pack's BYTE-LEVEL alphabet, which is how a vocabulary stores tokens."""
    symbols = byte_symbols()
    return "".join(symbols[byte] for byte in text.encode("utf-8"))


# Whole-piece entries: pre-token pieces that ARE vocabulary entries.  No merge rule
# reaches them, so a tokenizer that keeps merging can only produce that text as several
# byte-symbol tokens - which is what makes `ignore_merges` observable.
WHOLE_PIECES = [
    " the", " of", " a", " Paris", " capital", " France", " Answer", " word",
    " count", " line", " Japan", "12", "123", "45",
    "日", "本", "語", "１２", "²", "🐈",
]
# The merge-chain vocabulary: " zebra" is NOT an entry, so its piece reaches BPE, where
# these ranks fire for three steps and stop - §5.5's "only the leftovers go through BPE".
CHAIN_PIECES = [" z", " ze", " zeb"]
CHAIN_WORDS = [" z", " zeb", " zebra", "zebras"]
CONTROL_ONLY = ["<sop>"]  # type 3, in no fixture text: encode_text would refuse it

MERGE_PAIRS = [(" ", "z"), (" z", "e"), (" ze", "b"), ("1", "2"), ("12", "3"), ("4", "5")]


def pack_vocab() -> tuple[list[str], list[int], list[tuple[str, str]]]:
    tokens = list(byte_symbols().values())
    tokens += [mapped(piece) for piece in WHOLE_PIECES + CHAIN_PIECES]
    tokens += CONTROL_ONLY
    types = [1] * (len(tokens) - len(CONTROL_ONLY)) + [3] * len(CONTROL_ONLY)
    merges = [(mapped(left), mapped(right)) for left, right in MERGE_PAIRS]
    return tokens, types, merges


# ------------------------------------------------------------------ the 200 texts
FIXED_TEXTS = [
    "What is the capital of France? Answer with one word.",
    "You are a calculator. Reply with the number only.",
    "123456789012",
    "1 12 123 1234 12345 123456 1234567 12345678 123456789 1234567890 12345678901 123456789012",
    "123 1234 12345 45 456 1234567",
    "z zeb zebra zebras zebzx",
    " the of a Paris capital France Answer word count line",
    "日 本 語 日本 日本語",
    "１２３４５",
    "x=Δy², ½³, ²²",
    "🐈 😃 🐈🐈",
    "é ė ẽ e\u0301x\u0301 a\u0300\u0301b",
    "'s 'S 't 'T 're 'Re 'RE 've 'Ve 'VE 'm 'M 'll 'Ll 'LL 'd 'D",
    "I'm you're they've we'll he'd 'x 'z r'e",
    "  a\t\r\nb",
    "\n\n\n",
    "line1\nline2\nline3\r\n",
    "spaces   between\ttabs\t\there",
    "\u00a0nbsp\u00a0after \u2028 separator \u2029 end",
    "   ",
    " trailing and leading   ",
    "(),.;:!?\"'`()~!@#$%^&*()[]{}<>",
    "-- --\n-- \n\n --",
    "مرحبا بالعالم",
    "नमस्ते १२३",
    "สวัสดีครับ",
    "İstanbul ﬁ ﬂ ǅ",
    "\u0301leading combining mark",
    "a\u0301\u0301\u0301b",
    "\x0b\x0c vertical tab and form feed",
    "\x1c\x1d\x1e\x1f file separators",
    "soft\xadhyphen and\u200bzero width",
    "emoji🐈inside and CJK日本inside",
    " the123 Paris456 ",
    "123 the 45 Paris",
    "  the  of  a  ",
    "the thethe the",
    "\t\tthe\tthe",
    "\r\n\r\nthe\r\n",
    "000111222333444555",
    "9" * 13,
    " count from 1 to 400, one number per line",
    "\u65e5\u672c\U0001f408\uff12\uff13 the zebra\u0301\n",
]

WORD_POOL = ["the", "of", "a", "Paris", "capital", "France", "Answer", "word", "count", "line",
             "zebra", "zebras", "zeb", "z", "plith", "quux"]
DIGIT_POOL = ["1", "12", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789",
              "1234567890", "12345678901", "123456789012", "٣٤", "１２３", "½", "²"]
OTHER_POOL = ["日", "本", "語", "🐈", "😃", "Δ", "λ", "م", "न", "ส", "İ", "ﬁ",
              "é", "a\u0300\u0301b", "\xad", "\u200b", "'", "'s", "'re", "'ll"]
SPACE_POOL = [" ", "  ", "   ", "\t", "\n", "\r\n", "\n\n", " \n", "\u00a0", "\u2028", "\x0b", "\x0c"]
PUNCT_POOL = [".", ",", ";", ":", "!", "?", "(", ")", "(", ")", "-", "*", "#", "@", "\"", "%",
              "()!", ",,,", "..."]


def fixture_texts() -> list[str]:
    """200 distinct texts: the fixed edge cases first, then seeded random walks."""
    texts = list(FIXED_TEXTS)
    if len(texts) >= CASE_COUNT:
        raise SystemExit("the fixed list alone reaches the case count: %d" % len(texts))
    rng = random.Random(20261022)
    pools = (WORD_POOL, DIGIT_POOL, OTHER_POOL, SPACE_POOL, PUNCT_POOL)
    while len(texts) < CASE_COUNT:
        parts: list[str] = []
        for index in range(rng.randint(3, 14)):
            pool = pools[index] if index < len(pools) else rng.choice(pools)
            parts.append(rng.choice(pool))
        text = "".join(parts)
        if text in texts or "sop>" in text or len(text) > 220:
            continue
        texts.append(text)
    return texts[:CASE_COUNT]


# ------------------------------------------------------------------ unicode class ranges
def class_ranges(pattern: str) -> list[tuple[int, int]]:
    """Merged inclusive codepoint ranges the venv's `regex` matches for `pattern`."""
    compiled = regex.compile(pattern)
    ranges: list[tuple[int, int]] = []
    first = None
    for point in range(0x110000):
        if 0xD800 <= point <= 0xDFFF:
            hit = False                      # not valid UTF-8: the C++ reader never sees these
        else:
            hit = compiled.match(chr(point)) is not None
        if hit and first is None:
            first = point
        elif not hit and first is not None:
            ranges.append((first, point - 1))
            first = None
    if first is not None:
        ranges.append((first, 0x10FFFF))
    return ranges


def versions() -> str:
    return ("regex %s (the classifier the fixtures use), unicodedata %s, Python %s"
            % (regex.__version__, unicodedata.unidata_version, sys.version.split()[0]))


# ------------------------------------------------------------------ the two files
def encode_expectation(tokenizer: wrapper.Tokenizer, text: str) -> tuple[list[str], list[int]]:
    """The pieces and ids, recomputed piece by piece the way the C++ port does it."""
    ids_of = {token: index for index, token in enumerate(tokenizer.tokens)}
    pieces = tokenizer._re.findall(text)
    ids: list[int] = []
    for piece in pieces:
        word = mapped(piece)
        if word in ids_of:                            # §5.5 ignore_merges: an exact hit is whole
            ids.append(ids_of[word])
            continue
        for token in tokenizer._bpe(word):
            ids.append(ids_of[token])
    return pieces, ids


def fixture_text(texts: list[str]) -> str:
    tokens, types, merges = pack_vocab()
    merge_lines = ["%s %s" % (left, right) for left, right in merges]
    tokenizer = wrapper.Tokenizer(tokens, merge_lines, types, pre="glm4")
    lines = [
        "# GENERATED by tools/secure/gen_glm_tokenizer_fixtures.py - do not edit.",
        "# SP6 5.5: the pre-tokenizer pieces and ids of %d texts under `pre = glm4`" % len(texts),
        "# (the GLM split with ignore_merges), produced by tools/secure/secure_tokenizer.py.",
        "# %s" % versions(),
        "# Tags: PRE <name>, VOCAB <id> <token-type> <hex-utf8>, MERGE <hex-left> <hex-right>",
        "# in rank order, CASE <hex-utf8 text>, PIECES <hex>,<hex>,..., IDS <id> <id> ...",
        "PRE glm4",
    ]
    for index, token in enumerate(tokens):
        lines.append("VOCAB %d %d %s" % (index, types[index], token.encode("utf-8").hex()))
    for left, right in merges:
        lines.append("MERGE %s %s" % (left.encode("utf-8").hex(), right.encode("utf-8").hex()))
    for text in texts:
        pieces, ids = encode_expectation(tokenizer, text)
        assert ids == tokenizer.encode(text), "the fixture re-derivation disagrees with encode(): %r" % text
        lines.append("CASE %s" % text.encode("utf-8").hex())
        lines.append("PIECES %s" % ",".join(piece.encode("utf-8").hex() for piece in pieces))
        lines.append("IDS %s" % " ".join(str(id_) for id_ in ids))
    return "\n".join(lines) + "\n"


def tables_text() -> str:
    out = [
        "#pragma once",
        "// GENERATED by tools/secure/gen_glm_tokenizer_fixtures.py - do not edit.",
        "// Codepoint classes for the GLM pre-tokenizer regex of SP6 5.5 (the transcription of",
        "// llama.cpp's LLAMA_VOCAB_PRE_TYPE_CHATGLM4): \\p{L}, \\p{N} and \\s as merged inclusive",
        "// ranges, classified by the venv's `regex` module - the classifier that generated",
        "// secure_frontend/tests/fixtures/glm-tokenize.txt.  %s" % versions(),
        "// Sorted, disjoint, and U+D800-DFFF is in none of them (not valid UTF-8).",
        "// Rerun the generator after a `regex` upgrade; the pytest guard",
        "// tools/secure/test_glm_tokenizer_fixtures.py refuses drift.",
        "",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "namespace secure_frontend::glm_tables {",
        "",
        "struct Range final {",
        "  std::uint32_t first;",
        "  std::uint32_t last;",
        "};",
        "",
    ]
    for name, ranges in (("kLetterRanges", class_ranges(r"\p{L}")),
                         ("kNumberRanges", class_ranges(r"\p{N}")),
                         ("kSpaceRanges", class_ranges(r"\s"))):
        out.append("inline constexpr Range %s[] = {" % name)
        for start in range(0, len(ranges), 4):
            out.append("    " + " ".join("{0x%04XU, 0x%04XU}," % pair
                                         for pair in ranges[start:start + 4]))
        out.append("};")
        out.append("inline constexpr std::size_t %sCount = %dU;" % (name, len(ranges)))
        out.append("")
    out += ["}  // namespace secure_frontend::glm_tables", ""]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Write the SP6 5.5 GLM tokenizer fixtures and Unicode tables")
    ap.add_argument("--fixture", default=str(FIXTURE_PATH))
    ap.add_argument("--tables", default=str(TABLES_PATH))
    args = ap.parse_args(argv)

    texts = fixture_texts()
    fixture = Path(args.fixture)
    tables = Path(args.tables)
    fixture.parent.mkdir(parents=True, exist_ok=True)
    tables.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_text(fixture_text(texts), encoding="utf-8")
    tables.write_text(tables_text(), encoding="utf-8")
    print("fixture: %s (%d cases)" % (fixture, len(texts)))
    print("tables:  %s" % tables)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""GLM-5.3 (`glm4` / `chatglm-bpe`) pre-tokenizer regression tests.

These use a deliberately tiny byte-level vocabulary: no model weights or
network access are required, while BPE merges make a wrong split observable.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from secure_tokenizer import (GLM4_PATTERN, QWEN35_PATTERN, Tokenizer,  # noqa: E402
                              bytes_to_unicode, pre_tokenizer_pattern)


class GlmTokenizerTest(unittest.TestCase):
    def tokenizer(self, pre: str = "glm4") -> Tokenizer:
        tokens = list(bytes_to_unicode().values()) + ["12", "123", "45", "456", "123456", "<sop>"]
        return Tokenizer(tokens, ["1 2", "12 3", "4 5", "45 6", "123 456"],
                         [1] * (len(tokens) - 1) + [3], pre=pre)

    def whole_piece_tokenizer(self, pre: str) -> tuple[Tokenizer, dict[str, str]]:
        """Byte-symbol vocabulary plus whole-piece entries NO merge rule can reach.

        llama.cpp sets ignore_merges for glm4/glm5, so such a piece is emitted as the one
        vocabulary token it is; a tokenizer that keeps merging reaches the same TEXT only
        through several byte symbols, which is exactly what these cases make observable.
        """
        symbols = bytes_to_unicode()
        joined = lambda text: "".join(symbols[byte] for byte in text.encode("utf-8"))
        whole = [symbols[0x20] + "the", symbols[0x20] + "Paris", joined("日"), joined("²"), "12"]
        tokens = list(symbols.values()) + whole
        return (Tokenizer(tokens, ["1 2"], [1] * len(tokens), pre=pre), symbols)

    def test_three_digit_boundaries_are_observable_in_bpe_ids(self):
        tokenizer = self.tokenizer()
        self.assertEqual(tokenizer.encode("1234567"),
                         [tokenizer.ids["123"], tokenizer.ids["456"], tokenizer.ids["7"]])
        self.assertEqual(tokenizer.decode(tokenizer.encode("1234567")), "1234567")
        qwen = self.tokenizer("qwen35")
        self.assertEqual(qwen.encode("1234567"), [qwen.ids[str(i)] for i in range(1, 8)])

    def test_alias_has_identical_boundaries_and_lossless_round_trips(self):
        for text in ["Hello, world!", "I'm 1234567", "e\u0301", "日本語 🐈\n\n", "  a\t\r\nb"]:
            glm4 = self.tokenizer("glm4")
            alias = self.tokenizer("chatglm-bpe")
            self.assertEqual(glm4.encode(text), alias.encode(text))
            self.assertEqual(glm4.decode(glm4.encode(text)), text)

    def test_control_literals_remain_controlled_by_parse_special(self):
        tokenizer = self.tokenizer()
        self.assertEqual(tokenizer.encode("<sop>", parse_special=True), [tokenizer.ids["<sop>"]])
        self.assertNotEqual(tokenizer.encode("<sop>"), [tokenizer.ids["<sop>"]])

    def test_pattern_metadata_uses_declared_pre_tokenizer(self):
        self.assertEqual(pre_tokenizer_pattern("glm4")[0], GLM4_PATTERN)
        self.assertEqual(pre_tokenizer_pattern("chatglm-bpe")[0], GLM4_PATTERN)
        self.assertEqual(pre_tokenizer_pattern("qwen35")[0], QWEN35_PATTERN)

    def test_glm5_is_accepted_beside_glm4_and_the_alias(self):
        """§5.5: the C++ side selects by `pre`, and MAYA packs declare `glm5` too."""
        for name in ("glm4", "glm5", "chatglm-bpe"):
            self.assertEqual(pre_tokenizer_pattern(name)[0], GLM4_PATTERN)
            self.assertIn("CHATGLM4", pre_tokenizer_pattern(name)[1])
        glm5 = self.tokenizer("glm5")
        self.assertEqual(glm5.encode("1234567"),
                         [glm5.ids["123"], glm5.ids["456"], glm5.ids["7"]])

    def test_exact_vocabulary_pieces_are_emitted_whole_for_glm(self):
        """§5.5 / MAYA tools/strata_tokenizer.py:255: ignore_merges means an exact vocab hit wins."""
        for name in ("glm4", "glm5", "chatglm-bpe"):
            tokenizer, symbols = self.whole_piece_tokenizer(name)
            self.assertTrue(tokenizer.ignore_merges, "%s must set ignore_merges" % name)
            cjk = "".join(symbols[byte] for byte in "日".encode("utf-8"))
            squared = "".join(symbols[byte] for byte in "²".encode("utf-8"))
            self.assertEqual(tokenizer.encode(" the"), [tokenizer.ids[symbols[0x20] + "the"]],
                             "%s must emit the whole piece ' the' as one token" % name)
            self.assertEqual(tokenizer.encode(" Paris"), [tokenizer.ids[symbols[0x20] + "Paris"]])
            self.assertEqual(tokenizer.encode("日"), [tokenizer.ids[cjk]],
                             "%s must emit the byte-mapped whole piece for 日 as one token" % name)
            self.assertEqual(tokenizer.encode("²"), [tokenizer.ids[squared]],
                             "%s must look the piece up in the BYTE-LEVEL alphabet" % name)

    def test_qwen35_keeps_merging_the_same_vocabulary(self):
        """The GLM names are the only ones with ignore_merges; qwen35 keeps BPE merges."""
        tokenizer, symbols = self.whole_piece_tokenizer("qwen35")
        self.assertFalse(tokenizer.ignore_merges)
        cjk = "".join(symbols[byte] for byte in "日".encode("utf-8"))
        self.assertEqual(tokenizer.encode(" the"),
                         [tokenizer.ids[symbols[0x20]], tokenizer.ids["t"], tokenizer.ids["h"],
                          tokenizer.ids["e"]])
        self.assertEqual(tokenizer.encode("日"), [tokenizer.ids[byte] for byte in cjk])

    def test_pieces_that_are_not_vocabulary_entries_still_merge_for_glm(self):
        """ignore_merges skips merges for exact hits only; the leftovers still go through BPE."""
        for name in ("glm4", "glm5", "chatglm-bpe"):
            tokenizer, _ = self.whole_piece_tokenizer(name)
            self.assertEqual(tokenizer.encode("112"), [tokenizer.ids["1"], tokenizer.ids["12"]],
                             "%s must still merge the piece '112'" % name)


if __name__ == "__main__":
    unittest.main()

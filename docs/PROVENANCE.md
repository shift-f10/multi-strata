# Provenance

## Baseline

This working tree is a full Git clone of [Niko1221/Strata][strata] at the
annotated release tag `v0.1.43`.

- Tag object: `16374b3e6dfe452a163c3a961ae5faa3b4aec84b`
- Checked-out commit: `7695859aa13afb248bdb4d36f9b2e95707db079d`
- Upstream remote: `https://github.com/Niko1221/Strata.git` (named
  `upstream`)

The upstream history and licensing files are retained.  Changes made in this
repository must keep their own attribution and comply with the upstream
license.

## Security reference

[robertkarl/UnbiasedStrata][unbiased] at
`46c46ecfc11d2315512f21f7549b0a7792ccd2ae` (`main`, resolved 2026-10-11
Pacific time) is a design reference for a smaller, offline-verifiable runtime
and reduced service attack surface.  It is **not** imported as a code
baseline.  Any future adaptation must record the source, license, and exact
revision of copied material, and must preserve Windows and Linux compatibility
requirements.

## GLM-5.3 compatibility reference

[lighttransport/Strata][lighttransport] branch `glm53f`, resolved at commit
`4894c9967f5754a2052d7b05f10a01b6071bb6e4` on 2026-10-12 Pacific time, is
the requested reference for GLM-5.3 compatibility work. It is not imported as
a code baseline. The offline Python tokenizer's `glm4` / `chatglm-bpe`
pre-tokenizer regex was transcribed from that revision's
`tools/strata_tokenizer.py` (which identifies the upstream llama.cpp
`LLAMA_VOCAB_PRE_TYPE_CHATGLM4` behavior); no engine source or model artifact
was copied. It is covered by tiny local byte-BPE regression fixtures for the
three-digit numeric boundary, alias behavior, control-token parsing, and
UTF-8 round trips. This is portable Python code, but its runtime test still
requires the repository-pinned `regex` dependency. The GLM prompt template
and native engine remain separately reviewed work; the tokenizer port does not
make a model executable or claim complete frontend tokenizer parity.

[strata]: https://github.com/Niko1221/Strata/tree/v0.1.43
[unbiased]: https://github.com/robertkarl/UnbiasedStrata/tree/46c46ecfc11d2315512f21f7549b0a7792ccd2ae
[lighttransport]: https://github.com/lighttransport/Strata/tree/glm53f

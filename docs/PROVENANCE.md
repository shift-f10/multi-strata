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

## Upstream-owned files touched by this repository

Our code lives in our own directories (`secure_frontend/`, `scripts/dev/`,
`scripts/secure_distribution_check.py`, `docs/security/`, `docs/superpowers/`,
`tests/security/`, and our own `docs/*.md`). A file that exists in upstream
`v0.1.43`, or a new file placed where upstream owns the layout (the repository
root), may be touched only if it is on this allowlist; any exception is
marked as such below and needs the owner's approval. Each touch is recorded
below so `git merge upstream/main` conflicts can be resolved
deliberately.

Allowlist (owner decision, 2026-10-13):

- root `CMakeLists.txt` — only the secure-frontend integration hunk at the end
  of the file;
- `.gitignore` — appended entries only;
- `requirements.txt` — if ever needed (not touched so far).

Recorded touches:

| File | Change | Commit(s) |
| --- | --- | --- |
| `CMakeLists.txt` (lines 1660–1668 at the SP0 branch head) | Secure baseline added the integration hunk: `STRATA_BUILD_SECURE_FRONTEND`, `STRATA_BUILD_SECURE_FRONTEND_TESTS`, `add_subdirectory(secure_frontend)` (9 lines at head). SP0 changed the option default `ON` → `OFF` and added the one-line opt-in comment. | `7de35b0c`, `556e031a` |
| `.gitignore` | Appended six lines: a comment plus `/.venv-dev/`, `/.toolchains/`, `/secure_frontend/out/`, `/secure_frontend/build/`. | `f5f19f77` |
| `.gitignore` (second append) | Added `/.worktrees/` for parallel sub-project worktrees (SP1/SP2 execution). | this commit |
| `pytest.ini` | New root file added by SP0 (implementer addition, not an upstream edit; keep on upstream merges; owner approval of its placement pending). Collects `tools/test_*.py` only; ignores and deselects recorded with reasons in the file. | `f5f19f77`, `7e3bc409` |
| `conftest.py` | New root file (implementer addition; keep on upstream merges). Sets `collect_ignore` for `tools/test_conversation_cache_isolation.py` and `tools/test_shards.py` only when numpy is not importable, so the owner's pre-push hook passes with a system pytest; the full set runs in `.venv-dev`. | this commit |
| `tools/strata_tokenizer.py` | **Outside the allowlist; pre-dates it.** The secure baseline added the `glm4` / `chatglm-bpe` pre-tokenizer aliases (35 lines changed; see the GLM-5.3 section above). Expect merge conflicts here; a later sub-project should move this into our own directory or upstream it. | `7de35b0c` |

The upstream Python service (`serve/`), installer (`setup.py`) and engine
(`src/`, `include/`) are untouched.

[strata]: https://github.com/Niko1221/Strata/tree/v0.1.43
[unbiased]: https://github.com/robertkarl/UnbiasedStrata/tree/46c46ecfc11d2315512f21f7549b0a7792ccd2ae
[lighttransport]: https://github.com/lighttransport/Strata/tree/glm53f

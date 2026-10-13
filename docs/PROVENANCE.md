# Provenance

## Baseline

Upstream [Niko1221/Strata][strata] is the git submodule `upstream/`, pinned by
its gitlink at the annotated release tag `v0.1.43`.

- Submodule (`.gitmodules`): path `upstream`, URL
  `https://github.com/Niko1221/Strata.git`, no branch tracking.
- Pinned commit (the gitlink): `7695859aa13afb248bdb4d36f9b2e95707db079d`
- Tag object: `16374b3e6dfe452a163c3a961ae5faa3b4aec84b`
- Check: `git submodule status` prints
  ` 7695859aa13afb248bdb4d36f9b2e95707db079d upstream (v0.1.43)`.

The gitlink is the baseline record. Nothing under `upstream/` is edited and no
upstream file exists outside it; the repository root holds only our code (see
[`AGENT_HANDOFF.md`](AGENT_HANDOFF.md), "Repository layout"). Where we need
different behavior we wrap upstream from our own tree
(`tools/secure/secure_tokenizer.py`) or offer the change upstream. Exceptions:
none. `git -C upstream status --porcelain` is empty.

Everything under `upstream/` is under upstream's license
([`upstream/LICENSE`](../upstream/LICENSE)). The root [`LICENSE`](../LICENSE)
is the MIT text with the retained "Copyright (c) 2026 Niko1221 and the Strata
contributors" line, our line, and a pointer to `upstream/LICENSE`.

History: until 2026-10-13 this repository was a full clone of upstream with our
code mixed in, plus a recorded list of approved edits to upstream files. The
[submodule layout](superpowers/specs/2026-10-13-upstream-submodule-layout-design.md)
replaced it. The former integration hunk in upstream's root `CMakeLists.txt`
became our own root `CMakeLists.txt`; the appended `.gitignore` lines and the
README attribution header became our own `.gitignore` and `README.md`; the
`glm4` / `chatglm-bpe` edit to upstream's `tools/strata_tokenizer.py` became the
wrapper `tools/secure/secure_tokenizer.py`; and the root `pytest.ini` and
`conftest.py` are ours (they now collect `tools/secure/` only).

## Updating the baseline

An upstream update moves the gitlink; it is never a merge into our tree.

This is the canonical order; the runbooks in
[`AGENT_HANDOFF.md`](AGENT_HANDOFF.md) ("Update upstream") and
[`secure-frontend-ci.md`](secure-frontend-ci.md) ("Updating upstream") follow it.

1. `git -C upstream fetch --tags origin && git -C upstream checkout --detach <new tag>`
2. Gates: `pytest -q`; `ctest --preset linux-gcc` (in `secure_frontend/`); the
   `windows-llvm-mingw-cross` build; the root configure, build and `ctest`;
   then, in a separate venv, `pytest upstream/tools` (with its recorded
   exclusions) and `pytest upstream/serve` (exact commands in
   `secure-frontend-ci.md`). Re-check the SP5 pass-through table against the
   new engine's flags and protocol, and the upstream internals
   `tools/secure/secure_tokenizer.py` couples to (listed in its module
   docstring).
3. `git -C upstream status --porcelain` is empty and `git submodule status`
   shows no `-`/`U` (`+` is expected until the pointer is staged).
4. Update "Baseline" above (commit, tag object, tag) and
   [`AGENT_HANDOFF.md`](AGENT_HANDOFF.md) "Current baseline".
5. `git add upstream docs/PROVENANCE.md docs/AGENT_HANDOFF.md`; one commit:
   `upstream: bump to <new tag>`.

## Security reference

[robertkarl/UnbiasedStrata][unbiased] at
`46c46ecfc11d2315512f21f7549b0a7792ccd2ae` (`main`, resolved 2026-10-11
Pacific time) is a design reference for a smaller, offline-verifiable runtime
and reduced service attack surface.  It is **not** imported as a code
baseline.  Any future adaptation must record the source, license, and exact
revision of copied material, and must preserve Windows and Linux compatibility
requirements.

License: the GitHub API (`gh api repos/robertkarl/UnbiasedStrata/license`,
queried 2026-10-13, default branch) returns SPDX id `MIT`, name `MIT License`.
No code was taken from this repository, so its license governs nothing in
this tree.

## GLM-5.3 compatibility reference

[lighttransport/Strata][lighttransport] branch `glm53f`, resolved at commit
`4894c9967f5754a2052d7b05f10a01b6071bb6e4` on 2026-10-12 Pacific time, is
the requested reference for GLM-5.3 compatibility work. It is not imported as
a code baseline. The `glm4` / `chatglm-bpe` pre-tokenizer regex in our wrapper
`tools/secure/secure_tokenizer.py` (which imports upstream's unmodified
`upstream/tools/strata_tokenizer.py`) was transcribed from that revision's
`tools/strata_tokenizer.py` (which identifies the upstream llama.cpp
`LLAMA_VOCAB_PRE_TYPE_CHATGLM4` behavior); no engine source or model artifact
was copied. It is covered by tiny local byte-BPE regression fixtures
(`tools/secure/test_glm_tokenizer.py`: three-digit numeric boundary, alias
behavior, control-token parsing, UTF-8 round trips) and by
`tools/secure/test_secure_tokenizer.py` (the pattern shipped in a pack's
`tokenizer.json`). This is portable Python code, but its runtime test still
requires the pinned `regex` dependency (`scripts/dev/requirements-dev.txt`).
The GLM prompt template and native engine remain separately reviewed work; the
tokenizer port does not make a model executable or claim complete frontend
tokenizer parity.

License: the GitHub API (`gh api repos/lighttransport/Strata/license`,
queried 2026-10-13, default branch) returns SPDX id `MIT`, name `MIT License`.
The `LICENSE` file on branch `glm53f` (via the contents API, same date) carries
the copyright line "Copyright (c) 2026 Niko1221 and the Strata contributors".

## ggml / llama.cpp (bundled with upstream)

[ggml-org/llama.cpp][llamacpp] / ggml comes with the upstream baseline and is
unchanged by us (it is inside the `upstream/` submodule). It is present in two
forms:

- `upstream/third_party/ggml` — vendored headers;
  `upstream/third_party/ggml/VERSION.txt` records commit
  `3cf03257f219afbe7334045ff7c6a06ac68c627d`.
- The llama.cpp checkout fetched by `upstream/CMakeLists.txt`
  (`FetchContent_Declare(strata_llamacpp ...)`, lines 1255–1258) when
  `STRATA_NATIVE_EXPERTS=ON` and `STRATA_GGML_DIR` is unset, pinned to
  `GIT_TAG 3cf03257f219afbe7334045ff7c6a06ac68c627d`.

License: MIT, "Copyright (c) 2023-2026 The ggml authors"
([`upstream/third_party/ggml/LICENSE`](../upstream/third_party/ggml/LICENSE)).
Our root `CMakeLists.txt` seeds `STRATA_NATIVE_EXPERTS=OFF` and our CI
(`.github/workflows/secure-frontend.yml`) configures with
`-DSTRATA_NATIVE_EXPERTS=OFF`, so the llama.cpp checkout is never fetched by
default or in CI.

## llvm-mingw (build tool only)

[mstorsjo/llvm-mingw][llvmmingw] release `20261006` is the open-source
Windows cross toolchain fetched by `scripts/dev/bootstrap-llvm-mingw.sh`,
verified against sha256
`5f9c6ed95b2d4bdb2869a488c5fd5857fbdabcf288a0aa3eb1da43f6a08d8ab4`. It is a
build tool only; nothing from it is in this tree (it unpacks under the
git-ignored `/.toolchains/`).

License: the GitHub API (`gh api repos/mstorsjo/llvm-mingw/license`, queried
2026-10-13, default branch) returns SPDX id `NOASSERTION`, name `Other`. The
`LICENSE` file it returns states that the llvm-mingw scripts and wrappers are
licensed under the ISC license and that this covers only components provided
by llvm-mingw directly (the bundled LLVM, mingw-w64 and other components keep
their own licenses).

[strata]: https://github.com/Niko1221/Strata/tree/v0.1.43
[unbiased]: https://github.com/robertkarl/UnbiasedStrata/tree/46c46ecfc11d2315512f21f7549b0a7792ccd2ae
[lighttransport]: https://github.com/lighttransport/Strata/tree/glm53f
[llamacpp]: https://github.com/ggml-org/llama.cpp/tree/3cf03257f219afbe7334045ff7c6a06ac68c627d
[llvmmingw]: https://github.com/mstorsjo/llvm-mingw/releases/tag/20261006

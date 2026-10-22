# Provenance

## Baseline

Upstream [Niko1221/Strata][strata] is the git submodule `upstream/`, pinned by
its gitlink at the annotated release tag `v0.2.2`.

- Submodule (`.gitmodules`): path `upstream`, URL
  `https://github.com/Niko1221/Strata.git`, no branch tracking.
- Pinned commit (the gitlink): `011c9e600a93bbc9fd451c563501b5831c32bbca`
- Tag object: `e6fff4ad12908de74952abe53b2bade45a68aa0f`
- Check: `git submodule status` prints
  ` 011c9e600a93bbc9fd451c563501b5831c32bbca upstream (v0.2.2)`.
- Supply-chain review of `v0.2.1.3..v0.2.2` ([contract](security/engine-supply-chain.md), C9):
  rulings `security/engine-reviews/strata-v0.2.1.3-v0.2.2.json` (58 findings, 0 refused;
  SHA-256 `dfdf7e6b655977b1b2d4bbee1f824d3fb274f400a59cf8b5559efc5fea9510f7`), compiled-diff
  read `security/engine-reviews/strata-v0.2.1.3-v0.2.2-compiled-read.md` (0 concern; SHA-256
  `65e26faa115427e4181341341c30417a36f69cbab41d01fb12aaabd4f128aaa0`), binary gate PASS
  against `security/engine-binary-allowlist.json` (SHA-256
  `999d465a956e5a1087f41fbc10491240c6550a18ecf48912c1f2d2151200837f`), llama.cpp fetch
  `3cf03257` clean. Signed off by the owner on 2026-10-21. The review followed the build
  (the contract postdates it; C2).

The gitlink is the baseline record. Nothing under `upstream/` is edited and no
upstream file exists outside it; the repository root holds only our code (see
[`AGENT_HANDOFF.md`](AGENT_HANDOFF.md), "Repository layout"). Where we need
different behavior we wrap upstream from our own tree
(`tools/secure/secure_tokenizer.py`) or offer the change upstream. Exceptions:
none. `git -C upstream status --porcelain` is empty.

Everything under `upstream/` is under upstream's license
([`LICENSE` at `v0.2.2`](https://github.com/Niko1221/Strata/blob/v0.2.2/LICENSE);
offline: `upstream/LICENSE` in a checkout with the submodule initialized). The
root [`LICENSE`](../LICENSE)
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

This is the only copy of the runbook; [`AGENT_HANDOFF.md`](AGENT_HANDOFF.md)
and [`secure-frontend-ci.md`](secure-frontend-ci.md) link here instead of
repeating it. `<old tag>` / `<old short sha>` / `<old tag object>` are the
current pin (today `v0.2.2` / `011c9e60` / `e6fff4ad`), `<new tag>` the
target. `<L>` is a label unique to the run (for example `old-<old tag>` and
`new-<new tag>`): build directories and venvs are never reused or deleted
between runs, so every run uses its own `out/<name>-<L>`.

Shell: `export PATH="$(git rev-parse --show-toplevel)/.venv-dev/bin:$PATH"`.
For direct wine calls (not the test preset, which sets it) prefix
`WINEPREFIX=$PWD/out/wineprefix WINEDLLOVERRIDES=mscoree,mshtml=` from
`secure_frontend/`.

1. **Gates at the old pin first** (the gate list in step 3, with
   `<L>` = `old-<old tag>`), and record every count. Without this baseline a
   changed count cannot be attributed to the bump.
2. Fetch only: `git -C upstream fetch --tags origin`. Then the
   [engine supply-chain contract](security/engine-supply-chain.md) C1–C4 on
   `<old tag>..<new tag>` with read-only git: the diff scan with a ruling per
   finding (`scripts/security/engine_review.py diff`, rulings in
   `security/engine-reviews/`) and the full read of the compiled and build diff.
   Nothing from the new tree is configured, built, installed or run before both
   records exist. Then `git -C upstream checkout --detach <new tag>`.
3. Gates at the new pin (`<L>` = `new-<new tag>`), each with its working
   directory (plus, on any engine build made for the bump, the contract's C5
   binary gate — `engine_review.py binary` against
   `security/engine-binary-allowlist.json` — and the C1 check that the fetched
   `_deps` checkout equals the pinned commit and is clean):
   - `pytest -q` (repo root): our `tools/secure/` tests.
   - In `secure_frontend/`: `cmake --preset linux-gcc && cmake --build
     --preset linux-gcc && ctest --preset linux-gcc`, and the same three
     commands with the `windows-llvm-mingw-cross` preset (build with
     `-Werror`, then the wine `ctest`).
   - Root configure, build and `ctest` (repo root), from a fresh build
     directory, then confirm nothing was fetched:

         cmake -S . -B out/root-<L> -G Ninja && cmake --build out/root-<L> && ctest --test-dir out/root-<L>
         test ! -e out/root-<L>/_deps

   - Upstream's own suites in a separate venv (upstream's pins win there).
     `python3 -m venv` may lack `ensurepip`, so create the venv without pip
     and install into it with the dev venv's pip (repo root):

         python3 -m venv --without-pip out/venv-upstream-<L>
         .venv-dev/bin/pip --python out/venv-upstream-<L>/bin/python install \
           -r scripts/dev/requirements-dev.txt -r upstream/requirements.txt

     Then run them **from `upstream/`** (four `tools/` tests resolve
     `tools/...` against the working directory). Our root `pytest.ini` stays
     the rootdir, so `--deselect` ids keep the `upstream/tools/` prefix:

         ( cd upstream && ../out/venv-upstream-<L>/bin/pytest -q tools \
           --ignore=tools/test_iq_pack.py --ignore=tools/test_setup_engine_hash.py \
           --deselect upstream/tools/test_setup_choices.py::HipVision::test_the_cpu_encoder_is_built_once \
           --deselect upstream/tools/test_setup_choices.py::HipVision::test_without_images_nothing_changes \
           --deselect upstream/tools/test_setup_choices.py::CudaVision::test_the_encoder_is_built_native \
           --deselect upstream/tools/test_setup_golden.py::Golden::test_yes \
           --deselect upstream/tools/test_setup_golden.py::Golden::test_enter_for_every_question \
           --deselect upstream/tools/test_setup_download.py::ParallelDownload::test_a_big_file_comes_over_several_connections \
           && ../out/venv-upstream-<L>/bin/pytest -q serve \
           --deselect upstream/serve/test_lifeline.py::Lifeline::test_the_portable_watcher_ends_the_child_when_the_server_is_killed )

     The subshell keeps the shell at the repo root for the later steps.

     At `v0.2.2` the Linux counts are not recorded yet: the bump was made on
     the owner's Windows box (2026-10-21), where the same commands give
     `1027 passed, 11 failed, 30 skipped, 6 deselected` and `905 passed,
     23 skipped, 1 deselected` (at `v0.2.1.3` there: 1004/12 failed/24/6 and
     865/27/1; the 11 failures are Windows-host ones present at both tags —
     `docs/validation/2026-10-21-windows-gpu-session.md`, step 6). Run the
     Linux gate before treating the `v0.2.2` row as complete.
     At `v0.2.1.3`: `1027 passed, 13 skipped, 6 deselected` and `878 passed,
     14 skipped, 1 deselected`. At `v0.1.44.1`: `760 passed, 2 skipped,
     5 deselected` and `774 passed, 11 skipped` (at `v0.1.43`, with the first
     three deselects only: 616/2/3 and 695/11). Why each exclusion exists:
     - `test_iq_pack.py`: needs llama.cpp's `gguf` module.
     - `test_setup_engine_hash.py`: needs GitHub.
     - the three `test_setup_choices.py` ids: upstream drift against its
       `setup.py` (recorded at `v0.1.43`).
     - the two `test_setup_golden.py` ids: upstream `12be1059` re-recorded the
       golden configs on Windows; the `unsloth UD-Q4_K_XL` cases expect
       `strata-vision.exe`, which only matches on Windows.
     - `test_setup_download.py::ParallelDownload::test_a_big_file_comes_over_several_connections`
       (test new at `04221c3e`, retuned by `e2071c2f`, first runs at
       `v0.2.1.x`): the new length probe issues a whole-file ranged GET that
       the test's own `asked()` helper counts as a second piece-0 request
       (`[0, 0, 1, …]` where `[0, 1, …]` is expected); deterministic alone and
       under load. Upstream drift against its own test; quarantined Python.
     - `serve/test_lifeline.py::Lifeline::test_the_portable_watcher_ends_the_child_when_the_server_is_killed`
       (new at `48e6d64c`, first runs at `v0.2.1.3`): the watcher's liveness
       token is `ps -o lstart=,stat=`, and `stat` flips `R`→`S` as the child
       starts sleeping, so when the killed parent's pipe closes the token no
       longer matches and the watcher declines to end the child. A
       host-sensitive race in the new mechanism itself (the `pdeathsig` case —
       the Linux production path — passes); quarantined Python.

     **When the new tag adds a failing upstream test:** it is a finding, not
     something to force green. If it is in quarantined Python (`setup.py`,
     `serve/`, `tools/`) and the cause is upstream drift or the host, add a
     `--deselect` here with a one-line reason naming the upstream commit,
     record the new counts in this paragraph, and name it in the bump
     commit's body. A failure in anything we build or ship (engine, CMake,
     `strata_tokenizer.py`) stops the bump. Drop an exclusion once the new
     tag no longer needs it (run the excluded ids alone to check).
   - Re-audit upstream's top-level CMake assumptions (the table in
     [layout spec §3](superpowers/specs/2026-10-13-upstream-submodule-layout-design.md)):
     new `FetchContent`, changed option defaults, new options or targets, a
     `tests/CMakeLists.txt` that would flip `STRATA_BUILD_TESTS` on (and fetch
     Catch2), and that our root cache seeds (`STRATA_ENABLE_CUDA/HIP=OFF`,
     `STRATA_NATIVE_EXPERTS=OFF`) still land before the options they seed.
   - Re-check the engine's CLI flags and `--serve` protocol against
     `secure_frontend/src/engine_arguments.cpp` (deny list),
     `secure_frontend/src/engine_protocol_client.cpp` and
     [`security/engine-protocol-limits.md`](security/engine-protocol-limits.md)
     (`git -C upstream diff <old tag> <new tag> -- src/program/generate.cpp`),
     and the upstream internals `tools/secure/secure_tokenizer.py` couples to
     (listed in its module docstring).
4. `git -C upstream status --porcelain` is empty and `git submodule status`
   shows no `-`/`U` (`+` is expected until the pointer is staged). Worktrees
   share `.git/config`: a `git submodule deinit` in any worktree turns this
   into `-` everywhere; repair with `git submodule init` in the main checkout.
   Inspect the pointer with `git diff -- upstream` (a bare `upstream` is
   ambiguous with `upstream/...` branch names).
5. Update "Baseline" above (commit, tag object, tag), then find every other
   pin site:

       git grep -n '<old tag>\|<old short sha>\|<old tag object>' -- ':!docs/superpowers' ':!upstream'

   (escape the dots of `<old tag>`). Update each hit that states the
   **current** pin; leave verification-history rows (tables of past
   commands and results, dated sections) as they are. Known pin sites:
   `README.md` (the revision column and the pinned `blob/<tag>/...` links),
   the header comment of `.github/workflows/secure-frontend.yml`,
   [`AGENT_HANDOFF.md`](AGENT_HANDOFF.md) (owner decision 6, the "Repository
   layout" table header, "Current baseline"),
   [`secure-frontend-ci.md`](secure-frontend-ci.md) (the "Root build" note on
   `STRATA_BUILD_TESTS` and the offline-bundle commands, which carry the tag
   object), this file (the `[strata]` reference, the pinned `blob/<tag>/...`
   license links, the counts in step 3, and the ggml commit and
   `upstream/CMakeLists.txt` line numbers below — not found by the grep:
   re-derive them with `grep -n FetchContent_Declare -A3
   upstream/CMakeLists.txt`), and the `docs/security/` pages that name the
   baseline version. The SP5 M1 parity artifacts are line-number pin sites as
   well: `secure_frontend/tests/parity_keys_upstream.hpp` (its header comment
   carries the pin commit and tag, and its two grep commands must be re-run at
   the new pin), `secure_frontend/src/parity_table.cpp` (every row cites
   `serve/<file>.py:<line>` at the pin — re-pin each citation, then the
   parity meta-tests and the README mirror), and the `secure_frontend/README.md`
   parity section (regenerated from that table;
   `tools/secure/test_parity_readme_coverage.py` guards the mirror).
   Changing the version on a `docs/security/` page asserts
   its facts hold for the new tag: re-check each row against the new source
   first and add rows for new behavior.
   `upstream.version` (repository root, one line: the tag itself, today
   `v0.2.2`) is a pin site — bump it with the gitlink; configure fails
   when a reachable submodule tag disagrees with it. It is the source of the
   SP4 engine version `kEngineVersion` (`secure_frontend/CMakeLists.txt`); the
   `SECURE_STRATA_ENGINE_VERSION` cache override is for local experiments
   only and appears nowhere in `.github/workflows/secure-frontend.yml`.
6. `git add upstream docs/PROVENANCE.md` plus every file touched in step 5
   (at least `upstream.version`, `README.md`, `.github/workflows/secure-frontend.yml`,
   `docs/AGENT_HANDOFF.md`, `docs/secure-frontend-ci.md`); one commit:
   `upstream: bump to <new tag>`, whose body lists each gate with its counts
   (old → new), any exclusion added, and the upstream changes that matter to
   the frontend. The commit also carries the contract's review records
   (`docs/security/engine-reviews/<engine>-<old>-<new>.{json,md}` and the
   `-compiled-read.md` notes) and a row in the contract's Record table; the
   body cites their SHA-256 and the owner's sign-off (C9).

After a `git pull` that moves the gitlink, run `git submodule update --init`
(or set `git config submodule.recurse true` once). A `+` in front of the line
`git submodule status` prints means the checked-out `upstream/` commit differs
from the recorded gitlink (behind, ahead or elsewhere).

## Model catalog (SP4)

The `strata` binary embeds `secure_frontend/catalog/<name>/<tag>.json`
manifests, pinned by `secure_frontend/catalog/CATALOG.sha256`. **The v1
production catalog is empty** (SP4 D5 (D)): the Qwen `--pack` files have no
pinned digests until the owner's determinism check (D5 (A)) or a C++ pack
builder (D5 (C)). A catalog entry lands in the same commit as its pins here
(repository, revision, every file's size and SHA-256, re-verified by one
download on the dev machine); `tools/secure/test_catalog_provenance.py`
enforces that. The DFlash2 drafter (`Anbeeld/GLM-5.3-Flash-DFlash2-GGUF`,
CC BY-NC-ND 4.0) is never a catalog entry.

Developer-built bundles (D5 (B′), `tools/secure/make_bundle.py`) check the
downloaded shards against `tools/secure/qwen_bundle_pins.json`, read from the
Hugging Face tree API (`lfs.oid`, `lfs.size`) on 2026-10-14 at the revisions
upstream pins in `setup.py` `HF_REVISIONS`:

| Repository @ revision | File | Bytes | SHA-256 |
| --- | --- | --- | --- |
| `ISTA-DASLab/Qwen3.8-Flash-Next-GSQ-RCO-GGUF` @ `ed59f92082b1e93c0e96d60a8b11aab089b52f09` | `IQ2_XS/…-IQ2_XS-00001-of-00002.gguf` | 39225954592 | `92cee27ae5bbadcd732416a0f7a7f0acc092399dbbe8f5a5efa707c2ec0a49d7` |
| same | `IQ2_XS/…-IQ2_XS-00002-of-00002.gguf` | 28800138432 | `316b46f3a2dbd68c900f43136ab9449f9dcc3725dfd8c794847c204bc161e113` |
| same | `IQ3_XXS/…-IQ3_XXS-00001-of-00002.gguf` | 47039860096 | `219ea929900dfa9ef091f3aa473fdba6874b65fcb36526d7d851ac9e95856d15` |
| same | `IQ3_XXS/…-IQ3_XXS-00002-of-00002.gguf` | 28800138432 | `316b46f3a2dbd68c900f43136ab9449f9dcc3725dfd8c794847c204bc161e113` |
| same | `IQ3_S/…-IQ3_S-00001-of-00002.gguf` | 54817524224 | `4c1eb2ceb4915e1192f4f386021897bde56a97f40a0bb78bb86465e0f7d2aca3` |
| same | `IQ3_S/…-IQ3_S-00002-of-00002.gguf` | 28800138432 | `316b46f3a2dbd68c900f43136ab9449f9dcc3725dfd8c794847c204bc161e113` |
| `ISTA-DASLab/Qwen3.8-Flash-Next-GSQ-RCO-Coder-GGUF` @ `5348543e0147355ac9cbcb031184a3546350988e` | `IQ1_M/…-IQ1_M-00001-of-00002.gguf` | 29608446496 | `e11083ba855e7666b48ea3f2db6a9c3a20c18751a012cc24f948de91b7087fad` |
| same | `IQ1_M/…-IQ1_M-00002-of-00002.gguf` | 28800138432 | `316b46f3a2dbd68c900f43136ab9449f9dcc3725dfd8c794847c204bc161e113` |

`…` is `Qwen3.8-Flash-Next-GSQ-RCO`. These are Hub-reported digests, not yet
re-verified by a download here — **owner to confirm before any release**; `make_bundle.py` re-hashes every shard it uses.

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

## Project Maya (second GLM-5.3 reference, planned for SP6)

[mw00/project-maya][maya] was named by the owner on 2026-10-14 as a second
source for the GLM-5.3 engine work, beside the lighttransport branch above.
Resolved on 2026-10-14 (`gh api repos/mw00/project-maya/commits/main`) at tag
`v1.1.8`, commit `5c970a863ce2fdd87b6e23ffb4822f6d76522b1c`. It is a Strata
derivative (its README: "Maya's engine started from Strata's and was rewritten
for GLM-5.3-Flash"), covering NVIDIA (1–16 GPUs) and AMD HIP, Linux and
experimental Windows (VS 2022 + CUDA 12.8), MTP decoding, an OpenAI- and
Anthropic-compatible server, and its own quantization tooling. Its
`docs/GLM5-FLASH.md` is a component-by-component port study against Strata.
**No code, kernel, model or quant has been taken from it yet.** When SP6 uses
it, this section records the exact files or contracts used, as the sections
above do, and the README sources table is updated in the same commit.

**Vendored 2026-10-22 (SP5 M2, owner decision D-10):** the pinned source is
now the git submodule `engines/maya-ref/` at gitlink
`5c970a863ce2fdd87b6e23ffb4822f6d76522b1c` (tag `v1.1.8`), a **read-only
reference**: the GLM parity table cites it by `file:line` so a reviewer can
open the exact read site locally. It is never compiled, linked, or configured
by any CMake preset (a pytest guard checks that no CMake file mentions it);
`secure_distribution_check.py` rejects any staged path with a `maya-ref`
component; `pytest.ini` keeps its own test tree out of collection. This
vendoring pulls forward only the reference-source piece of SP6 — no SP6
engine work happens in SP5, and nothing here comes out of this submodule
into our binaries. **SP5 M2 use:** the submodule is the citation target of
the GLM parity table (`kMayaRows`, 178 rows) and of the dialect/vision
citations across `secure_frontend` and the kit docs — the whole table is
verifiable by opening the cited `file:line` locally. Still: **no code,
kernel, model or quant has been taken from it**; SP6 import work keeps the
rules above.

**Bumped 2026-10-21 to tag `v1.1.21`** (owner request, on the owner's Windows
box): gitlink `451f9cb6a21ea65673bdde2e57b4a670ae2b8859`, tag object
`ba26442d5c8b833fe8be466277ca52b09bf1ec63` (124 commits; no file renamed or
deleted). The Maya citations across `secure_frontend` and the kit docs were
re-pinned to it; the GLM key inventory (`parity_keys_maya.hpp`) is kept as
generated at `v1.1.8`, because at `v1.1.21` its documented greps no longer apply
(`docs/SETTINGS.md` respells every setting `MAYA_*`) — regenerating it is open,
as are the changed GLM penalty semantics
(`docs/validation/2026-10-21-windows-gpu-session.md`, issue 27). The `maya_118`
dialect now also accepts the bounded `VRAM`/`NOTE` records `v1.1.21` prints
before READY. The tag's `VERSION` file is empty, so a built Maya server reports
no version; record the tag and commit instead.

**SP5 parity acceptance kit (placeholder, SP5 M2):** the kit procedure is
`docs/validation/sp5-parity-kit.md` (corpus: `docs/validation/sp5-parity-corpus.txt`);
the GPU run happens on the owner's box. When it runs, record here: the
release commit, both servers' full command lines, both engine versions, the
model pack SHA-256, and the SHA-256 of both results files and of the corpus.
**No GLM parity claim is made until this entry exists.**

License: the GitHub API (`gh api repos/mw00/project-maya`, queried 2026-10-14,
default branch) returns SPDX id `MIT`. At `v1.1.21` (read from the local tag,
2026-10-21) its `LICENSE` is still the MIT text and carries two copyright lines:
"Copyright (c) 2026 Peasant Smith and the Project Maya contributors" (new) and
"Copyright (c) 2026 Niko1221 and the Strata contributors". It bundles
`third_party/ggml` (MIT), `third_party/exllamav3` (MIT, Turboderp),
`third_party/beellama.cpp` (MIT), `LICENSE.deepseek-v41` (MIT, Copyright (c)
2023 DeepSeek; new at `v1.1.21`, covers `serve/ds41_encoding.py`) and the Outfit
font (SIL OFL 1.1, `serve/web/fonts/OFL.txt`; present at `v1.1.8` too but not
recorded here before); any SP6 import from those paths carries their notices.
Its optional DFlash2 drafter weights are CC BY-NC-ND 4.0 and are never
bundled or fetched by this project; a tree-wide search at `v1.1.21` finds no
other non-commercial or copyleft component.

## ggml / llama.cpp (bundled with upstream)

[ggml-org/llama.cpp][llamacpp] / ggml comes with the upstream baseline and is
unchanged by us (it is inside the `upstream/` submodule). It is present in two
forms:

- `upstream/third_party/ggml` — vendored headers;
  `upstream/third_party/ggml/VERSION.txt` records commit
  `3cf03257f219afbe7334045ff7c6a06ac68c627d`.
- The llama.cpp checkout fetched by `upstream/CMakeLists.txt`
  (`FetchContent_Declare(strata_llamacpp ...)`, lines 1564–1567) when
  `STRATA_NATIVE_EXPERTS=ON` and `STRATA_GGML_DIR` is unset, pinned to
  `GIT_TAG 3cf03257f219afbe7334045ff7c6a06ac68c627d`.

License: MIT, "Copyright (c) 2023-2026 The ggml authors"
([`third_party/ggml/LICENSE` at `v0.2.2`](https://github.com/Niko1221/Strata/blob/v0.2.2/third_party/ggml/LICENSE);
offline: `upstream/third_party/ggml/LICENSE`).
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

## Vendored crypto (SP7 M2, spec D-2)

The release trust chain deliberately adds **no third-party crypto
dependency**. `secure_frontend/src/ed25519_verify.{hpp,cpp}` (lib
`secure_frontend_ed25519`) is our own dependency-free implementation of the
RFC 8032 §5.1.7 **verification path only** (strict verification equation as
the RFC's §6 reference, canonical-S rejection per §8.4, no cofactor
multiplication — the C++ never signs), with `sha512.{hpp,cpp}` alongside.
The release-side signer `scripts/release/sign.py` embeds the RFC 8032 §6
reference code **verbatim** (only page headers removed) from the text fetched
from rfc-editor.org on 2026-10-22. Test provenance follows the same rule:
every vector in `secure_frontend/tests/fixtures/release/rfc8032-vectors.json`
was fetched from the RFC's own §7.1/§7.2 listings and cryptographically
re-derived with the RFC's own code before being committed — no hex in this
repository's crypto tests is hand-transcribed.

License of the source material: RFC 8032 (and RFCs generally) is published
under the IETF Trust's legal provisions (Simplified BSD-style for the code
components); no copyright restriction conflicts with this repository's MIT.
Cited document: `RFC 8032, "Edwards-curve Digital Signature Algorithm
(EdDSA)"` (Josefsson & Liusvaara, January 2017), sections 5.1.7, 6, 7, 8.4
(<https://www.rfc-editor.org/rfc/rfc8032>).

## Built-in chat page: upstream's UI kit and font (2026-10-22, session log step 14)

The page served with `listener.web_ui` (`secure_frontend/web/`) takes upstream Strata's
look, by owner request. It is copied from the reviewed upstream pin (`v0.2.2`,
`serve/web/`, last changed in upstream commit `f2709679`) by `out/copy_upstream_ui.py`
(a session helper). The copy normalises line ends to LF and the three non-ASCII
characters in comments (em dash, ellipsis, degree sign) to ASCII. It drops the sprite's
embedded C2PA metadata block (an inert base64 provenance blob from the design tool) and
its inline style, points the font URLs at `/ui/fonts/`, and puts an attribution header
on each text file.

| File | Source | Licence | SHA-256 (as committed) |
| --- | --- | --- | --- |
| `web/tokens.css` | `serve/web/tokens.css` (adapted) | MIT | `b42489b95a279578244e1a4a080fc4c31169062652fced83b277ee6a295d5605` |
| `web/components.css` | `serve/web/components.css` | MIT | `c1d0cc2a77450817ee10b6cadaa7099c4b4afd20998bca45acdc14e820a666df` |
| `web/sprite.svg` | `serve/web/sprite.svg` (metadata dropped) | MIT | `55efc1936f17f21c645eac63579857bf565d21e30ac972b3d180e8bf7f022cf9` |
| `web/favicon.svg` | `serve/web/favicon.svg` | MIT | `84e586cd99715df7191c587e5b7289267f87e5035a0c4f5ab004d385809e0c1d` |
| `web/fonts/outfit-latin-wght.woff2` | `serve/web/fonts/` (byte-identical) | SIL OFL 1.1 | `6c18d579fd87c3776be068b762cbc83fde3acb543d49eabd3ade842eb987e887` |
| `web/fonts/outfit-latin-ext-wght.woff2` | `serve/web/fonts/` (byte-identical) | SIL OFL 1.1 | `0f53d1c03b3918d744a843b5039001ee31695ca1e255e3914188df81beb461e9` |
| `web/fonts/OFL.txt` | `serve/web/fonts/OFL.txt` | (the licence) | `c676351bf8576b9aba743cd5eaa8c0e7ee0d51f805d720447b4df4ddb6a2e416` |
| `web/LICENSE.strata-ui.txt` | upstream `LICENSE` | (the licence) | `949b9b0aada7476006469e58ee4ffb0e0f68c2d9137e90a356757b61a09d37f0` |

`web/index.html`, `web/app.css` and `web/app.js` are ours, modelled on upstream's
`index.html`, `app.css` and `app.js` (the markup and layout rules adapted, with the same
attribution; the script written for this server's routes). The Monitor tab (session log
step 16) follows the same rule: its markup (the state card, the context gauge and bars, the
requests table) and its layout rules are adapted from upstream's `index.html` and
`app.css`, and its rendering from upstream's `renderMonitor` in `app.js`, rewritten to
build DOM nodes (upstream's uses `innerHTML`) for this server's `/metrics`. Upstream's
conversation-cache and MCP cards and its disk and expert readings are left out (this
server has none of them). `web/theme.js` is ours. The
fonts are data, not code (contract C6 is about executables). They are WOFF2, checked by a
test, and the page's CSP allows fonts from this origin only. The licence texts are kept
beside the files and are not served.

## Release evidence (SP7 M2 — placeholder)

The SP7 offline release validation kit is `docs/validation/sp7-offline-kit.md`
(build → air-gap carry → offline validate → record). When a release kit run
happens on the owner's box, fill this entry — **blank means no claim**:

| field | value |
|---|---|
| date | _blank_ |
| host (GPU box) | _blank_ |
| source commit tested | _blank_ |
| release version | _blank_ |
| pinned release public key (64-hex) | _blank_ |
| signing key fingerprint used at build | _blank_ |
| tarball SHA-256 (`strata-<V>-linux-x86_64.tar.gz`) | _blank_ |
| `.deb` SHA-256 (`strata-secure_<V>_amd64.deb`) | _blank_ |
| `sha256sum -c SHA256SUMS` verdict | _blank_ |
| `doctor` / `doctor --deep` verdicts | _blank_ |
| `serve` + local chat verdict | _blank_ |
| `update` accept / `update --rollback` verdicts | _blank_ |
| unpinned-key and tampered-component refusal verdicts | _blank_ |
| results file SHA-256 | _blank_ |

**No offline-release, GPU, or update-chain claim is made until this entry
exists.** Windows installer runtime waits for the owner's own hardware on the
same terms (`NSIS_STATUS.txt` records the toolchain state on agent boxes).

[strata]: https://github.com/Niko1221/Strata/tree/v0.2.2
[unbiased]: https://github.com/robertkarl/UnbiasedStrata/tree/46c46ecfc11d2315512f21f7549b0a7792ccd2ae
[lighttransport]: https://github.com/lighttransport/Strata/tree/glm53f
[maya]: https://github.com/mw00/project-maya/tree/451f9cb6a21ea65673bdde2e57b4a670ae2b8859
[llamacpp]: https://github.com/ggml-org/llama.cpp/tree/3cf03257f219afbe7334045ff7c6a06ac68c627d
[llvmmingw]: https://github.com/mstorsjo/llvm-mingw/releases/tag/20261006

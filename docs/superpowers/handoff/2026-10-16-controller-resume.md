# Secure Strata — controller resume document (written 2026-10-16, at the owner's stop)

**Read this first if you are the agent resuming this project in a new chat.** It records what was built, how the work was run, every rule the owner (rflores) set, the exact state of every branch, what is waiting on the owner, and how to pick up. The code-level truth is `docs/AGENT_HANDOFF.md`; this file is the orchestration-level truth. Everything referenced here is committed in this repository; nothing needed to resume lives only in a chat transcript or a temp directory.

Owner's last instruction (2026-10-15 01:35 UTC): *"Close these out then push, then we stopped here until I tell you to."* Nothing may be started until rflores says so.

---

## 1. What this project is

Secure Strata (`shift-f10/multi-strata`, local checkout `/opt/projects/ai`) is a dependency-free C++20 **security frontend** around the upstream **Strata** inference engine (Niko1221/Strata, pinned as the never-modified git submodule `upstream/` at **v0.1.44.1**, gitlink `296b59d2`). The frontend owns the network edge, authentication, configuration, model acquisition, and supervision of the engine child; the engine does inference on an NVIDIA GPU. Goal: a hardened, privacy-first release for Linux and Windows, built and verified entirely without a GPU on the dev host, then validated once on the owner's offline NVIDIA box (Linux and Windows).

Decomposition (approved order): **SP0** foundation/hardening → **SP1** typed config, paths, tokens → **SP2** portable supervision → **SP3** API concurrency (M1) and streaming (M2) → **SP4** explicit verified pull/import/update → **SP5** frontend parity → **SP6** GLM-5.3 engine port → **SP7** release + offline GPU validation kit.

### Status at the stop

| Sub-project | State | Where |
| --- | --- | --- |
| Layout (upstream as submodule), shared pre-task (per-case CTest) | merged | main |
| SP0 foundation | merged | main |
| SP1 typed config / paths / tokens (24 tasks) | merged, real-Windows verified | main |
| SP2 portable supervision (30 tasks, two runs) | merged, real-Windows verified | main (merge 8333eccf) |
| Windows fixes after SP2 (harness 8.3 paths, conhost, handle baseline, **UTF-8 argv product fix**) | merged | main (863b3ff6) |
| SP4 part 1, Tasks 1–24b (SHA-256, manifests, store, index, bundles, fetch engine, `strata` verbs) | merged | main (merge 4b9fdd31) |
| **PP-line protocol fix** (Strata-profile prefill heartbeats accepted) | merged | main (c9629e6e) |
| SP4 part 2, Tasks 25–29 (confined curl downloader Linux + Windows, verbs end to end, privacy proofs) | merged, real-Windows verified | main (merge bd3b53a6) |
| **SP3 M1** concurrency + HTTP hardening (26 tasks: 0–5, 6a, 6b, 7, 8a, 8b, 9–23) | **Tasks 0–11 complete and reviewed; STOPPED by owner before Task 12** | branch `sp3-api-streaming` @ `9d30088b`, pushed; worktree `.worktrees/sp3` kept |
| SP3 M2 streaming (17 tasks) | plan written, not started | `docs/superpowers/plans/2026-10-14-sp3-m2-streaming.md` |
| SP6 GLM engine | DRAFT spec + research; **waits on the owner's decision sheet** | specs/research below |
| SP5, SP7 | not started, no spec | — |

**`main` = `bd3b53a6` = `origin/main`.** CI run 38660065273 on it is green on every blocking job: linux-gcc, linux-clang, linux-gcc-release (shipped configuration), windows-llvm-mingw-cross, top-level-integration, and **windows-msys2-clang on real Windows 516/516**. The `windows-msvc` job is informational and red by design (MSVC is not a supported toolchain for the frontend).

**2026-10-20 — the stop is lifted and the state has moved.** The owner directed the upstream update: **`main` = `7bddb9e1` = `origin/main`**, upstream `v0.1.44.1` → **`v0.2.1.3`** (gitlink `cbfd5b92`), with the `RESUME`/`REUSED` protocol hotfix `01ad7226` immediately before it; every gate green at the new pin, host and (last time) CI. Owner also disabled GitHub Actions (remote = storage; see the 2026-10-20 owner-decisions block in `docs/AGENT_HANDOFF.md`), so the CI statements below describe history unless the owner re-enables. SP3 M1 Task 12 resumes from this base.

Local gates on `main` (dev host): linux-gcc **560/560** (+2 environment skips: `proc03_other_uid_cannot_open_engine_fd`, `proc05_cgroup_kill_when_delegated`), linux-gcc-release 10/10 labelled (526/526 full), wine 260/260, pytest 25, 0 warnings under `-Werror` on every preset.

### Is it deployable? (owner asked 2026-10-14; answer still holds)
No. The frontend side is strongly evidenced; the system is not. It has **never run against a real engine or GPU** (every test uses a fake engine). Streaming does not exist and the serving path is single-threaded until SP3 lands. The downloader exists but the catalog ships **empty** by owner decision (D5(D)), so v1 acquisition is import-from-developer-bundle. No packaging, installer, validation kit, or GLM engine. The first real answer comes from one session on the GPU box (§8).

---

## 2. Owner rules (binding on every agent; violating one is stop-and-report)

1. **Touch only what you are told to.** The owner's standing rule across all his projects: only systems and paths he names. Never run `acid start`/`acid stop` or `az`. Never flip repository visibility. Never trigger paid services ("do not do anything that will trigger spending"). GitHub Actions on this **public** repo are free and are used freely.
2. **`upstream/` is never modified.** Bumps are submodule pin changes recorded in `docs/PROVENANCE.md` with the runbook there.
3. **Nothing installed outside** `.venv-dev/` (pip cmake 4.4.3, ninja, pytest) and `.toolchains/` (llvm-mingw). Both are git-ignored and symlinked into every worktree; never `git add` them.
4. **Sub-agents never push, merge, rebase, or switch branches**; the controller integrates. Commits are local to the lane branch.
5. **Commit authorship and trailers**, exactly: `git -c user.name=shift-f10 -c user.email=testdaflow.tv@gmail.com commit …` with two trailer lines written **literally** in every commit command (never via a shell variable): `Co-Authored-By: <model that wrote the commit> <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01XJi4XE2uAmBQoccdFoTPQw`. Sub-agent commits name the implementer's actual model (`Claude Opus 5.5` / `Claude Sonnet 5.5`); commits the controller makes itself name the controller's model (`Claude Fable 5.1`). A new session uses its own session URL. **Existing trailers are never rewritten** (owner: "keep trailers as-is", no force-push).
6. **The permission guard** blocks `rm -rf`, `git clean -fd*`, bypass flags, and sometimes rebase-conflict edits. Use unique directories and `find <dir> -delete`; retire worktrees by `mv` into the scratchpad then `git worktree prune` (git refuses to remove worktrees containing a submodule).
7. **Handoff discipline:** `docs/AGENT_HANDOFF.md` is updated as part of every change; proof status never lives only in chat. Never claim GPU or Windows behaviour verified from this host: Windows claims come only from the `windows-msys2-clang` CI job (wine is smoke); GPU claims come only from the owner's box. *(Owner update 2026-10-20: Actions are disabled — GitHub is storage; Windows runtime proof deferred to the owner's own hardware, and the green `windows-msys2-clang` run at `7bddb9e1` is the last CI-authorized Windows proof. Agents prove only the local `windows-llvm-mingw-cross` cross-build.)*
8. **`-Werror` everywhere; TDD per task with RED evidence in the report.** Tests never get weakened to pass; a wrong expectation is changed only with a written ruling.
9. **Commit and push after verified tests** (owner memory rule) — once the gates pass, the controller commits and pushes without being asked. (Suspended by the stop order until the owner resumed; since 2026-10-20 the push is **save-only** — no CI watching, no awaiting runs.)

---

## 3. How the work was run (the agent instructions)

### 3.1 Controller model
One **controller** (this document's author, Claude Fable 5.1 in the original session) orchestrates with the `superpowers` skills: `brainstorming` → spec, `writing-plans` → plan, `subagent-driven-development` → execution, `finishing-a-development-branch` → integration. The owner scaled it ("keep working and speed up development using workers"; "let the workers spawn additional workers") into:

- **Sub-controllers**, one per plan, each a `general-purpose` agent on **Opus** (alias `opus`), running the full `subagent-driven-development` loop in **its own git worktree** under `.worktrees/<lane>` on **its own branch**: implementer → task reviewer → fix rounds (≤5) → scoped re-review → final whole-branch review with one fix dispatch → final report. They decide conflicts themselves (spec binding, plan its argument), record `Ruling: … — why — cost if wrong` in a ledger, and stop only for the skill's four reasons.
- **Implementers/reviewers** on `opus`; pure transcription or single-file mechanical fixes on `sonnet`. Implementers may spawn **read-only** helpers (Explore / read-only general-purpose) but never a second editor of the same tree nor a reviewer of their own work. Never two implementers in one worktree.
- **The controller** owns: pre-flight reviews of plans, cross-plan rulings, the trial-merge gate, pushes, CI watching, owner communication, memory. It does not implement except for small hotfixes (the PP-line fix was one).

### 3.2 Briefs (verbatim copies in `docs/superpowers/handoff/briefs/`)
Every sub-controller received two files: `subcontroller-common.md` (project facts, tooling, owner rules, models, report format) and a plan-specific brief naming plan, spec, worktree, HEAD at launch, controller-verified baseline counts, scope, carry-ins from other lanes, and the final-report path. **Keep this pattern**: exact values live in the brief file, the dispatch prompt only points at it. Briefs preserved: `subcontroller-sp1.md`, `subcontroller-sp2.md`, `subcontroller-sp2-run2.md`, `subcontroller-sp4.md`, `subcontroller-sp4b.md`, `subcontroller-sp3m1.md` (the one to reuse), `winfix-brief.md`, `merge-sp4-brief.md`; plus `owner-decisions-2026-10-14.md`, `sp2-run2-handoff-items.md`, `sp3-m1-reanchor-notes.md`, `sp3-plans-preflight-review-1.md`.

Note: `subcontroller-common.md` still says the submodule pin is v0.1.43 in one line; the plan-specific brief (v0.1.44.1, `296b59d2`) is authoritative.

### 3.3 Integration gate (what the controller does after a lane reports COMPLETE)
1. `git worktree add --detach <scratchpad>/merge-<lane> main`; `git merge --no-ff --no-commit <branch>`; resolve conflicts (an Opus "merge resolver" agent with a brief did the 9-file SP4 merge — see `reports/fixes/merge-sp4-report.md`); `git submodule update --init -- upstream`; symlink `.venv-dev`/`.toolchains`.
2. Gates on the merged tree: `cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc`; `linux-gcc-release` preset (hooks OFF, `-L "release-only|release-also"`); `windows-llvm-mingw-cross` build (0 warnings) and `WINEPREFIX=$PWD/out/wineprefix WINEDLLOVERRIDES=mscoree,mshtml= ctest --preset windows-llvm-mingw-cross` from `secure_frontend/`; `pytest -q` from the root. Linux suites run **serially** (socket tests use fixed ports 20000–20099).
3. Commit the merge with gates in the message; `git merge --ff-only` in the main checkout; `git push origin main`; `gh run watch -R shift-f10/multi-strata` (always `-R`: plain `gh` resolves to the `upstream` remote); download the `windows-msys2-clang` log on red and open a fix lane. CI runs on **any branch push** (path-filtered), so a lane branch can be pushed for a real-Windows check before merging. *(Since 2026-10-20 Actions are disabled: skip the `gh run watch` and log-download parts; the push is the save, and the `windows-llvm-mingw-cross` build gate stands in for Windows until the owner runs real Windows himself.)*
4. Retire: `mv .worktrees/<lane> <scratchpad>/stale-worktrees/…`, `git worktree prune`, `git branch -d`, `git push origin --delete <branch>`.

### 3.4 Known harness behaviour
Sub-controllers were repeatedly **force-handed-back** mid-run by the harness (SP4 at Task 7, SP4 part 2 at Task 26, SP3 M1 at Tasks 6a, 8b, 11). Their in-flight implementer kept running and its report arrived at the controller instead. Recovery that worked every time: `SendMessage` to the sub-controller's agent id with "resume exactly from your ledger; reconcile children first; never redispatch the in-flight implementer; here is its report". The ledger (`progress.md`) is the recovery map; all are preserved under `reports/`.

---

## 4. Decisions already taken (do not re-litigate)

Owner, 2026-10-14 ("approve all and continue building") — full text in `briefs/owner-decisions-2026-10-14.md`, written into the specs:
- **SP6 (A1–A11):** evaluate both Maya (project-maya v1.1.8 @ `5c970a86`) and glm53f (@ `4894c996`) on the NVIDIA box, lean Maya; Windows in scope; MSVC v143 only as nvcc host for the engine; NVIDIA only; GGUF IQ/K + Maya quants; Maya serve/dashboard/updater/MCP/quant tooling out; **DFlash2 (CC BY-NC-ND) never**; single GPU first; engine as submodule, no local patches; env allowlist forces slots off and excludes DFLASH, no tuning knobs; loop guard off.
- **SP3 (B1–B12):** `max_tokens` omitted → auto; clamp; U+FFFD + tail drop; timeout → partial text `length`; chunked; neutral no-op + bounded temperature/top_p/seed; `/v1/completions`, `/v1/messages`, Ollama API out; CORS off with exact-origin opt-in `listener.cors_origins`; 8 workers, queue min(4, max(0, w−2)), 300 s, per-remote cap min(4, w); loopback residual accepted.
- **SP4 (C1–C7):** confined system-curl child; built-in digest catalog + `--trust-manifest`; curl floors 8.4.0 Win / 7.81.0 Linux; Qwen GSQ-RCO iq2_xs/iq3_xxs/iq3_s + Coder iq1_m but **catalog ships EMPTY** under D5(D) import-from-developer-bundle; `run` on a missing model = in-process pull after confirmation; no signature in v1 (Ed25519/SHA-512 → SP7); `update` exits 12.
- Task 22 (SP2) stdin-write bound; upstream bump to v0.1.44.1; rebase-conflict resolution approved.

Controller rulings of note (each ledgered with cost-if-wrong in the lane reports): D-2 uncounted client-STOP restarts bounded at `kMaxConsecutiveUncountedRestarts = 3`; `WinLaunchSpec` Job limits default ON, engine opts out; `EngineFamily` (SP2 env) vs `ManifestFamily` (SP4) rename; `compose_engine_launch` renders the typed `engine.gpu` list; Windows Job counts exclude `%SystemRoot%\System32\conhost.exe`; Windows handle-leak baseline taken at generation 2; link-set files written LF; Strata-profile `PP` heartbeats accepted (3–5 fields, two decimal counters, optional metrics, no ordering), GLM keeps its strict record.

Owner-visible behaviour changes already on the **SP3 branch** (not yet on main): 411 for Transfer-Encoding, 413 for oversized Content-Length, 404 `model_not_found`, 503 `server_shutting_down`, `invalid_json` for content-part arrays and deep tools bodies, `max_tokens` auto + clamp, `request_deadline_ms < 10000` requires `header_deadline_ms`, wildcard bind requires `host_aliases`, default 8 workers, `/v1/models` lists only the served model, listener and accepted sockets no-inherit (closes SP2 gap K4).

---

## 5. Waiting on the owner (none blocks the GPU session)

1. **SP6 decision sheet** (presented 2026-10-14 08:41, unanswered): S1 default pull `maya-s`; S2 include Maya-S24; S3 glm53f → keep pin + transcripts only; S4 fallback order; S5 `STRATA_GLM_SLOTS=0` only (prefix-reuse side channel noted); M1 Maya shipped flags as constants; M2 amend A10 for one typed `STRATA_GLM_RAM_HEADROOM_GB` default 16; M3 hand-built release engine accepted v1; M4 dev host = confined CPU configure+build only; M5 `STRATA_WATCHDOG_S=0`; M6 no-network-imports gate; M7 glm53f load-only. SP6 plan 1 cannot be written until this is answered.
2. **Delegated-cgroup live proof** on the dev host needs `systemd-run --user --scope -p Delegate=yes` (SP2 C5/C3; verified by reading only).
3. **Confirm the F-25 digest pins** for iq3_xxs, iq3_s, iq1_m before release (SP4 part 1), and **check `docs/PROVENANCE.md`**, which shows the **same shard-2 digest for all three Qwen quants and the Coder repo** — possibly a shared shard, possibly wrong; verify at source before trusting any pull.
4. Ratify two SP2 spec-vs-code rulings: C3 grandchild → membership assertion; K4 sockets (now closed on the SP3 branch).
5. SP1 `deployment.md`: the Windows token caveat can be removed.
6. The product-spec CLI verbs `serve`, `version`, `key` have **no owner** (SP4 created `strata` with its verbs only); assign to SP3 M2 or SP5.
7. Whether to resume SP3 M1 before or after the GPU session.

---

## 6. Exact resume procedure (when the owner says go)

1. Read this file, then `docs/AGENT_HANDOFF.md`, then the memory file if you are the same assistant (`/home/rflores/.claude/projects/-opt-projects/memory/project_multi_strata.md`).
2. Verify state: `git -C /opt/projects/ai status --short` clean; `git log --oneline -1 main` = `bd3b53a6`; `git worktree list` shows `.worktrees/sp3` at `9d30088b`; `git submodule status` = ` 296b59d2… upstream (v0.1.44.1)`; `.venv-dev` and `.toolchains` present (symlinked in the worktree).
3. **Resume SP3 M1:** launch a new Opus sub-controller with `briefs/subcontroller-common.md` + `briefs/subcontroller-sp3m1.md` plus this instruction: *"Resume from the ledger at `.worktrees/sp3/.superpowers/sdd/2026-10-14-sp3-m1-concurrency-hardening/progress.md` (copy in `reports/sp3-m1/`): Tasks 0–11 are complete at `9d30088b`; start with Task 12 from BASE `9d30088b`. Task 12 must prove: every admission call runs under the pool mutex; an evicted worker sees its abort within 20 ms; listener + linger entries stay within 128 poll entries. Carry the 37 rulings and 36 deferred minors listed in FINAL-REPORT.md. The task briefs 12–23 are already in the workspace."* If the lane workspace is gone, the sub-controller regenerates briefs from the plan with `scripts/task-brief`. Expect the forced hand-back; recover per §3.4.
4. Merge M1 via §3.3. Expected conflicts with main: none large (main did not move on SP3's surface after c9629e6e), but **consolidate the two egress interposers** (SP3 Task 19's own `LD_PRELOAD` interposer vs SP4's connect-audit shim) — ruled to be done at merge. Then push, CI, and update `AGENT_HANDOFF.md` to state the SP3 behaviour changes.
5. **SP3 M2** (streaming): plan on main; brief pattern as M1; it greps M1's seam names `RouteResult`, `StreamSink`, `HttpHead`, `StreamHandler`, `serialize_head`, `deliver_route_result`, `SocketStreamSink`.
6. **SP6 plan 1** only after the owner answers the sheet (§5.1); then SP5/SP7 specs via `brainstorming`.
7. Also queued: PX addendum reconciling `http.*` → `listener.*` names and `STRATA_CONFIG`; parked test-infrastructure items (fixed ports 20000–20099 collide under `ctest -j`; `make_private_directory` accepts an existing dir unchecked; `/tmp` fallback without `SECURE_FRONTEND_TEST_TMP`; stale `test-tmp` dirs after SIGKILLed runs; wine 0.01 s start-up flake).

---

## 7. Repository map (what to read for what)

- `docs/AGENT_HANDOFF.md` — code-level truth: every deliverable, proof status, known gaps. Updated by every lane.
- `docs/PROVENANCE.md` — upstream pin, bump runbook, digests. `upstream.version` (root) is the engine-version source.
- `docs/security/threat-model.md`, `docs/security/engine-protocol-limits.md` (engine wire facts incl. the `PP` row), `docs/secure-frontend-ci.md`, `docs/product-spec*` (PX), `tests/security/README.md` (acceptance IDs NET/AUTH/DOS/WEB/CFG/DL/PRIV/PROC/EXT).
- Specs: `docs/superpowers/specs/2026-10-13-sp0-*`, `…-sp1-*`, `…-sp2-portable-supervision-design.md`, `2026-10-14-sp3-api-concurrency-streaming-design.md` (APPROVED, D-1/D-2 re-anchored), `2026-10-14-sp4-acquire-design.md` (APPROVED), `2026-10-14-sp6-glm-engine-design.md` (DRAFT), `2026-10-13-upstream-submodule-layout-design.md`.
- Plans: `docs/superpowers/plans/…sp3-m1-concurrency-hardening.md`, `…sp3-m2-streaming.md`, `…sp4-acquire.md`, earlier SP0/SP1/SP2.
- Research: `docs/superpowers/research/2026-10-14-sp6-glm-engine-sources.md` (Maya vs glm53f facts; project-maya is the second SP6 source per the owner).
- This directory `docs/superpowers/handoff/`: `briefs/` (§3.2), `reports/` (SDD final reports and ledgers for SP1, SP2 run 1 and 2, SP4 part 1 and 2, SP3 M1 to Task 11, the Windows fix lane, the SP4 merge resolver, the SP0 ledger).
- Code: `secure_frontend/` (presets in `CMakePresets.json`: `linux-gcc`, `linux-clang`, `linux-gcc-release`, `windows-llvm-mingw-cross`, `windows-msys2-clang` CI-only; tests register per case through `secure_frontend_add_cases`, label `windows-runtime` for real-Windows-only cases). Binaries: `strata-secure-server`, `strata` (SP4 verbs). CI: `.github/workflows/secure-frontend.yml`, Linux jobs pinned `ubuntu-24.04`.

---

## 8. First GPU-box session checklist (the first real test of the system)

1. Build the upstream engine there (CUDA; Windows needs MSVC v143 as nvcc host — the frontend itself stays llvm-mingw/MSYS2). Hand-place engine, model shards and tokenizer pack (catalog is empty by design; or build a developer bundle with `make_bundle.py` and `strata import --trust-manifest`).
2. `strata-secure-server --config <file> --expert` with `--pack` and the weight flags in `engine.args`; one `POST /v1/chat/completions`. The `PP` heartbeat fix (c9629e6e) is the known first-request blocker that was fixed by reading; confirm it live.
3. Check `qwen35moe` family behaviour if that model is used (different serve loop: no QUIT, unknown flags skipped, no `--pack`, no `+8` margin — `engine-protocol-limits.md`).
4. Run the cgroup-delegation proof if the box is systemd (`systemd-run --user --scope -p Delegate=yes`) and the SP2 `proc05_cgroup_kill_when_delegated` case.
5. Measure STOP latency during a long prefill (SP3 risk R4) and the READY time against `ready_timeout_s` (900 s default).
6. Record every outcome in `docs/AGENT_HANDOFF.md` ("Verification performed", GPU column) — the first time any GPU row can be marked verified.

---

## 9. Lessons that cost time (do not repeat)

- Never `git merge … | tail` inside an `&&` chain (the pipe hides the failure).
- `git submodule deinit` in **any** worktree removes the shared `.git/config` submodule entry (repair: `git submodule init` in the main checkout).
- Fresh worktrees need `git submodule update --init -- upstream` (clones from the shared module store, no network) and the two symlinks.
- Windows CMake `file(WRITE)` writes CRLF; Windows `main(argc, argv)` is ANSI (now fixed with the shared `secure_frontend_utf8_argv` library); `CREATE_NO_WINDOW` spawns a `conhost.exe` inside the Job; `%TEMP%` on runners is an 8.3 path.
- A sub-controller's "COMPLETE" is not a merge gate: the trial merge found semantic conflicts (dropped GPU list, duplicate `EngineFamily`) that only compile-and-test exposed.
- The harness lists finished subagents as present until the session ends; `ps` is the truth for live processes.

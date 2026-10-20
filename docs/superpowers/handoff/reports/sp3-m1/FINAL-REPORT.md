# SP3 M1 sub-controller report — STOPPED BY OWNER at Task 11 (resume point)

**Branch** `sp3-api-streaming`. Worktree `/opt/projects/ai/.worktrees/sp3`.
**HEAD** `9d30088b`. **Base** `557a2cc7`.
Nothing was pushed, merged or rebased.

**`git status --short` at HEAD:** empty. There is no uncommitted work.

## Commits (`git log --oneline 557a2cc7..HEAD`, oldest first)

Every commit below passed task review. Where a review raised findings, the fix round that resolved them is noted.

| Task | Commit | Subject |
| --- | --- | --- |
| 0 | cf6df6dd | docs: SP3 M1 handoff section and baseline |
| 0, fix round 1 | 7f682eed | docs: move SP3 M1 handoff section after the SP2 section |
| 1 | 8aea2175 | api: one error table, one JSON writer, security headers and Date on every response |
| 2 | 64d96fee | http: request-head scan and strict parser, 414/431/411/413/505/417 |
| 2 | 0cb16cd2 | http: keep the ASCII helper inside SP3 (no SP4-file edits) |
| 3 | 211f8287 | http: Host allowlist from the listener, exact origins, fixed preflight list |
| 4 | 5134f4a6 | config: SP1 addendum A1 — Host aliases, CORS origins, HTTP deadlines, request logging key |
| 5 | e5fd2cad | config: SP1 addendum A2 — worker pool and queue keys with derived defaults; max_tokens auto and clamp |
| 6a | 9cc726cd | http: router types with the streaming seam; head serializer without Content-Length |
| 6b | a49ff6b2 | http: header-first routing; authenticate before the body; route table, 404/405/415/413 order |
| 6b, fix round 1 | 47a97a71 | docs: record SP1 addendum A6b (is_valid_utf8 export) |
| 7 | c2d51628 | chat: OpenAI request schema with fixed error params, sampling subset, opt-in JSON decimals |
| 8a | 53ed7f73 | net: non-blocking polled socket I/O with a progress-based write stall |
| 8a, fix round 1 | 701a725d | net: pin the progress-based write stall |
| 8b | 63b7ffe2 | net: header-first P1–P8 connection handler with the stream dispatch site |
| 9 | 7e441e27 | server: every request through the header-first router; 401/413 before the body over TCP |
| 9, fix round 1 | 29804f11 | test: ext01 pins extension_disabled for every reachable extension body |
| 10 | f7a150d0 | test: WEB-01..06 and AUTH-01 over TCP on every route; wildcard bind needs aliases and spawns nothing |
| 11 | 46ad217f | net: admission state with oldest-P1 eviction and per-remote cap; lingering close for refusals |
| 11, fix round 1 | 9d30088b | test: linger overflow pins which socket is evicted |

## Tests at HEAD 9d30088b

- **linux-gcc:** the controller ran `ctest --preset linux-gcc` on the committed HEAD. Result: `100% tests passed out of 596`. The two allowed skips are `proc03_other_uid_cannot_open_engine_fd` and `proc05_cgroup_kill_when_delegated`.
- **wine:** 312/312. This is the Task 11 implementer's run on 9d30088b, after its fix. The controller did not rerun wine, because it would not fit the close-out time limit.
- **Cross build:** clean with `-Werror`.
- **pytest:** 23 at Task 5. No later task touched Python.
- **Real Windows:** every new windows-runtime row is pending an MSYS2 run. Base rows were verified by CI run 38625663621 (488/488).

## Task state

- **Tasks 0–11 are complete.** Each has a task review that came back clean, either directly or after fix round 1, with no Critical or Important findings left open.
- **Task 12 was not started.** Its implementer was dispatched just before the owner's stop instruction arrived. It was told to stop, and reports that it changed no files and made no commit. The tree is clean.
- **Tasks 12–23 and the final whole-branch review remain.**

## Resume instructions

1. **Ledger.** Read `progress.md` in this workspace. It holds 37 "Ruling" lines, 36 deferred minors, and the per-task log. `preflight-scan.md` is the binding pre-flight table, with 143 rows and 79 conflicts, all ruled.
2. **Starting point.** Start Task 12 from BASE `9d30088b`. The briefs for Tasks 12–23 are already in this workspace as `task-N-brief.md`. Read `implementer-rules.md`, `reviewer-constraints.md` and `shared-interfaces.md`.
3. **Task 12 (ConnectionPool) must prove three things:**
   - every `admit`, `header_complete` and `finished` call runs under the pool mutex;
   - an evicted P1 worker sees its abort flag and closes within one 20 ms slice;
   - the listener plus the linger list fit in one `poll_sockets` call of at most `kMaxPollEntries` (128) entries per 100 ms slice.
4. **Other carry-ins for Task 12:**
   - `run_until` exits when the listener handle is invalid, and the stop predicate is `supervisor.stop_requested()` (P33).
   - When the listener fails, the server shuts the supervisor down and returns `EXIT_FAILURE` (T12b).
   - `net01` must assert the 200 count (D3) and reuse `wait_health_on` (D2).
   - Before closing the listener on POSIX, call `shutdown(SHUT_RDWR)` so a blocked poll wakes.
   - An in-flight response write must stop within `kShutdownDrainBudget` once shutdown starts.
5. **Later carry-ins:**
   - **Task 13:** fix the destructor comment in `engine_supervisor.hpp`.
   - **Task 15:** pass the stop cause on cancellation: `stop(EngineStopCause::client_cancelled)` (S1). Keep `begin_generation`'s `write_deadline`. Normalize a temperature of `-0.0`. Leave the PP branch alone: main c9629e6e changed it.
   - **Task 17:** add the case `dos02_cancel_drain_failure_is_not_counted`.
   - **Task 19:** build an interposer under its own names, not SP4's `secure_frontend_connect_audit` / `SF_CONNECT_AUDIT*`. Mark `socket` `noexcept` (glibc declares it `__THROW`), and make `run_lifecycle` assert its results (D4).
   - **Task 20:** ext02 follows T20.
   - **Task 22:** the TSan job is CI-only on this host, and the YAML privilege sentence is extended.
   - **Task 23:** the handoff and README state the owner-visible changes below, D-1/D-2 are recorded as landed, R4 records the uncounted-restart bound of 3, the README intro ("serial") is corrected, and CI run 38625663621 is cited for unchanged rows.
6. **Final review.** After Task 23, run the final whole-branch review: one fix dispatch, then one scoped re-review.

## Owner-visible behaviour changes so far

All of these follow the spec, and the coordinator has accepted them.

**Status codes**
- `Transfer-Encoding` now returns 411. It was 400.
- A `Content-Length` over the bound now returns 413. It was 400.
- An over-long header block returns 431, and an over-long request line returns 414.
- A wrong model id returns `404 model_not_found`. It was 400.
- A generating chat at server stop returns `503 server_shutting_down`.
- `/v1/models` lists only the served model, including in `--expert` mode.

**Request bodies**
- JSON depth is capped at 4. OpenAI content-part arrays therefore get `400 invalid_json`, not `unsupported_parameter`. Deep `tools` bodies get `400 invalid_json`. Shallow extension bodies get `extension_disabled` with `param`. Nothing is spawned in any of these cases. **Owner flag.**
- `max_tokens`, when omitted, defaults to auto: `min(max_completion_tokens, ctx − n − 8)`. A value above the limit is clamped (B1, B2).

**Configuration**
- A config with `request_deadline_ms` below 10000 must also set `header_deadline_ms`, or it is rejected.
- A wildcard bind needs `listener.host_aliases`, or it is rejected.
- An omitted `max_concurrent_requests` now means 8 workers. Configs that set it to 1 stay serial.
- SP1 addenda A1, A2, A3 and A6b are recorded in the handoff.

**Errors and sockets**
- Every error body is now JSON.
- Listener and accepted sockets are CLOEXEC / no-inherit, which closes the K4 gap.

## Notes

- **Two interposers.** SP4's connect-audit `LD_PRELOAD` shim is on main at bd3b53a6. SP3's Task 19 interposer is not built yet. Its names must not overlap SP4's, and the coordinator consolidates the two after merge.
- **Wine flakes.** Some tests fail in 0.01 s at start-up, before any test code runs: `json_tests.json_accepts_strict_document`, `http_socket_server_tests.oversize_header_with_431`, and once SP4's `fetch_tests.status_table_decisions`. Each passed on rerun. They are on the watch list.
- **Unowned CLI.** The product-spec CLI (`serve`, `version`, `key`) has no owner. The `strata` binary carries SP4 verbs only.
- **Task 2 history.** Task 2 has two commits. The first briefly edited SP4's `acquire_manifest.*`; the second reverts that. The net diff touches no SP4 file, and the integrator may squash the pair.
- **Incident.** The Task 8a implementer ran one read-only `git log` in `sp4b` and changed nothing there. Every dispatch now forbids running anything outside sp3.
- **Forced handbacks.** The harness forced a handback three times. Each time the run resumed with no work lost.

## Rulings

All are in `progress.md`, in order. Each records what was decided, why, and the cost if wrong.

- **Task 0, re-anchors 1–9.** Re-anchor 7 does not match the tree, so Task 19 builds its own interposer.
- **Process.** Commit trailers name the real model. M1 does not touch the stdin write bound. SP2 carry-ins bind. Tests prefer ephemeral ports. The plan was read through the scan.
- **Pre-flight.** Every proposed ruling in the scan is adopted, plus 10 refinements: S1, P12/P23, P11, P33/P34, V12, T13b, T22b, D3/D4, D10, T9a/T19c.
- **Task 2.** SP4 files are reverted and the helper is `ascii_to_lower`. Both commits are kept.
- **Task 4.** The two deadline/host-alias rejections are accepted. The SP1 test edits are accepted. The schema rows stay grouped.
- **Task 6a.** Origin is checked before preflight. The 411 and 413 changes are accepted.
- **Task 6b.** The SP1 edit A6b is allowed. A bad value on `/health` fails closed as `engine_unavailable`.
- **Task 7.** JSON depth stays at 4, and EXT-01 is tested under that limit.
- **Task 8a.** The `set_no_inherit` helper is kept.

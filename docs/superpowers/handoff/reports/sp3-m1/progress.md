# SDD ledger — plan: docs/superpowers/plans/2026-10-14-sp3-m1-concurrency-hardening.md

Spec: docs/superpowers/specs/2026-10-14-sp3-api-concurrency-streaming-design.md (APPROVED; §1.5 D-1/D-2 and §2.6 re-anchored 2026-10-14 — spec wins over plan on cancellation).
Worktree /opt/projects/ai/.worktrees/sp3, branch sp3-api-streaming, launch HEAD 557a2cc7 (verified), submodule 296b59d2 upstream (v0.1.44.1) clean, .venv-dev/.toolchains symlinks present.
MERGE_BASE = 557a2cc7da02f966cc92ed80ee137e9cc27d4364
Baseline (controller-verified): linux-gcc 520/520 (+2 skips), linux-gcc-release 510/510, wine 256/256, pytest 23.

## Task 0 anchor check (controller, 2026-10-14)
All 18 plan Step-1 greps hit on 557a2cc7 (kSchema is `std::array<ConfigKey, 43>`; FrontendConfig ctor now ends `PullSettings pull_value`; README `config-keys:begin` in secure_frontend/README.md).

Ruling: re-anchor 1 (CI YAML) — `upstream.version` is the engine-version source; Task 22's TSan job adds no `-D`; keep both header-comment sentences on any text conflict. Controller note 11 APPROVED: Task 22 edits the YAML locally (no push; nothing triggers Actions from this lane) — why: brief says the TSan job is non-blocking and to run the TSan preset locally — cost if wrong: one revertable YAML hunk.
Ruling: re-anchor 2 (CMakePresets) — SECURE_FRONTEND_TEST_HOOKS is already ON in test presets and `linux-gcc-release` exists; no task re-adds them; the TSan preset inherits from the hooks-ON base — why: fact on main — cost if wrong: none (no edit).
Ruling: re-anchor 3 (frontend_config.hpp) — Task 4's `logging` member + ctor parameter is appended AFTER `pull` (ctor becomes `(..., EngineLaunch, PullSettings, LoggingSettings)`); Task 5's ConcurrencyLimits rewrite replaces the current one-field struct; any SP3 use of `roots.tokenizer_pack` / `engine.profile` must handle `std::nullopt` — why: SP4 shape on main — cost if wrong: merge-time conflict in a ctor line.
Ruling: re-anchor 4 (secure_server_main.cpp) — router config takes `model_id = launch.model_id` (the `const std::string& model_id = launch.model_id;` line); `selected` is never reintroduced; `owned_by = "local"` (the `ModelRecord::owned_by` default; the launch record carries no owned_by). Per spec R3/§9.4 `/v1/models` lists only the served model (launch.model_id), not `launch.served_models`' expert inventory — why: spec is binding and plan says "lists only the served model" — cost if wrong: expert-mode /v1/models shows one id instead of the inventory; one-line change.
Ruling: re-anchor 5 (server harness/fixture) — every SP3 process launch uses what `ServerFixture::base_flags()` / `server_harness.cpp` pass today: `--expert`, `--models-root`, `--tokenizer-pack`, `--engine`, `--state-dir` (0700 owner-private dir); implementers read tests/support before writing launches — cost if wrong: test-only rework.
Ruling: re-anchor 6 — cfg01_* cases in `secure_frontend_typed_config_tests` (plan note 1 already does this).
Ruling: re-anchor 7 (egress shim) — FACT DIFFERS: SP4's `secure_frontend_connect_audit` shim (SP4 Task 28) is NOT on main 557a2cc7; it is being built concurrently in .worktrees/sp4b. Task 19 therefore builds SP3's interposer as the plan specifies (`tests/support/egress_tripwire.cpp` → `libstrata_egress_tripwire.so`), with no name, env var (`SF_CONNECT_AUDIT*`) or CMake target overlapping SP4's, and keeps the static-import tripwire (Task 18). Flag to controller: consolidate the two shims at/after integration — why: cannot reuse code that does not exist in this tree, and must not touch sp4b — cost if wrong: two LD_PRELOAD shims in tests until consolidated.
Ruling: re-anchor 8 — README key table regenerated with the SP1 generator in Tasks 4/5/23, never hand-merged; controller regenerates again at merge.
Ruling: re-anchor 9 — no `strata` binary work in M1; product-spec CLI (`serve`, `version`, `key`) still unowned — flagged in the final report.
Ruling: commit trailers — plan text's `Co-Authored-By: Claude Fable 5.1` is superseded by the common brief: implementer's actual model (`Claude Opus 5.5` / `Claude Sonnet 5.5`), literal lines — why: owner rule — cost if wrong: none.
Ruling: plan note 13 / SP2 R1 — stdin write bound belongs to SP2 (shipped in run 2); M1 does not touch it.
Ruling: SP2 carry-ins bind: cancellation = `stop(EngineStopCause::client_cancelled)` with reason via `kill_reason_for(protocol)`; uncounted restart bound `config_defaults::kMaxConsecutiveUncountedRestarts`; `wait_for_change` observes states; listener + accepted sockets get CLOEXEC / `WSA_FLAG_NO_HANDLE_INHERIT` (Task 8a/8b) and the handoff records the K4 gap closed; write-stall timeout slices sends on BOTH platforms (Task 8a); fix the `engine_supervisor.hpp` destructor "one exception" comment to cover Windows in Task 13 (lease lifecycle) — why: SP2 final report, binding per brief.
Ruling: socket tests touching the server fixture prefer ephemeral port 0 (plan's per-case port table in 8b may be replaced by port 0 where the fixture allows).
Ruling: plan read strategy — plan is 9094 lines; controller read header/constraints/interfaces/Task 0 directly and delegated the full pre-flight conflict scan to a read-only Opus agent (table below); per-task text reaches implementers via task-brief — why: protects controller context over 26 tasks — cost if wrong: a cross-task conflict the scan missed is caught by task review.

## Pre-flight conflict scan
Full table (143 rows: 50 pair, 26 per-task, 17 spec, 39 tree, 11 reviewer; 79 conflicts 23H/33M/23L): preflight-scan.md in this workspace — it is part of this ledger. Implementers read the rows naming their task.

Ruling: ADOPT every proposed ruling in preflight-scan.md §1–§5 as written (P10–P50, T1–T23, S1–S17, V1–V39, D1–D10), with the refinements below — why: each was checked against tree 557a2cc7 and the spec by the scan; spec binds — cost if wrong: per-row costs as stated in the scan.
Ruling (S1/P45/V26, H): cancel uses `stop(EngineStopCause::client_cancelled)`, timeout `stop(EngineStopCause::generation_timeout)`; Task 15 adds the stop_cause assertion; Task 17 (not 16 — it owns disconnect acceptance) adds `api_server_tests.dos02_cancel_drain_failure_is_not_counted` (assert via stderr reason `client_stop_drain_failed` and that a following chat succeeds after restart) — why: spec §2.6/D-2 — cost if wrong: one test moves between tasks.
Ruling (P12/V1/P23, H): the task that changes an API ports every in-tree user of it, including `src/smoke_main.cpp`, `src/smoke_server_main.cpp`, `secure_server_main.cpp` and old tests — Task 3 (HttpPolicy), 6b (ApiRouter), 8b (HttpSocketServer/bind; smoke mains hold a WinsockGuard), 9 (legacy handle_http_request removal). Every task ends with a green full build on both presets — why: build must never be red between tasks — cost if wrong: none beyond scope.
Ruling (P11): Task 3 takes 6a's forward-declaration change (`struct HttpPolicy;` in http_request_handler.hpp, include moved to .cpp).
Ruling (P33/P34/T12, H): adopt both: 8b wires `HttpSocketServer::State::stopped` as `WorkerSignals.shutting_down` in `serve_one`; Task 12's `run_until` exits when the listener handle is invalid, main's stop predicate is `supervisor.stop_requested()`, and `PoolExit::listener_failed` → `supervisor.shutdown(kShutdownBound)` + `return EXIT_FAILURE`.
Ruling (V12, carry-in): CLOEXEC/no-inherit on listener + accepted sockets lands in Task 8b with case `http_socket_server_tests.listener_and_accepted_sockets_are_not_inherited`; handoff records K4 gap closed.
Ruling (T13b/V22): Task 13 also fixes the engine_supervisor.hpp destructor comment (comment-only).
Ruling (T22b): no TSan preset is added (the plan adds `-D CMAKE_*_FLAGS` on linux-clang in the CI job only); local TSan run is NOT possible on this host if no Linux clang with the TSan runtime exists — Task 22 implementer checks (`which clang clang++`) and runs it locally if available, else records "CI-only, not run locally" — why: brief asks local TSan "where the plan says so"; plan defines none locally — cost if wrong: TSan findings surface only on the owner's push.
Ruling (D3/D4): assert-nothing traffic in net01_workers_add_no_listener and run_lifecycle gets real assertions as proposed.
Ruling (D10): new constants kMaxModelFieldBytes, kMaxPollEntries, kLogLineMaxBytes go in api_constants.hpp in the task that first needs them; use kContextMarginTokens in Task 5.
Ruling (T9a, T19c): RED lines may be "acceptance, passed before implementation" where earlier tasks already deliver the behavior; record honestly in the commit body.


Note (coordinator, 2026-10-14): CI run 38625663621 on base 557a2cc7 all green — MSYS2 real Windows 488/488, linux-gcc-release green. Every windows-runtime row on the base is verified on real Windows; cite run 38625663621 in Task 23 (and any handoff edit) for "pending MSYS2" rows M1 does not change. New M1 windows-runtime rows stay "pending MSYS2".

## Task log
Task 0: fix round 1/5 (1 addressed, 0 open — SP3 block split SP2 closing paragraph; commits cf6df6dd..7f682eed)
Task 0: complete (commits 557a2cc7..7f682eed, review clean) — N0 = 520 (+2 skips), W0 = 256
Task 1: BASE 7f682eed, dispatched (opus)
Task 1: ⚠️(a) resolved by controller — chat_schema.cpp already uses SP1's shared append_json_string (no copy left); ⚠️(b) carried to Task 6a dispatch (P3: delete local ascii_iequal in http_wire.cpp).
Task 1: minor (deferred): http_parser_test.cpp:111 guard `wire.size() >= 3U` should be `>= 7U` before substr(size-7).
Task 1: minor (deferred): §3.9 "UTF-8 copied unchanged after validation" — router model fields are not UTF-8-validated; carried to Task 6b dispatch (validate in the router rewrite).
Task 1: minor (deferred): http_wire.hpp:9 comment says six security headers, kSecurityHeaders holds five (+Connection).
Task 1: complete (commits 7f682eed..8aea2175, review clean) — linux-gcc 524/524, wine 260/260
Task 2: BASE 8aea2175, dispatched (opus)
Ruling (Task 2 concern): the implementer moved SP4's `secure_frontend::ascii_lower` out of acquire_manifest.{hpp,cpp} into a new ascii_text.hpp. Reverse it: SP4-lane files (src/acquire*, include/secure_frontend/acquire*) are owned by the concurrent sp4b lane; SP3 must not edit them. SP3's export is renamed `ascii_to_lower` (http_request_head.hpp) so no symbol collides; ascii_text.hpp is removed — why: brief assigns acquire* to SP4; a two-line duplicate is cheaper than a cross-lane merge conflict — cost if wrong: one small duplicated helper; controller may consolidate after both lanes merge.
Task 2: ⚠️ resolved — (a) trailers verified Claude Opus 5.5 on 8aea2175/64d96fee/0cb16cd2; (b) Task 3 brief pins single-Host → 400 (policy test "duplicate Host is 400"); (c) see ruling.
Ruling (Task 2 two commits): keep 64d96fee + 0cb16cd2 as-is (no rebase/squash allowed in this lane); the pair's net diff touches no SP4 file — integrator may squash when merging if desired — cost if wrong: one intermediate commit touches acquire_manifest.* in history only.
Task 2: minor (deferred): http_request_head.cpp Content-Length accumulates 10 digits in size_t — wraps on 32-bit targets (both presets 64-bit).
Task 2: minor (deferred): D6 helper assertions folded into head_request_line_and_header_syntax (mislabel risk).
Task 2: complete (commits 8aea2175..0cb16cd2, review clean) — linux-gcc 530/530, wine 266/266
Task 3: BASE 0cb16cd2, dispatched (opus)
Task 3: ⚠️ resolved — commit body carries RED, linux-gcc and wine lines; trailer Opus 5.5.
Task 3: minor (deferred): tests/http_request_handler_test.cpp policy(bool) ignores its argument (dead param) — remove when 6a/6b port these cases.
Task 3: minor (deferred): is_valid_host_alias/is_valid_cors_origin are noexcept but call non-noexcept is_valid_host_header.
Task 3: minor (deferred → carried to Task 4): mains pass their old bind authority as a host alias (keeps non-spec 0.0.0.0:<port> for wildcard binds); Task 4 wires listener.host_aliases/cors_origins into make_http_policy in the mains and drops that alias.
Task 3: complete (commits 0cb16cd2..211f8287, review clean) — linux-gcc 530/530 (5 policy cases replaced 1:1), wine 266/266
Task 4: BASE 211f8287, dispatched (opus)
Ruling (Task 4 concern 1): accept that an SP1 config setting request_deadline_ms < 10000 without header_deadline_ms, or a wildcard bind without listener.host_aliases, is now rejected — why: spec §5.1 table states both cross-field rules explicitly and §9.3 names cfg01_header_deadline_le_request_deadline / cfg01_wildcard_bind_requires_host_aliases; the "every SP1 config stays valid" sentence (§5.1 l.787) is argued only for the concurrency keys — cost if wrong: such configs need one extra key; handoff A1 row records it; flag to owner in final report.
Ruling (Task 4 concern 2): SP1 test edits (subsystem_limits header_deadline_ms=1500; auth04 allow-list gains logging.requests as a non-auth switch) accepted as the behavior-change-in-same-task rule requires — reviewer checks auth04 still forbids any auth-disabling switch.
Ruling (Task 4 concern 4): kSchema rows placed at the brief's grouped positions (listener after backlog, http after max_request_line_bytes, logging.requests last) rather than all after pull.* — why: brief is explicit; hunks are away from SP4's pull.* rows except logging.requests — cost if wrong: one merge hunk to resolve.
Task 4: ⚠️ resolved — only one HttpLimits{/ListenerConfig{ construction site exists (frontend_config.cpp validate), updated.
Task 4: minor (deferred): smoke_server_main wildcard bind still passes "0.0.0.0:<port>" as alias (smoke binary, no typed config) — record or reject wildcard in that binary.
Task 4: minor (deferred): wildcard host without allow_wildcard_bind reports both listener.host and host_aliases issues (noise).
Task 4: minor (deferred): host_aliases duplicate check is byte-exact (Box.lan:1 vs box.lan:1 both validate; make_http_policy dedupes).
Task 4: complete (commits 211f8287..5134f4a6, review clean) — linux-gcc 536/536, wine 272/272, pytest 23
Task 5: BASE 5134f4a6, dispatched (opus)
Task 5: note — README intro 'serial inference listener' left for Task 12/23 truth pass (carry to Task 23).
Task 5: ⚠️ resolved — frontend_init.cpp:86 still writes only flags + schema_version.
Task 5: minor (deferred): no execute()-level test of omitted max_tokens → auto (only resolve_max_tokens unit test).
Task 5: minor (deferred): max_connections_per_remote_address row default_integer 0 below its min 1 (masked by derived default; add comment).
Task 5: minor (deferred): chat_applies_engine_context_rule_with_eight_token_margin name/comment describe the old rule.
Task 5: complete (commits 5134f4a6..e5fd2cad, review clean) — linux-gcc 544/544, wine 280/280, pytest 23
Task 6a: BASE e5fd2cad, dispatched (opus)
Harness forced handback after Task 5 (interim FINAL-REPORT). Coordinator: resume; rulings on re-anchor 7 and owner-visible behaviour changes ACKNOWLEDGED/ACCEPTED — handoff + README key table must state them (carry to Task 23).
Task 6a: implementer committed 9cc726cd (hand-back routed to coordinator; report file present). BASE e5fd2cad.
Ruling (Task 6a concern): Origin before preflight in the legacy adapter stands — spec §4.1 order is step 3 Host+Origin policy, step 4 CORS preflight; Task 3's shim order was the deviation — cost if wrong: none observable (unknown-origin preflight 403 either way).
Ruling (Task 6a §9.4 status changes): TE → 411 (was 400) in http_request_handler_tests.rejects_malformed_and_ambiguous_messages and CL over bound → 413 (was 400) in http_socket_server_tests.parser_honors_configured_max_request_bytes accepted — spec §4.2 and §9.4 require them, and the "update tests in the task that changes behavior" rule applies — cost if wrong: two assertions.
Task 6a: ⚠️ carried — D7 deletion of DispatcherRouter + legacy overload checked at Task 9; kNoResponseStatus=0 handling carried to Task 8b dispatch.
Task 6a: minor (deferred): seam tests miss short-body (CL 2, 1 byte) and "handle not called when decision.early".
Task 6a: minor (deferred): no test that serialize_head drops Server/X-Powered-By/caller Date.
Task 6a: minor (deferred): legacy path no longer has GET/POST/OPTIONS allowlist (correct per §4.1 step 6) but untested there.
Task 6a: complete (commits e5fd2cad..9cc726cd, review clean) — linux-gcc 546/546, wine 282/282
Task 6b: BASE 9cc726cd, dispatched (opus)
Task 6b: note — wine flake once in SP4's fetch_tests.status_table_decisions (passed on rerun 3/3); watch list.
Ruling (Task 6b SP1 edit): Task 6b may make one SP1 edit — exporting `is_valid_utf8` (noexcept wrapper over json.cpp's existing valid_utf8) from json.hpp for §3.9 — recorded as SP1-addendum row "A6b" (A3 stays reserved for Task 7's JSON decimals per plan note 2) — why: avoids a sixth private UTF-8 copy; behaviour-neutral — cost if wrong: one exported function in SP1.
Ruling (Task 6b deviation 1): /health keeps SP2's literal allowlist; the fail-closed body for an unknown literal is §7.2 engine_unavailable — accepted (production snapshots cannot reach it; brief sets this body for a throwing provider); noted for final review.
Task 6b: fix round 1/5 (2 addressed, 0 open — A6b addendum row; RecordingRouter copy/move deleted; commits a49ff6b2..47a97a71)
Task 6b: minor (deferred): transitional public `handle_authenticated_get` bridge (api_router.hpp) not in shared-interfaces — Task 8b/9 must delete it; prefix/exact match duplicated with authorize.
Task 6b: minor (deferred): smoke mains serve only first inventory model; empty inventory → /v1/models 500 (smoke binaries untested; Task 8b takes them over per P23).
Task 6b: minor (deferred): secure_server_main builds a second HttpPolicy unused on the serial path until Task 9.
Task 6b: complete (commits 9cc726cd..47a97a71, review clean after round 1) — linux-gcc 549/549, wine 285/285
Task 7: BASE 47a97a71, dispatched (opus)
Ruling (Task 7 depth vs content arrays): keep kChatMaxJsonDepth = 4 everywhere (no per-path depth exception). OpenAI part arrays (`content:[{"type":"text",...}]`, depth 5) answer 400 invalid_json; shallow array content (`["Hi"]`, `[]`) answers 400 unsupported_parameter `content` — why: spec §3.1 l.378-379 fixes depth ≤ 4 with "deepest legal value is messages[i].content at depth 3" and §5.3 maps depth to invalid_json; both outcomes are 400 with no engine action — cost if wrong: clients sending part arrays see invalid_json instead of unsupported_parameter until SP5; flag to owner.
Ruling (EXT-01 under the depth limit, carried to Tasks 9/20): realistic deep `tools`/`functions` bodies may answer 400 invalid_json rather than extension_disabled; EXT-01's binding property is "spawn nothing, 400". ext01 cases assert extension_disabled with `param` for shallow forms (e.g. `"tools":[]`, `"tool_choice":"auto"`, `"functions":[]`, role `tool`) and 400 + nothing spawned for deep forms — cost if wrong: test expectation adjustments in 9/20; flag to owner.
Task 7: ⚠️ carried — ChatRequestError→ErrorOptions{.param} wire mapping verified at Task 9/16.
Task 7: minor (deferred → carried to Task 15): temperature -0.0 stored as -0.0 → GEN would render temperature=-0; normalize zero.
Task 7: minor (deferred): decimal underflow/overflow reported as integer_out_of_range (fail-closed; misleading name).
Task 7: minor (deferred): extension-precedence test lacks an invalid member BEFORE the extension key.
Task 7: minor (deferred → M2): stream_options value not type-checked.
Task 7: minor (deferred): handoff A3 row Task column style "7" vs "Task 6b".
Task 7: complete (commits 47a97a71..c2d51628, review clean) — linux-gcc 556/556, wine 292/292
Task 8a: BASE c2d51628, dispatched (opus)
Task 8a: incident — implementer ran one read-only git log/branch in .worktrees/sp4b (its inherited cwd) before reading the rules; nothing changed there. Mitigation: every dispatch now states the inherited cwd is NOT the worktree. Report to coordinator.
Ruling (Task 8a set_no_inherit extra): keep — it is the V12 helper Task 8b uses; binding test + K4 note remain 8b's.
Coordinator FYI: main c9629e6e changed engine_protocol_client.cpp read_generation PP branch (Strata accepts bounded 3–5-field PP; test renamed prefill_progress_is_bounded_in_both_profiles). Carry to Task 15: do not alter the PP branch/case semantics; if touched, preserve Strata PP acceptance.
Task 8a: fix round 1/5 (4 addressed, 0 open — progress-based stall test; stderr line; stall<=0 doc; EINTR drain; commits 53ed7f73..701a725d)
Task 8a: complete (commits c2d51628..701a725d, review clean after round 1) — linux-gcc 564/564, wine 300/300
Task 8b: BASE 701a725d, dispatched (opus)
Harness forced handback #2 during Task 8b (implementer a40a043c… still running its own build; BASE 701a725d). Resume: wait for 8b, review from 701a725d.
Task 8b: note — wine start-up flakes (0.01 s failures before test code: json_tests.json_accepts_strict_document, http_socket_server_tests.oversize_header_with_431) passed on rerun; watch list with SP4 fetch flake.
Task 8b: ⚠️ resolved — test main keeps install_process_defaults() + WinsockGuard (checked by controller); Task 9 must delete handle_authenticated_get + DispatcherRouter/make_dispatcher_router (carried); Windows rows pending MSYS2.
Task 8b: minor (deferred → carried to Task 12): an in-flight response write is not cut by shutdown (only writes starting after shutdown use kShutdownDrainBudget); a stalled reader can hold main up to write_stall (10 s) > SP2's 5 s bound.
Task 8b: minor (deferred → carried to Task 12): POSIX close() doesn't wake an in-progress poll — shutdown(fd, SHUT_RDWR) before close restores immediate wake.
Task 8b: minor (deferred): secure_server_main never checks WinsockGuard::ok().
Task 8b: minor (deferred → M2): placeholder SocketStreamSink writes chunked framing regardless of the head's Transfer-Encoding.
Task 8b: minor (deferred): legacy handle_http_request copies HttpPolicy + 2 std::functions per call (transitional until Task 9).
Task 8b: complete (commits 701a725d..63b7ffe2, review clean) — linux-gcc 571/571, wine 307/307 (two 0.01 s start-up flakes passed on rerun)
Task 9: BASE 63b7ffe2, dispatched (opus)
Task 9: fix round 1/5 (4 addressed, 0 open — ext01 asserts extension_disabled for reachable bodies + depth-5 400; dup link; dead fwd decls; record_of comment; commits 7e441e27..29804f11). Residual: task-9-report.md line 12 stale wording (workspace scratch, not shipped) — minor (deferred).
Task 9: notes — wrong model id → 404 model_not_found (spec §3.1/§7.2); proc05_sigterm_during_generation_exits_cleanly also accepts 503 server_shutting_down (spec §3.10); S11 direct supervisor calls remain until Task 16.
Task 9: minor (deferred): api_server_test record_of/count_of [[maybe_unused]] until later tasks.
Task 9: complete (commits 63b7ffe2..29804f11, review clean after round 1) — linux-gcc 580/580, wine 307/307 (9 api_server cases windows-runtime → pending MSYS2)
Task 10: BASE 29804f11, dispatched (opus)
Coordinator FYI: main bd3b53a6 has SP4 part 2 (connect-audit shim secure_frontend_connect_audit, privacy tests). Task 19 keeps non-overlapping names; coordinator consolidates after merge. No rebase.
Task 10: minor (deferred): has_no_cors_headers checks only ACAO/ACAC, not every Access-Control-* header.
Task 10: minor (deferred): "no preflight reached a route" check is near-vacuous.
Task 10: minor (deferred): WEB-04 matrix omits 408 (spec says reachable over TCP), 500/503.
Task 10: minor (deferred): auth01 repeats route_request prefix/target logic; stderr diagnostic only when ok empty.
Task 10: complete (commits 29804f11..f7a150d0, review clean) — linux-gcc 591/591, wine 307/307
Task 11: BASE f7a150d0, dispatched (opus)
Task 11: review — Important: linger overflow test can't tell oldest from any; fix round 1 dispatched (resume implementer).
Task 11: ⚠️ carried to Task 12: every admit/header_complete/finished under the pool mutex; evicted worker's abort flag seen within 20 ms; listener + linger poll entries ≤ kMaxPollEntries.
Harness forced handback #3 during Task 11 fix round 1 (implementer a8579bf3… running; FIX_BASE 46ad217f).
Task 11: fix round 1/5 (5 addressed, 0 open — linger overflow pins natives[1..64]; mutex comment; remote eviction count; EOF case; constants; commits 46ad217f..9d30088b)
Task 11: complete (commits f7a150d0..9d30088b, review clean after round 1) — linux-gcc 596/596, wine 312/312
Task 12: BASE 9d30088b, dispatched (opus)
OWNER CLOSE-OUT: stopped at Task 11 (complete, 9d30088b). Task 12 implementer was dispatched just before the instruction; told to stop — it made no edits, no commit (tree clean). Task 12 NOT started.

// parity_table.cpp — the SP5 M1 Strata parity table: one row per option the
// pinned upstream Strata v0.2.2 reads (inventory: tests/parity_keys_upstream.hpp),
// plus extra rule rows the flat grep cannot see (gpu_none, gpu_roles, mtp,
// mcpServers, vram_reserve_mib).
//
// Dispositions and destinations are assigned here once (Task 2); Tasks 4-10
// wire the destinations. A disposition changes only on implementation
// evidence, with the ledger Ruling (table = source of truth, plan Task 9 note).
// Citations are `serve/<file>.py:<line>` at the pin; rejected rows lead with
// the excluding spec rule (D-3).

#include "secure_frontend/parity_table.hpp"

#include <array>

#include "../tests/parity_keys_upstream.hpp"
#include "../tests/parity_keys_maya.hpp"

namespace secure_frontend::parity {

namespace {

constexpr ParityDisposition kTyped = ParityDisposition::typed;
constexpr ParityDisposition kRejected = ParityDisposition::rejected;
constexpr ParityDisposition kMapped = ParityDisposition::mapped_away;

using enum ParityDestination;

constexpr std::array<ParityRow, 127> kRows{{
    // ---- config keys, alphabetical (the generated inventory) --------------
    {"aliases", kTyped, frontend_behavior, "serve/server.py:8263, set_aliases :3951-3964; runconfig.py:34 (M1 Task 8: model.aliases — /v1/models lists them, chat matches exactly)"},
    {"allowed_hosts", kTyped, frontend_behavior, "already typed (SP1/SP3 listen); serve/server.py:8283"},
    {"answer_room", kTyped, config_only, "serve/server.py:8231 (`is not False`), formula :4893-4905; typed only: the pin's formula sits in its thinking parser, not in our §7.2 room rule (Ruling T8-d, Task 15)"},
    {"anthropic_thinking", kTyped, config_only, "serve/server.py:8319 (M1 Task 5: reasoning.anthropic_thinking)"},
    {"api_key", kMapped, none, "SP1 token store is the only auth source (CFG-06: no secret in config); serve/server.py:8078"},
    {"api_monitor", kRejected, none, "spec §4 web/desktop/telemetry; serve/server.py:8289"},
    {"arch", kMapped, none, "model identity comes from the SP4 manifest/GGUF inventory; serve/server.py:7857"},
    {"args", kRejected, none, "spec §4 free-form process control; serve/server.py:3226"},
    {"backend", kMapped, none, "engine identity: SP4 manifest + engine gate; serve/server.py:7889"},
    {"batch_telemetry", kRejected, none, "spec §4 telemetry endpoints; serve/server.py:898"},
    {"before_load", kRejected, none, "spec §4 command execution; serve/server.py:8108"},
    {"before_load_ignore_failure", kRejected, none, "spec §4 command execution; serve/server.py:8307"},
    {"before_load_strict", kRejected, none, "spec §4 command execution; serve/server.py:8308"},
    {"before_load_timeout_s", kRejected, none, "spec §4 command execution; serve/server.py:8303"},
    {"codex_compaction_cache", kTyped, config_only, "serve/server.py:8261 (M1 Task 9: session.codex_compaction_cache)"},
    {"codex_thread_titles", kTyped, config_only, "serve/server.py:8260 (M1 Task 9: session.codex_thread_titles)"},
    {"command", kRejected, none, "spec §4 MCP command; serve/mcp.py:610"},
    {"cors_origins", kTyped, frontend_behavior, "already typed (SP3 B12: listener.cors_origins); serve/server.py:8280"},
    {"cwd", kRejected, none, "spec §4 free-form process control; serve/mcp.py:106"},
    {"effort_position", kTyped, engine_arg, "serve/server.py:2880 (M1 Task 5: reasoning.effort_position composes the engine's --tail-role-token)"},
    // Ruling T7-d (Task 7): the elastic trio gates the frontend's vision turn and the
    // /v1/vram headroom — no argv composes for it (the consumer arrives with Task 11).
    {"elastic", kTyped, frontend_behavior, "serve/server.py:2557, :8138 (M1 Task 7: engine.elastic; Tasks 11-12 consume it)"},
    {"elastic_idle_s", kTyped, frontend_behavior, "serve/server.py:2559, :4041 (M1 Task 7: engine.elastic_idle_s)"},
    {"elastic_mib", kTyped, frontend_behavior, "serve/server.py:2558, :4019 (M1 Task 7: engine.elastic_mib; /v1/vram headroom)"},
    {"engine_silence_s", kTyped, frontend_behavior, "serve/server.py:942, default 300 at :277, engine_silence_s() :2905-2912; runconfig.py:39 (M1 Task 8: the pump's silence watchdog)"},
    {"env", kRejected, none, "spec §4 raw env dict; serve/server.py:3361"},
    {"env_to_user", kTyped, config_only, "serve/server.py:8327 (M1 Task 9: session.env_to_user)"},
    {"exe", kRejected, none, "spec §4 free-form process control (engine identity comes from the SP4 manifest); serve/server.py:7883"},
    {"expert_profile_save", kTyped, engine_arg, "serve/server.py:3071-3076 (M1 Task 9: --expert-profile-save; an operator-owned flag wins, :3072)"},
    {"expert_profile_save_every", kTyped, engine_arg, "serve/server.py:3075-3076, default 10 at :3067 (M1 Task 9: --expert-profile-save-every; rides the save, :3072)"},
    {"fit_max_tokens", kTyped, frontend_behavior, "serve/server.py:8213 (M1 Task 5: engine.fit_max_tokens)"},
    {"gpu", kTyped, engine_arg, "already typed (SP2 engine.gpu; compose renders --gpu); serve/server.py:2826 (gpu_list :2819-2826: a set `gpu` wins; unset, a saved `gpu_roles` picks the cards, Main last, :2822-2825 — see the gpu_roles row)"},
    // The pin reads this one through strata_control/gpu_roles.saved_roles, which the Task-2
    // inventory greps do not see; the row keeps the parity spine complete (extra rule row).
    {"gpu_none", kMapped, none, "strata_control/gpu_roles.py saved_roles :399; serve/server.py:2841 (gpu_all_off), :3353-3355 (every card Off: empty CUDA/HIP_VISIBLE_DEVICES), :2854-2859 (refused at start for a GPU engine); card choice is the typed engine.gpu (SP2 §3.9: rendered as --gpu, never a GPU variable), so the all-Off run has no counterpart"},
    {"gpu_order", kTyped, engine_arg, "serve/server.py:3224 (M1 Task 7: `as_given` keeps the order; at v0.2.2 active `gpu_roles` keep it too and a HIP built-in Radeon goes first before the speed sort, :3230-3247 — the typed auto or as_given vocabulary is unchanged)"},
    {"gpu_policy", kTyped, config_only, "serve/images.py:174 (M1 Task 7: engine.gpu_policy, re-scoped to the vision child's GPU turn; the pin's use is the image-generation turn)"},
    // The pin reads this one through strata_control/gpu_roles.saved_roles, which the Task-2
    // inventory greps do not see; the row keeps the parity spine complete (extra rule row).
    {"gpu_roles", kMapped, none, "strata_control/gpu_roles.py saved_roles :386-405 (:390); serve/server.py:2822-2825 (gpu_list: the cards, Main last, when `gpu` is unset), :3224 (keeps the given order); card choice and order are the typed engine.gpu (SP2 §3.9: rendered as --gpu), the Main/Helper/Off roles have no typed form"},
    {"headers", kRejected, none, "spec §4 MCP headers; serve/mcp.py:257"},
    {"hip_ordinal", kTyped, engine_arg, "serve/server.py:3094 (M1 Task 7)"},
    {"host", kTyped, frontend_behavior, "already typed (SP1 listen.host); serve/server.py:8071"},
    {"idle_unload_s", kTyped, frontend_behavior, "serve/server.py:4287-4296, :8298 (M1 Task 6: supervisor idle timer)"},
    {"images", kMapped, none, "spec D-9: image generation is out, the route answers 404 like an unknown route; serve/server.py:8233"},
    {"keep_files", kTyped, config_only, "serve/images.py:189 (`or 64`); typed only: the consumer is the pin's ImageService and D-9 keeps image generation out (Ruling T9-e, M1 Task 9)"},
    {"layer_split", kTyped, engine_arg, "serve/server.py:2921 (M1 Task 7)"},
    // Ruling T6-b (Task 6): the pin skips the child start (lazy :966-993), so no engine
    // argument composes — the deferral is frontend behaviour, like the idle timer.
    {"lazy_load", kTyped, frontend_behavior, "serve/server.py:8134, :967-994 (M1 Task 6: the first request spawns the same composed launch)"},
    {"lib_dirs", kRejected, none, "spec §4 free-form process control; serve/images.py:135"},
    {"log", kRejected, none, "spec §4 free-form process control; serve/replicas.py:99"},
    {"max_n", kTyped, frontend_behavior, "serve/images.py:103 (M1 Tasks 11-12: vision.max_n; the pin's cap lives on the images block)"},
    {"max_queue", kMapped, none, "the SP3 row limits.concurrency.max_queued_generations already carries queue admission (pin bound 0..4096 at serve/server.py:8044, derived default :3789-3791; Ruling T8-a)"},
    {"max_side", kTyped, frontend_behavior, "serve/images.py:102 (M1 Task 12: vision.max_side pre-decode cap)"},
    {"max_tokens", kTyped, request_rule, "serve/server.py:2571 (vision encoder at the pin); engine.max_tokens re-scoped as the request output ceiling (added, C-1; Ruling T8-e: caps at the §7.2 resolve site)"},
    {"mcp", kRejected, none, "spec §4 MCP; serve/mcp.py:632"},
    {"mcp_servers", kRejected, none, "spec §4 MCP; serve/mcp.py:651"},
    // Ruling T7-c (Task 7): the svc-side pre-load gate (no argv; the driver check runs
    // only where a GPU box can answer it).
    {"min_free_vram_mib", kTyped, frontend_behavior, "serve/server.py:8300 (M1 Task 7: engine.min_free_vram_mib)"},
    {"min_tokens", kTyped, request_rule, "serve/server.py:2573 (vision encoder at the pin); engine.min_tokens re-scoped as the request output floor (added, C-1; Ruling T8-e: lifts at the §7.2 resolve site)"},
    {"model_name", kMapped, none, "served-model identity comes from the SP4 manifest; serve/images.py:184"},
    // The pin reads this one through strata_control/draft_layer.is_off, which the Task-2
    // inventory greps do not see; the row keeps the parity spine complete (extra rule row).
    {"mtp", kTyped, engine_arg, "strata_control/draft_layer.py is_off; serve/server.py:2966-2969 (M1 Task 6: engine.mtp drops --mtp/--spec-min-p/--batch-mtp at every start)"},
    {"native", kMapped, none, "the SP4 manifest composes --native (engine_arguments); serve/images.py:126"},
    {"need_mib", kTyped, frontend_behavior, "serve/images.py:157 (M1 Task 11: vision.need_mib; added security bound)"},
    {"open_browser", kRejected, none, "spec §4 web/desktop; serve/server.py:8408"},
    {"out_dir", kMapped, none, "spec D-9 image generation is out; serve/images.py:186"},
    {"parallel", kTyped, engine_arg, "serve/server.py:3000-3020 (replicas.parallel renders --batch N, :3020; window PARALLEL_MAX 8 at :2999; cap 1024 from the pin's own bound :8054, M1 Task 10)"},
    {"pool_cores", kMapped, none, "the operator's engine.args carries the engine's own --pool-cores LIST (not frontend-owned and not a mode: engine_arguments.cpp passes it through; no typed row); serve/server.py:3031, pool_cores_args :3026-3046 (experimental, off by default; a --pool-cores already in the args wins, :3034), composed after parallel at :2995"},
    {"prevent_sleep", kRejected, none, "spec §4 desktop; serve/server.py:8248"},
    {"quant", kMapped, none, "quant identity comes from the SP4 manifest; serve/images.py:283"},
    {"queue_timeout", kMapped, none, "the SP3 row limits.concurrency.queue_timeout_ms already carries admission waiting (pin bound 0.1..600 at serve/server.py:8048; Ruling T8-a)"},
    {"reasoning_budget_tokens", kTyped, config_only, "serve/server.py:8337 (M1 Task 5: reasoning.budget_tokens)"},
    {"reasoning_close_retry", kTyped, config_only, "serve/server.py:8232 (M1 Task 5: reasoning.close_retry)"},
    {"reasoning_effort", kTyped, frontend_behavior, "serve/server.py:7642 (M1 Task 5: reasoning.effort; the qwen think tail, issue 19: none writes the closed block, unset/low/medium/high open it, the levels are not told apart)"},
    {"reasoning_loop_recovery", kTyped, config_only, "serve/server.py:8346 (M1 Task 5: reasoning.loop_recovery)"},
    {"reload", kMapped, none, "image-generation card reload mode (spec D-9); the vision child's lifecycle follows the vision/elastic rows; serve/images.py:177"},
    {"repeat_stop_tokens", kTyped, frontend_behavior, "serve/server.py:198 (REPEAT_STOP_TOKENS 256), the pin's detector is frontend-side at :5098, notice :5278, 0 = off :8332 (Ruling T8-f: no GEN key)"},
    {"replica_cpus", kRejected, none, "spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7758"},
    {"replica_load_tokens", kRejected, none, "spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7792"},
    {"replicas", kRejected, none, "spec C-4: N-child replica scheduling is the accepted narrowing; serve/replicas.py:44"},
    {"sampling", kTyped, config_only, "serve/server.py:7691 (M1 Task 4: defaults.sampling.*)"},
    {"sigmas", kMapped, none, "spec D-9 image generation is out; serve/images.py:120"},
    {"slot_save_path", kTyped, config_only, "serve/server.py:8311 + slot_save_dir :3656-3668; the pin uses it FRONTEND-side for its /slots file store (:3885-3902) — no argv append (Ruling T9-a, M1 Task 9)"},
    {"split_skip_if_fits", kTyped, engine_arg, "serve/server.py:2985 (M1 Task 7)"},
    {"steps", kMapped, none, "spec D-9 image generation is out; serve/images.py:104"},
    {"telemetry_read_key", kRejected, none, "spec §4 telemetry endpoints; serve/server.py:8270"},
    {"threads", kTyped, engine_arg, "serve/server.py:2569 (M1 Task 11: vision.threads; the only pin read of `threads`, inside the vision reader_args — the flag lands on the encoder child's argv)"},
    {"timeout_s", kMapped, none, "the SP3 row limits.engine.generation_timeout_s already carries the generation deadline (pin: generation job timeout at serve/images.py:227; Ruling T8-b)"},
    {"tokenizer", kMapped, none, "the SP4 manifest carries the tokenizer; serve/server.py:8092"},
    {"tool_call_recovery", kTyped, config_only, "serve/server.py:8323 (M1 Task 9: session.tool_call_recovery)"},
    {"trusted_origins", kTyped, frontend_behavior, "already typed (SP3 origins family); serve/server.py:8281"},
    {"type", kRejected, none, "spec §4 MCP entry type; serve/mcp.py:604"},
    // Ruling T7-d (Task 7): the APU hint arbitrates the frontend's image/vision turn —
    // no argv composes for it.
    {"uma", kTyped, frontend_behavior, "serve/images.py:23, :335 (M1 Task 7: engine.uma; Tasks 11-12 consume it)"},
    // SP7 M2 Task 3 (D-10): our own typed key as a disposition row (PX §4 reserved it).
    {"update.source", kTyped, config_only, "our key (PX §4 reserved; SP7 M2 D-10): the HTTPS mirror list read only by 'strata update'"},
    {"url", kRejected, none, "spec §4 MCP url; serve/mcp.py:384"},
    {"user_args", kRejected, none, "spec §4 free-form process control; serve/server.py:2962"},
    {"vision", kTyped, config_only, "serve/server.py:2974 (M1 Task 11: the vision.* block)"},
    {"vram_elastic", kTyped, engine_arg, "serve/server.py:2989 (M1 Task 7)"},
    {"vram_segment_mib", kTyped, engine_arg, "serve/server.py:2991 (M1 Task 7)"},

    // ---- env knobs (the generated inventory; semantics typed or excluded,
    //      never honored raw from the process environment — spec §4) --------
    {"STRATA_ADMIT_MAX_WAIT_S", kMapped, none, "serve/server.py:312; admission waiting is already carried by limits.concurrency.queue_timeout_ms (Ruling T8-a)"},
    {"STRATA_ADMIT_SHORT_FIRST", kMapped, none, "SP3 admission ordering is the pool policy (B8); serve/server.py:315"},
    {"STRATA_ALLOWED_HOSTS", kTyped, frontend_behavior, "same semantics as allowed_hosts, already typed; serve/server.py:3703"},
    {"STRATA_API_KEY", kMapped, none, "SP1 token store is the only auth source; serve/server.py:7425"},
    {"STRATA_BATCH_MTP", kTyped, engine_arg, "serve/server.py:3017; engine.mtp (M1 Task 6)"},
    {"STRATA_BATCH_TELEMETRY", kRejected, none, "spec §4 telemetry endpoints; serve/server.py:900"},
    {"STRATA_BATCH_TRACE", kRejected, none, "spec §4 no new web/diagnostics surface; serve/server.py:822"},
    {"STRATA_DEBUG", kRejected, none, "spec §4 no new web/diagnostics surface; serve/mcp.py:130"},
    {"STRATA_DROP_CACHE_ON_EXIT", kMapped, none, "the SP2 shutdown order (§3.7) is fixed by the supervisor; serve/cache_drop.py:1"},
    {"STRATA_ENGINE_NICE", kMapped, none, "the SP2 child pre-exec state (§3.12) is fixed by the supervisor, which sets no engine priority; serve/server.py:3161 (engine_nice :3154-3168: Linux only, +5 by default beside a built-in Radeon), applied at spawn :1017-1022"},
    {"STRATA_ENGINE_READY_S", kTyped, frontend_behavior, "already typed: ready_timeout (SP1); serve/server.py:292"},
    {"STRATA_ENGINE_STALL_S", kTyped, frontend_behavior, "serve/server.py:308; engine.silence_s (M1 Task 8)"},
    {"STRATA_FAIL_ONCE", kRejected, none, "spec §4 free-form process control (fault-injection knob); serve/test_server.py:4722"},
    {"STRATA_HTTP_BACKLOG", kMapped, none, "the listener backlog is fixed by the SP3 poll design (128 entries); serve/server.py:7230"},
    {"STRATA_KEEP_EMPTY_TURNS", kMapped, none, "the frontend serves stateless requests; conversation history is the client's; serve/frontend.py:60"},
    {"STRATA_KEEP_LEFTOVERS", kMapped, none, "lifecycle is teardown + respawn (M1 Task 6); serve/server.py:129"},
    {"STRATA_LIFELINE", kMapped, none, "SP2 supervision replaces the lifeline watcher (pdeathsig, monitor handle); serve/lifeline.py:33"},
    {"STRATA_MAX_BODY_MIB", kTyped, frontend_behavior, "already typed: limits.chat.max_body_bytes (SP1); serve/server.py:5869"},
    {"STRATA_NO_PRESET", kMapped, none, "launch is SP4 manifest-composed; serve/server.py:7657"},
    {"STRATA_OFFLINE", kMapped, none, "PRIV-01: the frontend never reaches the network; enforced by design and the DL-01 proof; serve/server.py:3373"},
    {"STRATA_OWNER_ATTEST_KEY", kRejected, none, "spec §4 signing material, deferred to SP7; serve/server.py:8029"},
    {"STRATA_PARALLEL_SOLO", kRejected, none, "spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:1734"},
    {"STRATA_RELEASE_PUBKEY_HEX", kMapped, none, "compile definition pinning the Ed25519 release public key (SP7 M2 D-2); read by the release-manifest verifier and reported by 'strata update'; empty refuses updates"},
    {"STRATA_REPLICA_START", kRejected, none, "spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7774"},
    {"STRATA_REQUEST_LINES", kMapped, none, "the wire record is fixed by docs/security/engine-protocol-limits.md; serve/server.py:640"},
    {"STRATA_RUNTIME_PROFILE", kRejected, none, "spec §4 no new web/diagnostics surface; serve/lifeline.py:265"},
    {"STRATA_START_RETRIES", kMapped, none, "respawn retries belong to the SP2 RestartTracker (restart_policy.hpp); serve/server.py:610"},
    {"STRATA_SYCL_BIN", kRejected, none, "spec §4 free-form process control (external binary path); serve/server.py:2868"},
    {"STRATA_TELEMETRY_KEY", kRejected, none, "spec §4 telemetry endpoints; serve/server.py:8270"},
    {"STRATA_TOKENIZER", kMapped, none, "the SP4 manifest carries the tokenizer; serve/test_detok.py:21"},
    {"STRATA_VERIFY_TRACE", kRejected, none, "spec §4 no new web/diagnostics surface; serve/server.py:1220"},
    {"STRATA_VISION_ENCODE_S", kTyped, frontend_behavior, "serve/server.py:329 (M1 Task 12: vision encode-timeout row)"},
    {"STRATA_VISION_READY_S", kTyped, frontend_behavior, "serve/server.py:328 (M1 Task 11: vision.ready_timeout_s; 0 = wait for ever, :292)"},

    // ---- extra rule rows the flat grep cannot see -------------------------
    {"mcpServers", kRejected, none, "spec §4 MCP (Claude Desktop block); serve/mcp.py:648"},
    {"vram_reserve_mib", kTyped, engine_arg, "serve/runconfig.py:42 renders --vram-reserve-mib (M1 Task 7)"},
}};

} // namespace

std::span<const std::string_view> upstream_config_keys() noexcept {
  return {kUpstreamConfigKeys};
}

std::span<const std::string_view> upstream_env_knobs() noexcept {
  return {kUpstreamEnvKnobs};
}

std::span<const ParityRow> strata_parity_rows() noexcept {
  return {kRows};
}

const ParityRow* strata_parity_row(std::string_view key) noexcept {
  for (const auto& row : kRows) {
    if (row.key == key) return &row;
  }
  return nullptr;
}

namespace {
// The GLM table: one row per option the vendored Maya reference reads
// (inventory: tests/parity_keys_maya.hpp, generated at v1.1.8 and kept as that
// set), plus extra rule rows the greps cannot see and the launcher-managed engine
// flags. Dispositions are assigned
// once here (Task 2); Tasks 3-8 wire destinations — a disposition moves only on
// evidence with a ledger Ruling. Citations are `file:line` under engines/maya-ref/
// at 451f9cb6 (tag v1.1.21); rejected rows lead with the excluding spec rule (D-3, C-5, PRIV-01).
constexpr std::array<ParityRow, 178> kMayaRows{{
    // ---- Maya config keys, alphabetical (the generated inventory) ------
    {"api_key", kMapped, none, "SP1 token store is the only auth source (CFG-06); serve/server.py:4094, maya.py:2791"},
    {"args", kRejected, none, "spec §4 free-form process control (raw engine argv); serve/server.py:4106, engine_args :1274-1277 (Task 7 retires the glm53 pass-through)"},
    {"backend", kMapped, none, "engine identity: the SP4 manifest + engine gate; serve/server.py:1284, maya.py:2752"},
    {"command", kRejected, none, "spec §4 MCP command; serve/mcp.py:604"},
    {"cors_origins", kTyped, frontend_behavior, "already typed (SP3 B12: listener.cors_origins); serve/server.py:4096"},
    {"cwd", kRejected, none, "spec §4 free-form process control; serve/server.py:4035, serve/mcp.py:104"},
    {"env", kRejected, none, "spec §4 raw env dict (Maya carries engine settings as raw env with no allowlist — the closed typed table replaces it); serve/server.py:1289, :3729"},
    {"exe", kRejected, none, "spec §4 free-form process control (engine identity from the SP4 manifest); serve/server.py:4035, maya.py:2757"},
    {"experimental_speed_projection", kTyped, config_only, "serve/server.py:3819 (shared settings, bool); Task 3: glm.experimental_speed_projection"},
    {"fit_max_tokens", kTyped, config_only, "serve/server.py:4077; Task 3: glm.fit_max_tokens (M1 engine.fit_max_tokens pattern)"},
    {"gpu", kTyped, engine_arg, "already typed (SP2 engine.gpu renders --gpu); serve/server.py:1264, child_env :1280-1288, maya.py:2429; Task 7"},
    {"headers", kRejected, none, "spec §4 MCP headers; serve/mcp.py:251, :601"},
    {"host", kTyped, frontend_behavior, "already typed (SP1 listen.host); serve/server.py:3983, maya.py:2790"},
    {"installer", kRejected, none, "spec §4 PRIV-01 forbids update checks and self-update (the Maya updater block, serve/update.py); maya.py:2298, :2541, :2560; the block's sub-keys (models_dir, quant, gguf, draft, data_dir, speed_calibration) ride the parent reject"},
    {"layer_split", kTyped, engine_arg, "serve/server.py:1274-1277 renders --layer-split; docs/SETTINGS.md:44; Task 7"},
    {"lib_dirs", kRejected, none, "spec §4 free-form process control (library search paths); serve/server.py:1291"},
    {"log", kRejected, none, "spec §4 free-form process control (the child's log path); serve/server.py:4009, :4035, maya.py:2503"},
    {"max_tokens", kTyped, request_rule, "serve/server.py:1053, :1213 (the vision block), shared settings :3815; engine.max_tokens stays the request output ceiling (M1 Ruling T8-e pattern)"},
    {"mcp", kRejected, none, "spec §4 MCP; serve/mcp.py:626"},
    {"mcp_servers", kRejected, none, "spec §4 MCP; serve/mcp.py:645"},
    {"min_p", kTyped, config_only, "serve/server.py:3808 (shared settings: 0 <= min_p < 1), sampling-block validator :3848; defaults.sampling.min_p"},
    {"model_name", kTyped, config_only, "serve/server.py:4075, maya.py:2805; Task 3: glm.model_name (Ruling T2-c: managed launches still take served identity from the SP4 manifest)"},
    {"no_flash_attn", kTyped, frontend_behavior, "serve/server.py:1055, :1222 (--no-flash-attn on the encoder child); Task 8: vision.no_flash_attn"},
    {"port", kTyped, frontend_behavior, "already typed (SP1 listen port); maya.py:2789, :3132"},
    {"reasoning_effort", kTyped, config_only, "serve/server.py:4081, shared settings :3798 (none|low|high|max); Task 3: glm.reasoning_effort"},
    {"resident", kTyped, config_only, "serve/server.py:4015 (on-demand vs resident encoder); Task 8: vision.resident"},
    {"sampling", kTyped, config_only, "serve/server.py:3829-3836 (supported keys, validators from :3840); maya.py:106 (SAMPLING defaults); defaults.sampling.* (M1 Task 4)"},
    {"seed", kTyped, config_only, "serve/server.py:3815 (shared settings: positive integer), :265; defaults.sampling.seed (SP3 B9 neutral seed)"},
    {"temperature", kTyped, config_only, "serve/server.py:3802 (shared settings: 0..2), config-block validator :3840 (>= 0, 0 = greedy); defaults.sampling.temperature"},
    {"thinking_budget", kTyped, config_only, "serve/server.py:4090 (default 32768); C-3 keeps Maya's name: Task 3 glm.thinking_budget; STRATA_GLM_THINK_RESERVE rides it (docs/SETTINGS.md:141)"},
    {"threads", kTyped, engine_arg, "serve/server.py:1051 (the vision block; the flag lands on the encoder child :1221-1222); Task 8 (M1 Task 11 vision.threads pattern)"},
    {"top_k", kTyped, config_only, "serve/server.py:3811 (shared settings: integer 1..64), validator :3852; defaults.sampling.top_k"},
    {"top_p", kTyped, config_only, "serve/server.py:3805 (shared settings: 0 < top_p <= 1), validator :3844; defaults.sampling.top_p"},
    {"tokenizer", kTyped, config_only, "serve/server.py:3989, maya.py:2758, :3144; Task 3: glm.tokenizer — managed launches still compose the tokenizer from the SP4 manifest (Ruling T2-c)"},
    {"type", kRejected, none, "spec §4 MCP entry type; serve/mcp.py:598"},
    {"url", kRejected, none, "spec §4 MCP url; serve/mcp.py:378, :597"},
    {"vision", kTyped, config_only, "serve/server.py:4008, :4011, :4015; the vision.* block (M1 Task 11); Task 8 the GLM side"},
    // ---- extra rule rows the flat grep cannot see ------------------------
    {"mcpServers", kRejected, none, "spec §4 MCP (Claude Desktop block); serve/mcp.py:646, serve/server.py:3970 (--mcp-config)"},
    {"mmproj", kTyped, manifest_artifact, "serve/server.py:1221 (the vision child's --mmproj); M1 Task 11: manifest files[] role mmproj (at most one entry)"},
    {"model", kTyped, manifest_artifact, "serve/server.py:1221 (the vision child's --model file); the SP4 manifest composes the vision model artifact (Task 8)"},
    {"presence_penalty", kTyped, config_only, "serve/server.py:263-265 (supported sampling fields), block docstring :3829-3834, validator from :3856; defaults.sampling.presence_penalty"},
    {"repetition_penalty", kTyped, config_only, "serve/server.py:263-265, :274-279 (llama.cpp repeat_penalty is taken as this one); defaults.sampling.repetition_penalty"},
    {"frequency_penalty", kTyped, config_only, "serve/server.py:263-265, :3829-3834; defaults.sampling.frequency_penalty"},
    {"penalty_last_n", kTyped, config_only, "serve/server.py:263-265, :280-283, :305-306 (repeat_last_n maps; 0 = no penalties, -1 = the whole context up to PENALTY_WINDOW_MAX 4096 :260, below -1 refused); defaults.sampling.penalty_last_n"},
    // ---- engine/server env knobs (the generated inventory; spec §4: their
    //      semantics are typed config — raw env is never honored as input) --
    {"MAYA_RESTART_ON_UPDATE", kRejected, none, "spec §4 PRIV-01 forbids the self-updater restart; maya.py:2809"},
    {"MAYA_UPDATE_CHECK", kRejected, none, "spec §4 PRIV-01 forbids update checks (the Maya self-updater block); serve/update.py:75"},
    {"STRATA_API_KEY", kMapped, none, "SP1 token store is the only auth source (CFG-06); serve/server.py:3967"},
    {"STRATA_DEBUG", kRejected, none, "spec §4 no new diagnostics surface (debug logging switch); serve/server.py:2430, :2465"},
    {"STRATA_ENGINE_QUIT_S", kMapped, none, "the SP2 shutdown order (§3.7) is fixed by the supervisor; serve/server.py:1010, docs/SETTINGS.md:145"},
    {"STRATA_ENGINE_STALL_S", kTyped, frontend_behavior, "serve/server.py:343, docs/SETTINGS.md:142 (the pump's silence watchdog — M1 engine.silence_s pattern)"},
    {"STRATA_ENGINE_WRAP_S", kMapped, none, "the SP3 shutdown drain is fixed in the frontend (no per-request wrap-up); serve/server.py:4172, docs/SETTINGS.md:146"},
    {"STRATA_FAIR_SLICE_S", kMapped, none, "SP3 admission/pool scheduling (B8/B9) is the frontend's policy; serve/server.py:234, docs/SETTINGS.md:147"},
    {"STRATA_GLM_AHEAD", kTyped, engine_env, "docs/SETTINGS.md:87"},
    {"STRATA_GLM_CKPT_EVERY", kTyped, engine_env, "docs/SETTINGS.md:69"},
    {"STRATA_GLM_CKPTS", kTyped, engine_env, "docs/SETTINGS.md:69"},
    {"STRATA_GLM_CPU_1T", kTyped, engine_env, "docs/SETTINGS.md:104"},
    {"STRATA_GLM_CPU_CAL", kRejected, none, "spec §4 free-form process control (the `log` rule: a timing cache in an operator-named file); docs/SETTINGS.md:51"},
    {"STRATA_GLM_CPU_LANE", kTyped, engine_env, "docs/SETTINGS.md:46"},
    {"STRATA_GLM_CPU_LANE0", kTyped, engine_env, "docs/SETTINGS.md:47"},
    {"STRATA_GLM_CPU_LANE1", kTyped, engine_env, "docs/SETTINGS.md:47"},
    {"STRATA_GLM_CPU_MT", kTyped, engine_env, "docs/SETTINGS.md:104"},
    {"STRATA_GLM_CPU_PIN", kTyped, engine_env, "docs/SETTINGS.md:48"},
    {"STRATA_GLM_CPU_PLAN", kTyped, engine_env, "docs/SETTINGS.md:54"},
    {"STRATA_GLM_CPU_RETIME", kTyped, engine_env, "docs/SETTINGS.md:55"},
    {"STRATA_GLM_CPU_SHARED", kTyped, engine_env, "docs/SETTINGS.md:48"},
    {"STRATA_GLM_CPU_SPLIT", kTyped, engine_env, "docs/SETTINGS.md:53"},
    {"STRATA_GLM_DFLASH", kRejected, none, "spec C-5: the DFlash2 drafter and its knobs stay rejected on the A7 licence ground (the drafter weights are CC BY-NC-ND 4.0, docs/SETTINGS.md:293) — not a knob-visibility call; docs/SETTINGS.md:322"},
    {"STRATA_GLM_DFLASH_MIN", kRejected, none, "spec C-5: the DFlash2 drafter and its knobs stay rejected on the A7 licence ground (the drafter weights are CC BY-NC-ND 4.0, docs/SETTINGS.md:293) — not a knob-visibility call; docs/SETTINGS.md:328"},
    {"STRATA_GLM_DFLASH_PROF", kRejected, none, "spec C-5: the DFlash2 drafter and its knobs stay rejected on the A7 licence ground (the drafter weights are CC BY-NC-ND 4.0, docs/SETTINGS.md:293) — not a knob-visibility call; docs/SETTINGS.md:134"},
    {"STRATA_GLM_DFLASH_STATS", kRejected, none, "spec C-5: the DFlash2 drafter and its knobs stay rejected on the A7 licence ground (the drafter weights are CC BY-NC-ND 4.0, docs/SETTINGS.md:293) — not a knob-visibility call; docs/SETTINGS.md:134"},
    {"STRATA_GLM_DISK_QD", kTyped, engine_env, "docs/SETTINGS.md:97"},
    {"STRATA_GLM_DISK_READERS", kTyped, engine_env, "docs/SETTINGS.md:97"},
    {"STRATA_GLM_DISK_SKIP_FROM", kTyped, engine_env, "docs/SETTINGS.md:87"},
    {"STRATA_GLM_DISK_SKIP_W", kTyped, engine_env, "docs/SETTINGS.md:87"},
    {"STRATA_GLM_DROP_CACHE", kTyped, engine_env, "docs/SETTINGS.md:119"},
    {"STRATA_GLM_DSA_SCORE", kTyped, engine_env, "docs/SETTINGS.md:109"},
    {"STRATA_GLM_EXL3_MMA_ROWS", kTyped, engine_env, "docs/SETTINGS.md:115"},
    {"STRATA_GLM_KDA_GRAPH", kTyped, engine_env, "docs/SETTINGS.md:52"},
    {"STRATA_GLM_KQ", kTyped, engine_env, "docs/SETTINGS.md:103"},
    {"STRATA_GLM_KV_INT8", kTyped, engine_env, "docs/SETTINGS.md:107"},
    {"STRATA_GLM_KV_PREFETCH", kTyped, engine_env, "docs/SETTINGS.md:108"},
    {"STRATA_GLM_KV_RESIDENT", kTyped, engine_env, "docs/SETTINGS.md:108"},
    {"STRATA_GLM_LOOP_ANSWER", kTyped, engine_env, "docs/SETTINGS.md:121 (the loop guard: SP6 §4.9 keeps the guards a forced default the table may move; Task 4)"},
    {"STRATA_GLM_LOOP_THINK", kTyped, engine_env, "docs/SETTINGS.md:121 (the loop guard: SP6 §4.9 keeps the guards a forced default the table may move; Task 4)"},
    {"STRATA_GLM_MMQ_GLU", kTyped, engine_env, "docs/SETTINGS.md:118"},
    {"STRATA_GLM_MTP_GGUF", kRejected, none, "spec §4 model files come from the SP4 manifest (a draft GGUF picked by free path); docs/SETTINGS.md:83"},
    {"STRATA_GLM_MTP_KEEP", kTyped, engine_env, "docs/SETTINGS.md:84"},
    {"STRATA_GLM_MTP_MISS", kTyped, engine_env, "docs/SETTINGS.md:84"},
    {"STRATA_GLM_MULTI_BENCH", kTyped, engine_env, "docs/SETTINGS.md:140"},
    {"STRATA_GLM_MULTI_BOUNDARY", kTyped, engine_env, "docs/SETTINGS.md:77"},
    {"STRATA_GLM_MULTI_ROOM", kTyped, engine_env, "docs/SETTINGS.md:77"},
    {"STRATA_GLM_MULTI_SPEC", kTyped, engine_env, "docs/SETTINGS.md:77"},
    {"STRATA_GLM_MV_RDNA", kTyped, engine_env, "docs/SETTINGS.md:82"},
    {"STRATA_GLM_NO_MTP", kTyped, engine_env, "docs/SETTINGS.md:83"},
    {"STRATA_GLM_NO_SPEC", kTyped, engine_env, "docs/SETTINGS.md:89"},
    {"STRATA_GLM_NUMA", kTyped, engine_env, "docs/SETTINGS.md:59"},
    {"STRATA_GLM_PARALLEL_LOAD", kTyped, engine_env, "docs/SETTINGS.md:45"},
    {"STRATA_GLM_PCIE_SHARE", kTyped, engine_env, "docs/SETTINGS.md:54"},
    {"STRATA_GLM_POOL_STATS", kTyped, engine_env, "docs/SETTINGS.md:137"},
    {"STRATA_GLM_PREFETCH_AT", kTyped, engine_env, "docs/SETTINGS.md:58"},
    {"STRATA_GLM_PREFETCH_BLOCKS", kTyped, engine_env, "docs/SETTINGS.md:58"},
    {"STRATA_GLM_PREFETCH_N", kTyped, engine_env, "docs/SETTINGS.md:58"},
    {"STRATA_GLM_PREFETCH_RANK", kTyped, engine_env, "docs/SETTINGS.md:58"},
    {"STRATA_GLM_PREFILL_ATTN", kTyped, engine_env, "docs/SETTINGS.md:114"},
    {"STRATA_GLM_PREFILL_ATTN_CHECK", kTyped, engine_env, "docs/SETTINGS.md:114"},
    {"STRATA_GLM_PREFILL_CHUNK", kTyped, engine_env, "docs/SETTINGS.md:61"},
    {"STRATA_GLM_PREFILL_CPU", kTyped, engine_env, "docs/SETTINGS.md:95"},
    {"STRATA_GLM_PREFILL_CPU_ROW_MS", kTyped, engine_env, "docs/SETTINGS.md:95"},
    {"STRATA_GLM_PREFILL_MB", kTyped, engine_env, "docs/SETTINGS.md:62"},
    {"STRATA_GLM_PREFILL_SUB", kTyped, engine_env, "docs/SETTINGS.md:106"},
    {"STRATA_GLM_PREFILL_TAIL_SKIP", kTyped, engine_env, "docs/SETTINGS.md:63"},
    {"STRATA_GLM_PREFILL_TRACE", kTyped, engine_env, "docs/SETTINGS.md:98"},
    {"STRATA_GLM_PREFILL_WINDOW", kTyped, engine_env, "docs/SETTINGS.md:64"},
    {"STRATA_GLM_PRESTAGE", kTyped, engine_env, "docs/SETTINGS.md:96"},
    {"STRATA_GLM_PRESTAGE_ADAPT", kTyped, engine_env, "docs/SETTINGS.md:96"},
    {"STRATA_GLM_PROFILE_WEIGHT", kTyped, engine_env, "docs/SETTINGS.md:120"},
    {"STRATA_GLM_PROMOTE", kTyped, engine_env, "docs/SETTINGS.md:78"},
    {"STRATA_GLM_PROMOTE_FILL", kTyped, engine_env, "docs/SETTINGS.md:80"},
    {"STRATA_GLM_PROMOTE_MIN", kTyped, engine_env, "docs/SETTINGS.md:79"},
    {"STRATA_GLM_RAM_GB", kTyped, engine_env, "docs/SETTINGS.md:39"},
    {"STRATA_GLM_RAM_HEADROOM_GB", kTyped, engine_env, "docs/SETTINGS.md:38"},
    {"STRATA_GLM_RAM_RESIDENT", kTyped, engine_env, "docs/SETTINGS.md:43"},
    {"STRATA_GLM_RAM_SLACK", kTyped, engine_env, "docs/SETTINGS.md:43"},
    {"STRATA_GLM_READ_CHUNKS", kTyped, engine_env, "docs/SETTINGS.md:60"},
    {"STRATA_GLM_RESERVE_MB", kTyped, engine_env, "maya.py:2241 (value from hip_reserve_mib, :642-648; the HIP calibration writes it into the config env); docs/SETTINGS.md:190-193 now documents MAYA_GLM_RESERVE_MB; the calibration flow is docs/SETTINGS.md:29"},
    {"STRATA_GLM_ROUTE_LOG", kRejected, none, "spec §4 free-form process control (the `log` rule: every route written to an operator-named prefix); docs/SETTINGS.md:138"},
    {"STRATA_GLM_SCORE", kTyped, engine_env, "docs/SETTINGS.md:139"},
    {"STRATA_GLM_SCORE_PREFILL", kTyped, engine_env, "docs/SETTINGS.md:139"},
    {"STRATA_GLM_SEQ_CTX", kTyped, engine_env, "docs/SETTINGS.md:72"},
    {"STRATA_GLM_SEQS", kTyped, engine_env, "docs/SETTINGS.md:72"},
    {"STRATA_GLM_SERVICE_IDLE_MS", kTyped, engine_env, "docs/SETTINGS.md:94"},
    {"STRATA_GLM_SLOT_DAYS", kTyped, engine_env, "docs/SETTINGS.md:71"},
    {"STRATA_GLM_SLOT_DIR", kRejected, none, "spec §4 free-form process control (the `cwd` rule: the slot folder moves off the pack root); docs/SETTINGS.md:70"},
    {"STRATA_GLM_SLOT_GB", kTyped, engine_env, "docs/SETTINGS.md:70"},
    {"STRATA_GLM_SLOT_KEEP", kTyped, engine_env, "docs/SETTINGS.md:71"},
    {"STRATA_GLM_SLOT_MIN", kTyped, engine_env, "docs/SETTINGS.md:70"},
    {"STRATA_GLM_SLOTS", kTyped, engine_env, "docs/SETTINGS.md:68 (SP6 §4.9: slots off is the forced default — the table may move it, nothing unknown is ever sent; Task 4)"},
    {"STRATA_GLM_SPEC_CANCEL", kTyped, engine_env, "docs/SETTINGS.md:90"},
    {"STRATA_GLM_SPEC_HEAD", kTyped, engine_env, "docs/SETTINGS.md:89"},
    {"STRATA_GLM_SPEC_SAMPLE", kTyped, engine_env, "docs/SETTINGS.md:90"},
    {"STRATA_GLM_SPLIT", kTyped, engine_env, "docs/SETTINGS.md:44 (SP6 §4.9: the forced split; glm.layer_split also renders --layer-split, serve/server.py:1274-1277; Task 4/7)"},
    {"STRATA_GLM_SPLIT_LAYER_MS", kTyped, engine_env, "docs/SETTINGS.md:44"},
    {"STRATA_GLM_SPLIT_LOG", kTyped, engine_env, "docs/SETTINGS.md:44"},
    {"STRATA_GLM_THINK_RESERVE", kTyped, config_only, "docs/SETTINGS.md:141, serve/server.py:2279 (server-side reserve; rides glm.thinking_budget — C-3; Task 3)"},
    {"STRATA_GLM_TIMING", kTyped, engine_env, "docs/SETTINGS.md:137"},
    {"STRATA_GLM_TRUNK_KEEP", kTyped, engine_env, "docs/SETTINGS.md:86"},
    {"STRATA_GLM_TRUNK_KEEP_MAP", kTyped, engine_env, "docs/SETTINGS.md:86"},
    {"STRATA_GLM_USAGE", kRejected, none, "spec §4 free-form process control (the `log` rule: an operator-named file the engine writes after every request); docs/SETTINGS.md:67"},
    {"STRATA_GLM_VISION_LEND_MB", kTyped, engine_env, "serve/server.py:4026 (the vision turn lends MB from the expert pool; the flow is docs/SETTINGS.md:29)"},
    {"STRATA_GLM_VRAM_EVICT", kTyped, engine_env, "docs/SETTINGS.md:81"},
    {"STRATA_GLM_WIN_ALLCPU", kTyped, engine_env, "docs/SETTINGS.md:130"},
    {"STRATA_GLM_WIN_CPU", kTyped, engine_env, "docs/SETTINGS.md:130"},
    {"STRATA_GLM_WIN_LANES", kTyped, engine_env, "docs/SETTINGS.md:130"},
    {"STRATA_GLM_WIN_PIPE", kTyped, engine_env, "docs/SETTINGS.md:122"},
    {"STRATA_GLM_WIN_SKIP", kTyped, engine_env, "docs/SETTINGS.md:123"},
    {"STRATA_GLM_WIN_STAGGER", kTyped, engine_env, "docs/SETTINGS.md:130"},
    {"STRATA_GLM_WIN_THREADS", kTyped, engine_env, "docs/SETTINGS.md:123"},
    {"STRATA_GLM_WIN_X3", kTyped, engine_env, "docs/SETTINGS.md:133"},
    {"STRATA_GLM_WIN_X3_POOLS", kTyped, engine_env, "docs/SETTINGS.md:133"},
    {"STRATA_HTTP_BACKLOG", kMapped, none, "the listener backlog is fixed by the SP3 poll design (128 entries); serve/server.py:2913, docs/SETTINGS.md:144"},
    {"STRATA_MAX_BODY_MIB", kTyped, frontend_behavior, "already typed: limits.chat.max_body_bytes (SP1); serve/server.py:2922, docs/SETTINGS.md:144"},
    {"STRATA_MOCK_RELOAD_S", kRejected, none, "spec §4 the mock engine is excluded (serve/server.py:3945 --engine mock); serve/server.py:1587"},
    {"STRATA_WATCHDOG_S", kTyped, engine_env, "docs/SETTINGS.md:143, src/program/generate.cpp:747 (engine-side watchdog; SP6 §4.9/M5 forces 0 pending the owner's sheet; Task 4)"},
    // ---- launcher-managed engine flags (maya.py composes them; the SP4
    //      manifest + the Task-7 composition replace the launcher) ---------
    {"--dflash", kRejected, none, "spec C-5: DFlash2 drafter rejected on the A7 licence ground (CC BY-NC-ND weights, docs/SETTINGS.md:293); maya.py:2301"},
    {"--dump-routing", kRejected, none, "spec §4 free-form process control (the trace dump writes an operator-named file); docs/SETTINGS.md:165"},
    {"--engine", kRejected, none, "spec §4 free-form process control (server-mode select; the mock engine is excluded, serve/server.py:3945); maya.py:2792"},
    {"--serve", kMapped, none, "the supervision composes the engine's serve mode at every start; serve/server.py:437, maya.py:3158"},
    {"--glm-pack", kMapped, manifest_artifact, "the SP4 manifest composes the pack role (Task 7); maya.py:2228 (the launcher's form)"},
    {"--max-context", kTyped, engine_arg, "maya.py:3148 (default 32768 when unset), :2228; Task 7 types glm.max_context at the pin default"},
    {"--prefill", kTyped, engine_arg, "maya.py:2229 (auto), :2284 keeps an operator's value; docs/SETTINGS.md:178-182; Task 7"},
    {"--kv-streaming", kTyped, engine_arg, "maya.py:2229 (the KV_STREAMING constant :104), :2285; docs/SETTINGS.md:108; Task 7"},
    {"--kv-resident", kTyped, engine_arg, "maya.py:2286; docs/SETTINGS.md:108 (the window stays at least 20480); Task 7"},
    {"--parallel", kTyped, engine_arg, "maya.py:3885 (choices 1..8), :2291; replicas.parallel renders --parallel N inside the one child (C-4, M1 Task 10 pattern); Task 7"},
    {"--expert-profile", kMapped, manifest_artifact, "the expert profile is an install/manifest artifact, not an operator path (Task 7); maya.py:2280, :2372-2374"},
    {"--expert-profile-save", kTyped, engine_arg, "docs/SETTINGS.md:164, maya.py:2285 (rides the save; M1 session.expert_profile_save pattern); Task 7"},
    {"--expert-profile-save-every", kTyped, engine_arg, "docs/SETTINGS.md:164 (default 10 minutes), maya.py:2285; Task 7"},
    {"--spec", kTyped, engine_arg, "docs/SETTINGS.md:323 (the verify window's tokens; MTP drafting, the DFlash2 drafter itself stays out per C-5); Task 7"},
    {"--spec-min-p", kTyped, engine_arg, "docs/SETTINGS.md:324 (the confidence cut); Task 7"},
}};
} // namespace

std::span<const std::string_view> maya_config_keys() noexcept {
  return {kMayaConfigKeys};
}

std::span<const std::string_view> maya_env_knobs() noexcept {
  return {kMayaEnvKnobs};
}

std::span<const ParityRow> maya_parity_rows() noexcept {
  return {kMayaRows};
}

const ParityRow* maya_parity_row(std::string_view key) noexcept {
  for (const auto& row : kMayaRows) {
    if (row.key == key) return &row;
  }
  return nullptr;
}

} // namespace secure_frontend::parity

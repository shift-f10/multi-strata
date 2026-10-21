// parity_table.cpp — the SP5 M1 Strata parity table: one row per option the
// pinned upstream Strata v0.2.1.3 reads (inventory: tests/parity_keys_upstream.hpp),
// plus extra rule rows the flat grep cannot see (mcpServers, vram_reserve_mib).
//
// Dispositions and destinations are assigned here once (Task 2); Tasks 4-10
// wire the destinations. A disposition changes only on implementation
// evidence, with the ledger Ruling (table = source of truth, plan Task 9 note).
// Citations are `serve/<file>.py:<line>` at the pin; rejected rows lead with
// the excluding spec rule (D-3).

#include "secure_frontend/parity_table.hpp"

#include <array>

#include "../tests/parity_keys_upstream.hpp"

namespace secure_frontend::parity {

namespace {

constexpr ParityDisposition kTyped = ParityDisposition::typed;
constexpr ParityDisposition kRejected = ParityDisposition::rejected;
constexpr ParityDisposition kMapped = ParityDisposition::mapped_away;

using enum ParityDestination;

constexpr std::array<ParityRow, 121> kRows{{
    // ---- config keys, alphabetical (the generated inventory) --------------
    {"aliases", kTyped, config_only, "serve/server.py:8046 (M1 Task 8: model.aliases)"},
    {"allowed_hosts", kTyped, frontend_behavior, "already typed (SP1/SP3 listen); serve/server.py:8066"},
    {"answer_room", kTyped, frontend_behavior, "serve/server.py:8014 (M1 Task 8)"},
    {"anthropic_thinking", kTyped, config_only, "serve/server.py:8102 (M1 Task 5: reasoning.anthropic_thinking)"},
    {"api_key", kMapped, none, "SP1 token store is the only auth source (CFG-06: no secret in config); serve/server.py:7869"},
    {"api_monitor", kRejected, none, "spec §4 web/desktop/telemetry; serve/server.py:8072"},
    {"arch", kMapped, none, "model identity comes from the SP4 manifest/GGUF inventory; serve/server.py:7648"},
    {"args", kRejected, none, "spec §4 free-form process control; serve/server.py:3114"},
    {"backend", kMapped, none, "engine identity: SP4 manifest + engine gate; serve/server.py:7680"},
    {"batch_telemetry", kRejected, none, "spec §4 telemetry endpoints; serve/server.py:897"},
    {"before_load", kRejected, none, "spec §4 command execution; serve/server.py:7899"},
    {"before_load_ignore_failure", kRejected, none, "spec §4 command execution; serve/server.py:8090"},
    {"before_load_strict", kRejected, none, "spec §4 command execution; serve/server.py:8091"},
    {"before_load_timeout_s", kRejected, none, "spec §4 command execution; serve/server.py:8086"},
    {"codex_compaction_cache", kTyped, config_only, "serve/server.py:8044 (M1 Task 9: session.codex_compaction_cache)"},
    {"codex_thread_titles", kTyped, config_only, "serve/server.py:8043 (M1 Task 9: session.codex_thread_titles)"},
    {"command", kRejected, none, "spec §4 MCP command; serve/mcp.py:610"},
    {"cors_origins", kTyped, frontend_behavior, "already typed (SP3 B12: listener.cors_origins); serve/server.py:8063"},
    {"cwd", kRejected, none, "spec §4 free-form process control; serve/mcp.py:106"},
    {"effort_position", kTyped, engine_arg, "serve/server.py:2836 (M1 Task 5: reasoning.effort_position composes the engine's --tail-role-token)"},
    {"elastic", kTyped, engine_arg, "serve/server.py:2550 (M1 Task 7: engine.elastic)"},
    {"elastic_idle_s", kTyped, engine_arg, "serve/server.py:2552 (M1 Task 7: engine.elastic_idle_s)"},
    {"elastic_mib", kTyped, engine_arg, "serve/server.py:2551 (M1 Task 7: engine.elastic_mib)"},
    {"engine_silence_s", kTyped, frontend_behavior, "serve/server.py:941, default 300.0 at serve/server.py:276 (M1 Task 8)"},
    {"env", kRejected, none, "spec §4 raw env dict; serve/server.py:3228"},
    {"env_to_user", kTyped, config_only, "serve/server.py:8110 (M1 Task 9: session.env_to_user)"},
    {"exe", kRejected, none, "spec §4 free-form process control (engine identity comes from the SP4 manifest); serve/server.py:7674"},
    {"expert_profile_save", kTyped, engine_arg, "serve/server.py:2999 (M1 Task 9: --expert-profile-save)"},
    {"expert_profile_save_every", kTyped, engine_arg, "serve/server.py:3003 (M1 Task 9: --expert-profile-save-every)"},
    {"fit_max_tokens", kTyped, frontend_behavior, "serve/server.py:7996 (M1 Task 5: engine.fit_max_tokens)"},
    {"gpu", kTyped, engine_arg, "already typed (SP2 engine.gpu; compose renders --gpu); serve/server.py:2815"},
    {"gpu_order", kTyped, engine_arg, "serve/server.py:3112 (M1 Task 7)"},
    {"gpu_policy", kTyped, config_only, "serve/images.py:173 (M1 Task 7: engine.gpu_policy, re-scoped to the vision child's GPU turn; the pin's use is the image-generation turn)"},
    {"headers", kRejected, none, "spec §4 MCP headers; serve/mcp.py:257"},
    {"hip_ordinal", kTyped, engine_arg, "serve/server.py:3023 (M1 Task 7)"},
    {"host", kTyped, frontend_behavior, "already typed (SP1 listen.host); serve/server.py:7862"},
    {"idle_unload_s", kTyped, frontend_behavior, "serve/server.py:4100-4109, :8081 (M1 Task 6: supervisor idle timer)"},
    {"images", kMapped, none, "spec D-9: image generation is out, the route answers 404 like an unknown route; serve/server.py:8016"},
    {"keep_files", kTyped, frontend_behavior, "serve/images.py:188 (M1 Task 9: session.keep_files, private-scratch retention count)"},
    {"layer_split", kTyped, engine_arg, "serve/server.py:2877 (M1 Task 7)"},
    // Ruling T6-b (Task 6): the pin skips the child start (lazy :966-993), so no engine
    // argument composes — the deferral is frontend behaviour, like the idle timer.
    {"lazy_load", kTyped, frontend_behavior, "serve/server.py:7925, :966-993 (M1 Task 6: the first request spawns the same composed launch)"},
    {"lib_dirs", kRejected, none, "spec §4 free-form process control; serve/images.py:135"},
    {"log", kRejected, none, "spec §4 free-form process control; serve/replicas.py:99"},
    {"max_n", kTyped, frontend_behavior, "serve/images.py:103 (M1 Tasks 11-12: vision.max_n; the pin's cap lives on the images block)"},
    {"max_queue", kTyped, frontend_behavior, "serve/server.py:7833, bound 0..4096 at serve/server.py:7835 (M1 Task 8)"},
    {"max_side", kTyped, frontend_behavior, "serve/images.py:102 (M1 Task 12: vision.max_side pre-decode cap)"},
    {"max_tokens", kTyped, request_rule, "serve/server.py:2564 (vision block at the pin); engine.max_tokens is the added frontend bound per C-1 (M1 Task 8)"},
    {"mcp", kRejected, none, "spec §4 MCP; serve/mcp.py:632"},
    {"mcp_servers", kRejected, none, "spec §4 MCP; serve/mcp.py:651"},
    {"min_free_vram_mib", kTyped, engine_arg, "serve/server.py:8083 (M1 Task 7)"},
    {"min_tokens", kTyped, request_rule, "serve/server.py:2566 (vision block at the pin); engine.min_tokens is the added frontend bound per C-1 (M1 Task 8)"},
    {"model_name", kMapped, none, "served-model identity comes from the SP4 manifest; serve/images.py:183"},
    // The pin reads this one through strata_control/draft_layer.is_off, which the Task-2
    // inventory greps do not see; the row keeps the parity spine complete (extra rule row).
    {"mtp", kTyped, engine_arg, "strata_control/draft_layer.py is_off; serve/server.py:2922-2925 (M1 Task 6: engine.mtp drops --mtp/--spec-min-p/--batch-mtp at every start)"},
    {"native", kMapped, none, "the SP4 manifest composes --native (engine_arguments); serve/images.py:126"},
    {"need_mib", kTyped, frontend_behavior, "serve/images.py:156 (M1 Task 11: vision.need_mib; added security bound)"},
    {"open_browser", kRejected, none, "spec §4 web/desktop; serve/server.py:8191"},
    {"out_dir", kMapped, none, "spec D-9 image generation is out; serve/images.py:185"},
    {"parallel", kTyped, engine_arg, "serve/server.py:2963, bound 1..1024 at serve/server.py:7844 (M1 Task 10: replicas.parallel)"},
    {"prevent_sleep", kRejected, none, "spec §4 desktop; serve/server.py:8031"},
    {"quant", kMapped, none, "quant identity comes from the SP4 manifest; serve/images.py:282"},
    {"queue_timeout", kTyped, frontend_behavior, "serve/server.py:7837, bound 0.1..600 at serve/server.py:7839 (M1 Task 8: engine.queue_timeout_s)"},
    {"reasoning_budget_tokens", kTyped, config_only, "serve/server.py:8120 (M1 Task 5: reasoning.budget_tokens)"},
    {"reasoning_close_retry", kTyped, config_only, "serve/server.py:8015 (M1 Task 5: reasoning.close_retry)"},
    {"reasoning_effort", kTyped, config_only, "serve/server.py:7433 (M1 Task 5: reasoning.effort)"},
    {"reasoning_loop_recovery", kTyped, config_only, "serve/server.py:8129 (M1 Task 5: reasoning.loop_recovery)"},
    {"reload", kMapped, none, "image-generation card reload mode (spec D-9); the vision child's lifecycle follows the vision/elastic rows; serve/images.py:176"},
    {"repeat_stop_tokens", kTyped, engine_arg, "serve/server.py:8115 (M1 Task 8: GEN keys)"},
    {"replica_cpus", kRejected, none, "spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7549"},
    {"replica_load_tokens", kRejected, none, "spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7583"},
    {"replicas", kRejected, none, "spec C-4: N-child replica scheduling is the accepted narrowing; serve/replicas.py:44"},
    {"sampling", kTyped, config_only, "serve/server.py:7482 (M1 Task 4: defaults.sampling.*)"},
    {"sigmas", kMapped, none, "spec D-9 image generation is out; serve/images.py:120"},
    {"slot_save_path", kTyped, engine_arg, "serve/server.py:8094 (M1 Task 9)"},
    {"split_skip_if_fits", kTyped, engine_arg, "serve/server.py:2941 (M1 Task 7)"},
    {"steps", kMapped, none, "spec D-9 image generation is out; serve/images.py:104"},
    {"telemetry_read_key", kRejected, none, "spec §4 telemetry endpoints; serve/server.py:8053"},
    {"threads", kTyped, engine_arg, "serve/server.py:2562 (M1 Task 7: engine.threads)"},
    {"timeout_s", kTyped, frontend_behavior, "serve/images.py:226 (generation job timeout at the pin); engine.timeout_s is the added frontend deadline per C-1 (M1 Task 8)"},
    {"tokenizer", kMapped, none, "the SP4 manifest carries the tokenizer; serve/server.py:7883"},
    {"tool_call_recovery", kTyped, config_only, "serve/server.py:8106 (M1 Task 9: session.tool_call_recovery)"},
    {"trusted_origins", kTyped, frontend_behavior, "already typed (SP3 origins family); serve/server.py:8064"},
    {"type", kRejected, none, "spec §4 MCP entry type; serve/mcp.py:604"},
    {"uma", kTyped, engine_arg, "serve/images.py:334 (M1 Task 7: engine.uma)"},
    {"url", kRejected, none, "spec §4 MCP url; serve/mcp.py:384"},
    {"user_args", kRejected, none, "spec §4 free-form process control; serve/server.py:2918"},
    {"vision", kTyped, config_only, "serve/server.py:2930 (M1 Task 11: the vision.* block)"},
    {"vram_elastic", kTyped, engine_arg, "serve/server.py:2945 (M1 Task 7)"},
    {"vram_segment_mib", kTyped, engine_arg, "serve/server.py:2947 (M1 Task 7)"},

    // ---- env knobs (the generated inventory; semantics typed or excluded,
    //      never honored raw from the process environment — spec §4) --------
    {"STRATA_ADMIT_MAX_WAIT_S", kTyped, frontend_behavior, "serve/server.py:311; admission waiting is typed as engine.queue_timeout_s (M1 Task 8)"},
    {"STRATA_ADMIT_SHORT_FIRST", kMapped, none, "SP3 admission ordering is the pool policy (B8); serve/server.py:314"},
    {"STRATA_ALLOWED_HOSTS", kTyped, frontend_behavior, "same semantics as allowed_hosts, already typed; serve/server.py:3516"},
    {"STRATA_API_KEY", kMapped, none, "SP1 token store is the only auth source; serve/server.py:7216"},
    {"STRATA_BATCH_MTP", kTyped, engine_arg, "serve/server.py:2972; engine.mtp (M1 Task 6)"},
    {"STRATA_BATCH_TELEMETRY", kRejected, none, "spec §4 telemetry endpoints; serve/server.py:899"},
    {"STRATA_BATCH_TRACE", kRejected, none, "spec §4 no new web/diagnostics surface; serve/server.py:821"},
    {"STRATA_DEBUG", kRejected, none, "spec §4 no new web/diagnostics surface; serve/mcp.py:130"},
    {"STRATA_DROP_CACHE_ON_EXIT", kMapped, none, "the SP2 shutdown order (§3.7) is fixed by the supervisor; serve/cache_drop.py:1"},
    {"STRATA_ENGINE_READY_S", kTyped, frontend_behavior, "already typed: ready_timeout (SP1); serve/server.py:291"},
    {"STRATA_ENGINE_STALL_S", kTyped, frontend_behavior, "serve/server.py:307; engine.silence_s (M1 Task 8)"},
    {"STRATA_FAIL_ONCE", kRejected, none, "spec §4 free-form process control (fault-injection knob); serve/test_server.py:4610"},
    {"STRATA_HTTP_BACKLOG", kMapped, none, "the listener backlog is fixed by the SP3 poll design (128 entries); serve/server.py:7021"},
    {"STRATA_KEEP_EMPTY_TURNS", kMapped, none, "the frontend serves stateless requests; conversation history is the client's; serve/frontend.py:60"},
    {"STRATA_KEEP_LEFTOVERS", kMapped, none, "lifecycle is teardown + respawn (M1 Task 6); serve/server.py:128"},
    {"STRATA_LIFELINE", kMapped, none, "SP2 supervision replaces the lifeline watcher (pdeathsig, monitor handle); serve/lifeline.py:33"},
    {"STRATA_MAX_BODY_MIB", kTyped, frontend_behavior, "already typed: limits.chat.max_body_bytes (SP1); serve/server.py:5660"},
    {"STRATA_NO_PRESET", kMapped, none, "launch is SP4 manifest-composed; serve/server.py:7448"},
    {"STRATA_OFFLINE", kMapped, none, "PRIV-01: the frontend never reaches the network; enforced by design and the DL-01 proof; serve/server.py:3240"},
    {"STRATA_OWNER_ATTEST_KEY", kRejected, none, "spec §4 signing material, deferred to SP7; serve/server.py:7820"},
    {"STRATA_PARALLEL_SOLO", kRejected, none, "spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:1727"},
    {"STRATA_REPLICA_START", kRejected, none, "spec C-4: N-child replica scheduling is the accepted narrowing; serve/server.py:7565"},
    {"STRATA_REQUEST_LINES", kMapped, none, "the wire record is fixed by docs/security/engine-protocol-limits.md; serve/server.py:639"},
    {"STRATA_RUNTIME_PROFILE", kRejected, none, "spec §4 no new web/diagnostics surface; serve/lifeline.py:265"},
    {"STRATA_START_RETRIES", kMapped, none, "respawn retries belong to the SP2 RestartTracker (restart_policy.hpp); serve/server.py:609"},
    {"STRATA_SYCL_BIN", kRejected, none, "spec §4 free-form process control (external binary path); serve/server.py:2824"},
    {"STRATA_TELEMETRY_KEY", kRejected, none, "spec §4 telemetry endpoints; serve/server.py:8053"},
    {"STRATA_TOKENIZER", kMapped, none, "the SP4 manifest carries the tokenizer; serve/test_detok.py:21"},
    {"STRATA_VERIFY_TRACE", kRejected, none, "spec §4 no new web/diagnostics surface; serve/server.py:1213"},
    {"STRATA_VISION_ENCODE_S", kTyped, frontend_behavior, "serve/server.py:328 (M1 Task 12: vision encode-timeout row)"},
    {"STRATA_VISION_READY_S", kTyped, frontend_behavior, "serve/server.py:291 (M1 Task 11: vision ready-timeout row)"},

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

} // namespace secure_frontend::parity

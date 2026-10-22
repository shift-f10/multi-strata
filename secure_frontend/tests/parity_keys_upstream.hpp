// parity_keys_upstream.hpp — the option-surface inventory of the pinned
// upstream Strata, generated once and committed (SP5 M1 Task 2).
//
// Pin: upstream submodule commit 011c9e600a93bbc9fd451c563501b5831c32bbca (tag v0.2.2).
// Generating commands (run in `upstream/`, lists verbatim — no edits, no additions):
//   grep -rhoE 'cfg\.get\("[a-z_0-9]+"' serve/*.py | sort -u | sed 's/cfg.get("//;s/"//'
//   grep -rhoE 'STRATA_[A-Z0-9_]+' serve/*.py | sort -u
// Counts: 88 config keys, 32 env knobs (the spec's "~35" estimate; the grep
// over serve/*.py at the pin yields 32).
//
// NOTE: the flat grep mixes names read inside config *blocks* (the `vision`
// dict, the `images` image-generation dict, `mcp_servers` entries, replica
// entries). The parity table dispositions cite the governing read site.

#ifndef SECURE_FRONTEND_TESTS_PARITY_KEYS_UPSTREAM_HPP
#define SECURE_FRONTEND_TESTS_PARITY_KEYS_UPSTREAM_HPP

#include <string_view>

namespace secure_frontend::parity {

inline constexpr std::string_view kUpstreamConfigKeys[] = {
    "aliases",
    "allowed_hosts",
    "answer_room",
    "anthropic_thinking",
    "api_key",
    "api_monitor",
    "arch",
    "args",
    "backend",
    "batch_telemetry",
    "before_load",
    "before_load_ignore_failure",
    "before_load_strict",
    "before_load_timeout_s",
    "codex_compaction_cache",
    "codex_thread_titles",
    "command",
    "cors_origins",
    "cwd",
    "effort_position",
    "elastic",
    "elastic_idle_s",
    "elastic_mib",
    "engine_silence_s",
    "env",
    "env_to_user",
    "exe",
    "expert_profile_save",
    "expert_profile_save_every",
    "fit_max_tokens",
    "gpu",
    "gpu_order",
    "gpu_policy",
    "headers",
    "hip_ordinal",
    "host",
    "idle_unload_s",
    "images",
    "keep_files",
    "layer_split",
    "lazy_load",
    "lib_dirs",
    "log",
    "max_n",
    "max_queue",
    "max_side",
    "max_tokens",
    "mcp",
    "mcp_servers",
    "min_free_vram_mib",
    "min_tokens",
    "model_name",
    "native",
    "need_mib",
    "open_browser",
    "out_dir",
    "parallel",
    "pool_cores",
    "prevent_sleep",
    "quant",
    "queue_timeout",
    "reasoning_budget_tokens",
    "reasoning_close_retry",
    "reasoning_effort",
    "reasoning_loop_recovery",
    "reload",
    "repeat_stop_tokens",
    "replica_cpus",
    "replica_load_tokens",
    "replicas",
    "sampling",
    "sigmas",
    "slot_save_path",
    "split_skip_if_fits",
    "steps",
    "telemetry_read_key",
    "threads",
    "timeout_s",
    "tokenizer",
    "tool_call_recovery",
    "trusted_origins",
    "type",
    "uma",
    "url",
    "user_args",
    "vision",
    "vram_elastic",
    "vram_segment_mib",
};

inline constexpr std::string_view kUpstreamEnvKnobs[] = {
    "STRATA_ADMIT_MAX_WAIT_S",
    "STRATA_ADMIT_SHORT_FIRST",
    "STRATA_ALLOWED_HOSTS",
    "STRATA_API_KEY",
    "STRATA_BATCH_MTP",
    "STRATA_BATCH_TELEMETRY",
    "STRATA_BATCH_TRACE",
    "STRATA_DEBUG",
    "STRATA_DROP_CACHE_ON_EXIT",
    "STRATA_ENGINE_NICE",
    "STRATA_ENGINE_READY_S",
    "STRATA_ENGINE_STALL_S",
    "STRATA_FAIL_ONCE",
    "STRATA_HTTP_BACKLOG",
    "STRATA_KEEP_EMPTY_TURNS",
    "STRATA_KEEP_LEFTOVERS",
    "STRATA_LIFELINE",
    "STRATA_MAX_BODY_MIB",
    "STRATA_NO_PRESET",
    "STRATA_OFFLINE",
    "STRATA_OWNER_ATTEST_KEY",
    "STRATA_PARALLEL_SOLO",
    "STRATA_REPLICA_START",
    "STRATA_REQUEST_LINES",
    "STRATA_RUNTIME_PROFILE",
    "STRATA_START_RETRIES",
    "STRATA_SYCL_BIN",
    "STRATA_TELEMETRY_KEY",
    "STRATA_TOKENIZER",
    "STRATA_VERIFY_TRACE",
    "STRATA_VISION_ENCODE_S",
    "STRATA_VISION_READY_S",
};

} // namespace secure_frontend::parity

#endif // SECURE_FRONTEND_TESTS_PARITY_KEYS_UPSTREAM_HPP

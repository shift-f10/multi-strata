// parity_keys_maya.hpp — the option-surface inventory of the vendored Project
// Maya reference, generated once and committed (SP5 M2 Task 2). The GLM parity
// table gives every name here exactly one disposition (meta-tests).
//
// Pin: engines/maya-ref submodule commit 5c970a863ce2fdd87b6e23ffb4822f6d76522b1c (tag v1.1.8).
// Config keys (37) — generating commands, run in the repository root, lists
// verbatim (no edits, no additions):
//   grep -rhoE 'cfg\.get\("[a-z_0-9]+"' engines/maya-ref/serve/*.py engines/maya-ref/maya.py | sort -u | sed 's/cfg\.get("//;s/"$//'
//   plus the shared-settings names the validator enumerates at
//   engines/maya-ref/serve/server.py:3223-3260 (its elif chain):
//   experimental_speed_projection, min_p, seed, temperature, top_k, top_p
//   (reasoning_effort and max_tokens are already in the grep).
// NOTE: the flat grep mixes names read inside config *blocks* (the `sampling`
// and `vision` dicts, `mcp_servers` entries). Names the grep cannot see —
// mcpServers (camelCase, serve/mcp.py:646), the vision block's mmproj/model
// (serve/server.py:1157), and the sampling block's presence_penalty,
// repetition_penalty, frequency_penalty, penalty_last_n (serve/server.py:250-252,
// :3265-3270) — are extra rule rows in the table. The `installer` block's
// sub-keys (models_dir, quant, gguf, draft, data_dir, speed_calibration —
// maya.py:938, :1879, :2093, :2110, :2649-2650) ride its rejected parent row.
//
// Env knobs (119) — the documented engine/server env surface:
//   sed -n '26,101p' engines/maya-ref/docs/SETTINGS.md | grep -ohE 'STRATA_GLM_[A-Z0-9_]+' | sort -u    (103)
//   grep -ohE 'STRATA_GLM_[A-Z0-9_]+' engines/maya-ref/docs/SETTINGS.md | sort -u                       (105; adds STRATA_GLM_DFLASH, STRATA_GLM_DFLASH_MIN)
//   grep -rhoE 'STRATA_GLM_[A-Z0-9_]+' engines/maya-ref/serve/*.py engines/maya-ref/maya.py | sort -u   (12; adds STRATA_GLM_RESERVE_MB, STRATA_GLM_VISION_LEND_MB)
//   grep -rhoE 'environ\.get\("STRATA_[A-Z0-9_]+' engines/maya-ref/serve/server.py | sort -u            (the nine server names)
//   plus STRATA_WATCHDOG_S (engine-side: engines/maya-ref/src/program/generate.cpp:727, docs/SETTINGS.md:97)
//   and the updater's MAYA_UPDATE_CHECK (serve/update.py:74) / MAYA_RESTART_ON_UPDATE (maya.py:2240).
// Excluded from the inventory as launcher internals, not engine/server knobs
// (Ruling T2-b, lane ledger): MAYA_SH (maya.py:2781 — maya.sh's self-detection
// marker), MAYA_VERSION (serve/server.py:58 — a module constant read from
// VERSION), and the engine-BUILD env names maya.py passes to a *build*
// (STRATA_BUILD_TESTS, STRATA_ENABLE_CUDA, STRATA_ENABLE_HIP, STRATA_GGML_DIR,
// STRATA_NATIVE_EXPERTS, STRATA_PORTABLE, STRATA_GGUF_PY, STRATA_HIPBLASLT_TUNING,
// STRATA_VISION_CUDA, STRATA_PREFILL_MMQ, STRATA_TOKENIZER — maya.py:2160-2210
// region; maya.py is the launcher the SP4 manifest replaces). The engine's
// undocumented src-internal getenv names (STRATA_GLM_DEV1 and friends) sit
// outside the documented surface; the closed child-env allowlist (Task 4)
// renders only table names, so no name outside this table can reach a child.

#ifndef SECURE_FRONTEND_TESTS_PARITY_KEYS_MAYA_HPP
#define SECURE_FRONTEND_TESTS_PARITY_KEYS_MAYA_HPP

#include <string_view>

namespace secure_frontend::parity {

inline constexpr std::string_view kMayaConfigKeys[] = {
    "api_key",
    "args",
    "backend",
    "command",
    "cors_origins",
    "cwd",
    "env",
    "exe",
    "experimental_speed_projection",
    "fit_max_tokens",
    "gpu",
    "headers",
    "host",
    "installer",
    "layer_split",
    "lib_dirs",
    "log",
    "max_tokens",
    "mcp",
    "mcp_servers",
    "min_p",
    "model_name",
    "no_flash_attn",
    "port",
    "reasoning_effort",
    "resident",
    "sampling",
    "seed",
    "temperature",
    "thinking_budget",
    "threads",
    "tokenizer",
    "top_k",
    "top_p",
    "type",
    "url",
    "vision",
};

inline constexpr std::string_view kMayaEnvKnobs[] = {
    "MAYA_RESTART_ON_UPDATE",
    "MAYA_UPDATE_CHECK",
    "STRATA_API_KEY",
    "STRATA_DEBUG",
    "STRATA_ENGINE_QUIT_S",
    "STRATA_ENGINE_STALL_S",
    "STRATA_ENGINE_WRAP_S",
    "STRATA_FAIR_SLICE_S",
    "STRATA_GLM_AHEAD",
    "STRATA_GLM_CKPT_EVERY",
    "STRATA_GLM_CKPTS",
    "STRATA_GLM_CPU_1T",
    "STRATA_GLM_CPU_CAL",
    "STRATA_GLM_CPU_LANE",
    "STRATA_GLM_CPU_LANE0",
    "STRATA_GLM_CPU_LANE1",
    "STRATA_GLM_CPU_MT",
    "STRATA_GLM_CPU_PIN",
    "STRATA_GLM_CPU_PLAN",
    "STRATA_GLM_CPU_RETIME",
    "STRATA_GLM_CPU_SHARED",
    "STRATA_GLM_CPU_SPLIT",
    "STRATA_GLM_DFLASH",
    "STRATA_GLM_DFLASH_MIN",
    "STRATA_GLM_DFLASH_PROF",
    "STRATA_GLM_DFLASH_STATS",
    "STRATA_GLM_DISK_QD",
    "STRATA_GLM_DISK_READERS",
    "STRATA_GLM_DISK_SKIP_FROM",
    "STRATA_GLM_DISK_SKIP_W",
    "STRATA_GLM_DROP_CACHE",
    "STRATA_GLM_DSA_SCORE",
    "STRATA_GLM_EXL3_MMA_ROWS",
    "STRATA_GLM_KDA_GRAPH",
    "STRATA_GLM_KQ",
    "STRATA_GLM_KV_INT8",
    "STRATA_GLM_KV_PREFETCH",
    "STRATA_GLM_KV_RESIDENT",
    "STRATA_GLM_LOOP_ANSWER",
    "STRATA_GLM_LOOP_THINK",
    "STRATA_GLM_MMQ_GLU",
    "STRATA_GLM_MTP_GGUF",
    "STRATA_GLM_MTP_KEEP",
    "STRATA_GLM_MTP_MISS",
    "STRATA_GLM_MULTI_BENCH",
    "STRATA_GLM_MULTI_BOUNDARY",
    "STRATA_GLM_MULTI_ROOM",
    "STRATA_GLM_MULTI_SPEC",
    "STRATA_GLM_MV_RDNA",
    "STRATA_GLM_NO_MTP",
    "STRATA_GLM_NO_SPEC",
    "STRATA_GLM_NUMA",
    "STRATA_GLM_PARALLEL_LOAD",
    "STRATA_GLM_PCIE_SHARE",
    "STRATA_GLM_POOL_STATS",
    "STRATA_GLM_PREFETCH_AT",
    "STRATA_GLM_PREFETCH_BLOCKS",
    "STRATA_GLM_PREFETCH_N",
    "STRATA_GLM_PREFETCH_RANK",
    "STRATA_GLM_PREFILL_ATTN",
    "STRATA_GLM_PREFILL_ATTN_CHECK",
    "STRATA_GLM_PREFILL_CHUNK",
    "STRATA_GLM_PREFILL_CPU",
    "STRATA_GLM_PREFILL_CPU_ROW_MS",
    "STRATA_GLM_PREFILL_MB",
    "STRATA_GLM_PREFILL_SUB",
    "STRATA_GLM_PREFILL_TAIL_SKIP",
    "STRATA_GLM_PREFILL_TRACE",
    "STRATA_GLM_PREFILL_WINDOW",
    "STRATA_GLM_PRESTAGE",
    "STRATA_GLM_PRESTAGE_ADAPT",
    "STRATA_GLM_PROFILE_WEIGHT",
    "STRATA_GLM_PROMOTE",
    "STRATA_GLM_PROMOTE_FILL",
    "STRATA_GLM_PROMOTE_MIN",
    "STRATA_GLM_RAM_GB",
    "STRATA_GLM_RAM_HEADROOM_GB",
    "STRATA_GLM_RAM_RESIDENT",
    "STRATA_GLM_RAM_SLACK",
    "STRATA_GLM_READ_CHUNKS",
    "STRATA_GLM_RESERVE_MB",
    "STRATA_GLM_ROUTE_LOG",
    "STRATA_GLM_SCORE",
    "STRATA_GLM_SCORE_PREFILL",
    "STRATA_GLM_SEQ_CTX",
    "STRATA_GLM_SEQS",
    "STRATA_GLM_SERVICE_IDLE_MS",
    "STRATA_GLM_SLOT_DAYS",
    "STRATA_GLM_SLOT_DIR",
    "STRATA_GLM_SLOT_GB",
    "STRATA_GLM_SLOT_KEEP",
    "STRATA_GLM_SLOT_MIN",
    "STRATA_GLM_SLOTS",
    "STRATA_GLM_SPEC_CANCEL",
    "STRATA_GLM_SPEC_HEAD",
    "STRATA_GLM_SPEC_SAMPLE",
    "STRATA_GLM_SPLIT",
    "STRATA_GLM_SPLIT_LAYER_MS",
    "STRATA_GLM_SPLIT_LOG",
    "STRATA_GLM_THINK_RESERVE",
    "STRATA_GLM_TIMING",
    "STRATA_GLM_TRUNK_KEEP",
    "STRATA_GLM_TRUNK_KEEP_MAP",
    "STRATA_GLM_USAGE",
    "STRATA_GLM_VISION_LEND_MB",
    "STRATA_GLM_VRAM_EVICT",
    "STRATA_GLM_WIN_ALLCPU",
    "STRATA_GLM_WIN_CPU",
    "STRATA_GLM_WIN_LANES",
    "STRATA_GLM_WIN_PIPE",
    "STRATA_GLM_WIN_SKIP",
    "STRATA_GLM_WIN_STAGGER",
    "STRATA_GLM_WIN_THREADS",
    "STRATA_GLM_WIN_X3",
    "STRATA_GLM_WIN_X3_POOLS",
    "STRATA_HTTP_BACKLOG",
    "STRATA_MAX_BODY_MIB",
    "STRATA_MOCK_RELOAD_S",
    "STRATA_WATCHDOG_S",
};

} // namespace secure_frontend::parity

#endif // SECURE_FRONTEND_TESTS_PARITY_KEYS_MAYA_HPP

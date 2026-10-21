#include "secure_frontend/frontend_config.hpp"

#include "secure_frontend/config_defaults.hpp"
#include "secure_frontend/engine_arguments.hpp"
#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/json.hpp"
#include "secure_frontend/model_inventory.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <charconv>
#include <limits>
#include <set>
#include <string>
#include <utility>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#endif

namespace secure_frontend {
namespace {
namespace d = config_defaults;
using T = ConfigValueType;

// SP5 M1 Task 4: a decimal row with this default has no default — an absent
// entry stays unset (never sent to the engine).
constexpr double kUnsetDecimal = std::numeric_limits<double>::quiet_NaN();

// Shortest round-trip decimal text (shared by issue messages and --check).
std::string decimal_text(const double value) {
  char buffer[32];
  const auto [end, ec] = std::to_chars(buffer, buffer + sizeof(buffer), value);
  return ec == std::errc{} ? std::string{buffer, end} : std::string{"?"};
}

constexpr std::array<ConfigKey, 43 + 7 + 3 + 9 + 7 + 3 + 13 + 6 + 8 + 1 + 9 + 8> kSchema{{
    {"schema_version", T::integer, false, 1, 1, d::kSchemaVersion, false, "", "",
     "Config format version; must be 1. Required in a config file."},
    {"listener.host", T::string, false, 0, 0, 0, false, "127.0.0.1", "--host",
     "Bind address: an IPv4/IPv6 literal or localhost. Other hostnames are rejected (never resolved)."},
    {"listener.port", T::integer, false, 1, 65535, d::kListenerPort, false, "", "--port", "TCP port."},
    {"listener.allow_remote", T::boolean, false, 0, 0, 0, false, "", "--allow-remote",
     "Required for every non-loopback address."},
    {"listener.allow_wildcard_bind", T::boolean, false, 0, 0, 0, false, "", "--allow-wildcard-bind",
     "Also required for 0.0.0.0, :: and every other spelling of the unspecified address."},
    {"listener.backlog", T::integer, false, 1, 4096, d::kListenerBacklog, false, "", "", "listen() backlog."},
    {"listener.cors_origins", T::string_array, false, 0, 0, 0, false, "", "",
     "Exact browser origins allowed CORS: http:// or https://, a lower-case host, an optional port, no path; never * or null; at most 16."},
    {"listener.host_aliases", T::string_array, false, 0, 0, 0, false, "", "",
     "Extra exact Host values (host or host:port) clients use; required when the bind is a wildcard; at most 16."},
    {"limits.http.request_deadline_ms", T::integer, false, 1, 3'600'000, d::kRequestDeadlineMs, false, "", "",
     "Total time to read one request, header and body."},
    {"limits.http.max_request_bytes", T::integer, false, 4096, 16'777'216, d::kMaxRequestBytes, false, "", "",
     "Largest request (header and body) the listener and parser accept."},
    {"limits.http.max_header_bytes", T::integer, false, 1024, 65'536, d::kMaxHeaderBytes, false, "", "",
     "Largest header block; at most limits.http.max_request_bytes."},
    {"limits.http.max_headers", T::integer, false, 8, 256, d::kMaxHeaders, false, "", "", "Most header fields."},
    {"limits.http.max_request_line_bytes", T::integer, false, 256, 16'384, d::kMaxRequestLineBytes, false, "", "",
     "Longest request line; at most limits.http.max_header_bytes."},
    {"limits.http.header_deadline_ms", T::integer, false, 1, 3'600'000, d::kHeaderDeadlineMs, false, "", "",
     "Time from accept to the end of the request header; at most limits.http.request_deadline_ms."},
    {"limits.http.write_stall_ms", T::integer, false, 100, 300'000, d::kWriteStallMs, false, "", "",
     "Longest send without progress before the client is treated as gone."},
    {"limits.http.response_write_deadline_ms", T::integer, false, 1'000, 3'600'000, d::kResponseWriteDeadlineMs, false, "", "",
     "Time to send a whole complete response, or a stream's tail after DONE; at least limits.http.write_stall_ms."},
    {"limits.http.stream_keepalive_ms", T::integer, false, 1'000, 300'000, d::kStreamKeepaliveMs, false, "", "",
     "SSE comment interval while no content flows (streaming)."},
    {"limits.chat.max_body_bytes", T::integer, false, 1, 16'777'216, d::kChatMaxBodyBytes, false, "", "",
     "Largest chat request body; at most max_request_bytes minus max_header_bytes."},
    {"limits.chat.max_messages", T::integer, false, 1, 128, d::kChatMaxMessages, false, "", "",
     "Most messages in one chat request."},
    {"limits.chat.max_message_bytes", T::integer, false, 1, 65'536, d::kChatMaxMessageBytes, false, "", "",
     "Largest single message content."},
    {"limits.chat.max_prompt_tokens", T::integer, false, 1, 262'144, d::kChatMaxPromptTokens, false, "", "",
     "Largest tokenized prompt sent to the engine."},
    {"limits.chat.max_completion_tokens", T::integer, false, 1, 16'384, d::kChatMaxCompletionTokens, false, "", "",
     "Largest max_tokens a request may ask for."},
    {"limits.chat.default_max_tokens", T::integer, false, 0, 16'384, d::kChatDefaultMaxTokens, false, "", "",
     "max_tokens when a request omits it; 0 = auto: min(max_completion_tokens, context - prompt - 8); at most limits.chat.max_completion_tokens."},
    {"limits.chat.max_generated_bytes", T::integer, false, 1, 16'777'216, d::kChatMaxGeneratedBytes, false, "", "",
     "Largest generated text returned."},
    {"limits.engine.ready_timeout_s", T::integer, false, 1, 86'400, d::kEngineReadyTimeoutS, false, "", "",
     "How long the supervisor waits for the engine's READY after each start; a miss kills and restarts it (upstream STRATA_ENGINE_READY_S)."},
    {"limits.engine.generation_timeout_s", T::integer, false, 1, 86'400, d::kEngineGenerationTimeoutS, false, "", "",
     "Total time for one generation before STOP."},
    {"limits.engine.stop_drain_timeout_s", T::integer, false, 1, 600, d::kEngineStopDrainTimeoutS, false, "", "",
     "Time to drain to DONE after STOP before the engine is marked failed."},
    {"limits.concurrency.max_concurrent_requests", T::integer, false, 1, 256, d::kMaxConcurrentRequests, false, "", "",
     "Worker threads: connections read or answered at once; 1 = serial."},
    {"limits.concurrency.max_queued_generations", T::integer, false, 0, 254, 0, false, "", "",
     "Chats waiting behind the running generation; 0 when max_concurrent_requests is 1, otherwise at most max_concurrent_requests - 2."},
    {"limits.concurrency.queue_timeout_ms", T::integer, false, 1'000, 3'600'000, d::kQueueTimeoutMs, false, "", "",
     "Longest wait for the engine before 503 server_busy."},
    {"limits.concurrency.max_connections_per_remote_address", T::integer, false, 1, 256, 0, false, "", "",
     "Workers one non-loopback address may hold; at most max_concurrent_requests. Loopback is exempt."},
    {"roots.models", T::string, true, 0, 0, 0, false, "", "--models-root",
     "Absolute directory of .gguf files. The root itself may be a symlink; nothing below it may be."},
    {"roots.tokenizer_pack", T::string, false, 0, 0, 0, false, "", "--tokenizer-pack",
     "Absolute tokenizer directory; only with strata-secure-server --expert (a managed model brings its own)."},
    {"roots.secret", T::string, false, 0, 0, 0, false, "", "--secret-root",
     "Absolute directory holding the token file. Default: the config file's directory."},
    {"roots.logs", T::string, false, 0, 0, 0, false, "", "", "Absolute log directory (created 0700; unused in SP1)."},
    {"roots.cache", T::string, false, 0, 0, 0, false, "", "",
     "Absolute cache directory (created 0700); when set, it holds the engine's CUDA cache in its cuda subdirectory."},
    {"roots.state", T::string, false, 0, 0, 0, false, "", "--state-dir",
     "Absolute, existing owner-only directory for engine state: the engine's cwd, per-generation temp and (without roots.cache) the CUDA cache. Required to serve."},
    {"token.source", T::string, false, 0, 0, 0, false, "file:token", "--token-file, --token-env",
     "file:<relative path below roots.secret> or env:<NAME>. Metadata only; the token is never in the config."},
    {"engine.profile", T::string, false, 0, 0, 0, false, "", "--profile",
     "qwen or glm53; only with --expert (a managed model's manifest sets it)."},
    {"engine.executable", T::string, true, 0, 0, 0, false, "", "--engine",
     "Absolute path of the engine; a regular file not writable by group or others."},
    {"engine.model_id", T::string, true, 0, 0, 0, false, "", "--model-id",
     "Default model reference name[:tag] from the model index (or, with --expert, an inventory ID)."},
    {"engine.args", T::string_array, false, 0, 0, 0, false, "", "--engine-arg (repeatable)",
     "Extra engine arguments; frontend-owned and unsupported flags are rejected."},
    {"engine.lib_dirs", T::string_array, false, 0, 0, 0, false, "", "--engine-lib-dir (repeatable)",
     "Absolute library directories for the engine (default: the engine executable's directory)."},
    {"engine.gpu", T::string, false, 0, 0, 0, false, "", "--gpu",
     "GPU device indices for the engine, e.g. 0 or 0,1 (distinct, 0-255, at most 16); rendered as the engine's --gpu argument (strata family: no GPU variable). Not supported with engine.profile glm53."},
    {"engine.allow_new_privileges", T::boolean, false, 0, 0, 0, false, "", "--allow-new-privileges",
     "Linux: do not set PR_SET_NO_NEW_PRIVS on the engine (default: set). Only for hosts whose NVIDIA driver must run setuid nvidia-modprobe to create /dev/nvidia-uvm on first use."},
    {"pull.downloader", T::string, false, 0, 0, 0, false, "", "",
     "Absolute path of curl for pull/update. Default /usr/bin/curl (Windows: System32\\curl.exe). Validated when a "
     "transfer or doctor --downloader runs, never at serve start."},
    {"pull.proxy", T::string, false, 0, 0, 0, false, "", "",
     "http://host:port or https://host:port; absent = --noproxy *. No credentials. Environment proxies are never read."},
    {"pull.allow_private_addresses", T::boolean, false, 0, 0, 0, false, "", "",
     "Allow sources that resolve to private or special-use addresses."},
    {"pull.max_total_bytes", T::integer, false, 1048576, 17592186044416, 1099511627776, false, "", "",
     "Largest manifest total a pull accepts (bytes)."},
    {"pull.max_duration_s", T::integer, false, 60, 604800, 172800, false, "", "", "Time budget for a whole pull run."},
    {"pull.stall_timeout_s", T::integer, false, 10, 3600, 120, false, "", "", "Abort a transfer slower than 1024 B/s for this long."},
    {"pull.connect_timeout_s", T::integer, false, 1, 300, 30, false, "", "", "TCP/TLS connect timeout per request."},
    {"logging.requests", T::boolean, false, 0, 0, 0, false, "", "",
     "One line per request to stderr: route, status, code, time, bytes, loopback or remote; never paths, headers, tokens or text."},
    // SP5 M1 Task 4 (parity row `sampling`): bounds copied from the pin —
    // clean_shared_defaults (serve/server.py:7331-7367) and the wire conditions
    // (serve/server.py:1360-1394). Unset rows are never sent. The 2.0 caps,
    // the 8192 window cap and the 32-bit seed cap are added security bounds (C-1).
    {"defaults.sampling.temperature", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default temperature (pin: 0..2); unset keeps the engine default.", 0.0, 2.0, kUnsetDecimal, false},
    {"defaults.sampling.top_p", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default top_p (pin: 0 < top_p <= 1); unset keeps the engine default.", 0.0, 1.0, kUnsetDecimal, true},
    {"defaults.sampling.top_k", T::integer, false, 1, 64, -1, false, "", "",
     "Request default top_k candidates (pin: an integer 1..64); unset keeps the engine default.", 0.0, 0.0, kUnsetDecimal, false},
    {"defaults.sampling.min_p", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default min_p (pin wire: only 0 < min_p <= 1 is sent; 0 stays off).", 0.0, 1.0, kUnsetDecimal, false},
    {"defaults.sampling.presence_penalty", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default presence penalty (0 off; cap 2 added, C-1).", 0.0, 2.0, kUnsetDecimal, false},
    {"defaults.sampling.repetition_penalty", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default repetition penalty (pin wire: only != 1.0 is sent; cap 2 added, C-1).", 0.0, 2.0, kUnsetDecimal, true},
    {"defaults.sampling.frequency_penalty", T::decimal, false, 0, 0, 0, false, "", "",
     "Request default frequency penalty (0 off; cap 2 added, C-1).", 0.0, 2.0, kUnsetDecimal, false},
    {"defaults.sampling.penalty_last_n", T::integer, false, 0, 8192, -1, false, "", "",
     "Penalty window; unset means the pin default of 64 when any penalty is on (cap added, C-1).", 0.0, 0.0, kUnsetDecimal, false},
    {"defaults.sampling.seed", T::integer, false, 1, 4294967295, -1, false, "", "",
     "Request default sampling seed (pin: a positive integer; 32-bit cap added, C-1).", 0.0, 0.0, kUnsetDecimal, false},
    // SP5 M1 Task 5 (parity rows reasoning_* / fit_max_tokens): kinds and defaults copied from the
    // pin — effort clean_shared_defaults serve/server.py:7341-7343; budget_tokens :8120-8127 and
    // reasoning_budget :3794-3807 (a whole number, 0 = no budget; the 0..4294967295 bounds are ADDED
    // security bounds, C-1); close_retry :8015; loop_recovery :8129-8136 (the pin also takes bools,
    // the typed row names the three words); effort_position :2841-2843; anthropic_thinking
    // :8102-8104; fit_max_tokens :3485-3488 read at :7996 (false answers 400 over the room, :4536).
    {"reasoning.effort", T::string, false, 0, 0, 0, false, "", "",
     "Thinking level for requests that name none: none, low, medium or high (pin levels); unset names none."},
    {"reasoning.budget_tokens", T::integer, false, 0, 4294967295, 0, false, "", "",
     "Default thinking budget in tokens (0 = none, the pin default); bounds added, C-1."},
    {"reasoning.close_retry", T::boolean, false, 0, 0, 0, false, "", "",
     "Close an unfinished thinking block once when the reply ends inside it (pin opt-in, off)."},
    {"reasoning.loop_recovery", T::string, false, 0, 0, 0, false, "off", "",
     "A reasoning loop ends the reply (off, the pin default), stops (stop) or continues once (recover)."},
    {"reasoning.effort_position", T::string, false, 0, 0, 0, false, "start", "",
     "Where a non-default effort sits in the prompt: start (the pin default) or end; end adds the engine's --tail-role-token."},
    {"reasoning.anthropic_thinking", T::string, false, 0, 0, 0, false, "model", "",
     "Thinking default for /v1/messages-shaped clients: model (the pin default) or on_request."},
    {"engine.fit_max_tokens", T::boolean, false, 0, 0, 0, true, "", "",
     "Fit an over-room max_tokens to the context room (true, the pin default); false answers the §7.2 400 instead."},
    // SP5 M1 Task 6 (parity rows lazy_load / idle_unload_s / mtp): runconfig.py:38 "Start
    // without loading the model; the first request loads it (text only)"; :35 "0 or empty:
    // never" (whole seconds; the 86400 cap is ADDED, C-1); :36 + strata_control/
    // draft_layer.py is_off: the draft layer is on unless an explicit false.
    {"engine.lazy_load", T::boolean, false, 0, 0, 0, false, "", "",
     "Start with the engine unloaded; the first request loads it (the pin's lazy_load, text only)."},
    {"engine.idle_unload_s", T::integer, false, 0, 86400, 0, false, "", "",
     "Seconds without a request before the engine is unloaded (0: never, the pin default); cap added, C-1."},
    {"engine.mtp", T::boolean, false, 0, 0, 0, true, "", "",
     "Draft layer (MTP): on unless explicitly false; false drops --mtp/--spec-min-p/--batch-mtp at every start."},
    // SP5 M1 Task 7 (the VRAM / GPU / elastic family). Kinds and defaults verbatim from the
    // pin; caps and closed vocabularies added (C-1). vram_reserve_mib: runconfig.py:42-43
    // renders --vram-reserve-mib (engine default 700, unset composes nothing). min_free_vram_mib:
    // int-or 0 svc-side gate (serve/server.py:8083-8084). vram_elastic/vram_segment_mib:
    // #533 (:2943-2948, engine segment default 512). elastic/elastic_mib/elastic_idle_s:
    // the vision turn (server.py:2548-2552, defaults 2048 MiB / 120 s; Task 11 consumes them).
    // gpu_order: only "as_given" is read (:3105-3112). gpu_policy: images.py POLICIES
    // (:45, :173-175). layer_split: "auto" or rising first-layer numbers (:2870-2894).
    // split_skip_if_fits: :2940-2942. hip_ordinal: :3016-3030. uma: images.py:23/:334.
    {"engine.vram_reserve_mib", T::integer, false, 0, 1048576, -1, false, "", "",
     "VRAM MiB the engine leaves free (renders --vram-reserve-mib; unset: the engine's own 700)."},
    {"engine.min_free_vram_mib", T::integer, false, 0, 1048576, 0, false, "", "",
     "Refuse to load when free VRAM is below this (0: never; the driver check runs on the owner's GPU box)."},
    {"engine.vram_elastic", T::boolean, false, 0, 0, 0, false, "", "",
     "Segment the expert cache so VRAM can be given back and taken back (renders --vram-elastic, #533)."},
    {"engine.vram_segment_mib", T::integer, false, 1, 1048576, -1, false, "", "",
     "Segment size for vram_elastic (renders --vram-segment-mib; unset: the engine's own 512)."},
    {"engine.elastic", T::boolean, false, 0, 0, 0, false, "", "",
     "The image encoder starts with the first picture and stops when idle (needs vram_elastic; the vision turn)."},
    {"engine.elastic_idle_s", T::integer, false, 1, 86400, 120, false, "", "",
     "Seconds without a picture before the elastic encoder stops (pin default 120); whole seconds, cap added."},
    {"engine.elastic_mib", T::integer, false, 1, 1048576, 2048, false, "", "",
     "VRAM MiB the expert cache keeps free while the encoder runs (pin default 2048)."},
    {"engine.gpu_order", T::string, false, 0, 0, 0, false, "auto", "",
     "GPU order: auto (reorder by card speed, where the driver can tell) or as_given (keep the configured order)."},
    {"engine.gpu_policy", T::string, false, 0, 0, 0, false, "auto", "",
     "GPU turn for a picture: auto, keep, shrink or unload the engine's VRAM first (the POLICIES set)."},
    {"engine.layer_split", T::string, false, 0, 0, 0, false, "auto", "",
     "First layer of each later GPU (rising numbers from 2), or auto; renders --layer-split with several GPUs."},
    {"engine.split_skip_if_fits", T::boolean, false, 0, 0, 0, false, "", "",
     "Let an auto split run on the first card alone when it holds every expert and the KV (renders --split-skip-if-fits)."},
    {"engine.hip_ordinal", T::integer, false, 0, 127, -1, false, "", "",
     "The HIP number of the discrete card (setup-recorded); wins over one (or zero) configured GPUs."},
    {"engine.uma", T::boolean, false, 0, 0, 0, false, "", "",
     "An APU: engine and image turn share the RAM either way, so a picture never needs the engine moved."},
    // SP5 M1 Task 8 (the timeout / queue / request-shape family). engine_silence_s:
    // runconfig.py:39 "num>=0 ... default 300 s, 0 = wait" (cap added, C-1); the watchdog
    // is serve/server.py:274-276/:2861-2868. answer_room: :3490/:8014 `is not False`
    // (default true). repeat_stop_tokens: :8115-8118 whole number >= 0, default
    // REPEAT_STOP_TOKENS=256 (:197; 0 = off; cap added, C-1). max/min tokens: the pin's
    // keys bound the vision encoder (:2564-2567); the typed rows re-scope to request
    // output bounds (added, C-1; Ruling T8-e). model.aliases: runconfig.py:34 +
    // set_aliases :3764-3777.
    {"engine.silence_s", T::integer, false, 0, 86400, 300, false, "", "",
     "End a request when the engine says nothing valid for this long (pin default 300 s; 0: wait, still bounded by the total generation timeout)."},
    {"engine.answer_room", T::boolean, false, 0, 0, 0, true, "", "",
     "Close a long un-budgeted thinking reply early enough to leave the answer room (true, the pin default)."},
    {"engine.repeat_stop_tokens", T::integer, false, 0, 65536, 256, false, "", "",
     "One token this many times in a row ends a reply as length (pin default 256; 0: off). Cap added, C-1."},
    {"engine.max_tokens", T::integer, false, 1, 1048576, -1, false, "", "",
     "Ceiling on a request's output budget (unset: the completion cap; an added frontend bound, C-1)."},
    {"engine.min_tokens", T::integer, false, 1, 1048576, -1, false, "", "",
     "Floor on a request's output budget (unset: none; an added frontend bound, C-1)."},
    {"model.aliases", T::string_array, false, 0, 0, 0, false, "", "",
     "Other model names the server lists and answers to (exact match only, like the pin's set_aliases)."},
    // SP5 M1 Task 9 (the session family). slot_save_path: the pin's /slots file directory
    // (:8092-8100 + slot_save_dir :3469-3481) — typed with our absolute rule; the route
    // itself is not in our spec (Rulings T9-a/b). expert_profile_save / -every: the pin
    // appends both engine flags when the path is set (:3000-3005; docstring default 10
    // minutes, 0 = at QUIT only, :2996; added cap C-1). The four booleans are the pin's
    // opt-in falses (:8043-:8044 `is True`, :8106/:8110 strict bool) whose pin-side
    // consumers (OutputParser recovery, frontend._env_to_user, the Codex routes) we do not
    // serve (config_only). keep_files: the pin's ImageService scratch retention
    // (images.py:188 `or 64`); typed with added bounds, D-9 keeps image generation out.
    {"session.slot_save_path", T::string, false, 0, 0, 0, false, "", "",
     "Directory for engine slot session save/restore files (absolute; the /slots route is not served today)."},
    {"session.expert_profile_save", T::string, false, 0, 0, 0, false, "", "",
     "Where the engine re-saves its learned expert profile (absolute path; --expert-profile-save)."},
    {"session.expert_profile_save_every", T::integer, false, 0, 1440, 10, false, "", "",
     "Re-save the learned expert profile every N minutes (pin default 10; 0: at engine exit only). Cap added, C-1."},
    {"session.tool_call_recovery", T::boolean, false, 0, 0, 0, false, "", "",
     "Attempt to recover malformed tool-call output (the pin's opt-in; stored for parity today)."},
    {"session.env_to_user", T::boolean, false, 0, 0, 0, false, "", "",
     "Pass configured environment hints to the user prompt path (the pin's opt-in; stored for parity today)."},
    {"session.codex_thread_titles", T::boolean, false, 0, 0, 0, false, "", "",
     "Codex thread titles (#923; the pin's opt-in; the route is not served here)."},
    {"session.codex_compaction_cache", T::boolean, false, 0, 0, 0, false, "", "",
     "Codex compaction cache (#924; the pin's opt-in; the route is not served here)."},
    {"session.keep_files", T::integer, false, 1, 1024, 64, false, "", "",
     "How many image-scratch files to retain (pin default 64; bounds added, C-1; the consumer is out per D-9)."},
    // SP5 M1 Task 10 (the C-4 narrowing): engine-internal parallelism only — the pin renders
    // this as --batch N (serve/server.py:2975); 2..8 is the engine's batch window
    // (PARALLEL_MAX :2954) and larger values ride on for the engine to adjust (:2969-2974).
    // The cap 1024 is added (C-1), taken from the pin's own --parallel bound (:7845).
    {"replicas.parallel", T::integer, false, 1, 1024, 1, false, "", "",
     "Decode up to N requests together inside the one engine (1: one at a time; the N-child scheduler is not implemented)."},
    // SP5 M1 Task 11 (D-9 vision split): image INPUT is typed and plumbed, generation stays
    // out. Defaults at the pin — max_side/max_n carry the images-block values (images.py:102-
    // 103 `or 2048`/`or 4`; caps added, C-1); need_mib overrides the pin's VRAM arithmetic
    // (images.py:156; the driver gate itself is owner-box, cf. T7-c); no_flash_attn rides the
    // spec §5.1 family (not read by this pin — the kit proves the child flag); resident is
    // the pin's eager encoder (server.py:2511/:2552; false: the first image wakes it);
    // threads 0 = the pin's unset (truthy -> --threads, server.py:2562).
    {"vision.enabled", T::boolean, false, 0, 0, 0, false, "", "",
     "Read images: a supervised strata-vision child encodes image_url parts for the engine."},
    {"vision.max_side", T::integer, false, 1, 16384, 2048, false, "", "",
     "Largest image side accepted before decoding (pin default 2048; cap added, C-1)."},
    {"vision.max_n", T::integer, false, 1, 64, 4, false, "", "",
     "Most images one request may carry (pin default 4; cap added, C-1)."},
    {"vision.need_mib", T::integer, false, 1, 1048576, -1, false, "", "",
     "Override the free-VRAM figure the encoder is checked against (unset: computed; bounds added, C-1)."},
    {"vision.no_flash_attn", T::boolean, false, 0, 0, 0, false, "", "",
     "Run the encoder without flash attention (added, spec §5.1; the encoder's --no-flash-attn)."},
    {"vision.resident", T::boolean, false, 0, 0, 0, true, "", "",
     "Keep the encoder running from boot (the pin's eager resident encoder; false: the first image starts it)."},
    {"vision.threads", T::integer, false, 0, 256, 0, false, "", "",
     "Encoder CPU threads (0: the tool's own default; cap added, C-1)."},
    // The STRATA_VISION_READY_S counterpart the Task-2 parity row promises (its gate
    // default 300 s, server.py:327; 0 = wait for ever, :291 — the shape engine.silence_s
    // took in Task 8; bound added, C-1).
    {"vision.ready_timeout_s", T::integer, false, 0, 86400, 300, false, "", "",
     "Seconds the encoder gets to print READY (0: wait for ever, as at the pin)."},
    // The STRATA_VISION_ENCODE_S counterpart promised by the Task-2 parity row
    // (gate default 300 s, server.py:328; 0 = wait for ever, :291; bound added, C-1).
    {"vision.encode_timeout_s", T::integer, false, 0, 86400, 300, false, "", "",
     "Seconds one image encoding may take (0: wait for ever, as at the pin)."},
    // SP5 M2 Task 3 (spec §D-2; C-3 keeps Maya's names): the engine-side GLM
    // knobs. Kinds and defaults are Maya v1.1.8's verbatim (parity table rows
    // cite the vendored pin); the caps and closed sets are added (C-1). The
    // rows are accepted while engine.profile is absent (a managed model's
    // SP4 manifest decides the profile; the launch, Task 7, refuses them for
    // a qwen manifest) and refused by name when engine.profile is "qwen".
    {"glm.thinking_budget", T::integer, false, 0, 1000000000, 32768, false, "", "",
     "Thinking-token budget when a request names none (Maya's default 32768; 0 disables the budget)."},
    {"glm.reasoning_effort", T::string, false, 0, 0, 0, false, "", "",
     "Thinking level when a request names none: none, low, high or max (Maya's canonical levels; Maya's aliases such as \"medium\" are not accepted here)."},
    {"glm.fit_max_tokens", T::boolean, false, 0, 0, 0, false, "", "",
     "Fit a request's output budget to the context room on the GLM side (Maya's default: false)."},
    {"glm.experimental_speed_projection", T::boolean, false, 0, 0, 0, false, "", "",
     "GLM speed projection (Maya's default: false)."},
    {"glm.gpu", T::string, false, 0, 0, 0, false, "", "",
     "GPU device indices for the GLM engine, e.g. 0 or 0,1 (distinct, 0-255, at most 16)."},
    {"glm.layer_split", T::string, false, 0, 0, 0, false, "auto", "",
     "First layer of each later GPU's share (rising numbers, e.g. 18 or 16,32), or auto; the GLM engine's --layer-split."},
    {"glm.tokenizer", T::string, false, 0, 0, 0, false, "", "",
     "Absolute tokenizer-pack path for the GLM engine (default: the pack named by the model)."},
    {"glm.model_name", T::string, false, 0, 0, 0, false, "", "",
     "Served model id for the GLM engine (1-256 characters; a managed model takes its identity from the manifest)."},
}};

void add(ConfigErrors& errors, std::string key, const ConfigIssueCode code, std::string reason) {
  errors.push_back(ConfigIssue{std::move(key), code, std::move(reason)});
}

// Reads one key with its schema type, range and default; records issues.
class DraftReader final {
 public:
  DraftReader(const FrontendConfigDraft& draft, ConfigErrors& errors) : draft_(draft), errors_(errors) {}

  std::int64_t integer(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) return key.default_integer;
    const auto* value = std::get_if<std::int64_t>(&entry->value);
    if (value == nullptr) return wrong_type(key), key.default_integer;
    if (*value < key.minimum || *value > key.maximum) {
      add(errors_, std::string{path}, ConfigIssueCode::out_of_range,
          "must be between " + std::to_string(key.minimum) + " and " + std::to_string(key.maximum));
      return key.default_integer;
    }
    return *value;
  }
  bool boolean(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) return key.default_boolean;
    const auto* value = std::get_if<bool>(&entry->value);
    if (value == nullptr) return wrong_type(key), key.default_boolean;
    return *value;
  }
  std::optional<std::string> string(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) {
      if (key.default_string.empty()) return std::nullopt;
      return std::string{key.default_string};
    }
    const auto* value = std::get_if<std::string>(&entry->value);
    if (value == nullptr) return wrong_type(key), std::nullopt;
    return *value;
  }
  std::vector<std::string> strings(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) return {};
    const auto* value = std::get_if<std::vector<std::string>>(&entry->value);
    if (value == nullptr) return wrong_type(key), std::vector<std::string>{};
    return *value;
  }
  // SP5 M1 Task 4: an optional integer row (default_integer outside the range
  // = unset); range-checked when present.
  std::optional<std::int64_t> optional_integer(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) return std::nullopt;
    const auto* value = std::get_if<std::int64_t>(&entry->value);
    if (value == nullptr) return wrong_type(key), std::nullopt;
    if (*value < key.minimum || *value > key.maximum) {
      add(errors_, std::string{path}, ConfigIssueCode::out_of_range,
          "must be between " + std::to_string(key.minimum) + " and " + std::to_string(key.maximum));
      return std::nullopt;
    }
    return *value;
  }
  // SP5 M1 Task 4: a decimal row; integers are accepted (JSON "1" is a valid
  // number); the NaN default means "unset".
  std::optional<double> decimal(const std::string_view path) {
    const ConfigKey& key = *find_config_key(path);
    const auto* entry = lookup(key);
    if (entry == nullptr) {
      if (std::isnan(key.default_decimal)) return std::nullopt;
      return key.default_decimal;
    }
    double value = 0.0;
    if (const auto* i = std::get_if<std::int64_t>(&entry->value)) value = static_cast<double>(*i);
    else if (const auto* dp = std::get_if<double>(&entry->value)) value = *dp;
    else return wrong_type(key), std::nullopt;
    if (value < key.minimum_decimal || value > key.maximum_decimal ||
        (key.minimum_exclusive && value == key.minimum_decimal)) {
      add(errors_, std::string{path}, ConfigIssueCode::out_of_range,
          (key.minimum_exclusive ? "must be greater than " : "must be at least ") + decimal_text(key.minimum_decimal) +
          (key.minimum_exclusive ? " and at most " : " and at most ") + decimal_text(key.maximum_decimal));
      return std::nullopt;
    }
    return value;
  }
  bool present(const std::string_view path) const { return draft_.entries.find(path) != draft_.entries.end(); }

 private:
  const ConfigDraftEntry* lookup(const ConfigKey& key) {
    const auto it = draft_.entries.find(key.path);
    if (it != draft_.entries.end()) return &it->second;
    if (key.required) add(errors_, std::string{key.path}, ConfigIssueCode::missing_required, "is required");
    return nullptr;
  }
  void wrong_type(const ConfigKey& key) {
    add(errors_, std::string{key.path}, ConfigIssueCode::wrong_type, std::string{type_reason(key.type)});
  }
  const FrontendConfigDraft& draft_;
  ConfigErrors& errors_;
};

std::optional<CanonicalRoot> canonical_root(DraftReader& read, ConfigErrors& errors, const std::string_view path) {
  const auto text = read.string(path);
  if (!text.has_value()) return std::nullopt;
  auto opened = open_root(path_from_utf8(*text));
  if (auto* error = std::get_if<PathError>(&opened)) {
    add(errors, std::string{path}, ConfigIssueCode::invalid_value, error->message);
    return std::nullopt;
  }
  return std::get<CanonicalRoot>(std::move(opened));
}

// roots.logs / roots.cache: checked, never created, during validation.
std::optional<std::filesystem::path> creatable_root(DraftReader& read, ConfigErrors& errors, const std::string_view path) {
  const auto text = read.string(path);
  if (!text.has_value()) return std::nullopt;
  auto checked = check_creatable_root(path_from_utf8(*text));
  if (auto* error = std::get_if<PathError>(&checked)) {
    add(errors, std::string{path}, ConfigIssueCode::invalid_value, error->message);
    return std::nullopt;
  }
  return std::get<std::filesystem::path>(std::move(checked));
}

// roots.state: absolute, non-empty, no NUL. No filesystem access here, so
// --check stays side-effect free; serve checks it is an existing owner-only
// directory before anything is spawned.
std::optional<std::filesystem::path> absolute_path(DraftReader& read, ConfigErrors& errors, const std::string_view path) {
  const auto text = read.string(path);
  if (!text.has_value()) return std::nullopt;
  if (text->empty() || text->find('\0') != std::string::npos || !path_from_utf8(*text).is_absolute()) {
    add(errors, std::string{path}, ConfigIssueCode::invalid_value, "must be an absolute directory");
    return std::nullopt;
  }
  return path_from_utf8(*text);
}

std::optional<SecretSource> token_source(const std::string& text) {
  if (text.rfind("env:", 0) == 0) {
    auto result = make_environment_secret_source(std::string_view{text}.substr(4));
    if (auto* source = std::get_if<SecretSource>(&result)) return std::move(*source);
    return std::nullopt;
  }
  if (text.rfind("file:", 0) == 0) {
    auto result = make_protected_file_secret_source(std::string_view{text}.substr(5));
    if (auto* source = std::get_if<SecretSource>(&result)) return std::move(*source);
  }
  return std::nullopt;
}

std::string json_quoted(const std::string_view text) {
  std::string out;
  append_json_string(&out, text);
  return out;
}

}  // namespace

std::filesystem::path default_downloader_path() {
#if defined(_WIN32)
  // Pre-flight F-32: a failure or a directory longer than the buffer never
  // yields the relative "curl.exe"; the buffer grows to the reported size once.
  std::wstring system(MAX_PATH, L'\0');
  for (int attempt = 0; attempt < 2; ++attempt) {
    const UINT length = GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
    if (length == 0) return {};
    if (length < system.size()) {
      system.resize(length);
      const std::filesystem::path directory(system);
      if (!directory.is_absolute()) return {};
      return directory / L"curl.exe";
    }
    system.assign(length, L'\0');  // length includes the terminator when the buffer was too small
  }
  return {};
#else
  return std::filesystem::path{"/usr/bin/curl"};
#endif
}

std::span<const ConfigKey> config_schema() noexcept { return kSchema; }

const ConfigKey* find_config_key(const std::string_view path) noexcept {
  for (const auto& key : kSchema) if (key.path == path) return &key;
  return nullptr;
}

namespace {

// SP5 M1 Task 8 (parity row aliases): the entry grammar is SP1's one model-ID grammar
// (validate_model_id) with an added 64-character cap (C-1); aliases join /v1/models and
// must stay inside the JSON model-field bounds. set_aliases (:3764-3777) drops empties
// and duplicates at use; the typed row rejects an empty entry outright.
bool is_valid_model_alias(const std::string_view value) noexcept {
  return !value.empty() && value.size() <= 64U && std::holds_alternative<std::string>(validate_model_id(value));
}

// SP5 M1 Task 9 (Ruling T9-b): the pin's slot_save_dir shape — non-empty, no control
// characters (serve/server.py:3472-3475) — plus our added absolute rule (C-1, like
// engine.lib_dirs): there is no config-cwd to resolve a relative path against, and
// validation never touches the filesystem.
bool is_absolute_store_path(const std::string& text) noexcept {
  return !text.empty() && text.find('\0') == std::string::npos &&
         std::none_of(text.begin(), text.end(), [](const char c) {
           return static_cast<unsigned char>(c) < 0x20U || c == 0x7f;
         }) &&
         path_from_utf8(text).is_absolute();
}

constexpr std::array<ConfigKeyExtension, 5> kSchemaExtensions{{
    {"listener.cors_origins", static_cast<std::size_t>(config_defaults::kMaxListEntries), &is_valid_cors_origin,
     "each entry must be http:// or https://, a lower-case host, an optional port and no path; * and null are not allowed", ""},
    {"listener.host_aliases", static_cast<std::size_t>(config_defaults::kMaxListEntries), &is_valid_host_alias,
     "each entry must be a host or host:port", ""},
    // SP5 M1 Task 8 (parity row aliases): the entry grammar is SP1's one model-ID grammar
    // (validate_model_id) with an added 64-character cap (C-1). set_aliases (:3764-3777)
    // strips and drops empties and duplicates at use; the typed row rejects outright.
    {"model.aliases", static_cast<std::size_t>(config_defaults::kMaxListEntries), &is_valid_model_alias,
     "each entry must be a model name: ASCII letters, digits, dot, underscore or hyphen, at most 64 characters", ""},
    {"limits.concurrency.max_queued_generations", 0U, nullptr, "", "derived: min(4, max(0, workers-2))"},
    {"limits.concurrency.max_connections_per_remote_address", 0U, nullptr, "", "derived: min(4, workers)"},
}};

// Reads a string-array row and applies its SP3 bounds; any failure records one
// fixed issue naming the key and yields an empty list.
std::vector<std::string> read_bounded_strings(DraftReader& read, ConfigErrors& errors, const std::string_view path) {
  std::vector<std::string> values = read.strings(path);
  const ConfigKeyExtension* extension = find_config_key_extension(path);
  if (extension == nullptr) return values;
  if (extension->max_entries != 0U && values.size() > extension->max_entries) {
    add(errors, std::string{path}, ConfigIssueCode::out_of_range,
        "must have at most " + std::to_string(extension->max_entries) + " entries");
    return {};
  }
  std::set<std::string> seen;
  for (const auto& value : values) {
    if (extension->entry_valid != nullptr && !extension->entry_valid(value)) {
      add(errors, std::string{path}, ConfigIssueCode::invalid_value, std::string{extension->entry_reason});
      return {};
    }
    if (!seen.insert(value).second) {
      add(errors, std::string{path}, ConfigIssueCode::invalid_value, "must not repeat an entry");
      return {};
    }
  }
  return values;
}

bool has_issue_for(const ConfigErrors& errors, const std::string_view path) {
  return std::any_of(errors.begin(), errors.end(), [path](const ConfigIssue& issue) { return issue.key_path == path; });
}
}  // namespace

const ConfigKeyExtension* find_config_key_extension(const std::string_view path) noexcept {
  for (const auto& extension : kSchemaExtensions) if (extension.path == path) return &extension;
  return nullptr;
}

std::uint32_t derived_max_queued_generations(const std::uint32_t workers) noexcept {
  const std::uint32_t spare = workers > 2U ? workers - 2U : 0U;
  return std::min<std::uint32_t>(static_cast<std::uint32_t>(config_defaults::kDerivedQueueCap), spare);
}

std::uint32_t derived_max_connections_per_remote_address(const std::uint32_t workers) noexcept {
  return std::min<std::uint32_t>(static_cast<std::uint32_t>(config_defaults::kDerivedRemoteCap), workers);
}

bool is_config_section(const std::string_view path) noexcept {
  return std::any_of(kSchema.begin(), kSchema.end(), [path](const ConfigKey& key) {
    return key.path.size() > path.size() && key.path.substr(0, path.size()) == path && key.path[path.size()] == '.';
  });
}

std::string_view type_reason(const ConfigValueType type) noexcept {
  switch (type) {
    case ConfigValueType::boolean: return "must be true or false";
    case ConfigValueType::integer: return "must be an integer";
    case ConfigValueType::string: return "must be a string";
    case ConfigValueType::string_array: return "must be an array of strings";
    case ConfigValueType::decimal: return "must be a number";
  }
  return "has the wrong type";
}

std::string render_config_schema_markdown() {
  std::string out = "| Key | Type | Default | Range | Option | Meaning |\n| --- | --- | --- | --- | --- | --- |\n";
  for (const auto& key : kSchema) {
    std::string type;
    std::string fallback;
    std::string range = "-";
    switch (key.type) {
      case ConfigValueType::boolean:
        type = "boolean";
        fallback = key.default_boolean ? "`true`" : "`false`";
        break;
      case ConfigValueType::integer:
        type = "integer";
        fallback = (key.default_integer < key.minimum || key.default_integer > key.maximum)
                       ? "unset"
                       : "`" + std::to_string(key.default_integer) + "`";
        if (const auto* ext = find_config_key_extension(key.path); ext != nullptr && !ext->derived_default.empty()) {
          fallback = "`" + std::string{ext->derived_default} + "`";
        }
        range = std::to_string(key.minimum) + "-" + std::to_string(key.maximum);
        break;
      case ConfigValueType::string:
        type = "string";
        fallback = !key.default_string.empty() ? "`" + std::string{key.default_string} + "`"
                   : key.required             ? "required"
                                              : "unset";
        break;
      case ConfigValueType::string_array:
        type = "string array";
        fallback = "`[]`";
        break;
      case ConfigValueType::decimal:
        type = "number";
        fallback = std::isnan(key.default_decimal) ? "unset" : "`" + decimal_text(key.default_decimal) + "`";
        range = (key.minimum_exclusive ? ">" : "") + decimal_text(key.minimum_decimal) + "-" +
                decimal_text(key.maximum_decimal);
        break;
    }
    const std::string option = key.flag.empty() ? "-" : "`" + std::string{key.flag} + "`";
    out += "| `" + std::string{key.path} + "` | " + type + " | " + fallback + " | " + range + " | " + option + " | " +
           std::string{key.description} + " |\n";
  }
  return out;
}

std::string format_issue(const ConfigIssue& issue) { return issue.key_path + ": " + issue.reason; }

std::optional<ModelId> make_model_id(const std::string_view text) {
  const auto colon = text.find(':');
  const auto name = text.substr(0, colon);
  const bool ok = std::holds_alternative<std::string>(validate_model_id(name)) &&
                  (colon == std::string_view::npos ||
                   std::holds_alternative<std::string>(validate_model_id(text.substr(colon + 1))));
  if (!ok) return std::nullopt;
  return ModelId{std::string{text}};
}

ConfigValidationResult validate(const FrontendConfigDraft& draft) {
  ConfigErrors errors;
  for (const auto& [path, entry] : draft.entries) {
    if (find_config_key(path) == nullptr) add(errors, path, ConfigIssueCode::unknown_key, "unknown key");
  }
  DraftReader read(draft, errors);
  if (draft.config_directory.has_value() && !read.present("schema_version")) {
    add(errors, "schema_version", ConfigIssueCode::missing_required, "is required in a config file");
  }
  (void)read.integer("schema_version");

  // listener
  const std::string host_text = read.string("listener.host").value_or("127.0.0.1");
  const auto port = read.integer("listener.port");
  const bool allow_remote = read.boolean("listener.allow_remote");
  const bool allow_wildcard = read.boolean("listener.allow_wildcard_bind");
  const auto backlog = read.integer("listener.backlog");
  const auto host = parse_listener_address(host_text);
  if (!host.has_value()) {
    add(errors, "listener.host", ConfigIssueCode::invalid_value,
        "must be an IP literal or localhost; hostnames are never resolved");
  } else if (host->scope() != AddressScope::loopback && !allow_remote) {
    add(errors, "listener.host", ConfigIssueCode::remote_not_enabled,
        "a non-loopback address needs listener.allow_remote (--allow-remote)");
  } else if (host->scope() == AddressScope::wildcard && !allow_wildcard) {
    add(errors, "listener.host", ConfigIssueCode::wildcard_bind_not_enabled,
        "a wildcard address also needs listener.allow_wildcard_bind (--allow-wildcard-bind)");
  }
  // SP3 §4.3/§4.4: a wildcard bind trusts only the configured Host aliases.
  std::vector<std::string> cors_origins = read_bounded_strings(read, errors, "listener.cors_origins");
  std::vector<std::string> host_aliases = read_bounded_strings(read, errors, "listener.host_aliases");
  if (host.has_value() && host->scope() == AddressScope::wildcard && host_aliases.empty() &&
      !has_issue_for(errors, "listener.host_aliases")) {
    add(errors, "listener.host_aliases", ConfigIssueCode::invalid_value,
        "must name at least one Host value when the bind is a wildcard");
  }

  // limits
  const auto deadline_ms = read.integer("limits.http.request_deadline_ms");
  const auto max_request = read.integer("limits.http.max_request_bytes");
  const auto max_header = read.integer("limits.http.max_header_bytes");
  const auto max_headers = read.integer("limits.http.max_headers");
  const auto max_line = read.integer("limits.http.max_request_line_bytes");
  const auto header_deadline_ms = read.integer("limits.http.header_deadline_ms");
  const auto write_stall_ms = read.integer("limits.http.write_stall_ms");
  const auto response_deadline_ms = read.integer("limits.http.response_write_deadline_ms");
  const auto keepalive_ms = read.integer("limits.http.stream_keepalive_ms");
  const bool log_requests = read.boolean("logging.requests");
  // SP5 M1 Task 4: defaults.sampling.* (unset rows stay unset).
  SamplingDefaults sampling_defaults{
      read.decimal("defaults.sampling.temperature"), read.decimal("defaults.sampling.top_p"),
      read.decimal("defaults.sampling.min_p"), read.decimal("defaults.sampling.presence_penalty"),
      read.decimal("defaults.sampling.repetition_penalty"), read.decimal("defaults.sampling.frequency_penalty"),
      read.optional_integer("defaults.sampling.top_k"), read.optional_integer("defaults.sampling.penalty_last_n"),
      read.optional_integer("defaults.sampling.seed")};
  // SP5 M1 Task 5: reasoning.* (pin vocabularies; the string rows carry the pin's defaults).
  ReasoningConfig reasoning;
  if (const auto text = read.string("reasoning.effort")) {
    if (*text == "none") reasoning.effort = ReasoningEffort::none;
    else if (*text == "low") reasoning.effort = ReasoningEffort::low;
    else if (*text == "medium") reasoning.effort = ReasoningEffort::medium;
    else if (*text == "high") reasoning.effort = ReasoningEffort::high;
    else add(errors, "reasoning.effort", ConfigIssueCode::invalid_value, "must be none, low, medium or high");
  }
  reasoning.budget_tokens = read.integer("reasoning.budget_tokens");
  reasoning.close_retry = read.boolean("reasoning.close_retry");
  if (const auto text = read.string("reasoning.loop_recovery")) {
    if (*text == "off") reasoning.loop_recovery = LoopRecovery::off;
    else if (*text == "stop") reasoning.loop_recovery = LoopRecovery::stop;
    else if (*text == "recover") reasoning.loop_recovery = LoopRecovery::recover;
    else add(errors, "reasoning.loop_recovery", ConfigIssueCode::invalid_value, "must be off, stop or recover");
  }
  if (const auto text = read.string("reasoning.effort_position")) {
    if (*text == "start") reasoning.effort_position = EffortPosition::start;
    else if (*text == "end") reasoning.effort_position = EffortPosition::end;
    else add(errors, "reasoning.effort_position", ConfigIssueCode::invalid_value, "must be start or end");
  }
  if (const auto text = read.string("reasoning.anthropic_thinking")) {
    if (*text == "model") reasoning.anthropic_thinking = AnthropicThinking::model;
    else if (*text == "on_request") reasoning.anthropic_thinking = AnthropicThinking::on_request;
    else add(errors, "reasoning.anthropic_thinking", ConfigIssueCode::invalid_value, "must be model or on_request");
  }
  const bool fit_max_tokens = read.boolean("engine.fit_max_tokens");
  // SP5 M1 Task 6 (parity rows lazy_load / idle_unload_s / mtp, runconfig.py:35-38):
  // lifecycle family reads; mtp is on unless an explicit false (draft_layer.py is_off).
  const bool lazy_load = read.boolean("engine.lazy_load");
  const std::int64_t idle_unload_s = read.integer("engine.idle_unload_s");
  const bool mtp = read.boolean("engine.mtp");
  const auto max_body = read.integer("limits.chat.max_body_bytes");
  const auto max_messages = read.integer("limits.chat.max_messages");
  const auto max_message = read.integer("limits.chat.max_message_bytes");
  const auto max_prompt = read.integer("limits.chat.max_prompt_tokens");
  const auto max_completion = read.integer("limits.chat.max_completion_tokens");
  const auto default_max = read.integer("limits.chat.default_max_tokens");
  const auto max_generated = read.integer("limits.chat.max_generated_bytes");
  const auto ready_s = read.integer("limits.engine.ready_timeout_s");
  const auto generation_s = read.integer("limits.engine.generation_timeout_s");
  const auto drain_s = read.integer("limits.engine.stop_drain_timeout_s");
  const auto concurrent = read.integer("limits.concurrency.max_concurrent_requests");
  // SP3 §5.1: a derived value is used only when the key is absent; an explicit
  // value is validated as written and never adjusted.
  const auto workers = static_cast<std::uint32_t>(concurrent);
  const bool queue_set = read.present("limits.concurrency.max_queued_generations");
  const auto queued = queue_set ? read.integer("limits.concurrency.max_queued_generations")
                                : static_cast<std::int64_t>(derived_max_queued_generations(workers));
  const auto queue_timeout_ms = read.integer("limits.concurrency.queue_timeout_ms");
  const bool cap_set = read.present("limits.concurrency.max_connections_per_remote_address");
  const auto remote_cap = cap_set ? read.integer("limits.concurrency.max_connections_per_remote_address")
                                  : static_cast<std::int64_t>(derived_max_connections_per_remote_address(workers));
  if (max_header > max_request) {
    add(errors, "limits.http.max_header_bytes", ConfigIssueCode::conflicting_values,
        "must not exceed limits.http.max_request_bytes");
  }
  if (max_line > max_header) {
    add(errors, "limits.http.max_request_line_bytes", ConfigIssueCode::conflicting_values,
        "must not exceed limits.http.max_header_bytes");
  }
  if (max_body > max_request - max_header) {
    add(errors, "limits.chat.max_body_bytes", ConfigIssueCode::conflicting_values,
        "must not exceed limits.http.max_request_bytes minus limits.http.max_header_bytes");
  }
  if (default_max > max_completion) {
    add(errors, "limits.chat.default_max_tokens", ConfigIssueCode::conflicting_values,
        "must not exceed limits.chat.max_completion_tokens");
  }
  if (header_deadline_ms > deadline_ms) {
    add(errors, "limits.http.header_deadline_ms", ConfigIssueCode::conflicting_values,
        "must not exceed limits.http.request_deadline_ms");
  }
  if (response_deadline_ms < write_stall_ms) {
    add(errors, "limits.http.response_write_deadline_ms", ConfigIssueCode::conflicting_values,
        "must be at least limits.http.write_stall_ms");
  }
  if (concurrent == 1 && queued != 0) {
    add(errors, "limits.concurrency.max_queued_generations", ConfigIssueCode::conflicting_values,
        "must be 0 when limits.concurrency.max_concurrent_requests is 1");
  } else if (concurrent >= 2 && queued + 2 > concurrent) {
    add(errors, "limits.concurrency.max_queued_generations", ConfigIssueCode::conflicting_values,
        "plus 2 must not exceed limits.concurrency.max_concurrent_requests");
  }
  if (remote_cap > concurrent) {
    add(errors, "limits.concurrency.max_connections_per_remote_address", ConfigIssueCode::conflicting_values,
        "must not exceed limits.concurrency.max_concurrent_requests");
  }

  // roots: each is opened once, here, and held open by the FrontendConfig.
  const auto models = canonical_root(read, errors, "roots.models");
  const auto tokenizer = canonical_root(read, errors, "roots.tokenizer_pack");
  auto secret = canonical_root(read, errors, "roots.secret");
  const auto logs = creatable_root(read, errors, "roots.logs");
  const auto cache = creatable_root(read, errors, "roots.cache");
  const auto state = absolute_path(read, errors, "roots.state");

  // token. An unset roots.secret defaults to the config file's folder, and only
  // for a file: token: an env: token reads nothing below a secret root (spec
  // §3.2, §4), so that folder is not opened or checked for it.
  const std::string source_text = read.string("token.source").value_or("file:token");
  auto token = token_source(source_text);
  if (!token.has_value()) {
    add(errors, "token.source", ConfigIssueCode::invalid_value,
        "must be env:NAME ([A-Za-z_][A-Za-z0-9_]{0,127}) or file:RELATIVE-PATH below roots.secret");
  } else if (token->kind() == SecretSourceKind::protected_file && !read.present("roots.secret")) {
    if (!draft.config_directory.has_value()) {
      add(errors, "roots.secret", ConfigIssueCode::missing_required, "is required when token.source is file:…");
    } else {
      auto opened = open_root(*draft.config_directory);
      if (auto* root = std::get_if<CanonicalRoot>(&opened)) {
        secret = std::move(*root);
      } else {
        add(errors, "roots.secret", ConfigIssueCode::invalid_value,
            "is unset, so it defaults to the config file's folder, which is not usable: " +
                std::get<PathError>(opened).message);
      }
    }
  }

  // engine
  std::optional<EngineProfile> profile;
  if (const auto text = read.string("engine.profile")) {
    if (*text == "qwen") profile = EngineProfile::qwen;
    else if (*text == "glm53") profile = EngineProfile::glm53;
    else add(errors, "engine.profile", ConfigIssueCode::invalid_value, "must be qwen or glm53");
  }
  std::optional<CanonicalFile> executable;
  if (const auto text = read.string("engine.executable")) {
    auto opened = open_executable(path_from_utf8(*text));
    if (auto* error = std::get_if<PathError>(&opened)) {
      add(errors, "engine.executable", ConfigIssueCode::invalid_value, error->message);
    } else {
      executable = std::get<CanonicalFile>(std::move(opened));
    }
  }
  const auto model_text = read.string("engine.model_id");
  std::optional<ModelId> model_id = model_text ? make_model_id(*model_text) : std::nullopt;
  if (model_text.has_value() && !model_id.has_value()) {
    add(errors, "engine.model_id", ConfigIssueCode::invalid_value,
        "must be name or name:tag, each 1-128 characters of [A-Za-z0-9._-], starting with a letter or digit");
  }
  const auto args = read.strings("engine.args");
  const auto arguments_profile = profile.value_or(EngineProfile::qwen) == EngineProfile::glm53
                                     ? EngineArgumentsProfile::lighttransport_glm53
                                     : EngineArgumentsProfile::strata_0143;
  if (const auto rejected = validate_engine_user_arguments(arguments_profile, args)) {
    add(errors, "engine.args", ConfigIssueCode::invalid_value, rejected->message);
  }
  if (profile == EngineProfile::glm53 && args.empty()) {
    add(errors, "engine.args", ConfigIssueCode::missing_required, "--profile glm53 requires at least one --engine-arg");
  }
  // Each entry is one directory: the platform's list separator would split
  // LD_LIBRARY_PATH (':') or PATH (';') into extra, unvalidated entries.
#if defined(_WIN32)
  constexpr char kListSeparator = ';';
#else
  constexpr char kListSeparator = ':';
#endif
  std::vector<std::filesystem::path> lib_dirs;
  for (const auto& text : read.strings("engine.lib_dirs")) {
    if (text.empty() || text.find('\0') != std::string::npos || text.find(kListSeparator) != std::string::npos ||
        !path_from_utf8(text).is_absolute()) {
      add(errors, "engine.lib_dirs", ConfigIssueCode::invalid_value, "every entry must be an absolute directory");
      break;
    }
    lib_dirs.push_back(path_from_utf8(text));
  }
  std::vector<unsigned> gpus;
  if (const auto gpu_text = read.string("engine.gpu")) {
    if (const auto parsed = parse_gpu_list(*gpu_text)) {
      if (profile == EngineProfile::glm53) {
        add(errors, "engine.gpu", ConfigIssueCode::conflicting_values, "is not supported with engine.profile glm53");
      } else {
        gpus = *parsed;
      }
    } else {
      add(errors, "engine.gpu", ConfigIssueCode::invalid_value,
          "must be a comma-separated list of distinct device indices 0-255, at most 16");
    }
  }
  const bool allow_new_privileges = read.boolean("engine.allow_new_privileges");
  // SP5 M1 Task 7: the VRAM / GPU / elastic family. Kinds/defaults verbatim from the pin
  // (runconfig.py:42-43; serve/server.py:2548-2552, 2870-2894, 2947, 8083; images.py:45);
  // the layer_split grammar is the pin's own (layer_split_value, :2875-2892: blank or
  // "auto" is the default; otherwise rising integers from >=2, one per GPU after the
  // first — the count rule applies only with several GPUs, as at :2888).
  const auto vram_reserve_mib = read.optional_integer("engine.vram_reserve_mib");
  const std::int64_t min_free_vram = read.integer("engine.min_free_vram_mib");
  const bool vram_elastic = read.boolean("engine.vram_elastic");
  const auto vram_segment_mib = read.optional_integer("engine.vram_segment_mib");
  const bool elastic = read.boolean("engine.elastic");
  const std::int64_t elastic_idle_s = read.integer("engine.elastic_idle_s");
  const std::int64_t elastic_mib = read.integer("engine.elastic_mib");
  GpuOrder gpu_order{GpuOrder::auto_order};
  if (const auto text = read.string("engine.gpu_order")) {
    if (*text == "auto") gpu_order = GpuOrder::auto_order;
    else if (*text == "as_given") gpu_order = GpuOrder::as_given;
    else add(errors, "engine.gpu_order", ConfigIssueCode::invalid_value, "must be auto or as_given");
  }
  GpuTurnPolicy gpu_policy{GpuTurnPolicy::auto_policy};
  if (const auto text = read.string("engine.gpu_policy")) {
    if (*text == "auto") gpu_policy = GpuTurnPolicy::auto_policy;
    else if (*text == "keep") gpu_policy = GpuTurnPolicy::keep;
    else if (*text == "shrink") gpu_policy = GpuTurnPolicy::shrink;
    else if (*text == "unload") gpu_policy = GpuTurnPolicy::unload;
    else add(errors, "engine.gpu_policy", ConfigIssueCode::invalid_value, "must be auto, keep, shrink or unload");
  }
  const std::string layer_split = read.string("engine.layer_split").value_or("");
  if (auto trimmed = layer_split; !(trimmed.empty() || trimmed == "auto")) {
    std::vector<std::int64_t> layers;
    bool grammar = true;
    std::size_t start = 0;
    while (start <= trimmed.size()) {
      const auto comma = trimmed.find(',', start);
      const auto token = trimmed.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
      std::size_t begin = token.find_first_not_of(" \t");
      std::size_t end = token.find_last_not_of(" \t");
      if (begin == std::string::npos) {
        grammar = false;
        break;
      }
      std::int64_t value = 0;
      const auto [ptr, ec] = std::from_chars(token.data() + begin, token.data() + end + 1, value);
      if (ec != std::errc{} || ptr != token.data() + end + 1) {
        grammar = false;
        break;
      }
      layers.push_back(value);
      if (comma == std::string::npos) break;
      start = comma + 1;
    }
    bool rising = grammar && !layers.empty() && layers.front() >= 2;
    for (std::size_t i = 1; i < layers.size(); ++i) {
      if (layers[i] <= layers[i - 1]) rising = false;
    }
    const bool count_ok = gpus.size() <= 1 || layers.size() == gpus.size() - 1;
    if (!grammar || !rising || !count_ok) {
      add(errors, "engine.layer_split", ConfigIssueCode::invalid_value,
          "must be auto, or the first layer of each later GPU: rising numbers from 2, one per GPU after the first (for example \"24,36,42\" for 4 GPUs), not a count per card");
    }
  }
  const bool split_skip_if_fits = read.boolean("engine.split_skip_if_fits");
  const auto hip_ordinal = read.optional_integer("engine.hip_ordinal");
  const bool uma = read.boolean("engine.uma");
  // SP5 M1 Task 8: the timeout / request-shape family. silence 0 = wait (the pin's),
  // repeat 0 = off (:8115); the token bounds stay unset until configured; aliases keep
  // set_aliases' grammar (dedup and dropping the model's own name happen at wiring).
  const std::int64_t silence_s = read.integer("engine.silence_s");
  const bool answer_room = read.boolean("engine.answer_room");
  const std::int64_t repeat_stop_tokens = read.integer("engine.repeat_stop_tokens");
  const auto max_output = read.optional_integer("engine.max_tokens");
  const auto min_output = read.optional_integer("engine.min_tokens");
  const std::vector<std::string> aliases = read_bounded_strings(read, errors, "model.aliases");
  // SP5 M1 Task 9 (the session family; serve/server.py:2999-3005, :8043-8110, :8092-8100 +
  // slot_save_dir :3469-3481, images.py:188). Path rows keep the pin's shape (non-empty, no
  // control characters) and ride our added absolute rule (T9-b, engine.lib_dirs precedent):
  // there is no config-cwd to resolve a relative path against, and load never touches the
  // filesystem (the pin's makedirs 0700 is a runtime act).
  SessionPolicy session;
  const auto slot_text = read.string("session.slot_save_path");
  if (slot_text.has_value()) {
    if (is_absolute_store_path(*slot_text)) session.slot_save_path = *slot_text;
    else add(errors, "session.slot_save_path", ConfigIssueCode::invalid_value, "must be an absolute path without control characters");
  }
  const auto profile_text = read.string("session.expert_profile_save");
  if (profile_text.has_value()) {
    if (is_absolute_store_path(*profile_text)) session.expert_profile_save = *profile_text;
    else add(errors, "session.expert_profile_save", ConfigIssueCode::invalid_value, "must be an absolute path without control characters");
  }
  session.expert_profile_save_every = read.integer("session.expert_profile_save_every");
  session.tool_call_recovery = read.boolean("session.tool_call_recovery");
  session.env_to_user = read.boolean("session.env_to_user");
  session.codex_thread_titles = read.boolean("session.codex_thread_titles");
  session.codex_compaction_cache = read.boolean("session.codex_compaction_cache");
  session.keep_files = read.integer("session.keep_files");
  // SP5 M1 Task 10 (the C-4 narrowing): engine-internal parallelism only.
  const ReplicasConfig replicas{read.integer("replicas.parallel")};
  // SP5 M1 Task 11 (D-9 vision split): image input plumbing; generation stays out.
  VisionConfig vision;
  vision.enabled = read.boolean("vision.enabled");
  vision.max_side = read.integer("vision.max_side");
  vision.max_n = read.integer("vision.max_n");
  vision.need_mib = read.optional_integer("vision.need_mib");
  vision.no_flash_attn = read.boolean("vision.no_flash_attn");
  vision.resident = read.boolean("vision.resident");
  vision.threads = read.integer("vision.threads");
  vision.ready_timeout_s = read.integer("vision.ready_timeout_s");
  vision.encode_timeout_s = read.integer("vision.encode_timeout_s");

  // SP5 M2 Task 3 (spec §D-2): the glm.* family. Kinds and defaults are the
  // vendored pin's (serve/server.py:3440/:3427/:3255/:1210-1213, validators
  // :3234); the caps, the closed effort vocabulary and the layer_split
  // grammar are added (C-1). The qwen-profile gate mirrors the existing
  // engine.gpu rule the other way: an explicit engine.profile "qwen" refuses
  // every present glm.* row by name (conflicting_values); with no explicit
  // profile a managed model's SP4 manifest decides at launch, so the rows
  // validate here and Task 7 refuses them for a qwen manifest (R-T3-a).
  GlmSettings glm;
  bool any_glm_row = false;
  for (const auto& [path, entry] : draft.entries) {
    static_cast<void>(entry);
    if (path.rfind("glm.", 0) == 0) any_glm_row = true;
  }
  glm.thinking_budget = read.integer("glm.thinking_budget");
  if (const auto text = read.string("glm.reasoning_effort")) {
    if (*text == "none") glm.reasoning_effort = GlmReasoningEffort::none;
    else if (*text == "low") glm.reasoning_effort = GlmReasoningEffort::low;
    else if (*text == "high") glm.reasoning_effort = GlmReasoningEffort::high;
    else if (*text == "max") glm.reasoning_effort = GlmReasoningEffort::max;
    else add(errors, "glm.reasoning_effort", ConfigIssueCode::invalid_value, "must be none, low, high or max");
  }
  glm.fit_max_tokens = read.boolean("glm.fit_max_tokens");
  glm.experimental_speed_projection = read.boolean("glm.experimental_speed_projection");
  if (const auto gpu_text = read.string("glm.gpu")) {
    if (const auto parsed = parse_gpu_list(*gpu_text)) glm.gpus = *parsed;
    else add(errors, "glm.gpu", ConfigIssueCode::invalid_value,
             "must be a comma-separated list of distinct device indices 0-255, at most 16");
  }
  glm.layer_split = read.string("glm.layer_split").value_or("");
  if (glm.layer_split.empty()) glm.layer_split = "auto";
  if (glm.layer_split != "auto") {
    // The vendored grammar (serve/server.py:1210-1213): the first layer of
    // each later GPU's share, e.g. "18" or "16,32". The rising-numbers check
    // is added (C-1); the count-against-gpus check belongs to the launch
    // (Task 7), because a manifest may name the cards the config does not.
    std::vector<std::int64_t> layers;
    bool grammar = true;
    std::size_t start = 0;
    while (start <= glm.layer_split.size()) {
      const auto comma = glm.layer_split.find(',', start);
      const auto token = glm.layer_split.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
      const std::size_t begin = token.find_first_not_of(" \t");
      const std::size_t end = token.find_last_not_of(" \t");
      if (begin == std::string::npos) {
        grammar = false;
        break;
      }
      std::int64_t value = 0;
      const auto [ptr, ec] = std::from_chars(token.data() + begin, token.data() + end + 1, value);
      if (ec != std::errc{} || ptr != token.data() + end + 1 || value < 1) {
        grammar = false;
        break;
      }
      layers.push_back(value);
      if (comma == std::string::npos) break;
      start = comma + 1;
    }
    bool rising = grammar && !layers.empty();
    for (std::size_t i = 1; i < layers.size(); ++i) {
      if (layers[i] <= layers[i - 1]) rising = false;
    }
    if (!rising) {
      add(errors, "glm.layer_split", ConfigIssueCode::invalid_value,
          "must be auto, or the first layer of each later GPU's share: rising numbers from 1 (for example \"18\" or \"16,32\")");
    }
  }
  if (const auto text = read.string("glm.tokenizer")) {
    if (is_absolute_store_path(*text)) glm.tokenizer = *text;
    else add(errors, "glm.tokenizer", ConfigIssueCode::invalid_value, "must be an absolute path");
  }
  if (const auto text = read.string("glm.model_name")) {
    if (text->empty() || text->size() > 256 || text->find('\0') != std::string::npos) {
      add(errors, "glm.model_name", ConfigIssueCode::invalid_value, "must be 1-256 characters");
    } else {
      glm.model_name = *text;
    }
  }
  if (any_glm_row && profile == EngineProfile::qwen) {
    for (const auto& [path, entry] : draft.entries) {
      static_cast<void>(entry);
      if (path.rfind("glm.", 0) == 0) {
        add(errors, path, ConfigIssueCode::conflicting_values, "is only supported with engine.profile glm53");
      }
    }
  }

  // pull (SP4 §3.9)
  std::filesystem::path downloader = default_downloader_path();
  if (const auto text = read.string("pull.downloader")) {
    const auto candidate = path_from_utf8(*text);
    if (!candidate.is_absolute()) add(errors, "pull.downloader", ConfigIssueCode::invalid_value, "must be an absolute path");
    else downloader = candidate;
  }
  std::optional<ProxySetting> proxy;
  if (const auto text = read.string("pull.proxy")) {
    auto parsed = parse_proxy(*text);
    if (std::holds_alternative<UrlProblem>(parsed)) {
      add(errors, "pull.proxy", ConfigIssueCode::invalid_value,
          "must be http://host:port or https://host:port without credentials, path or query");
    } else {
      proxy = std::get<ProxySetting>(std::move(parsed));
    }
  }
  const bool allow_private = read.boolean("pull.allow_private_addresses");
  const auto max_total = read.integer("pull.max_total_bytes");
  const auto max_duration = read.integer("pull.max_duration_s");
  const auto stall = read.integer("pull.stall_timeout_s");
  const auto connect = read.integer("pull.connect_timeout_s");

  if (!errors.empty() || !host || !models || !token || !executable || !model_id) {
    if (errors.empty()) add(errors, "config file", ConfigIssueCode::invalid_value, "is incomplete");
    return errors;
  }
  const auto u32 = [](const std::int64_t v) { return static_cast<std::uint32_t>(v); };
  ListenerConfig listener{*host, static_cast<std::uint16_t>(port), allow_remote, allow_wildcard, u32(backlog),
                          std::move(cors_origins), std::move(host_aliases)};
  const Limits limits{
      HttpLimits{std::chrono::milliseconds(deadline_ms), u32(max_request), u32(max_header), u32(max_headers), u32(max_line),
                 std::chrono::milliseconds(header_deadline_ms), std::chrono::milliseconds(write_stall_ms),
                 std::chrono::milliseconds(response_deadline_ms), std::chrono::milliseconds(keepalive_ms)},
      ChatLimits{u32(max_body), u32(max_messages), u32(max_message), u32(max_prompt), u32(max_completion), u32(default_max),
                 u32(max_generated)},
      EngineLimits{std::chrono::seconds(ready_s), std::chrono::seconds(generation_s), std::chrono::seconds(drain_s)},
      ConcurrencyLimits{u32(concurrent), u32(queued), std::chrono::milliseconds(queue_timeout_ms), u32(remote_cap), !queue_set,
                        !cap_set}};
  Roots roots{*models, tokenizer, secret, logs, cache, state};
  EngineLaunch engine{profile,
                      *executable,
                      std::move(*model_id),
                      args,
                      std::move(lib_dirs),
                      std::move(gpus),
                      allow_new_privileges,
                      fit_max_tokens,
                      lazy_load,
                      std::chrono::seconds(idle_unload_s),
                      mtp,
                      vram_reserve_mib,
                      min_free_vram,
                      vram_elastic,
                      vram_segment_mib,
                      elastic,
                      std::chrono::seconds(elastic_idle_s),
                      elastic_mib,
                      gpu_order,
                      gpu_policy,
                      layer_split.empty() ? std::string{"auto"} : layer_split,
                      split_skip_if_fits,
                      hip_ordinal,
                      uma,
                      std::chrono::seconds(silence_s),
                      answer_room,
                      static_cast<std::size_t>(repeat_stop_tokens),
                      max_output.has_value() ? std::optional<std::size_t>{static_cast<std::size_t>(*max_output)}
                                             : std::optional<std::size_t>{},
                      min_output.has_value() ? std::optional<std::size_t>{static_cast<std::size_t>(*min_output)}
                                             : std::optional<std::size_t>{},
                      std::move(aliases)};
  auto config_ptr = std::shared_ptr<const FrontendConfig>(
      new FrontendConfig(std::move(listener), limits, std::move(roots), std::move(*token), std::move(engine),
                         PullSettings{std::move(downloader), std::move(proxy), allow_private,
                                      static_cast<std::uint64_t>(max_total), std::chrono::seconds(max_duration),
                                      std::chrono::seconds(stall), std::chrono::seconds(connect)},
                         LoggingConfig{log_requests}, std::move(sampling_defaults), reasoning, std::move(session),
                         replicas, vision, std::move(glm)));
  return ValidatedConfig{std::move(config_ptr)};
}

std::string describe(const FrontendConfig& c) {
  std::string out;
  const auto line = [&out](const std::string_view key, const std::string& value) {
    out.append(key).append(" = ").append(value).push_back('\n');
  };
  const auto root_text = [](const CanonicalRoot& root) { return json_quoted(path_to_utf8(root.path())); };
  const auto root_or_unset = [&root_text](const std::optional<CanonicalRoot>& root) {
    return root.has_value() ? root_text(*root) : std::string{"(unset)"};
  };
  const auto path_or_unset = [](const std::optional<std::filesystem::path>& p) {
    return p.has_value() ? json_quoted(path_to_utf8(*p)) : std::string{"(unset)"};
  };
  line("schema_version", "1");
  line("listener.host", json_quoted(c.listener.host.canonical_text()));
  line("listener.port", std::to_string(c.listener.port));
  line("listener.allow_remote", c.listener.allow_remote ? "true" : "false");
  line("listener.allow_wildcard_bind", c.listener.allow_wildcard_bind ? "true" : "false");
  line("listener.backlog", std::to_string(c.listener.backlog));
  const auto list_text = [](const std::vector<std::string>& values) {
    std::string text = "[";
    for (std::size_t i = 0; i < values.size(); ++i) text += (i ? "," : "") + json_quoted(values[i]);
    return text + "]";
  };
  line("listener.cors_origins", list_text(c.listener.cors_origins));
  line("listener.host_aliases", list_text(c.listener.host_aliases));
  line("limits.http.request_deadline_ms", std::to_string(c.limits.http.request_deadline.count()));
  line("limits.http.max_request_bytes", std::to_string(c.limits.http.max_request_bytes));
  line("limits.http.max_header_bytes", std::to_string(c.limits.http.max_header_bytes));
  line("limits.http.max_headers", std::to_string(c.limits.http.max_headers));
  line("limits.http.max_request_line_bytes", std::to_string(c.limits.http.max_request_line_bytes));
  line("limits.http.header_deadline_ms", std::to_string(c.limits.http.header_deadline.count()));
  line("limits.http.write_stall_ms", std::to_string(c.limits.http.write_stall.count()));
  line("limits.http.response_write_deadline_ms", std::to_string(c.limits.http.response_write_deadline.count()));
  line("limits.http.stream_keepalive_ms", std::to_string(c.limits.http.stream_keepalive.count()));
  line("limits.chat.max_body_bytes", std::to_string(c.limits.chat.max_body_bytes));
  line("limits.chat.max_messages", std::to_string(c.limits.chat.max_messages));
  line("limits.chat.max_message_bytes", std::to_string(c.limits.chat.max_message_bytes));
  line("limits.chat.max_prompt_tokens", std::to_string(c.limits.chat.max_prompt_tokens));
  line("limits.chat.max_completion_tokens", std::to_string(c.limits.chat.max_completion_tokens));
  line("limits.chat.default_max_tokens", std::to_string(c.limits.chat.default_max_tokens));
  line("limits.chat.max_generated_bytes", std::to_string(c.limits.chat.max_generated_bytes));
  line("limits.engine.ready_timeout_s", std::to_string(c.limits.engine.ready_timeout.count()));
  line("limits.engine.generation_timeout_s", std::to_string(c.limits.engine.generation_timeout.count()));
  line("limits.engine.stop_drain_timeout_s", std::to_string(c.limits.engine.stop_drain_timeout.count()));
  const auto& cc = c.limits.concurrency;
  line("limits.concurrency.max_concurrent_requests", std::to_string(cc.max_concurrent_requests));
  line("limits.concurrency.max_queued_generations",
       std::to_string(cc.max_queued_generations) + (cc.queue_derived ? " (derived)" : ""));
  line("limits.concurrency.queue_timeout_ms", std::to_string(cc.queue_timeout.count()));
  line("limits.concurrency.max_connections_per_remote_address",
       std::to_string(cc.max_connections_per_remote_address) + (cc.remote_cap_derived ? " (derived)" : ""));
  line("roots.models", root_text(c.roots.models));
  line("roots.tokenizer_pack", root_or_unset(c.roots.tokenizer_pack));
  line("roots.secret", root_or_unset(c.roots.secret));
  line("roots.logs", path_or_unset(c.roots.logs));
  line("roots.cache", path_or_unset(c.roots.cache));
  line("roots.state", path_or_unset(c.roots.state));
  line("token.source", json_quoted((c.token.kind() == SecretSourceKind::environment_variable ? "env:" : "file:") +
                              c.token.location()));
  line("engine.profile", !c.engine.profile                              ? std::string{"(unset)"}
                         : *c.engine.profile == EngineProfile::glm53 ? std::string{"\"glm53\""}
                                                                     : std::string{"\"qwen\""});
  line("engine.executable", json_quoted(path_to_utf8(c.engine.executable.path())));
  line("engine.model_id", json_quoted(c.engine.model_id.value()));
  std::string args = "[";
  for (const auto& arg : c.engine.args) args += (args.size() > 1U ? "," : "") + json_quoted(arg);
  line("engine.args", args + "]");
  std::string libs = "[";
  for (const auto& directory : c.engine.lib_dirs) libs += (libs.size() > 1U ? "," : "") + json_quoted(path_to_utf8(directory));
  line("engine.lib_dirs", libs + "]");
  std::string gpu_list;
  for (const unsigned device : c.engine.gpus) gpu_list += (gpu_list.empty() ? "" : ",") + std::to_string(device);
  line("engine.gpu", gpu_list.empty() ? std::string{"(unset)"} : json_quoted(gpu_list));
  line("engine.allow_new_privileges", c.engine.allow_new_privileges ? "true" : "false");
  line("pull.downloader", json_quoted(path_to_utf8(c.pull.downloader)));
  line("pull.proxy", c.pull.proxy ? json_quoted(render_proxy(*c.pull.proxy)) : std::string{"(unset)"});
  line("pull.allow_private_addresses", c.pull.allow_private_addresses ? "true" : "false");
  line("pull.max_total_bytes", std::to_string(c.pull.max_total_bytes));
  line("pull.max_duration_s", std::to_string(c.pull.max_duration.count()));
  line("pull.stall_timeout_s", std::to_string(c.pull.stall_timeout.count()));
  line("pull.connect_timeout_s", std::to_string(c.pull.connect_timeout.count()));
  line("logging.requests", c.logging.requests ? "true" : "false");
  // SP5 M1 Task 4: the defaults.sampling.* rows; an unset row stays unset and
  // is never sent (the engine keeps its own default).
  const auto decimal_or_unset = [](const std::optional<double>& value) {
    return value.has_value() ? decimal_text(*value) : std::string{"(unset)"};
  };
  const auto integer_or_unset = [](const std::optional<std::int64_t>& value) {
    return value.has_value() ? std::to_string(*value) : std::string{"(unset)"};
  };
  line("defaults.sampling.temperature", decimal_or_unset(c.sampling.temperature));
  line("defaults.sampling.top_p", decimal_or_unset(c.sampling.top_p));
  line("defaults.sampling.min_p", decimal_or_unset(c.sampling.min_p));
  line("defaults.sampling.presence_penalty", decimal_or_unset(c.sampling.presence_penalty));
  line("defaults.sampling.repetition_penalty", decimal_or_unset(c.sampling.repetition_penalty));
  line("defaults.sampling.frequency_penalty", decimal_or_unset(c.sampling.frequency_penalty));
  line("defaults.sampling.top_k", integer_or_unset(c.sampling.top_k));
  line("defaults.sampling.penalty_last_n", integer_or_unset(c.sampling.penalty_last_n));
  line("defaults.sampling.seed", integer_or_unset(c.sampling.seed));
  // SP5 M1 Task 5: the reasoning.* family and engine.fit_max_tokens.
  line("reasoning.effort",
       !c.reasoning.effort.has_value()                  ? std::string{"(unset)"}
       : *c.reasoning.effort == ReasoningEffort::none   ? "none"
       : *c.reasoning.effort == ReasoningEffort::low    ? "low"
       : *c.reasoning.effort == ReasoningEffort::medium ? "medium"
                                                        : "high");
  line("reasoning.budget_tokens", std::to_string(c.reasoning.budget_tokens));
  line("reasoning.close_retry", c.reasoning.close_retry ? "true" : "false");
  line("reasoning.loop_recovery",
       c.reasoning.loop_recovery == LoopRecovery::off      ? "off"
       : c.reasoning.loop_recovery == LoopRecovery::stop   ? "stop"
                                                           : "recover");
  line("reasoning.effort_position", c.reasoning.effort_position == EffortPosition::start ? "start" : "end");
  line("reasoning.anthropic_thinking",
       c.reasoning.anthropic_thinking == AnthropicThinking::model ? "model" : "on_request");
  // SP5 M1 Task 9: the session family.
  line("session.slot_save_path", c.session.slot_save_path.empty() ? std::string{"(unset)"} : json_quoted(c.session.slot_save_path));
  line("session.expert_profile_save", c.session.expert_profile_save.empty() ? std::string{"(unset)"} : json_quoted(c.session.expert_profile_save));
  line("session.expert_profile_save_every", std::to_string(c.session.expert_profile_save_every));
  line("session.tool_call_recovery", c.session.tool_call_recovery ? "true" : "false");
  line("session.env_to_user", c.session.env_to_user ? "true" : "false");
  line("session.codex_thread_titles", c.session.codex_thread_titles ? "true" : "false");
  line("session.codex_compaction_cache", c.session.codex_compaction_cache ? "true" : "false");
  line("session.keep_files", std::to_string(c.session.keep_files));
  // SP5 M1 Task 10: engine-internal parallelism (the C-4 narrowing's surviving half).
  line("replicas.parallel", std::to_string(c.replicas.parallel));
  // SP5 M1 Task 11: the vision family (D-9 split).
  line("vision.enabled", c.vision.enabled ? "true" : "false");
  line("vision.max_side", std::to_string(c.vision.max_side));
  line("vision.max_n", std::to_string(c.vision.max_n));
  line("vision.need_mib", c.vision.need_mib.has_value() ? std::to_string(*c.vision.need_mib) : std::string{"unset"});
  line("vision.no_flash_attn", c.vision.no_flash_attn ? "true" : "false");
  line("vision.resident", c.vision.resident ? "true" : "false");
  line("vision.threads", std::to_string(c.vision.threads));
  line("vision.ready_timeout_s", std::to_string(c.vision.ready_timeout_s));
  // SP5 M2 Task 3: the glm.* family (spec §D-2).
  line("glm.thinking_budget", std::to_string(c.glm.thinking_budget));
  line("glm.reasoning_effort",
       !c.glm.reasoning_effort.has_value()
           ? std::string{"(unset)"}
           : *c.glm.reasoning_effort == GlmReasoningEffort::none ? "none"
           : *c.glm.reasoning_effort == GlmReasoningEffort::low  ? "low"
           : *c.glm.reasoning_effort == GlmReasoningEffort::high ? "high"
                                                                  : "max");
  line("glm.fit_max_tokens", c.glm.fit_max_tokens ? "true" : "false");
  line("glm.experimental_speed_projection", c.glm.experimental_speed_projection ? "true" : "false");
  std::string glm_gpus;
  for (const unsigned device : c.glm.gpus) glm_gpus += (glm_gpus.empty() ? "" : ",") + std::to_string(device);
  line("glm.gpu", glm_gpus.empty() ? std::string{"(unset)"} : json_quoted(glm_gpus));
  line("glm.layer_split", json_quoted(c.glm.layer_split));
  line("glm.tokenizer", c.glm.tokenizer.has_value() ? json_quoted(*c.glm.tokenizer) : std::string{"(unset)"});
  line("glm.model_name", c.glm.model_name.has_value() ? json_quoted(*c.glm.model_name) : std::string{"(unset)"});
  line("engine.fit_max_tokens", c.engine.fit_max_tokens ? "true" : "false");
  // SP5 M1 Task 6: the lifecycle family (runconfig.py:35-38).
  line("engine.lazy_load", c.engine.lazy_load ? "true" : "false");
  line("engine.idle_unload_s", std::to_string(c.engine.idle_unload.count()));
  line("engine.mtp", c.engine.mtp ? "true" : "false");
  // SP5 M1 Task 7: the VRAM / GPU / elastic family.
  line("engine.vram_reserve_mib", integer_or_unset(c.engine.vram_reserve_mib));
  line("engine.min_free_vram_mib", std::to_string(c.engine.min_free_vram));
  line("engine.vram_elastic", c.engine.vram_elastic ? "true" : "false");
  line("engine.vram_segment_mib", integer_or_unset(c.engine.vram_segment_mib));
  line("engine.elastic", c.engine.elastic ? "true" : "false");
  line("engine.elastic_idle_s", std::to_string(c.engine.elastic_idle.count()));
  line("engine.elastic_mib", std::to_string(c.engine.elastic_mib));
  line("engine.gpu_order", c.engine.gpu_order == GpuOrder::as_given ? "as_given" : "auto");
  line("engine.gpu_policy",
       c.engine.gpu_policy == GpuTurnPolicy::keep    ? "keep"
       : c.engine.gpu_policy == GpuTurnPolicy::shrink ? "shrink"
       : c.engine.gpu_policy == GpuTurnPolicy::unload ? "unload"
                                                      : "auto");
  line("engine.layer_split", c.engine.layer_split);
  line("engine.split_skip_if_fits", c.engine.split_skip_if_fits ? "true" : "false");
  line("engine.hip_ordinal", integer_or_unset(c.engine.hip_ordinal));
  line("engine.uma", c.engine.uma ? "true" : "false");
  // SP5 M1 Task 8: the timeout / request-shape family.
  line("engine.silence_s", std::to_string(c.engine.silence.count()));
  line("engine.answer_room", c.engine.answer_room ? "true" : "false");
  line("engine.repeat_stop_tokens", std::to_string(c.engine.repeat_stop_tokens));
  line("engine.max_tokens", c.engine.max_tokens ? std::to_string(*c.engine.max_tokens) : std::string{"unset"});
  line("engine.min_tokens", c.engine.min_tokens ? std::to_string(*c.engine.min_tokens) : std::string{"unset"});
  line("model.aliases", list_text(c.engine.aliases));
  return out;
}

Config listener_config(const FrontendConfig& c) {
  return Config{c.listener.host.canonical_text(), c.listener.port, true,
                c.listener.host.scope() == AddressScope::loopback, c.listener.allow_remote,
                c.listener.allow_wildcard_bind};
}

ConfigErrors create_runtime_roots(const FrontendConfig& c) {
  ConfigErrors errors;
  const std::pair<const char*, const std::optional<std::filesystem::path>*> roots[] = {
      {"roots.logs", &c.roots.logs}, {"roots.cache", &c.roots.cache}};
  for (const auto& [key, root] : roots) {
    if (!root->has_value()) continue;
    auto opened = open_root(**root, RootPolicy::create_private);
    if (const auto* failure = std::get_if<PathError>(&opened)) add(errors, key, ConfigIssueCode::invalid_value, failure->message);
  }
  return errors;
}

}  // namespace secure_frontend

#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>

// The one place every tunable default lives (SP1 §4). The schema table and
// every subsystem struct default read these; no other file may hardcode a
// tuning limit. Internal format/protocol constants are listed in
// docs/security/engine-protocol-limits.md and are not here.
namespace secure_frontend::config_defaults {
inline constexpr std::int64_t kSchemaVersion = 1;
inline constexpr std::int64_t kListenerPort = 8080;
inline constexpr std::int64_t kListenerBacklog = 16;
inline constexpr std::int64_t kRequestDeadlineMs = 30'000;
inline constexpr std::int64_t kMaxRequestBytes = 65'536;
inline constexpr std::int64_t kMaxHeaderBytes = 16'384;
inline constexpr std::int64_t kMaxHeaders = 64;
inline constexpr std::int64_t kMaxRequestLineBytes = 4'096;
inline constexpr std::int64_t kChatMaxBodyBytes = kMaxRequestBytes - kMaxHeaderBytes;  // 49152, see the plan's Global Constraints
inline constexpr std::int64_t kChatMaxMessages = 128;
inline constexpr std::int64_t kChatMaxMessageBytes = 65'536;
inline constexpr std::int64_t kChatMaxPromptTokens = 32'768;
inline constexpr std::int64_t kChatMaxCompletionTokens = 4'096;
inline constexpr std::int64_t kChatDefaultMaxTokens = 256;
inline constexpr std::int64_t kChatMaxGeneratedBytes = 1'048'576;
inline constexpr std::int64_t kEngineReadyTimeoutS = 900;   // upstream STRATA_ENGINE_READY_S
inline constexpr std::int64_t kEngineGenerationTimeoutS = 120;
inline constexpr std::int64_t kEngineStopDrainTimeoutS = 5;
inline constexpr std::int64_t kMaxConcurrentRequests = 1;

// Supervision (SP2). Restart policy (spec §3.3, owner decision 2026-10-13);
// the READY timeout is kEngineReadyTimeoutS above, not a second copy.
inline constexpr std::uint32_t kMaxConsecutiveFailures = 3U;
inline constexpr std::chrono::milliseconds kBackoffInitial{1'000};
inline constexpr std::uint32_t kBackoffFactor = 2U;
inline constexpr std::chrono::milliseconds kBackoffMax{60'000};
inline constexpr std::chrono::milliseconds kHealthyWindow{300'000};
inline constexpr std::chrono::milliseconds kReapTimeout{30'000};
inline constexpr std::chrono::milliseconds kMonitorFallbackPoll{100};  // kernels without pidfd_open
inline constexpr std::chrono::milliseconds kReadyPollSlice{100};       // READY waits stay responsive to shutdown
// Orderly shutdown (spec §3.7): EOF, wait, SIGTERM, wait, SIGKILL; past the bound exit 1.
inline constexpr std::chrono::milliseconds kShutdownStdinWait{2'000};
inline constexpr std::chrono::milliseconds kShutdownTermWait{1'000};
inline constexpr std::chrono::milliseconds kShutdownBound{5'000};
// Engine stdin writes (spec §3.10): fail when a chunk makes no progress for this long.
inline constexpr std::chrono::milliseconds kStdinWriteDeadline{1'000};
inline constexpr std::size_t kStdinWriteChunk = 65'536U;
// PR_SET_NO_NEW_PRIVS for the engine (owner decision 2026-10-13: default ON;
// --allow-new-privileges turns it off for the GPU-box validation kit).
inline constexpr bool kNoNewPrivilegesDefault = true;
}  // namespace secure_frontend::config_defaults

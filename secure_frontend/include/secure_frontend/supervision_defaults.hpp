#pragma once

// SP2's named stand-ins for values SP1 makes typed, validated configuration
// (SP2 spec §2). This is the ONLY header that holds them; SP1 replaces each
// constant with its config field when the branches merge.

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace secure_frontend::supervision_defaults {

// Restart policy (spec §3.3, owner decision 2026-10-13).
inline constexpr std::uint32_t kMaxConsecutiveFailures = 3U;
inline constexpr std::chrono::milliseconds kBackoffInitial{1'000};
inline constexpr std::uint32_t kBackoffFactor = 2U;
inline constexpr std::chrono::milliseconds kBackoffMax{60'000};
inline constexpr std::chrono::milliseconds kHealthyWindow{300'000};
inline constexpr std::chrono::milliseconds kReadyTimeout{900'000};   // upstream STRATA_ENGINE_READY_S
inline constexpr std::chrono::milliseconds kReapTimeout{30'000};

// Supervisor timing.
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

}  // namespace secure_frontend::supervision_defaults

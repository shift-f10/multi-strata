#pragma once
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
}  // namespace secure_frontend::config_defaults

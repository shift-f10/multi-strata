#pragma once

#include "secure_frontend/api_constants.hpp"
#include "secure_frontend/engine_protocol_client.hpp"
#include "secure_frontend/tokenizer_pack.hpp"

#include <chrono>
#include <cstddef>
#include <string_view>

namespace secure_frontend {

// Why a generation was cut short from the frontend side.
enum class RunCancel { none, client_gone, write_stall, shutting_down };

// How one driven generation ended.
// stop: DONE … stop. length: DONE … length, the byte cap, or the generation
// timeout (B4). cancelled: the observer cancelled (client gone, stall or
// shutdown) and STOP drained. engine_error: DONE … nonfinite (engine idle),
// ERR/fatal line (protocol closed), or more tokens than GEN allowed
// (abandoned). engine_unavailable: exit, protocol failure, a failed STOP
// write or a drain that missed its deadline (protocol closed).
// undecodable: a generated id that is not ordinary output, STOP drained.
enum class RunEnd { stop, length, cancelled, engine_error, engine_unavailable, undecodable };

struct GenerationRunLimits final {
  std::chrono::milliseconds generation_timeout{std::chrono::seconds(120)};
  std::chrono::milliseconds stop_drain_timeout{std::chrono::seconds(5)};
  std::size_t max_generated_bytes{1048576U};
  std::size_t max_tokens{0};  // the GEN max_new; 0 = unchecked
  std::chrono::milliseconds slice{api_constants::kStreamPollSlice};
  std::chrono::milliseconds shutdown_drain{api_constants::kShutdownDrainBudget};  // drain cap when cancel == shutting_down
};

struct GenerationRunResult final {
  RunEnd end{RunEnd::engine_unavailable};
  std::size_t completion_tokens{0};
  bool timed_out{false};
  bool bytes_capped{false};
  RunCancel cancel{RunCancel::none};
};

// Receives the decoded text and the liveness beat of one driven generation.
class GenerationObserver {
 public:
  virtual void on_text(std::string_view text) = 0;  // complete UTF-8, never empty
  virtual RunCancel on_tick(bool progress) = 0;     // at least once per slice, and after every PP
  virtual ~GenerationObserver() = default;
};

// One generation loop for both paths (spec §3.3/§3.4): reads records as
// events in bounded slices, decodes tokens through the pack and the UTF-8
// stream decoder, enforces the byte cap on code-point boundaries, and
// answers timeout / cap / observer cancel with exactly one STOP and a
// bounded drain to DONE. The protocol must already be past READY and GEN.
[[nodiscard]] GenerationRunResult drive_generation(EngineProtocolClient& protocol, const TokenByteDecoder& decoder,
                                                   const GenerationRunLimits& limits, GenerationObserver& observer);

}  // namespace secure_frontend

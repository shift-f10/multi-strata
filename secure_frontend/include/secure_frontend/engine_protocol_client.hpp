#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace secure_frontend {

// The process layer deliberately does not expose stdin/stdout handles.  This
// narrow interface permits a pipe-backed implementation later while keeping
// protocol parsing independently testable and refusing ambiguous I/O results.
enum class EngineReadKind { line, timeout, closed, failure };

struct EngineReadResult final {
  EngineReadKind kind;
  std::string line;
  std::string message;
};

class EngineLineTransport {
 public:
  virtual ~EngineLineTransport() = default;
  // `line` never contains a newline. Implementations must write it as one
  // atomic protocol record (line plus LF) or report failure.
  [[nodiscard]] virtual bool write_line(std::string_view line, std::string& error) = 0;
  [[nodiscard]] virtual EngineReadResult read_line(std::chrono::milliseconds timeout) = 0;
};

enum class EngineProtocolErrorCode {
  invalid_argument,
  invalid_state,
  transport_write_failed,
  transport_read_failed,
  timeout,
  closed,
  line_too_long,
  malformed_line,
  unexpected_line,
  engine_error,
  response_limit,
};

struct EngineProtocolError final {
  EngineProtocolErrorCode code;
  std::string message;
};

struct EngineProtocolLimits final {
  std::size_t max_line_bytes{8192};
  std::size_t max_prompt_tokens{262144};
  std::size_t max_generated_tokens{262144};
  std::uint32_t max_new_tokens{262144};
};

// The original Strata profile has no prefill progress record. The separately
// built LightTransport GLM-5.3 engine may emit its documented PP progress
// record while it reads a prompt. This is an explicit engine-wire contract,
// never auto-detected from untrusted output.
enum class EngineProtocolFlavor {
  strata_0143,
  lighttransport_glm53,
};

struct EngineReady final {
  std::uint32_t max_context_tokens;
  bool supports_stop;
};

struct EngineGeneration final {
  std::vector<std::uint32_t> token_ids;
  std::string done_line;
};

// Serial, fail-closed client for Strata's documented solo --serve protocol:
// READY <context> [stop], GEN <max_new> <comma-separated token ids>, T <id>,
// DONE ..., ERR ..., STOP and QUIT. The explicitly selected LightTransport
// GLM-5.3 flavor also recognizes its bounded PP prefill heartbeat; all other
// extensions are rejected rather than guessed at.
class EngineProtocolClient final {
 public:
  explicit EngineProtocolClient(EngineLineTransport& transport,
                                EngineProtocolLimits limits = {},
                                EngineProtocolFlavor flavor = EngineProtocolFlavor::strata_0143);

  [[nodiscard]] std::optional<EngineProtocolError> await_ready(std::chrono::milliseconds timeout,
                                                                 EngineReady& ready);
  [[nodiscard]] std::optional<EngineProtocolError> begin_generation(
      std::uint32_t max_new_tokens, const std::vector<std::uint32_t>& prompt_token_ids);
  // Reads until DONE. A timeout leaves a generation active so the caller may
  // issue STOP and continue draining; all malformed/terminal failures close it.
  [[nodiscard]] std::optional<EngineProtocolError> read_generation(
      std::chrono::milliseconds timeout, EngineGeneration& generation);
  [[nodiscard]] std::optional<EngineProtocolError> stop();
  [[nodiscard]] std::optional<EngineProtocolError> quit();

  [[nodiscard]] bool ready() const noexcept;
  [[nodiscard]] bool generating() const noexcept;
  [[nodiscard]] bool closed() const noexcept;

 private:
  enum class State { waiting_ready, idle, generating, closed, failed };

  EngineLineTransport& transport_;
  EngineProtocolLimits limits_;
  EngineProtocolFlavor flavor_;
  State state_{State::waiting_ready};
  EngineGeneration active_generation_;
  bool supports_stop_{false};
  bool stop_requested_{false};

  [[nodiscard]] std::optional<EngineProtocolError> write_command(std::string_view command);
  [[nodiscard]] std::optional<EngineProtocolError> validate_incoming(std::string_view line) const;
  [[nodiscard]] std::optional<EngineProtocolError> fail(EngineProtocolErrorCode code,
                                                         std::string message);
};

}  // namespace secure_frontend

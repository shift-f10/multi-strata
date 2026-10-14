#include "secure_frontend/engine_protocol_client.hpp"

#include "secure_frontend/deadline.hpp"

#include <algorithm>
#include <charconv>
#include <limits>

namespace secure_frontend {
namespace {

bool ascii_printable(const std::string_view text) {
  for (const unsigned char character : text) {
    if (character < 0x20U || character > 0x7eU) return false;
  }
  return true;
}

bool nonnegative_decimal_metric(const std::string_view text) {
  if (text.empty()) return false;
  bool seen_digit = false;
  bool seen_dot = false;
  for (const char character : text) {
    if (character >= '0' && character <= '9') {
      seen_digit = true;
      continue;
    }
    if (character == '.' && !seen_dot) {
      seen_dot = true;
      continue;
    }
    return false;
  }
  return seen_digit;
}

template <typename Number>
bool parse_decimal(const std::string_view text, Number& value) {
  if (text.empty()) return false;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  return error == std::errc{} && end == text.data() + text.size();
}

std::vector<std::string_view> fields(const std::string_view line) {
  std::vector<std::string_view> result;
  std::size_t begin = 0;
  while (begin < line.size()) {
    const auto end = line.find(' ', begin);
    if (end == std::string_view::npos) {
      result.push_back(line.substr(begin));
      break;
    }
    result.push_back(line.substr(begin, end - begin));
    begin = end + 1;
  }
  return result;
}

}  // namespace

bool is_engine_fatal_line(const std::string_view line) noexcept {
  return std::any_of(kEngineFatalPrefixes.begin(), kEngineFatalPrefixes.end(),
                     [line](const std::string_view prefix) { return line.substr(0, prefix.size()) == prefix; });
}

EngineProtocolClient::EngineProtocolClient(EngineLineTransport& transport,
                                           const EngineProtocolLimits limits,
                                           const EngineProtocolFlavor flavor)
    : transport_(transport),
      limits_(limits),
      flavor_(flavor),
      effective_max_line_bytes_(limits.max_line_bytes != 0U ? limits.max_line_bytes : kDefaultInboundLineBytes) {}

std::size_t EngineProtocolClient::inbound_max_line_bytes() const noexcept {
  return limits_.max_line_bytes != 0U ? limits_.max_line_bytes : kDefaultInboundLineBytes;
}

std::optional<EngineProtocolError> EngineProtocolClient::fail(const EngineProtocolErrorCode code,
                                                              std::string message) {
  state_ = State::failed;
  failure_code_ = code;
  return EngineProtocolError{code, std::move(message)};
}

std::optional<EngineProtocolError> EngineProtocolClient::validate_incoming(const std::string_view line) const {
  if (line.empty() || line.size() > inbound_max_line_bytes()) {
    return EngineProtocolError{line.empty() ? EngineProtocolErrorCode::malformed_line
                                             : EngineProtocolErrorCode::line_too_long,
                               "engine sent an empty or oversized protocol line"};
  }
  if (!ascii_printable(line)) {
    return EngineProtocolError{EngineProtocolErrorCode::malformed_line,
                               "engine sent a non-ASCII or control protocol line"};
  }
  return std::nullopt;
}

std::optional<EngineProtocolError> EngineProtocolClient::write_command(const std::string_view command) {
  if (command.empty() || command.size() > effective_max_line_bytes_ || !ascii_printable(command)) {
    return fail(EngineProtocolErrorCode::invalid_argument, "outbound protocol command is invalid");
  }
  std::string transport_error;
  if (!transport_.write_line(command, transport_error)) {
    return fail(EngineProtocolErrorCode::transport_write_failed,
                transport_error.empty() ? "engine command write failed" : transport_error);
  }
  return std::nullopt;
}

std::optional<EngineProtocolError> EngineProtocolClient::await_ready(const std::chrono::milliseconds timeout,
                                                                      EngineReady& ready) {
  if (state_ != State::waiting_ready) {
    return EngineProtocolError{EngineProtocolErrorCode::invalid_state, "engine is not awaiting READY"};
  }
  const auto deadline = deadline_after(timeout);
  while (true) {
    const auto remaining = remaining_until(deadline);
    if (remaining.count() == 0) {
      return EngineProtocolError{EngineProtocolErrorCode::timeout, "engine did not report READY before timeout"};
    }
    const auto response = transport_.read_line(remaining);
    if (response.kind == EngineReadKind::timeout) {
      return EngineProtocolError{EngineProtocolErrorCode::timeout, "engine did not report READY before timeout"};
    }
    if (response.kind == EngineReadKind::closed) return fail(EngineProtocolErrorCode::closed, "engine closed before READY");
    if (response.kind == EngineReadKind::failure) {
      return fail(EngineProtocolErrorCode::transport_read_failed,
                  response.message.empty() ? "engine READY read failed" : response.message);
    }
    if (const auto validation = validate_incoming(response.line); validation.has_value()) {
      return fail(validation->code, validation->message);
    }
    if (is_engine_fatal_line(response.line)) {
      return fail(EngineProtocolErrorCode::fatal_engine_line, "engine reported a fatal verification failure");
    }
    const auto parsed = fields(response.line);
    if (parsed.size() >= 2 && parsed.front() == "INFO") continue;
    if (parsed.size() < 2 || parsed.front() != "READY") {
      return fail(EngineProtocolErrorCode::unexpected_line, "engine did not report a valid READY line");
    }
    std::uint32_t context = 0;
    if (!parse_decimal(parsed[1], context) || context == 0) {
      return fail(EngineProtocolErrorCode::malformed_line, "engine READY context is invalid");
    }
    bool can_stop = false;
    for (std::size_t index = 2; index < parsed.size(); ++index) {
      if (parsed[index].empty()) return fail(EngineProtocolErrorCode::malformed_line, "engine READY contains empty field");
      if (parsed[index] == "stop") can_stop = true;
    }
    ready = EngineReady{context, can_stop};
    // The engine reads stdin lines without bound, so the frontend caps its own
    // GEN line: a full-context prompt of 10-digit ids plus separators and header,
    // clamped to the transport's hard write cap so a huge advertised context
    // yields a clean invalid_argument instead of a write the transport refuses.
    effective_max_line_bytes_ = limits_.max_line_bytes != 0U
        ? limits_.max_line_bytes
        : std::min<std::size_t>(32U + 11U * static_cast<std::size_t>(context), kProtocolMaxLineBytes);
    supports_stop_ = can_stop;
    state_ = State::idle;
    return std::nullopt;
  }
}

std::optional<EngineProtocolError> EngineProtocolClient::begin_generation(
    const std::uint32_t max_new_tokens, const std::vector<std::uint32_t>& prompt_token_ids) {
  if (state_ != State::idle) return EngineProtocolError{EngineProtocolErrorCode::invalid_state, "engine is not idle"};
  if (max_new_tokens == 0 || max_new_tokens > limits_.max_new_tokens || prompt_token_ids.empty() ||
      prompt_token_ids.size() > limits_.max_prompt_tokens) {
    return EngineProtocolError{EngineProtocolErrorCode::invalid_argument, "generation request exceeds protocol limits"};
  }
  std::string command = "GEN " + std::to_string(max_new_tokens) + " ";
  for (std::size_t index = 0; index < prompt_token_ids.size(); ++index) {
    if (index != 0) command.push_back(',');
    command += std::to_string(prompt_token_ids[index]);
    if (command.size() > effective_max_line_bytes_) {
      return EngineProtocolError{EngineProtocolErrorCode::invalid_argument, "generation command exceeds line limit"};
    }
  }
  if (const auto error = write_command(command); error.has_value()) return error;
  active_generation_ = EngineGeneration{};
  stop_requested_ = false;
  state_ = State::generating;
  return std::nullopt;
}

std::optional<EngineProtocolError> EngineProtocolClient::read_generation(const std::chrono::milliseconds timeout,
                                                                          EngineGeneration& generation) {
  if (state_ != State::generating) return EngineProtocolError{EngineProtocolErrorCode::invalid_state, "no generation is active"};
  generation = active_generation_;
  const auto deadline = deadline_after(timeout);
  while (true) {
    const auto remaining = remaining_until(deadline);
    if (remaining.count() == 0) {
      return EngineProtocolError{EngineProtocolErrorCode::timeout, "engine generation read timed out"};
    }
    const auto response = transport_.read_line(remaining);
    if (response.kind == EngineReadKind::timeout) {
      return EngineProtocolError{EngineProtocolErrorCode::timeout, "engine generation read timed out"};
    }
    if (response.kind == EngineReadKind::closed) return fail(EngineProtocolErrorCode::closed, "engine closed during generation");
    if (response.kind == EngineReadKind::failure) {
      return fail(EngineProtocolErrorCode::transport_read_failed,
                  response.message.empty() ? "engine generation read failed" : response.message);
    }
    if (const auto validation = validate_incoming(response.line); validation.has_value()) {
      return fail(validation->code, validation->message);
    }
    if (is_engine_fatal_line(response.line)) {
      return fail(EngineProtocolErrorCode::fatal_engine_line, "engine reported a fatal verification failure");
    }
    if (response.line.rfind("T ", 0) == 0) {
      const auto token_text = std::string_view(response.line).substr(2);
      std::uint32_t token = 0;
      if (!parse_decimal(token_text, token)) return fail(EngineProtocolErrorCode::malformed_line, "engine token line is invalid");
      if (active_generation_.token_ids.size() >= limits_.max_generated_tokens) {
        return fail(EngineProtocolErrorCode::response_limit, "engine exceeded generated-token limit");
      }
      active_generation_.token_ids.push_back(token);
      generation = active_generation_;
      continue;
    }
    if (response.line.rfind("PP ", 0) == 0) {
      // PP is allowed only for the startup-selected GLM wire profile. Its
      // exact shape is either `PP <read> <total>` or the extended
      // `PP <read> <total> <milliseconds> <tokens-per-second>` form. It is a
      // private prefill heartbeat, not client-visible output.
      const auto progress = fields(response.line);
      std::uint32_t read = 0;
      std::uint32_t total = 0;
      const bool extended = progress.size() == 5U &&
          nonnegative_decimal_metric(progress[3]) && nonnegative_decimal_metric(progress[4]);
      if (flavor_ != EngineProtocolFlavor::lighttransport_glm53 ||
          (progress.size() != 3U && !extended) || !parse_decimal(progress[1], read) ||
          !parse_decimal(progress[2], total) || total == 0U || read > total) {
        return fail(EngineProtocolErrorCode::unexpected_line,
                    "engine emitted an invalid or unsupported prefill progress line");
      }
      continue;
    }
    if (response.line.rfind("DONE ", 0) == 0 && response.line.size() > 5) {
      active_generation_.done_line = response.line;
      generation = active_generation_;
      state_ = State::idle;
      // Full record: DONE <generated> <prompt> <prompt_ms> <decode_ms> <finish> ...
      // A nonfinite finish means the engine's NaN guard tripped: no usable
      // output, but the engine is alive and resets on the next GEN, so this
      // fails the request without failing the protocol.
      const auto done_fields = fields(response.line);
      if (done_fields.size() >= 6U && done_fields[5] == "nonfinite") {
        return EngineProtocolError{EngineProtocolErrorCode::engine_error, "engine reported a non-finite result"};
      }
      return std::nullopt;
    }
    if (response.line.rfind("ERR", 0) == 0 && (response.line.size() == 3 || response.line[3] == ' ')) {
      return fail(EngineProtocolErrorCode::engine_error, response.line);
    }
    return fail(EngineProtocolErrorCode::unexpected_line, "engine emitted an unexpected generation line");
  }
}

std::optional<EngineProtocolError> EngineProtocolClient::stop() {
  if (state_ != State::generating) return EngineProtocolError{EngineProtocolErrorCode::invalid_state, "no generation is active"};
  if (!supports_stop_) return EngineProtocolError{EngineProtocolErrorCode::invalid_state, "engine did not advertise STOP support"};
  if (stop_requested_) return std::nullopt;
  if (const auto error = write_command("STOP"); error.has_value()) return error;
  stop_requested_ = true;
  return std::nullopt;
}

std::optional<EngineProtocolError> EngineProtocolClient::quit() {
  if (state_ == State::closed) return std::nullopt;
  if (state_ == State::failed) return EngineProtocolError{EngineProtocolErrorCode::invalid_state, "engine protocol has failed"};
  if (const auto error = write_command("QUIT"); error.has_value()) return error;
  state_ = State::closed;
  return std::nullopt;
}

void EngineProtocolClient::abandon() noexcept {
  state_ = State::failed;
  if (!failure_code_) failure_code_ = EngineProtocolErrorCode::abandoned;  // ignored STOP: drain failed (§3.5(3))
}

bool EngineProtocolClient::ready() const noexcept { return state_ == State::idle || state_ == State::generating; }
bool EngineProtocolClient::generating() const noexcept { return state_ == State::generating; }
bool EngineProtocolClient::idle() const noexcept { return state_ == State::idle; }
bool EngineProtocolClient::closed() const noexcept { return state_ == State::closed || state_ == State::failed; }

}  // namespace secure_frontend

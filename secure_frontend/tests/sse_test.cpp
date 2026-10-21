#include "secure_frontend/api_constants.hpp"
#include "secure_frontend/sse_encoder.hpp"
#include "secure_frontend/utf8_stream_decoder.hpp"
#include "support/test_support.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

using secure_frontend::Utf8StreamDecoder;

int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}
const std::string kR{secure_frontend::kReplacementCharacter};

void utf8_split_across_tokens_is_held_then_released() {
  Utf8StreamDecoder decoder;
  expect(decoder.push("A\xE2") == "A", "ASCII released, a lead byte held");
  expect(decoder.held_bytes() == 1U, "one byte held");
  expect(decoder.push("\x82").empty(), "still incomplete");
  expect(decoder.push("\xAC") == "\xE2\x82\xAC", "the euro sign released whole");
  expect(decoder.push("\xF0\x9F").empty() && decoder.push("\x98\x80!") == "\xF0\x9F\x98\x80!", "4-byte sequence across tokens");
  expect(decoder.finish(false).empty() && decoder.held_bytes() == 0U, "nothing held at the end");
}

void utf8_invalid_sequence_becomes_replacement_character() {
  Utf8StreamDecoder decoder;
  expect(decoder.push("a\x80" "b") == "a" + kR + "b", "lone continuation byte");
  expect(decoder.push("\xC0\xAF") == kR + kR, "overlong lead C0 and its continuation");
  expect(decoder.push("\xE2\x82" "A") == kR + "A", "truncated sequence then ASCII: one U+FFFD");
  expect(decoder.push("\xED\xA0\x80") == kR + kR + kR, "surrogate encoding");
  expect(decoder.push("\xF5\xFF") == kR + kR, "bytes that never start a sequence");
  expect(decoder.push("\xF4\x90\x80\x80") == kR + kR + kR + kR, "above U+10FFFF");
  expect(decoder.push("ok") == "ok", "the decoder continues after invalid input");
}

void utf8_incomplete_tail_dropped_on_length_and_cancel() {
  Utf8StreamDecoder decoder;
  expect(decoder.push("ok\xF0\x9F\x98") == "ok", "three bytes of an emoji held");
  expect(decoder.finish(true).empty(), "length/cancel end: the cut tail is dropped");
  expect(decoder.held_bytes() == 0U, "finish resets the decoder");
}

void utf8_incomplete_tail_on_stop_becomes_one_replacement() {
  Utf8StreamDecoder decoder;
  expect(decoder.push("ok\xE2\x82") == "ok", "two bytes held");
  expect(decoder.finish(false) == kR, "stop end: the tail is one U+FFFD");
}

// SP3 M2 Task 6: the SSE encoder.
const secure_frontend::SseIdentity kIdentity{"chatcmpl-0123456789abcdef0123456789abcdef", 1760000000, "fake-model"};

// True when the only LF bytes are the event's own "\n\n" terminator.
bool single_line_event(const std::string& event) {
  return event.size() >= 2U && event.compare(event.size() - 2U, 2U, "\n\n") == 0 && event.find('\n') == event.size() - 2U;
}

void sse_events_never_contain_raw_newline() {
  const std::string hostile = "a\nb\r\nc\x01\"\\\xE2\x80\xA8 end";
  const std::vector<std::string> events{
      secure_frontend::render_role_event(kIdentity), secure_frontend::render_content_event(kIdentity, hostile),
      secure_frontend::render_final_event(kIdentity, "stop"), secure_frontend::render_usage_event(kIdentity, 3, 4),
      secure_frontend::render_error_event(secure_frontend::ApiError::engine_error)};
  for (const auto& event : events) {
    expect(single_line_event(event), "one line per event: " + event);
    expect(event.rfind("data: {", 0) == 0, "every event is a data line");
    expect(event.find('\r') == std::string::npos, "no raw CR either");
  }
  expect(events[1].find(R"("content":"a\nb\r\nc\u0001\"\\)") != std::string::npos, "escaped by the shared writer: " + events[1]);
  expect(events[4] == R"(data: {"error":{"message":")" + std::string(secure_frontend::api_error_row(secure_frontend::ApiError::engine_error).message) +
                         R"(","type":"server_error","param":null,"code":"engine_error"}})" "\n\n",
         "OpenAI error shape with the fixed §7.2 message");
}

void sse_coalesced_control_heavy_text_respects_event_cap() {
  const std::string pattern = std::string("\"\\\x01\x1f") + "\xC3\xA9" + "\xF0\x9F\x98\x80" + "x";  // 4 escapes, 2-byte, 4-byte, ASCII
  std::string text;
  while (text.size() < 1048576U) text += pattern;
  std::string rebuilt;
  std::size_t events = 0;
  for (std::string_view rest = text; !rest.empty();) {
    const std::size_t size = secure_frontend::next_delta_size(rest);
    expect(size > 0U && size <= secure_frontend::api_constants::kMaxDeltaTextBytes, "delta within 16 KiB");
    secure_frontend::Utf8StreamDecoder check;
    const std::string_view delta = rest.substr(0, size);
    expect(check.push(delta) == delta && check.held_bytes() == 0U, "delta ends on a code-point boundary");
    const auto event = secure_frontend::render_content_event(kIdentity, delta);
    expect(event.size() <= secure_frontend::api_constants::kMaxSseEventBytes, "event within 128 KiB: " + std::to_string(event.size()));
    rebuilt += delta;
    rest.remove_prefix(size);
    ++events;
  }
  expect(rebuilt == text, "deltas concatenate to the text");
  expect(events >= 64U, "1 MiB is split into at least 64 deltas");
  const std::string worst(secure_frontend::api_constants::kMaxDeltaTextBytes, '\x01');
  expect(secure_frontend::render_content_event(kIdentity, worst).size() <= secure_frontend::api_constants::kMaxSseEventBytes, "6x escape growth fits the cap");
}

void sse_chunk_framing_units() {
  expect(secure_frontend::frame_chunk("data: [DONE]\n\n") == "e\r\ndata: [DONE]\n\n\r\n", "hex size, CRLF, bytes, CRLF");
  expect(secure_frontend::kChunkedTerminator == "0\r\n\r\n", "terminal chunk");
}

}  // namespace

int main(int argc, char* argv[]) {
  return secure_frontend_test::run_cases(argc, argv,
                                         {
                                             {"utf8_split_across_tokens_is_held_then_released", utf8_split_across_tokens_is_held_then_released},
                                             {"utf8_invalid_sequence_becomes_replacement_character", utf8_invalid_sequence_becomes_replacement_character},
                                             {"utf8_incomplete_tail_dropped_on_length_and_cancel", utf8_incomplete_tail_dropped_on_length_and_cancel},
                                             {"utf8_incomplete_tail_on_stop_becomes_one_replacement", utf8_incomplete_tail_on_stop_becomes_one_replacement},
                                             {"sse_events_never_contain_raw_newline", sse_events_never_contain_raw_newline},
                                             {"sse_coalesced_control_heavy_text_respects_event_cap", sse_coalesced_control_heavy_text_respects_event_cap},
                                             {"sse_chunk_framing_units", sse_chunk_framing_units},
                                         },
                                         failures);
}

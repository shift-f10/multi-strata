#include "secure_frontend/utf8_stream_decoder.hpp"
#include "support/test_support.hpp"

#include <iostream>
#include <string>

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

}  // namespace

int main(int argc, char* argv[]) {
  return secure_frontend_test::run_cases(argc, argv,
                                         {
                                             {"utf8_split_across_tokens_is_held_then_released", utf8_split_across_tokens_is_held_then_released},
                                             {"utf8_invalid_sequence_becomes_replacement_character", utf8_invalid_sequence_becomes_replacement_character},
                                             {"utf8_incomplete_tail_dropped_on_length_and_cancel", utf8_incomplete_tail_dropped_on_length_and_cancel},
                                             {"utf8_incomplete_tail_on_stop_becomes_one_replacement", utf8_incomplete_tail_on_stop_becomes_one_replacement},
                                         },
                                         failures);
}

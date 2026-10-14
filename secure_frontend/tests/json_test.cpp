#include "secure_frontend/json.hpp"
#include "support/test_support.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <variant>

namespace {
int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}
constexpr secure_frontend::JsonLimits kLimits{.max_bytes = 4096, .max_depth = 4, .max_container_entries = 64,
                                              .max_string_bytes = 256};

bool fails_with(const std::string& text, const secure_frontend::JsonErrorCode code,
                const secure_frontend::JsonLimits& limits = kLimits) {
  const auto result = secure_frontend::parse_json(text, limits);
  const auto* error = std::get_if<secure_frontend::JsonError>(&result);
  return error != nullptr && error->code == code;
}

void json_accepts_strict_document() {
  const auto result = secure_frontend::parse_json(
      R"( {"a": 1, "b": [true, false, null], "c": {"d": "xé\n"}, "e": -9223372036854775808} )", kLimits);
  const auto* value = std::get_if<secure_frontend::JsonValue>(&result);
  expect(value != nullptr && value->if_object() != nullptr, "a strict document must parse");
  if (value == nullptr || value->if_object() == nullptr) return;
  const auto& members = *value->if_object();
  expect(members.size() == 4U && members[0].key == "a" && *members[0].value.if_integer() == 1,
         "members keep their order and integer values");
  expect(members[2].value.if_object() != nullptr &&
             *(*members[2].value.if_object())[0].value.if_string() == "x\xC3\xA9\n",
         "escapes decode to UTF-8");
  expect(*members[3].value.if_integer() == INT64_MIN, "the int64 minimum is representable");
}

void json_rejects_duplicate_keys() {
  expect(fails_with(R"({"a":1,"a":2})", secure_frontend::JsonErrorCode::duplicate_key), "top-level duplicate");
  expect(fails_with(R"({"o":{"k":1,"x":0,"k":1}})", secure_frontend::JsonErrorCode::duplicate_key), "nested duplicate");
  expect(fails_with(R"({"a":1,"\u0061":2})", secure_frontend::JsonErrorCode::duplicate_key),
         "duplicates compare decoded keys");
}

void json_rejects_depth_over_limit() {
  expect(std::holds_alternative<secure_frontend::JsonValue>(secure_frontend::parse_json("[[[[1]]]]", kLimits)),
         "depth 4 is allowed");
  expect(fails_with("[[[[[1]]]]]", secure_frontend::JsonErrorCode::depth_exceeded), "depth 5 is rejected");
  expect(fails_with(R"({"a":{"b":{"c":{"d":{}}}}})", secure_frontend::JsonErrorCode::depth_exceeded),
         "object nesting counts the same way");
}

void json_rejects_non_integer_numbers() {
  for (const char* text : {"1.0", "8080.0", "1e3", "1E3", "-0.5", "[2.5]"}) {
    expect(fails_with(text, secure_frontend::JsonErrorCode::non_integer_number), std::string{"non-integer: "} + text);
  }
  for (const char* text : {"+1", "01", "-", ".5"}) {
    expect(fails_with(text, secure_frontend::JsonErrorCode::syntax), std::string{"malformed number: "} + text);
  }
  // The reader takes "0" as a complete number and then finds "x10" after the document.
  expect(fails_with("0x10", secure_frontend::JsonErrorCode::trailing_data), "hex is not a JSON number: 0x10");
  expect(fails_with("9223372036854775808", secure_frontend::JsonErrorCode::integer_out_of_range), "int64 overflow");
}

void json_rejects_bom_trailing_data_and_comments() {
  expect(fails_with("\xEF\xBB\xBF{}", secure_frontend::JsonErrorCode::byte_order_mark), "UTF-8 BOM");
  expect(fails_with("{} {}", secure_frontend::JsonErrorCode::trailing_data), "two documents");
  expect(fails_with(R"({"a":1,})", secure_frontend::JsonErrorCode::syntax), "trailing comma");
  expect(fails_with("{\"a\":1 // c\n}", secure_frontend::JsonErrorCode::syntax), "comment");
  expect(fails_with("{\"a\":\"\x01\"}", secure_frontend::JsonErrorCode::invalid_string), "raw control byte");
  expect(fails_with(R"({"a":"\ud800"})", secure_frontend::JsonErrorCode::invalid_string), "lone surrogate");
  expect(fails_with("{\"a\":\"\xFF\"}", secure_frontend::JsonErrorCode::invalid_string), "invalid UTF-8");
}

void json_enforces_size_entry_and_string_limits() {
  const secure_frontend::JsonLimits tiny{.max_bytes = 8, .max_depth = 4, .max_container_entries = 2, .max_string_bytes = 3};
  expect(fails_with("[1,2,3,4,5]", secure_frontend::JsonErrorCode::too_large, tiny), "document size");
  expect(fails_with("[1,2,3]", secure_frontend::JsonErrorCode::too_many_entries, tiny), "entry count");
  expect(fails_with(R"(["abcd"])", secure_frontend::JsonErrorCode::string_too_long, tiny), "string length");
}

void json_string_escaper_round_trips() {
  std::string out;
  secure_frontend::append_json_string(&out, std::string{"q\"b\\n\n\x01"});
  expect(out == "\"q\\\"b\\\\n\\n\\u0001\"", "escaper output: " + out);
  const auto parsed = secure_frontend::parse_json(out, kLimits);
  const auto* value = std::get_if<secure_frontend::JsonValue>(&parsed);
  expect(value != nullptr && value->if_string() != nullptr && *value->if_string() == std::string{"q\"b\\n\n\x01"},
         "escaped text parses back to the original");
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"json_accepts_strict_document", json_accepts_strict_document},
      {"json_rejects_duplicate_keys", json_rejects_duplicate_keys},
      {"json_rejects_depth_over_limit", json_rejects_depth_over_limit},
      {"json_rejects_non_integer_numbers", json_rejects_non_integer_numbers},
      {"json_rejects_bom_trailing_data_and_comments", json_rejects_bom_trailing_data_and_comments},
      {"json_enforces_size_entry_and_string_limits", json_enforces_size_entry_and_string_limits},
      {"json_string_escaper_round_trips", json_string_escaper_round_trips},
  }, failures);
}

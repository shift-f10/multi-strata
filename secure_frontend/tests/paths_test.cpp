#include "secure_frontend/canonical_path.hpp"
#include "support/test_support.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <variant>

namespace {
int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}
using secure_frontend::PathErrorCode;

bool rejects(const std::string& text, const PathErrorCode code) {
  const auto result = secure_frontend::parse_relative_path(text);
  const auto* error = std::get_if<secure_frontend::PathError>(&result);
  return error != nullptr && error->code == code;
}

void relative_path_accepts_portable_forms() {
  for (const char* text : {"model.gguf", "qwen/model-00001-of-00004.gguf", "Jos\xC3\xA9/mod\xC3\xA8le.gguf", "x~y", "~",
                           "CONSOLE", "COM10", "LPT", "NULL.txt", "con-fig"}) {
    expect(std::holds_alternative<secure_frontend::RelativePath>(secure_frontend::parse_relative_path(text)),
           std::string{"portable path must be accepted: "} + text);
  }
  const auto normalized = secure_frontend::parse_relative_path("a\\b\\c.gguf");
  const auto* path = std::get_if<secure_frontend::RelativePath>(&normalized);
  expect(path != nullptr && path->generic() == "a/b/c.gguf" && path->components().size() == 3U,
         "a backslash is accepted on input and normalized to '/'");
  expect(rejects("\xFF", PathErrorCode::invalid_utf8), "invalid UTF-8");
  expect(rejects(std::string(1025, 'a'), PathErrorCode::too_long), "total length is at most 1024 bytes");
  expect(rejects(std::string(256, 'a'), PathErrorCode::component_too_long), "a component is at most 255 bytes");
}

void cfg02_rejects_traversal_and_absolute() {
  for (const char* text : {"..", "../x", "a/../b", "a/..", ".", "a/./b"}) {
    expect(rejects(text, PathErrorCode::traversal), std::string{"traversal: "} + text);
  }
  for (const char* text : {"/etc/passwd", "\\x", "\\\\server\\share\\x", "\\\\?\\C:\\x", "//x"}) {
    expect(rejects(text, PathErrorCode::absolute), std::string{"absolute or UNC: "} + text);
  }
  for (const char* text : {"", "a//b", "a/", "a\\\\b"}) {
    expect(rejects(text, PathErrorCode::empty), std::string{"empty component: "} + text);
  }
}

void cfg02_rejects_nul_and_control_bytes() {
  for (const std::string& text : {std::string("a\0b", 3), std::string("a\nb"), std::string("a\tb"), std::string("a\x7f"),
                                 std::string("\x01")}) {
    expect(rejects(text, PathErrorCode::control_character), "control byte must be rejected");
  }
}

void cfg04_rejects_reserved_and_device_names() {
  for (const char* text : {"CON", "con", "Con.txt", "nul.gguf", "AUX", "PRN.log", "COM0", "COM1", "com9.x", "LPT0",
                           "LPT9", "COM\xC2\xB9", "LPT\xC2\xB3.txt", "CONIN$", "conout$", "CLOCK$", "dir/NUL/file",
                           "CON .txt"}) {
    expect(rejects(text, PathErrorCode::reserved_name), std::string{"reserved device name: "} + text);
  }
}

void cfg04_rejects_trailing_dot_space_and_8dot3() {
  for (const char* text : {"model.", "model ", "dir./x", "dir /x"}) {
    expect(rejects(text, PathErrorCode::trailing_dot_or_space), std::string{"trailing dot or space: "} + text);
  }
  for (const char* text : {"PROGRA~1", "MODEL~2.GGU", "a/b~1/c"}) {
    expect(rejects(text, PathErrorCode::short_name_alias), std::string{"8.3 alias: "} + text);
  }
}

void cfg04_rejects_ads_and_drive_forms() {
  for (const char* text : {"C:x", "C:\\x", "model.gguf:stream", "model.gguf::$DATA", "a/b:c"}) {
    expect(rejects(text, PathErrorCode::drive_or_stream), std::string{"drive or stream: "} + text);
  }
  for (const char* text : {"a<b", "a>b", "a\"b", "a|b", "a?b", "a*b"}) {
    expect(rejects(text, PathErrorCode::invalid_character), std::string{"invalid character: "} + text);
  }
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"relative_path_accepts_portable_forms", relative_path_accepts_portable_forms},
      {"cfg02_rejects_traversal_and_absolute", cfg02_rejects_traversal_and_absolute},
      {"cfg02_rejects_nul_and_control_bytes", cfg02_rejects_nul_and_control_bytes},
      {"cfg04_rejects_reserved_and_device_names", cfg04_rejects_reserved_and_device_names},
      {"cfg04_rejects_trailing_dot_space_and_8dot3", cfg04_rejects_trailing_dot_space_and_8dot3},
      {"cfg04_rejects_ads_and_drive_forms", cfg04_rejects_ads_and_drive_forms},
  }, failures);
}

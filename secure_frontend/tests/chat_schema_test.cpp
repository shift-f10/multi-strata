#include "secure_frontend/chat_schema.hpp"
#include "support/test_support.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {
int failures = 0;
void expect(bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}

void parses_minimal_text_request() {
  const auto request = secure_frontend::parse_chat_completion_request(
      R"({"model":"local-model.Q4_K_M","messages":[{"role":"system","content":"Be concise."},{"role":"user","content":"Hello"}],"max_tokens":42,"stream":false})");
  expect(request.has_value(), "valid text-only request should parse");
  if (!request) return;
  expect(request->model == "local-model.Q4_K_M", "model should be retained");
  expect(request->messages.size() == 2U, "messages should be retained");
  expect(request->messages[1].content == "Hello", "content should be retained");
  expect(request->max_tokens == 42U, "max_tokens should be retained");
}

void rejects_unsupported_and_unsafe_features() {
  for (const std::string json : {
           R"({"model":"local","messages":[{"role":"user","content":"hi"}],"stream":true})",
           R"({"model":"local","messages":[{"role":"user","content":"hi"}],"tools":[]})",
           R"({"model":"local","messages":[{"role":"user","content":[{"type":"image_url"}]]})",
           R"({"model":"local","messages":[{"role":"user","content":"https://example.test/a"}]})",
           R"({"model":"mcp://remote","messages":[{"role":"user","content":"hi"}]})",
           R"({"model":"local","messages":[{"role":"tool","content":"hi"}]})",
           R"({"model":"local","messages":[{"role":"user","content":"hi","mcp":"x"}]})",
           R"({"model":"local","messages":[{"role":"user"}]})",
           R"({"model":"local","messages":[],"max_tokens":-1})",
       }) {
    expect(!secure_frontend::parse_chat_completion_request(json), "unsafe or unsupported request must fail closed");
  }
}

void rejects_duplicate_and_malformed_json() {
  expect(!secure_frontend::parse_chat_completion_request(
             R"({"model":"a","model":"b","messages":[{"role":"user","content":"x"}]})"),
         "duplicate keys must fail closed");
  expect(!secure_frontend::parse_chat_completion_request(
             R"({"model":"a","messages":[{"role":"user","content":"\ud800"}]})"),
         "unpaired UTF-16 surrogates must be rejected");
  expect(!secure_frontend::parse_chat_completion_request("{not json}"), "malformed JSON must fail closed");
}

void renders_escaped_minimal_response() {
  const auto request = secure_frontend::parse_chat_completion_request(
      R"({"model":"local","messages":[{"role":"user","content":"hi"}]})");
  expect(request.has_value(), "render fixture should parse");
  if (!request) return;
  const auto response = secure_frontend::render_chat_completion_response(*request, "quote \" slash \\ newline\n");
  expect(response.has_value(), "safe generated text should render");
  if (response) {
    expect(response->find("\"content\":\"quote \\\" slash \\\\ newline\\n\"") != std::string::npos,
           "generated text must be JSON escaped rather than interpolated");
    expect(response->find("\"stream\"") == std::string::npos, "response must be non-streaming only");
  }
}
// SP3 Task 15 (spec §3.5): the non-streaming OpenAI completion shape, exact bytes.
void renders_openai_completion_shape() {
  const auto body = secure_frontend::render_chat_completion({.id = "chatcmpl-0123456789abcdef0123456789abcdef", .created = 1791963785,
                                                             .model = "fake-model", .text = "Hi \"there\"\n", .finish_reason = "length",
                                                             .prompt_tokens = 7U, .completion_tokens = 3U});
  expect(body == std::optional<std::string>{
                      "{\"id\":\"chatcmpl-0123456789abcdef0123456789abcdef\",\"object\":\"chat.completion\",\"created\":1791963785,"
                      "\"model\":\"fake-model\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"Hi \\\"there\\\"\\n\"},"
                      "\"logprobs\":null,\"finish_reason\":\"length\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n"},
         "spec §3.5 shape: " + body.value_or("<nullopt>"));
  expect(!secure_frontend::render_chat_completion({.id = "x", .created = 0, .model = "m", .text = "\xff", .finish_reason = "stop",
                                                   .prompt_tokens = 0U, .completion_tokens = 0U}).has_value(), "invalid UTF-8 is refused");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"parses_minimal_text_request", parses_minimal_text_request},
      {"rejects_unsupported_and_unsafe_features", rejects_unsupported_and_unsafe_features},
      {"rejects_duplicate_and_malformed_json", rejects_duplicate_and_malformed_json},
      {"renders_escaped_minimal_response", renders_escaped_minimal_response},
      {"renders_openai_completion_shape", renders_openai_completion_shape},
  }, failures);
}

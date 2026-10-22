#include "secure_frontend/api_errors.hpp"
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

// SP5 M1 Task 12 (C-9 carve-out; Ruling T12-b): the content ARRAY opens only for a model
// the composition proved can read images (vision_capable = vision.enabled AND the manifest's
// launch.mmproj). Without the flag today's 400 unsupported_parameter "content" stands
// verbatim; with it, text/image_url parts parse into ChatMessage.parts, the image keeps its
// data URL, and the caps fire BEFORE any decode: max_n on the count (vision.max_n) and the
// base64 LENGTH bound on each URL (32 MiB decoded = the pin's IMAGE_URL_MAX, :2474).
void image_url_parts_accepted_only_for_vision_models() {
  const std::string body =
      R"({"model":"m","messages":[{"role":"user","content":[)"
      R"({"type":"text","text":"look"},)"
      R"({"type":"image_url","image_url":{"url":"data:image/png;base64,YWJj"}}]}]})";
  const auto plain = secure_frontend::parse_chat_request(body);  // default limits: no capability
  const auto* plain_error = std::get_if<secure_frontend::ChatRequestError>(&plain);
  expect(plain_error != nullptr && plain_error->error == secure_frontend::ApiError::unsupported_parameter &&
             plain_error->param == "content",
         "without mmproj the today-400 on content arrays stands (C-9: the carve-out is capability-gated)");
  expect(!secure_frontend::parse_chat_completion_request(body), "the optional-form gate keeps rejecting arrays");

  secure_frontend::ChatSchemaLimits vision;
  vision.vision_capable = true;
  const auto parsed = secure_frontend::parse_chat_request(body, vision);
  const auto* request = std::get_if<secure_frontend::ChatCompletionRequest>(&parsed);
  if (request == nullptr) {
    const auto* error = std::get_if<secure_frontend::ChatRequestError>(&parsed);
    expect(false, "a vision model accepts the parts array (got " +
                      std::string{error == nullptr ? "nothing" : secure_frontend::api_error_row(error->error).code} + ")");
    return;
  }
  expect(request->messages.size() == 1U && request->messages[0].parts.size() == 2U, "both parts are retained");
  expect(request->messages[0].content == "look", "the text parts still drive the content string");
  expect(request->messages[0].parts[1].image_data_url == "data:image/png;base64,YWJj", "the data URL survives verbatim");
}

void image_part_caps_and_shape_are_checked_before_decode() {
  secure_frontend::ChatSchemaLimits vision;
  vision.vision_capable = true;
  const auto image = [](const std::string& url) { return "{\"type\":\"image_url\",\"image_url\":{\"url\":\"" + url + "\"}}"; };
  const auto body = [&](const std::string& parts) {
    return std::string(R"({"model":"m","messages":[{"role":"user","content":[)") + parts + R"(]}]})";
  };
  const auto named_image = [&](const char* expect_why, const std::string& url) {
    const auto result = secure_frontend::parse_chat_request(body(image(url)), vision);
    const auto* error = std::get_if<secure_frontend::ChatRequestError>(&result);
    expect(error != nullptr && error->error == secure_frontend::ApiError::unsupported_parameter &&
               error->param == "image_url",
           expect_why);
  };
  vision.max_images = 1U;
  {
    // Two data-URL images where one is allowed: refused by name, before any decode.
    const auto second = secure_frontend::parse_chat_request(
        body(image("data:image/png;base64,YWJj") + "," + image("data:image/png;base64,YWJk")), vision);
    const auto* second_error = std::get_if<secure_frontend::ChatRequestError>(&second);
    expect(second_error != nullptr && second_error->error == secure_frontend::ApiError::unsupported_parameter &&
               second_error->param == "image_url",
           "max_n: a second image in one request is refused by name");
  }
  const auto two = secure_frontend::parse_chat_request(
      body(image("data:image/png;base64,YWJj") + "," + image("data:image/png;base64,YWJk")), vision);
  const auto* two_error = std::get_if<secure_frontend::ChatRequestError>(&two);
  expect(two_error != nullptr && two_error->error == secure_frontend::ApiError::unsupported_parameter &&
             two_error->param == "image_url",
         "over max_n names image_url");
  vision.max_images = 8U;
  secure_frontend::ChatSchemaLimits tiny_b64 = vision;
  tiny_b64.max_image_b64_chars = 8U;
  const auto long_url = "data:image/png;base64," + std::string(64U, 'A');
  const auto length_result = secure_frontend::parse_chat_request(body(image(long_url)), tiny_b64);
  const auto* length_error = std::get_if<secure_frontend::ChatRequestError>(&length_result);
  expect(length_error != nullptr && length_error->error == secure_frontend::ApiError::unsupported_parameter &&
             length_error->param == "image_url",
         "the base64 LENGTH cap fires first (never decoded, nothing staged)");
  // Shape strictness: unknown part keys, a missing/odd image_url member, and an empty array
  // are plain invalid_request — the plan's parts vocabulary is closed.
  for (const auto& bad : {body(R"({"type":"text","text":"a","extra":1})"),
                                body(R"({"type":"image_url","image_url":{}})"),
                                body(R"({"type":"image_url","image_url":"data:image/png;base64,YWJj"})"),
                                body(R"({"type":"file"})"),
                                std::string{"[]"},
                                body(R"({"type":"text"})")}) {
    expect(!std::holds_alternative<secure_frontend::ChatCompletionRequest>(secure_frontend::parse_chat_request(bad, vision)),
           "closed part vocabulary: " + bad);
  }
  // An http(s) URL is out for M1 (Ruling T12-a): the same fixed 400 naming image_url.
  named_image("http(s) image URLs are not fetched in M1", "https://example.test/a.png");
}

void rejects_unsupported_and_unsafe_features() {
  for (const std::string json : {
           R"({"model":"local","messages":[{"role":"user","content":"hi"}],"stream":"true"})",
           R"({"model":"local","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_usage":"yes"}}"),
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

// Issue 19: a Qwen3 think block comes back as message.reasoning_content beside the
// answer, written only when non-empty (upstream serve/server.py:5511-5513).
void renders_reasoning_content_beside_the_answer() {
  const auto body = secure_frontend::render_chat_completion({.id = "x", .created = 0, .model = "m", .text = "Paris.", .finish_reason = "stop",
                                                             .prompt_tokens = 1U, .completion_tokens = 2U,
                                                             .reasoning = "The capital\nis Paris."});
  expect(body.has_value() && body->find(R"("message":{"role":"assistant","content":"Paris.","reasoning_content":"The capital\nis Paris."})") !=
                                 std::string::npos,
         "reasoning_content follows content in the message: " + body.value_or("<nullopt>"));
  const auto plain = secure_frontend::render_chat_completion({.id = "x", .created = 0, .model = "m", .text = "Paris.", .finish_reason = "stop",
                                                              .prompt_tokens = 1U, .completion_tokens = 2U});
  expect(plain.has_value() && plain->find("reasoning_content") == std::string::npos, "no reasoning, no field");
  expect(!secure_frontend::render_chat_completion({.id = "x", .created = 0, .model = "m", .text = "ok", .finish_reason = "stop",
                                                   .prompt_tokens = 0U, .completion_tokens = 0U, .reasoning = "\xff"}).has_value(),
         "invalid UTF-8 reasoning is refused");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"parses_minimal_text_request", parses_minimal_text_request},
      {"image_url_parts_accepted_only_for_vision_models", image_url_parts_accepted_only_for_vision_models},
      {"image_part_caps_and_shape_are_checked_before_decode", image_part_caps_and_shape_are_checked_before_decode},
      {"rejects_unsupported_and_unsafe_features", rejects_unsupported_and_unsafe_features},
      {"rejects_duplicate_and_malformed_json", rejects_duplicate_and_malformed_json},
      {"renders_escaped_minimal_response", renders_escaped_minimal_response},
      {"renders_openai_completion_shape", renders_openai_completion_shape},
      {"renders_reasoning_content_beside_the_answer", renders_reasoning_content_beside_the_answer},
  }, failures);
}

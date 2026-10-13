#include "secure_frontend/chat_execution.hpp"

#include <chrono>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

std::string byte_symbol(const unsigned char byte) {
  if (byte >= 33U && byte <= 126U) return std::string(1U, static_cast<char>(byte));
  unsigned int printable_before = 0U;
  for (unsigned int value = 33U; value <= 126U && value < byte; ++value) ++printable_before;
  const unsigned int code_point = 256U + static_cast<unsigned int>(byte) - printable_before;
  return {static_cast<char>(0xc0U | (code_point >> 6U)),
          static_cast<char>(0x80U | (code_point & 0x3fU))};
}

secure_frontend::TokenizerPack tokenizer_for(const std::string& text) {
  secure_frontend::TokenizerPack pack;
  std::unordered_set<std::string> seen;
  for (const unsigned char byte : text) {
    const std::string token = byte_symbol(byte);
    if (seen.insert(token).second) pack.tokens_by_id.push_back(token);
  }
  pack.token_types.assign(pack.tokens_by_id.size(), 1);
  // The fixed Qwen renderer owns these framing literals.  They must be
  // modeled as tokenizer CONTROL tokens, never as ordinary user text.
  pack.tokens_by_id.push_back("<|im_start|>");
  pack.token_types.push_back(3);
  pack.tokens_by_id.push_back("<|im_end|>");
  pack.token_types.push_back(3);
  return pack;
}

std::size_t token_id_for(const secure_frontend::TokenizerPack& pack, const std::string& token) {
  for (std::size_t index = 0; index < pack.tokens_by_id.size(); ++index) {
    if (pack.tokens_by_id[index] == token) return index;
  }
  return pack.tokens_by_id.size();
}

class FakeTransport final : public secure_frontend::EngineLineTransport {
 public:
  std::deque<secure_frontend::EngineReadResult> reads;
  std::vector<std::string> writes;

  bool write_line(const std::string_view line, std::string&) override {
    writes.emplace_back(line);
    return true;
  }

  secure_frontend::EngineReadResult read_line(std::chrono::milliseconds) override {
    if (reads.empty()) return {secure_frontend::EngineReadKind::timeout, {}, {}};
    auto result = std::move(reads.front());
    reads.pop_front();
    return result;
  }
};

secure_frontend::EngineReadResult line(std::string value) {
  return {secure_frontend::EngineReadKind::line, std::move(value), {}};
}

secure_frontend::ChatCompletionRequest valid_request(const std::size_t max_tokens = 2U) {
  return {"qwen-local", {{"user", "Hi"}}, max_tokens};
}

secure_frontend::TokenizerPack glm_tokenizer_for(const std::string& text) {
  auto pack = tokenizer_for(text);
  // The Qwen control entries supplied by tokenizer_for are harmless here: the
  // GLM encoder allows only its own exact fixed control sequence.
  for (const std::string_view marker :
       {"[gMASK]", "<sop>", "<|system|>", "<|user|>", "<|assistant|>", "<think>"}) {
    pack.tokens_by_id.emplace_back(marker);
    pack.token_types.push_back(3);
  }
  return pack;
}

void executes_a_bounded_non_streaming_completion() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt + "OK");
  const auto output_o = token_id_for(tokenizer, "O");
  const auto output_k = token_id_for(tokenizer, "K");
  expect(output_o < tokenizer.tokens_by_id.size() && output_k < tokenizer.tokens_by_id.size(),
         "test tokenizer must include generated tokens");

  FakeTransport transport;
  transport.reads = {line("INFO private-engine"), line("READY 512"),
                     line("T " + std::to_string(output_o)),
                     line("T " + std::to_string(output_k)), line("DONE 2")};
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol);
  const auto result = service.execute(valid_request(), tokenizer);
  const auto* completion = std::get_if<secure_frontend::ChatExecutionResult>(&result);
  expect(completion != nullptr && completion->text == "OK" && completion->generated_tokens == 2U,
         "READY, GEN, token output, and local decode must compose into text");
  expect(transport.writes.size() == 1U && transport.writes.front().rfind("GEN 2 ", 0) == 0,
         "only canonical GEN may be sent to the local engine");

  transport.reads = {line("T " + std::to_string(output_o)), line("DONE 1")};
  const auto next_result = service.execute(valid_request(1U), tokenizer);
  const auto* next_completion = std::get_if<secure_frontend::ChatExecutionResult>(&next_result);
  expect(next_completion != nullptr && next_completion->text == "O" &&
             transport.writes.size() == 2U && transport.writes.back().rfind("GEN 1 ", 0) == 0,
         "an idle private engine may serve a second request without accepting a second READY");
}

void rejects_context_and_output_limits_before_generation() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto tokenizer = tokenizer_for(prompt);
  FakeTransport context_transport;
  context_transport.reads = {line("READY 1")};
  secure_frontend::EngineProtocolClient context_protocol(context_transport);
  secure_frontend::ChatExecutionService context_service(context_protocol);
  const auto context_result = context_service.execute(valid_request(), tokenizer);
  const auto* context_error = std::get_if<secure_frontend::ChatExecutionError>(&context_result);
  expect(context_error != nullptr &&
             context_error->code == secure_frontend::ChatExecutionErrorCode::context_limit_exceeded &&
             context_transport.writes.empty(),
         "context overflow must not emit GEN");

  FakeTransport limit_transport;
  limit_transport.reads = {line("READY 512")};
  secure_frontend::EngineProtocolClient limit_protocol(limit_transport);
  secure_frontend::ChatExecutionService limit_service(
      limit_protocol, {.maximum_prompt_tokens = 128U, .maximum_output_tokens = 1U});
  const auto limit_result = limit_service.execute(valid_request(2U), tokenizer);
  const auto* limit_error = std::get_if<secure_frontend::ChatExecutionError>(&limit_result);
  expect(limit_error != nullptr &&
             limit_error->code == secure_frontend::ChatExecutionErrorCode::invalid_request &&
             limit_transport.writes.empty(),
         "local output bound must reject before GEN");
}

void fails_closed_on_invalid_engine_output() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  auto tokenizer = tokenizer_for(prompt + "Z");
  const auto forbidden = token_id_for(tokenizer, "Z");
  expect(forbidden < tokenizer.token_types.size(), "test tokenizer must include forbidden output token");
  if (forbidden >= tokenizer.token_types.size()) return;
  tokenizer.token_types[forbidden] = 3;

  FakeTransport transport;
  transport.reads = {line("READY 512"), line("T " + std::to_string(forbidden)), line("DONE 1")};
  secure_frontend::EngineProtocolClient protocol(transport);
  secure_frontend::ChatExecutionService service(protocol);
  const auto result = service.execute(valid_request(1U), tokenizer);
  const auto* failure = std::get_if<secure_frontend::ChatExecutionError>(&result);
  expect(failure != nullptr &&
             failure->code == secure_frontend::ChatExecutionErrorCode::output_decode_failed,
         "CONTROL token output must fail closed rather than be returned as text");
}

void executes_glm53_only_when_explicitly_selected() {
  const std::string prompt = "[gMASK]<sop><|user|>Hi<|assistant|><think>";
  const auto tokenizer = glm_tokenizer_for(prompt + "OK");
  const auto output_o = token_id_for(tokenizer, "O");
  const auto output_k = token_id_for(tokenizer, "K");
  FakeTransport transport;
  transport.reads = {line("READY 512"), line("PP 8 16 2.0 4.0"), line("T " + std::to_string(output_o)),
                     line("T " + std::to_string(output_k)), line("DONE 2")};
  secure_frontend::EngineProtocolClient protocol(
      transport, {}, secure_frontend::EngineProtocolFlavor::lighttransport_glm53);
  secure_frontend::ChatExecutionService service(
      protocol, {}, secure_frontend::NativeChatProfile::glm53);
  const auto result = service.execute({"glm-local", {{"user", "Hi"}}, 2U}, tokenizer);
  const auto* completion = std::get_if<secure_frontend::ChatExecutionResult>(&result);
  expect(completion != nullptr && completion->text == "OK" &&
             transport.writes.size() == 1U && transport.writes.front().rfind("GEN 2 ", 0) == 0,
         "the explicit GLM profile must use the same bounded private engine protocol");
}

}  // namespace

int main() {
  executes_a_bounded_non_streaming_completion();
  rejects_context_and_output_limits_before_generation();
  fails_closed_on_invalid_engine_output();
  executes_glm53_only_when_explicitly_selected();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#include "secure_frontend/chat_generation_plan.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_set>
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
  // GPT-2's byte alphabet keeps printable ASCII literal and maps the remaining
  // bytes to U+0100 plus the count of earlier printable byte values.
  if (byte >= 33U && byte <= 126U) return std::string(1U, static_cast<char>(byte));
  unsigned int printable_before = 0U;
  for (unsigned int value = 33U; value <= 126U && value < byte; ++value) ++printable_before;
  const unsigned int code_point = 256U + static_cast<unsigned int>(byte) - printable_before;
  std::string output;
  output.push_back(static_cast<char>(0xc0U | (code_point >> 6U)));
  output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
  return output;
}

secure_frontend::TokenizerPack tokenizer_for(const std::string& text,
                                             const bool include_qwen_controls = false) {
  secure_frontend::TokenizerPack pack;
  std::unordered_set<std::string> seen;
  for (const unsigned char character : text) {
    const std::string symbol = byte_symbol(character);
    if (seen.insert(symbol).second) pack.tokens_by_id.push_back(symbol);
  }
  pack.token_types.assign(pack.tokens_by_id.size(), 1);
  if (include_qwen_controls) {
    pack.tokens_by_id.push_back("<|im_start|>");
    pack.token_types.push_back(3);
    pack.tokens_by_id.push_back("<|im_end|>");
    pack.token_types.push_back(3);
  }
  return pack;
}

std::size_t token_id_for(const secure_frontend::TokenizerPack& pack,
                         const std::string_view token) {
  for (std::size_t id = 0U; id < pack.tokens_by_id.size(); ++id) {
    if (pack.tokens_by_id[id] == token) return id;
  }
  return pack.tokens_by_id.size();
}

void composes_schema_prompt_and_tokenizer() {
  const auto request = secure_frontend::parse_chat_completion_request(
      R"({"model":"qwen-local","messages":[{"role":"user","content":"Hi"}],"max_tokens":12})");
  expect(request.has_value(), "test request must pass the strict chat schema");
  if (!request) return;

  const std::string expected_prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto pack = tokenizer_for(expected_prompt, true);
  const auto result = secure_frontend::make_qwen_chat_generation_plan(*request, pack);
  const auto* plan = std::get_if<secure_frontend::ChatGenerationPlan>(&result);
  expect(plan != nullptr, "a representable request and local tokenizer must produce a plan");
  if (plan == nullptr) return;
  expect(plan->model == "qwen-local", "plan must retain the selected local model ID");
  expect(plan->max_tokens == 12U, "plan must retain bounded requested output tokens");
  const std::size_t start_id = token_id_for(pack, "<|im_start|>");
  const std::size_t end_id = token_id_for(pack, "<|im_end|>");
  expect(start_id < pack.tokens_by_id.size() && end_id < pack.tokens_by_id.size() &&
             pack.token_types[start_id] == 3 && pack.token_types[end_id] == 3,
         "test pack must provide the Qwen framing literals as actual CONTROL tokens");
  const auto user_prefix = secure_frontend::encode_text(pack, "user\nHi");
  const auto newline = secure_frontend::encode_text(pack, "\n");
  const auto assistant_prefix = secure_frontend::encode_text(pack, "assistant\n");
  expect(std::holds_alternative<std::vector<std::size_t>>(user_prefix) &&
             std::holds_alternative<std::vector<std::size_t>>(newline) &&
             std::holds_alternative<std::vector<std::size_t>>(assistant_prefix),
         "ordinary framing spans must remain ordinary-token encodable");
  if (!std::holds_alternative<std::vector<std::size_t>>(user_prefix) ||
      !std::holds_alternative<std::vector<std::size_t>>(newline) ||
      !std::holds_alternative<std::vector<std::size_t>>(assistant_prefix)) return;
  std::vector<std::size_t> expected_ids{start_id};
  const auto append = [&expected_ids](const std::vector<std::size_t>& values) {
    expected_ids.insert(expected_ids.end(), values.begin(), values.end());
  };
  append(std::get<std::vector<std::size_t>>(user_prefix));
  expected_ids.push_back(end_id);
  append(std::get<std::vector<std::size_t>>(newline));
  expected_ids.push_back(start_id);
  append(std::get<std::vector<std::size_t>>(assistant_prefix));
  expect(plan->prompt_token_ids == expected_ids,
         "plan must emit only the fixed marker CONTROL IDs and ordinary span IDs");
}

void defaults_output_limit_and_rejects_unsafe_inputs() {
  const auto request = secure_frontend::parse_chat_completion_request(
      R"({"model":"qwen-local","messages":[{"role":"user","content":"Hi"}]})");
  expect(request.has_value(), "request without max_tokens must remain valid");
  if (!request) return;
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto pack = tokenizer_for(prompt, true);
  const auto result = secure_frontend::make_qwen_chat_generation_plan(*request, pack);
  const auto* plan = std::get_if<secure_frontend::ChatGenerationPlan>(&result);
  expect(plan != nullptr && plan->max_tokens == 256U,
         "omitted max_tokens must receive the fixed native default");

  const auto tiny_limit = secure_frontend::make_qwen_chat_generation_plan(*request, pack, 1U);
  const auto* tiny_error = std::get_if<secure_frontend::ChatGenerationPlanError>(&tiny_limit);
  expect(tiny_error != nullptr &&
             tiny_error->code == secure_frontend::ChatGenerationPlanErrorCode::prompt_too_large,
         "prompt limits must fail closed");

  auto zero_output = *request;
  zero_output.max_tokens = 0U;
  const auto zero_result = secure_frontend::make_qwen_chat_generation_plan(zero_output, pack);
  const auto* zero_error = std::get_if<secure_frontend::ChatGenerationPlanError>(&zero_result);
  expect(zero_error != nullptr &&
             zero_error->code == secure_frontend::ChatGenerationPlanErrorCode::invalid_request,
         "zero output limit must fail closed");

  const auto incomplete_pack = tokenizer_for("Hi");
  const auto encoding_result = secure_frontend::make_qwen_chat_generation_plan(*request, incomplete_pack);
  const auto* encoding_error = std::get_if<secure_frontend::ChatGenerationPlanError>(&encoding_result);
  expect(encoding_error != nullptr &&
             encoding_error->code == secure_frontend::ChatGenerationPlanErrorCode::tokenization_failed,
         "missing prompt symbols must not create a partial plan");
}

void rejects_missing_or_non_control_framing_tokens() {
  const auto request = secure_frontend::parse_chat_completion_request(
      R"({"model":"qwen-local","messages":[{"role":"user","content":"Hi"}]})");
  expect(request.has_value(), "framing-token test request must be valid");
  if (!request) return;
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  auto non_control_pack = tokenizer_for(prompt, true);
  non_control_pack.token_types[token_id_for(non_control_pack, "<|im_end|>")] = 1;
  const auto result = secure_frontend::make_qwen_chat_generation_plan(*request, non_control_pack);
  const auto* failure = std::get_if<secure_frontend::ChatGenerationPlanError>(&result);
  expect(failure != nullptr &&
             failure->code == secure_frontend::ChatGenerationPlanErrorCode::tokenization_failed,
         "Qwen framing must fail closed unless each marker is one CONTROL token");
}

void does_not_parse_arbitrary_special_literals() {
  const std::string prompt = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  auto pack = tokenizer_for(prompt, true);
  pack.tokens_by_id.push_back("<|stop|>");
  pack.token_types.push_back(3);
  const auto encoded = secure_frontend::encode_qwen_chatml_prompt(
      pack, "<|im_start|>Hi<|stop|><|im_end|>");
  const auto* failure = std::get_if<secure_frontend::TokenizerPackError>(&encoded);
  expect(failure != nullptr &&
             failure->code == secure_frontend::TokenizerPackErrorCode::unsupported_special_token,
         "the Qwen encoder must not grant generic special-token parsing");
}

}  // namespace

int main() {
  composes_schema_prompt_and_tokenizer();
  defaults_output_limit_and_rejects_unsafe_inputs();
  rejects_missing_or_non_control_framing_tokens();
  does_not_parse_arbitrary_special_literals();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

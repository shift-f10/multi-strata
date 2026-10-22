#include "secure_frontend/tokenizer_pack.hpp"
#include "support/test_support.hpp"
#include "support/test_tokenizer.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>
#include <variant>
#include <vector>

namespace {
int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}

std::filesystem::path temporary_pack() {
  return secure_frontend_test::make_scratch_directory();
}
void write(const std::filesystem::path& path, const std::string_view data) {
  std::ofstream output(path, std::ios::binary); output << data;
}
bool has_error(const secure_frontend::TokenizerPackLoadResult& result,
               const secure_frontend::TokenizerPackErrorCode expected) {
  const auto* value = std::get_if<secure_frontend::TokenizerPackError>(&result);
  return value != nullptr && value->code == expected;
}

void loads_validates_and_decodes_offline_pack() {
  const auto root = temporary_pack();
  // "a" and "b" map directly; U+0120 is the GPT-2 byte alphabet encoding of a space.
  write(root / "vocab.json", R"({"a":0,"b":1,"ab":2,"Ġ":3,"Ã":4,"©":5,"Ã©":6})");
  write(root / "merges.txt", "a b\nÃ ©\n");
  write(root / "token_type.json", "[0,0,0,0,0,0,0]");
  const auto loaded = secure_frontend::load_local_tokenizer_pack(root);
  const auto* pack = std::get_if<secure_frontend::TokenizerPack>(&loaded);
  expect(pack != nullptr, "valid extracted local pack must load");
  if (pack != nullptr) {
    expect(pack->tokens_by_id.size() == 7U && pack->merges_by_rank.size() == 2U,
           "loader must retain vocabulary and merge rank order");
    const auto decoded = secure_frontend::decode_token_ids(*pack, {2U, 3U, 0U});
    const auto* text = std::get_if<std::string>(&decoded);
    expect(text != nullptr && *text == "ab a", "decoder must reverse byte-level BPE symbols by token ID");
    expect(std::holds_alternative<secure_frontend::TokenizerPackError>(
               secure_frontend::decode_token_ids(*pack, {99U})),
           "decoder must reject out-of-range IDs");
    const auto encoded = secure_frontend::encode_text(*pack, "ab ab");
    const auto* ids = std::get_if<std::vector<std::size_t>>(&encoded);
    expect(ids != nullptr && *ids == std::vector<std::size_t>({2U, 3U, 2U}),
           "encoder must apply BPE ranks after byte-level conversion");
    const auto utf8_encoded = secure_frontend::encode_text(*pack, "é");
    const auto* utf8_ids = std::get_if<std::vector<std::size_t>>(&utf8_encoded);
    expect(utf8_ids != nullptr && *utf8_ids == std::vector<std::size_t>({6U}),
           "encoder must preserve UTF-8 bytes through the GPT-2 byte alphabet");
  }
  std::filesystem::remove_all(root);
}

void encoding_fails_closed_for_special_invalid_and_missing_tokens() {
  const auto root = temporary_pack();
  write(root / "vocab.json", R"({"a":0,"<|stop|>":1})");
  write(root / "merges.txt", "");
  write(root / "token_type.json", "[0,3]");
  const auto loaded = secure_frontend::load_local_tokenizer_pack(root);
  const auto* pack = std::get_if<secure_frontend::TokenizerPack>(&loaded);
  expect(pack != nullptr, "special-token pack must load for fail-closed encoder tests");
  if (pack != nullptr) {
    const auto special = secure_frontend::encode_text(*pack, "<|stop|>");
    expect(std::get_if<secure_frontend::TokenizerPackError>(&special) != nullptr &&
               std::get<secure_frontend::TokenizerPackError>(special).code == secure_frontend::TokenizerPackErrorCode::unsupported_special_token,
           "encoder must reject special-token literals");
    const auto invalid = secure_frontend::encode_text(*pack, std::string{"\xff", 1U});
    expect(std::get_if<secure_frontend::TokenizerPackError>(&invalid) != nullptr &&
               std::get<secure_frontend::TokenizerPackError>(invalid).code == secure_frontend::TokenizerPackErrorCode::input_text_not_utf8,
           "encoder must reject invalid UTF-8");
    expect(std::holds_alternative<secure_frontend::TokenizerPackError>(secure_frontend::encode_text(*pack, "b")),
           "encoder must reject input without ordinary vocabulary coverage");
  }
  std::filesystem::remove_all(root);
}

void rejects_ambiguous_or_incompatible_pack_assets() {
  const auto root = temporary_pack();
  write(root / "vocab.json", R"({"a":0,"b":2})");
  write(root / "merges.txt", "a b\n");
  write(root / "token_type.json", "[0,0]");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root),
                   secure_frontend::TokenizerPackErrorCode::invalid_vocabulary),
         "vocabulary IDs must be contiguous and zero based");
  write(root / "vocab.json", R"({"a":0,"b":1})");
  write(root / "merges.txt", "a c\n");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root),
                   secure_frontend::TokenizerPackErrorCode::invalid_merge),
         "merge tokens outside vocabulary must fail closed");
  write(root / "merges.txt", "a b\na b\n");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root),
                   secure_frontend::TokenizerPackErrorCode::invalid_merge),
         "duplicate merge ranks must fail closed");
  write(root / "merges.txt", "");
  write(root / "token_type.json", "[0]");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root),
                   secure_frontend::TokenizerPackErrorCode::invalid_token_types),
         "token type count must equal vocabulary size");
  std::filesystem::remove_all(root);
}

void rejects_malformed_json_and_special_literals_for_decode() {
  const auto root = temporary_pack();
  write(root / "vocab.json", R"({"a":0,"a":1})");
  write(root / "merges.txt", "");
  write(root / "token_type.json", "[0]");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root),
                   secure_frontend::TokenizerPackErrorCode::invalid_json),
         "duplicate JSON keys must fail closed");
  write(root / "vocab.json", R"({"<|control|>":0})");
  write(root / "token_type.json", "[3]");
  const auto loaded = secure_frontend::load_local_tokenizer_pack(root);
  const auto* pack = std::get_if<secure_frontend::TokenizerPack>(&loaded);
  expect(pack != nullptr, "control literals are valid pack vocabulary entries");
  if (pack != nullptr) {
    const auto decoded = secure_frontend::decode_token_ids(*pack, {0U});
    const auto* error = std::get_if<secure_frontend::TokenizerPackError>(&decoded);
    expect(error != nullptr && error->code == secure_frontend::TokenizerPackErrorCode::undecodable_token,
           "decoder must not silently treat control literals as ordinary output bytes");
  }
  std::filesystem::remove_all(root);
}

#ifndef _WIN32
void rejects_symlinked_assets() {
  const auto root = temporary_pack();
  write(root / "actual.json", R"({"a":0})");
  std::filesystem::create_symlink(root / "actual.json", root / "vocab.json");
  write(root / "merges.txt", "");
  write(root / "token_type.json", "[0]");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root),
                   secure_frontend::TokenizerPackErrorCode::symbolic_link_not_allowed),
         "loader must reject symlinked tokenizer files");
  std::filesystem::remove_all(root);
}

void cfg03_tokenizer_file_swapped_to_symlink_rejected() {
  const auto root = temporary_pack();
  const auto outside = temporary_pack();
  write(outside / "vocab.json", R"({"a":0})");
  write(root / "merges.txt", "");
  write(root / "token_type.json", "[0]");
  write(root / "vocab.json", R"({"a":0})");
  expect(std::holds_alternative<secure_frontend::TokenizerPack>(secure_frontend::load_local_tokenizer_pack(root)),
         "the regular pack loads");
  std::filesystem::remove(root / "vocab.json");
  std::filesystem::create_symlink(outside / "vocab.json", root / "vocab.json");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root), secure_frontend::TokenizerPackErrorCode::symbolic_link_not_allowed),
         "after the swap the file is opened by handle with O_NOFOLLOW and rejected");
  std::filesystem::remove_all(root);  // removes the link, not its target
  std::filesystem::remove_all(outside);
}
#endif

#if defined(_WIN32)
void cfg03_tokenizer_file_swapped_to_junction_rejected() {
  const auto root = temporary_pack();
  const auto outside = temporary_pack();
  write(outside / "vocab.json", R"({"a":0})");
  write(root / "merges.txt", "");
  write(root / "token_type.json", "[0]");
  write(root / "vocab.json", R"({"a":0})");
  expect(std::holds_alternative<secure_frontend::TokenizerPack>(secure_frontend::load_local_tokenizer_pack(root)),
         "the regular pack loads");
  std::filesystem::remove(root / "vocab.json");
  expect(secure_frontend_test::create_junction(root / "vocab.json", outside), "junction created without privilege");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root), secure_frontend::TokenizerPackErrorCode::symbolic_link_not_allowed),
         "a junction swapped in for vocab.json is opened with FILE_FLAG_OPEN_REPARSE_POINT and rejected");
  std::error_code ignored;
  std::filesystem::remove(root / "vocab.json", ignored);  // the junction itself first, never its target's contents
  std::filesystem::remove_all(root, ignored);
  std::filesystem::remove_all(outside, ignored);
}
#endif

void token_byte_decoder_returns_raw_token_bytes() {
  const auto pack = test_support::byte_tokenizer();
  const secure_frontend::TokenByteDecoder decoder(pack);
  const auto lead = decoder.bytes_for(test_support::id_for_byte(0xE2U));
  expect(std::holds_alternative<std::string>(lead) && std::get<std::string>(lead) == "\xE2", "a lead byte alone is returned, not rejected");
  const auto long_token = decoder.bytes_for(test_support::kLongTokenId);
  expect(std::holds_alternative<std::string>(long_token) && std::get<std::string>(long_token) == std::string(1024U, 'a'), "multi-symbol token");
  const auto control = decoder.bytes_for(256U);
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(control) &&
             std::get<secure_frontend::TokenizerPackError>(control).code == secure_frontend::TokenizerPackErrorCode::undecodable_token,
         "control tokens are not ordinary output");
  const auto outside = decoder.bytes_for(100000U);
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(outside) &&
             std::get<secure_frontend::TokenizerPackError>(outside).code == secure_frontend::TokenizerPackErrorCode::token_id_out_of_range,
         "ids outside the vocabulary");
}

// The byte pack plus the Qwen3 reasoning markers as Qwen3.8 packs carry them (USER_DEFINED, 4).
secure_frontend::TokenizerPack think_pack() {
  auto pack = test_support::byte_tokenizer();
  pack.tokens_by_id.emplace_back("<think>");
  pack.token_types.push_back(4);
  pack.tokens_by_id.emplace_back("</think>");
  pack.token_types.push_back(4);
  return pack;
}

// The markers resolve only as exactly one CONTROL or USER_DEFINED token each.
void finds_qwen_think_tokens_only_when_unambiguous() {
  expect(!secure_frontend::find_qwen_think_tokens(test_support::byte_tokenizer()).has_value(),
         "a ChatML pack without the markers has no reasoning split");
  const auto pack = think_pack();
  const std::size_t open = pack.tokens_by_id.size() - 2U;
  const std::size_t close = pack.tokens_by_id.size() - 1U;
  const auto found = secure_frontend::find_qwen_think_tokens(pack);
  expect(found.has_value() && found->open == open && found->close == close, "USER_DEFINED markers resolve");
  auto control = pack;
  control.token_types[open] = 3;
  control.token_types[close] = 3;
  const auto control_found = secure_frontend::find_qwen_think_tokens(control);
  expect(control_found.has_value() && control_found->open == open && control_found->close == close, "CONTROL markers resolve too");
  auto only_open = test_support::byte_tokenizer();
  only_open.tokens_by_id.emplace_back("<think>");
  only_open.token_types.push_back(4);
  expect(!secure_frontend::find_qwen_think_tokens(only_open).has_value(), "one marker alone is no split");
  auto ordinary = pack;
  ordinary.token_types[close] = 1;
  expect(!secure_frontend::find_qwen_think_tokens(ordinary).has_value(), "an ordinary-typed marker is not a reasoning tag");
  auto duplicated = pack;
  duplicated.tokens_by_id.emplace_back("<think>");
  duplicated.token_types.push_back(4);
  expect(!secure_frontend::find_qwen_think_tokens(duplicated).has_value(), "a duplicated marker is ambiguous and fails closed");
}

std::vector<std::size_t> ids_of(const secure_frontend::TokenizerEncodeResult& result) {
  const auto* ids = std::get_if<std::vector<std::size_t>>(&result);
  return ids != nullptr ? *ids : std::vector<std::size_t>{};
}

// The markers are encoded only as the renderer's generation tail (QwenThinking::on/off);
// anywhere else they keep encode_text()'s special-literal rejection.
void qwen_encoder_takes_think_markers_only_as_generation_tail() {
  const auto pack = think_pack();
  const std::size_t open = pack.tokens_by_id.size() - 2U;
  const std::size_t close = pack.tokens_by_id.size() - 1U;
  const std::string head = "<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n";
  const auto head_ids = ids_of(secure_frontend::encode_qwen_chatml_prompt(pack, head));
  const auto newline = ids_of(secure_frontend::encode_text(pack, "\n"));
  const auto two_newlines = ids_of(secure_frontend::encode_text(pack, "\n\n"));
  expect(!head_ids.empty() && !newline.empty() && !two_newlines.empty(), "the plain prompt and newlines encode");

  std::vector<std::size_t> open_tail = head_ids;
  open_tail.push_back(open);
  open_tail.insert(open_tail.end(), newline.begin(), newline.end());
  const auto on = secure_frontend::encode_qwen_chatml_prompt(pack, head + "<think>\n");
  expect(ids_of(on) == open_tail, "the open think tail encodes as <think> plus the newline");

  std::vector<std::size_t> closed_tail = head_ids;
  closed_tail.push_back(open);
  closed_tail.insert(closed_tail.end(), two_newlines.begin(), two_newlines.end());
  closed_tail.push_back(close);
  closed_tail.insert(closed_tail.end(), two_newlines.begin(), two_newlines.end());
  const auto off = secure_frontend::encode_qwen_chatml_prompt(pack, head + "<think>\n\n</think>\n\n");
  expect(ids_of(off) == closed_tail, "the closed think tail encodes as the template writes it");

  const std::vector<std::string> misplaced{"<|im_start|>user\n<think>\n<|im_end|>\n<|im_start|>assistant\n<think>\n",
                                          head + "<think>\nmore", head + "</think>\n\n", head + "<think>\n<think>\n"};
  for (const auto& prompt : misplaced) {
    const auto encoded = secure_frontend::encode_qwen_chatml_prompt(pack, prompt);
    const auto* failure = std::get_if<secure_frontend::TokenizerPackError>(&encoded);
    expect(failure != nullptr && failure->code == secure_frontend::TokenizerPackErrorCode::unsupported_special_token,
           "a marker outside the exact generation tail fails closed");
  }
  const auto without_markers = secure_frontend::encode_qwen_chatml_prompt(test_support::byte_tokenizer(), head + "<think>\n");
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(without_markers), "a think tail needs the pack's markers");
}

std::size_t id_of(const secure_frontend::TokenizerPack& pack, const std::string_view literal) {
  for (std::size_t id = 0U; id < pack.tokens_by_id.size(); ++id) {
    if (pack.tokens_by_id[id] == literal) return id;
  }
  return pack.tokens_by_id.size();
}

// Issue 26: upstream's stop ids (serve/server.py:3770-3771), each only as one CONTROL token.
void finds_qwen_end_of_turn_tokens() {
  auto pack = test_support::byte_tokenizer();
  const std::size_t im_end = id_of(pack, "<|im_end|>");
  expect(secure_frontend::find_qwen_end_of_turn_tokens(pack) == std::vector<std::size_t>{im_end}, "a ChatML pack ends turns on <|im_end|>");
  pack.tokens_by_id.emplace_back("<|endoftext|>");
  pack.token_types.push_back(3);
  const std::size_t endoftext = pack.tokens_by_id.size() - 1U;
  expect(secure_frontend::find_qwen_end_of_turn_tokens(pack) == std::vector<std::size_t>({im_end, endoftext}),
         "<|endoftext|> joins it when the pack has it");
  auto ordinary = pack;
  ordinary.token_types[endoftext] = 1;
  expect(secure_frontend::find_qwen_end_of_turn_tokens(ordinary) == std::vector<std::size_t>{im_end},
         "an ordinary-typed literal is not an end-of-turn token");
  auto duplicated = pack;
  duplicated.tokens_by_id.emplace_back("<|im_end|>");
  duplicated.token_types.push_back(3);
  expect(secure_frontend::find_qwen_end_of_turn_tokens(duplicated) == std::vector<std::size_t>{endoftext},
         "a duplicated literal is ambiguous and is left out");
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"finds_qwen_think_tokens_only_when_unambiguous", finds_qwen_think_tokens_only_when_unambiguous},
      {"qwen_encoder_takes_think_markers_only_as_generation_tail", qwen_encoder_takes_think_markers_only_as_generation_tail},
      {"finds_qwen_end_of_turn_tokens", finds_qwen_end_of_turn_tokens},
      {"loads_validates_and_decodes_offline_pack", loads_validates_and_decodes_offline_pack},
      {"rejects_ambiguous_or_incompatible_pack_assets", rejects_ambiguous_or_incompatible_pack_assets},
      {"rejects_malformed_json_and_special_literals_for_decode", rejects_malformed_json_and_special_literals_for_decode},
      {"encoding_fails_closed_for_special_invalid_and_missing_tokens", encoding_fails_closed_for_special_invalid_and_missing_tokens},
      {"token_byte_decoder_returns_raw_token_bytes", token_byte_decoder_returns_raw_token_bytes},
#ifndef _WIN32
      {"rejects_symlinked_assets", rejects_symlinked_assets},
      {"cfg03_tokenizer_file_swapped_to_symlink_rejected", cfg03_tokenizer_file_swapped_to_symlink_rejected},
#endif
#if defined(_WIN32)
      {"cfg03_tokenizer_file_swapped_to_junction_rejected", cfg03_tokenizer_file_swapped_to_junction_rejected},
#endif
  }, failures);
}

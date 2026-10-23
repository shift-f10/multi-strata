#include "secure_frontend/tokenizer_pack.hpp"
#include "secure_frontend/crt_environment.hpp"
#include "secure_frontend/json.hpp"
#include "support/test_support.hpp"
#include "support/test_tokenizer.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <system_error>
#include <tuple>
#include <variant>
#include <vector>

namespace {
int failures = 0;
// Gemma 4 plan 1 Task 4: the mode is the caller's (the profile's), never the files'.
constexpr auto kByte = secure_frontend::TokenizerMode::byte_bpe;
constexpr auto kSpm = secure_frontend::TokenizerMode::spm_bpe;
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
  const auto loaded = secure_frontend::load_local_tokenizer_pack(root, kByte);
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
  const auto loaded = secure_frontend::load_local_tokenizer_pack(root, kByte);
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
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root, kByte),
                   secure_frontend::TokenizerPackErrorCode::invalid_vocabulary),
         "vocabulary IDs must be contiguous and zero based");
  write(root / "vocab.json", R"({"a":0,"b":1})");
  write(root / "merges.txt", "a c\n");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root, kByte),
                   secure_frontend::TokenizerPackErrorCode::invalid_merge),
         "merge tokens outside vocabulary must fail closed");
  write(root / "merges.txt", "a b\na b\n");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root, kByte),
                   secure_frontend::TokenizerPackErrorCode::invalid_merge),
         "duplicate merge ranks must fail closed");
  write(root / "merges.txt", "");
  write(root / "token_type.json", "[0]");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root, kByte),
                   secure_frontend::TokenizerPackErrorCode::invalid_token_types),
         "token type count must equal vocabulary size");
  std::filesystem::remove_all(root);
}

void rejects_malformed_json_and_special_literals_for_decode() {
  const auto root = temporary_pack();
  write(root / "vocab.json", R"({"a":0,"a":1})");
  write(root / "merges.txt", "");
  write(root / "token_type.json", "[0]");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root, kByte),
                   secure_frontend::TokenizerPackErrorCode::invalid_json),
         "duplicate JSON keys must fail closed");
  write(root / "vocab.json", R"({"<|control|>":0})");
  write(root / "token_type.json", "[3]");
  const auto loaded = secure_frontend::load_local_tokenizer_pack(root, kByte);
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
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root, kByte),
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
  expect(std::holds_alternative<secure_frontend::TokenizerPack>(secure_frontend::load_local_tokenizer_pack(root, kByte)),
         "the regular pack loads");
  std::filesystem::remove(root / "vocab.json");
  std::filesystem::create_symlink(outside / "vocab.json", root / "vocab.json");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root, kByte), secure_frontend::TokenizerPackErrorCode::symbolic_link_not_allowed),
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
  expect(std::holds_alternative<secure_frontend::TokenizerPack>(secure_frontend::load_local_tokenizer_pack(root, kByte)),
         "the regular pack loads");
  std::filesystem::remove(root / "vocab.json");
  expect(secure_frontend_test::create_junction(root / "vocab.json", outside), "junction created without privilege");
  expect(has_error(secure_frontend::load_local_tokenizer_pack(root, kByte), secure_frontend::TokenizerPackErrorCode::symbolic_link_not_allowed),
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

// ---- Gemma 4 plan 1 Task 4 (spec §6.2): the spm_bpe mode reads merges.json ----

secure_frontend::TokenizerPackErrorCode error_code(const secure_frontend::TokenizerPackLoadResult& result) {
  const auto* failure = std::get_if<secure_frontend::TokenizerPackError>(&result);
  return failure != nullptr ? failure->code : secure_frontend::TokenizerPackErrorCode::pack_root_unavailable;
}

// Gemma's merges hold "\n", "\t" and runs of U+2581 (spec §2.6); a line-based merges.txt cannot.
void write_spm_pack(const std::filesystem::path& root, const std::string_view merges_json) {
  write(root / "vocab.json",
        "{\"\\n\":0,\"\\n\\n\":1,\"\\n\\n\\n\":2,\"\\t\":3,\"\\t\\t\":4,\"\xE2\x96\x81\":5,\"\xE2\x96\x81\xE2\x96\x81\":6,"
        "\"\xE2\x96\x81\xE2\x96\x81\xE2\x96\x81\":7,\"a b\":8,\"c\":9,\"a bc\":10}");
  write(root / "merges.json", merges_json);
  write(root / "token_type.json", "[1,1,1,1,1,1,1,1,1,1,1]");
}

constexpr std::string_view kSpmMerges =
    "[[\"\\n\\n\",\"\\n\"],[\"\\t\",\"\\t\"],[\"\xE2\x96\x81\xE2\x96\x81\",\"\xE2\x96\x81\"],[\"\\n\",\"\\n\"],"
    "[\"\xE2\x96\x81\",\"\xE2\x96\x81\"],[\"a b\",\"c\"]]";

void spm_pack_loads_merges_json_with_newline_and_tab_tokens() {
  const auto root = temporary_pack();
  write_spm_pack(root, kSpmMerges);
  const auto loaded = secure_frontend::load_local_tokenizer_pack(root, kSpm);
  const auto* pack = std::get_if<secure_frontend::TokenizerPack>(&loaded);
  expect(pack != nullptr, "an spm_bpe pack with merges.json loads");
  if (pack != nullptr) {
    const std::vector<std::pair<std::string, std::string>> expected{
        {"\n\n", "\n"}, {"\t", "\t"}, {"\xE2\x96\x81\xE2\x96\x81", "\xE2\x96\x81"}, {"\n", "\n"},
        {"\xE2\x96\x81", "\xE2\x96\x81"}, {"a b", "c"}};
    expect(pack->merges_by_rank == expected, "merges keep \\n, \\t, U+2581 runs and inner spaces, in rank order");
    expect(pack->mode == secure_frontend::TokenizerMode::spm_bpe, "the pack records the mode it was loaded in");
    expect(pack->tokens_by_id.size() == 11U && pack->tokens_by_id[2] == "\n\n\n", "the vocabulary decodes JSON escapes");
  }
  write(root / "merges.json", "[]");
  const auto empty = secure_frontend::load_local_tokenizer_pack(root, kSpm);
  expect(std::holds_alternative<secure_frontend::TokenizerPack>(empty) &&
             std::get<secure_frontend::TokenizerPack>(empty).merges_by_rank.empty(),
         "an empty merges array is a pack without merges");
  std::filesystem::remove_all(root);
}

// The spm_bpe encoder's tables are built once at load (the Gemma 4 route encodes every request)
// and give the same ids as tables built per call; copies share them; a byte_bpe pack has none.
void spm_pack_load_prepares_the_encode_index_once() {
  const auto root = temporary_pack();
  test_support::write_spm_tokenizer_pack(root);
  const auto loaded = secure_frontend::load_local_tokenizer_pack(root, kSpm);
  const auto* pack = std::get_if<secure_frontend::TokenizerPack>(&loaded);
  expect(pack != nullptr, "the synthetic spm pack loads");
  if (pack == nullptr) return;
  expect(pack->spm_index != nullptr, "the loader prepares the spm encode index");
  auto plain = *pack;
  plain.spm_index.reset();
  const std::vector<std::string> texts{"Hi world", "  x", "x   ", "abc", "thought", "a\n\nb", "\t\t", "\r\n", "Hi\n world", ""};
  for (const auto& text : texts) {
    expect(ids_of(secure_frontend::encode_text(*pack, text)) == ids_of(secure_frontend::encode_text(plain, text)),
           "the prepared index encodes as the per-call one");
  }
  std::optional<secure_frontend::TokenizerPack> copy;
  {
    auto scoped = std::get<secure_frontend::TokenizerPack>(secure_frontend::load_local_tokenizer_pack(root, kSpm));
    copy = scoped;  // the original goes out of scope: the shared tables own their data
  }
  expect(copy->spm_index != nullptr && ids_of(secure_frontend::encode_text(*copy, "Hi world")) ==
                                           ids_of(secure_frontend::encode_text(plain, "Hi world")),
         "a copy outliving the loaded pack encodes the same");
  auto grown = *pack;
  grown.merges_by_rank.pop_back();
  auto grown_plain = grown;
  grown_plain.spm_index.reset();
  expect(ids_of(secure_frontend::encode_text(grown, "abc thought")) == ids_of(secure_frontend::encode_text(grown_plain, "abc thought")),
         "a pack whose merges changed after load is not encoded with the stale tables");
  test_support::write_tokenizer_pack(root);
  std::filesystem::remove(root / "merges.json");
  const auto byte_pack = secure_frontend::load_local_tokenizer_pack(root, kByte);
  expect(std::holds_alternative<secure_frontend::TokenizerPack>(byte_pack) &&
             std::get<secure_frontend::TokenizerPack>(byte_pack).spm_index == nullptr,
         "a byte_bpe pack carries no spm index");
  std::filesystem::remove_all(root);
}

// Review Focus 2: the profile picks the mode; a pack holding the other mode's merges file fails at load.
void mode_comes_from_the_profile_never_the_files() {
  const auto spm = temporary_pack();
  write_spm_pack(spm, kSpmMerges);
  write(spm / "merges.txt", "a b\n");
  expect(error_code(secure_frontend::load_local_tokenizer_pack(spm, kSpm)) == secure_frontend::TokenizerPackErrorCode::invalid_merge,
         "spm_bpe refuses a pack that also has merges.txt");
  std::filesystem::remove(spm / "merges.json");
  expect(error_code(secure_frontend::load_local_tokenizer_pack(spm, kSpm)) == secure_frontend::TokenizerPackErrorCode::invalid_merge,
         "spm_bpe never falls back to merges.txt");
  std::filesystem::remove_all(spm);

  const auto byte = temporary_pack();
  write(byte / "vocab.json", R"({"a":0,"b":1,"ab":2})");
  write(byte / "merges.txt", "a b\n");
  write(byte / "token_type.json", "[1,1,1]");
  const auto plain = secure_frontend::load_local_tokenizer_pack(byte, kByte);
  expect(std::holds_alternative<secure_frontend::TokenizerPack>(plain) &&
             std::get<secure_frontend::TokenizerPack>(plain).mode == secure_frontend::TokenizerMode::byte_bpe,
         "byte_bpe loads merges.txt and records its mode");
  expect(error_code(secure_frontend::load_local_tokenizer_pack(byte, kSpm)) == secure_frontend::TokenizerPackErrorCode::invalid_merge,
         "a byte-level pack is refused in spm_bpe mode (merges.txt present)");
  write(byte / "merges.json", R"([["a","b"]])");
  expect(error_code(secure_frontend::load_local_tokenizer_pack(byte, kByte)) == secure_frontend::TokenizerPackErrorCode::invalid_merge,
         "byte_bpe refuses a pack that also has merges.json");
  std::filesystem::remove(byte / "merges.txt");
  expect(error_code(secure_frontend::load_local_tokenizer_pack(byte, kByte)) == secure_frontend::TokenizerPackErrorCode::invalid_merge,
         "byte_bpe never falls back to merges.json");
  std::filesystem::remove_all(byte);
}

void merges_json_is_bounded_and_validated() {
  const auto root = temporary_pack();
  using Code = secure_frontend::TokenizerPackErrorCode;
  const std::vector<std::tuple<std::string, Code, std::string>> cases{
      {R"([[["\n","\n"]]])", Code::invalid_json, "depth 3"},
      {R"([["\n",1]])", Code::invalid_json, "a non-string side"},
      {R"([["\n"]])", Code::invalid_json, "one string"},
      {R"([["\n","\n","\n"]])", Code::invalid_json, "three strings"},
      {R"({"\n":"\n"})", Code::invalid_json, "an object, not an array"},
      {R"(["\n \n"])", Code::invalid_json, "a merges.txt line as a string"},
      {R"([["\n","\n"],)", Code::invalid_json, "truncated JSON"},
      {R"([["\n","x"]])", Code::invalid_merge, "an unknown token"},
      {R"([["\n","\n"],["\n","\n"]])", Code::invalid_merge, "a duplicate merge"},
      {R"([["","\n"]])", Code::invalid_merge, "an empty side"},
  };
  for (const auto& [text, code, why] : cases) {
    write_spm_pack(root, text);
    expect(error_code(secure_frontend::load_local_tokenizer_pack(root, kSpm)) == code, "merges.json refused: " + why);
  }
  write_spm_pack(root, std::string(64U * 1024U * 1024U + 1U, ' '));
  expect(error_code(secure_frontend::load_local_tokenizer_pack(root, kSpm)) == Code::file_too_large,
         "merges.json above the 64 MiB file cap is refused before parsing");
  std::filesystem::remove_all(root);
}
// ---- Gemma 4 plan 1 Task 5 (spec §2.5, §6.2; LC llama-vocab.cpp:528-537, 637-644, 3186-3200) ----

std::vector<std::size_t> spm_ids(const secure_frontend::TokenizerPack& pack, const std::vector<std::string>& tokens) {
  std::vector<std::size_t> ids;
  for (const auto& token : tokens) ids.push_back(test_support::token_id(pack, token));
  return ids;
}

std::string spm_byte(const unsigned char byte) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  return std::string{"<0x"} + kHex[byte >> 4U] + kHex[byte & 15U] + ">";
}

const std::string kU2581{test_support::kSpmSpace};

// Spaces become U+2581 (no space prefix); merges apply by lowest rank, then leftmost.
void spm_encodes_spaces_as_u2581_and_merges_by_rank() {
  const auto pack = test_support::spm_tokenizer();
  const auto encode = [&pack](const std::string_view text) { return ids_of(secure_frontend::encode_text(pack, text)); };
  expect(encode("Hi world") == spm_ids(pack, {"Hi", kU2581 + "world"}), "Hi world -> Hi, U+2581world");
  expect(encode("x") == spm_ids(pack, {"x"}), "no space prefix is added");
  expect(encode("  x") == spm_ids(pack, {kU2581 + kU2581, "x"}), "two leading spaces merge into one U+2581U+2581 token");
  expect(encode("x   ") == spm_ids(pack, {"x", kU2581 + kU2581, kU2581}), "trailing spaces: leftmost pair first");
  expect(encode("abc") == spm_ids(pack, {"a", "bc"}), "b+c (rank 7) wins over a+b (rank 8)");
  expect(encode("aaa") == spm_ids(pack, {"aa", "a"}), "equal ranks merge leftmost first");
  expect(encode("thought") == spm_ids(pack, {"thought"}), "a chain of merges reaches the long token");
  expect(encode("\t\t") == spm_ids(pack, {"\t\t"}), "tabs merge like any character");
  expect(encode("") == std::vector<std::size_t>{}, "empty text is no tokens (no BOS: the renderer adds it)");
  const auto merges_of = [&pack](const std::string& literal) { return test_support::token_id(pack, literal); };
  expect(merges_of(kU2581) != pack.tokens_by_id.size(), "fixture: U+2581 is a token");
}

// The pre-tokenizer splits [^\n]+ from [\n]+; a newline-only run that is a token is that token.
void spm_newline_runs_are_single_tokens_when_known() {
  const auto pack = test_support::spm_tokenizer();
  const auto encode = [&pack](const std::string_view text) { return ids_of(secure_frontend::encode_text(pack, text)); };
  expect(encode("a\n\nb") == spm_ids(pack, {"a", "\n\n", "b"}), "a known newline run is one token");
  expect(encode("\n\n\n") == spm_ids(pack, {"\n\n", "\n"}), "an unknown run is merged by rank");
  expect(encode("Hi\n world") == spm_ids(pack, {"Hi", "\n", kU2581 + "world"}), "merges never cross a newline");
  expect(encode("\r\n") == spm_ids(pack, {spm_byte(0x0D), "\n"}), "\\r has no token: its byte, then the newline");
  auto no_merge = pack;
  no_merge.merges_by_rank.erase(no_merge.merges_by_rank.begin() + 10);  // ("\n", "\n")
  expect(ids_of(secure_frontend::encode_text(no_merge, "\n\n")) == spm_ids(pack, {"\n\n"}),
         "the newline-run rule needs no merge");
  expect(ids_of(secure_frontend::encode_text(no_merge, "\n\n\n")) == spm_ids(pack, {"\n", "\n", "\n"}),
         "without the token or a merge a run is its characters");
}

// A character the merges cannot reach becomes its UTF-8 bytes' <0xXX> tokens.
void spm_unknown_characters_fall_back_to_byte_tokens() {
  const auto pack = test_support::spm_tokenizer();
  const auto encode = [&pack](const std::string_view text) { return ids_of(secure_frontend::encode_text(pack, text)); };
  expect(encode("\xC3\xA9") == spm_ids(pack, {spm_byte(0xC3), spm_byte(0xA9)}), "e-acute: two byte tokens");
  expect(encode("\xF0\x9F\x98\x80") == spm_ids(pack, {spm_byte(0xF0), spm_byte(0x9F), spm_byte(0x98), spm_byte(0x80)}),
         "an emoji: four byte tokens");
  expect(encode("e\xCC\x81") == spm_ids(pack, {"e", spm_byte(0xCC), spm_byte(0x81)}), "a combining mark after e");
  expect(encode(std::string{"\x01\x7f", 2U}) == spm_ids(pack, {spm_byte(0x01), spm_byte(0x7F)}), "C0 control and DEL");
  expect(encode(std::string{"\0", 1U}) == spm_ids(pack, {spm_byte(0x00)}), "NUL is byte 0");
  expect(encode("\xE4\xBD\xA0\xE5\xA5\xBD") == spm_ids(pack, {"\xE4\xBD\xA0\xE5\xA5\xBD"}), "CJK characters merge as whole characters");
  auto missing = pack;
  missing.tokens_by_id[test_support::kSpmByteBase + 0xA9U] = "<0xA9-gone>";
  const auto refused = secure_frontend::encode_text(missing, "\xC3\xA9");
  const auto* failure = std::get_if<secure_frontend::TokenizerPackError>(&refused);
  expect(failure != nullptr && failure->code == secure_frontend::TokenizerPackErrorCode::unencodable_text,
         "a missing byte token fails closed (llama.cpp would drop the byte)");
  for (const auto& [literal, type] : test_support::gemma4_special_tokens()) {
    const auto special = secure_frontend::encode_text(pack, "a " + literal + " b");
    const auto* error = std::get_if<secure_frontend::TokenizerPackError>(&special);
    expect(error != nullptr && error->code == secure_frontend::TokenizerPackErrorCode::unsupported_special_token,
           "a Gemma marker in text is refused: " + literal);
    static_cast<void>(type);
  }
  const auto invalid = secure_frontend::encode_text(pack, std::string{"\xff", 1U});
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(invalid), "invalid UTF-8 is refused");
}

// upstream tools/strata_tokenizer.py --check's corpus: decode(encode(s)) == s.
void spm_round_trips_the_upstream_corpus() {
  const auto pack = test_support::spm_tokenizer();
  const std::vector<std::string> corpus{"",
                                        "Hello, world!",
                                        "  leading and trailing  ",
                                        "a\n\n\nb",
                                        "def f(x):\n\treturn x  # comment\n",
                                        "\xE4\xBD\xA0\xE5\xA5\xBD\xEF\xBC\x8C\xE4\xB8\x96\xE7\x95\x8C",
                                        "\xD9\x85\xD8\xB1\xD8\xAD\xD8\xA8\xD8\xA7",
                                        "\xF0\x9F\x98\x80\xF0\x9F\x9A\x80\xF0\x9F\x87\xBA\xF0\x9F\x87\xB8",
                                        "e\xCC\x81\xCC\x81 combining",
                                        std::string{"\x00\x01\x7f control", 11U},
                                        "\xC2\xA0non-breaking\xC2\xA0space",
                                        "1234567890",
                                        "MixedCASE_and-dashes",
                                        "\r\n\r\n",
                                        "\xE2\x80\xA8\xE2\x80\xA9",
                                        std::string(5000U, 'x')};
  for (const auto& text : corpus) {
    const auto encoded = secure_frontend::encode_text(pack, text);
    const auto* ids = std::get_if<std::vector<std::size_t>>(&encoded);
    expect(ids != nullptr, "the corpus string encodes: " + text.substr(0U, 20U));
    if (ids == nullptr) continue;
    const auto decoded = secure_frontend::decode_token_ids(pack, *ids);
    expect(std::holds_alternative<std::string>(decoded) && std::get<std::string>(decoded) == text,
           "round trip: " + text.substr(0U, 20U));
  }
}

// Decode: U+2581 -> space, <0xXX> (BYTE) -> that byte; CONTROL/USER_DEFINED fail closed; a byte
// token in a byte_bpe pack stays refused.
void spm_decoder_maps_u2581_and_byte_tokens() {
  const auto pack = test_support::spm_tokenizer();
  const auto decoded = secure_frontend::decode_token_ids(pack, spm_ids(pack, {"Hi", kU2581 + "world", kU2581 + kU2581}));
  expect(std::holds_alternative<std::string>(decoded) && std::get<std::string>(decoded) == "Hi world  ", "U+2581 decodes to a space");
  const auto bytes = secure_frontend::decode_token_ids(pack, spm_ids(pack, {spm_byte(0xC3), spm_byte(0xA9)}));
  expect(std::holds_alternative<std::string>(bytes) && std::get<std::string>(bytes) == "\xC3\xA9", "byte tokens join into UTF-8");
  const secure_frontend::TokenByteDecoder decoder(pack);
  const auto lead = decoder.bytes_for(test_support::kSpmByteBase + 0xE2U);
  expect(std::holds_alternative<std::string>(lead) && std::get<std::string>(lead) == "\xE2",
         "one byte token is its raw byte (Utf8StreamDecoder joins a split character)");
  const auto split = secure_frontend::decode_token_ids(pack, spm_ids(pack, {spm_byte(0xC3)}));
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(split), "a lone lead byte is not valid UTF-8 text");
  for (const auto& [literal, type] : test_support::gemma4_special_tokens()) {
    const auto special = decoder.bytes_for(test_support::token_id(pack, literal));
    const auto* failure = std::get_if<secure_frontend::TokenizerPackError>(&special);
    expect(failure != nullptr && failure->code == secure_frontend::TokenizerPackErrorCode::undecodable_token,
           "a special token is never ordinary output: " + literal);
    static_cast<void>(type);
  }
  auto malformed = pack;
  malformed.tokens_by_id[test_support::kSpmByteBase] = "<0xzz>";
  const auto bad_byte = secure_frontend::TokenByteDecoder(malformed).bytes_for(test_support::kSpmByteBase);
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(bad_byte), "a BYTE token not spelled <0xXX> fails closed");
  auto unused = pack;
  unused.token_types[test_support::token_id(pack, "x")] = 5;
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(secure_frontend::TokenByteDecoder(unused).bytes_for(
             test_support::token_id(pack, "x"))),
         "an UNUSED (type 5) token fails closed in spm_bpe");
  auto byte_level = test_support::byte_tokenizer();
  byte_level.tokens_by_id.emplace_back("<0x41>");
  byte_level.token_types.push_back(6);
  const auto refused = secure_frontend::TokenByteDecoder(byte_level).bytes_for(byte_level.tokens_by_id.size() - 1U);
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(refused), "a BYTE token in a byte_bpe pack stays refused");
}
// ---- Gemma 4 plan 1 Task 7: the real vocabulary (the owner's GGUF, never committed) ----

const secure_frontend::JsonValue* member(const secure_frontend::JsonValue& object, const std::string_view key) {
  const auto* members = object.if_object();
  if (members == nullptr) return nullptr;
  for (const auto& entry : *members) {
    if (entry.key == key) return &entry.value;
  }
  return nullptr;
}

// The pack built by `secure_tokenizer.py --profile gemma4` from the UD-Q8_K_XL GGUF, named by
// SECURE_FRONTEND_GEMMA4_PACK (its tokenizer/ directory); skipped, with the reason printed, when
// unset. The fixture's ids come from llama.cpp's llama-tokenize at 3cf03257 and equal
// tools/secure/spm_bpe.py's (session log, Gemma step).
void gemma4_real_pack_matches_the_fixture() {
  const char* configured = secure_frontend::crt_getenv("SECURE_FRONTEND_GEMMA4_PACK");
  if (configured == nullptr || *configured == '\0' || !std::filesystem::is_directory(std::filesystem::path{configured})) {
    std::cout << "SKIPPED: SECURE_FRONTEND_GEMMA4_PACK names no Gemma 4 tokenizer pack directory (build one with "
                 "tools/secure/secure_tokenizer.py --profile gemma4; it is never committed)\n";
    return;
  }
  const auto loaded = secure_frontend::load_local_tokenizer_pack(std::filesystem::path{configured}, kSpm);
  const auto* pack = std::get_if<secure_frontend::TokenizerPack>(&loaded);
  const auto* load_error = std::get_if<secure_frontend::TokenizerPackError>(&loaded);
  expect(pack != nullptr, "the real Gemma 4 pack loads in spm_bpe mode: " + (load_error ? load_error->message : std::string{}));
  if (pack == nullptr) return;
  expect(pack->tokens_by_id.size() == 262144U && pack->merges_by_rank.size() == 514906U,
         "the UD-Q8_K_XL vocabulary: 262,144 tokens, 514,906 merges");
  const std::string text = secure_frontend_test::read_file(secure_frontend_test::extra_arguments().at(0));
  const auto parsed = secure_frontend::parse_json(
      text, secure_frontend::JsonLimits{.max_bytes = 1U << 20U, .max_depth = 4U, .max_container_entries = 65536U,
                                        .max_string_bytes = 1U << 16U});
  const auto* root = std::get_if<secure_frontend::JsonValue>(&parsed);
  const auto* entries = root != nullptr && member(*root, "texts") != nullptr ? member(*root, "texts")->if_array() : nullptr;
  expect(entries != nullptr && entries->size() >= 60U, "the fixture parses");
  if (entries == nullptr) return;
  std::size_t checked = 0U;
  for (const auto& entry : *entries) {
    const auto* input = member(entry, "text") != nullptr ? member(entry, "text")->if_string() : nullptr;
    expect(input != nullptr, "every fixture entry has a text");
    if (input == nullptr) continue;
    const auto encoded = secure_frontend::encode_text(*pack, *input);
    if (const auto* refused = member(entry, "refused"); refused != nullptr) {
      const auto* failure = std::get_if<secure_frontend::TokenizerPackError>(&encoded);
      expect(failure != nullptr && failure->code == secure_frontend::TokenizerPackErrorCode::unsupported_special_token,
             "a Gemma control literal as text is refused: " + input->substr(0U, 40U));
      continue;
    }
    std::vector<std::size_t> expected;
    if (const auto* ids = member(entry, "ids") != nullptr ? member(entry, "ids")->if_array() : nullptr) {
      for (const auto& id : *ids) expected.push_back(static_cast<std::size_t>(*id.if_integer()));
    }
    const auto* actual = std::get_if<std::vector<std::size_t>>(&encoded);
    expect(actual != nullptr && *actual == expected, "llama.cpp's ids for: " + input->substr(0U, 40U));
    if (actual != nullptr) {
      const auto decoded = secure_frontend::decode_token_ids(*pack, *actual);
      expect(std::holds_alternative<std::string>(decoded) && std::get<std::string>(decoded) == *input,
             "decode(encode(text)) == text: " + input->substr(0U, 40U));
    }
    ++checked;
  }
  expect(checked >= 60U, "at least 60 texts are compared id for id");
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
      {"spm_pack_loads_merges_json_with_newline_and_tab_tokens", spm_pack_loads_merges_json_with_newline_and_tab_tokens},
      {"mode_comes_from_the_profile_never_the_files", mode_comes_from_the_profile_never_the_files},
      {"merges_json_is_bounded_and_validated", merges_json_is_bounded_and_validated},
      {"spm_encodes_spaces_as_u2581_and_merges_by_rank", spm_encodes_spaces_as_u2581_and_merges_by_rank},
      {"spm_newline_runs_are_single_tokens_when_known", spm_newline_runs_are_single_tokens_when_known},
      {"spm_unknown_characters_fall_back_to_byte_tokens", spm_unknown_characters_fall_back_to_byte_tokens},
      {"spm_round_trips_the_upstream_corpus", spm_round_trips_the_upstream_corpus},
      {"spm_decoder_maps_u2581_and_byte_tokens", spm_decoder_maps_u2581_and_byte_tokens},
      {"gemma4_real_pack_matches_the_fixture", gemma4_real_pack_matches_the_fixture},
      {"spm_pack_load_prepares_the_encode_index_once", spm_pack_load_prepares_the_encode_index_once},
#ifndef _WIN32
      {"rejects_symlinked_assets", rejects_symlinked_assets},
      {"cfg03_tokenizer_file_swapped_to_symlink_rejected", cfg03_tokenizer_file_swapped_to_symlink_rejected},
#endif
#if defined(_WIN32)
      {"cfg03_tokenizer_file_swapped_to_junction_rejected", cfg03_tokenizer_file_swapped_to_junction_rejected},
#endif
  }, failures);
}

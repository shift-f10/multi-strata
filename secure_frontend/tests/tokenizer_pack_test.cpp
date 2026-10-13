#include "secure_frontend/tokenizer_pack.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <variant>

namespace {
int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}

std::filesystem::path temporary_pack() {
  const auto path = std::filesystem::temp_directory_path() /
                    ("secure-frontend-tokenizer-pack-" + std::to_string(std::rand()));
  std::filesystem::create_directories(path);
  return path;
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
#endif
}  // namespace

int main() {
  loads_validates_and_decodes_offline_pack();
  rejects_ambiguous_or_incompatible_pack_assets();
  rejects_malformed_json_and_special_literals_for_decode();
  encoding_fails_closed_for_special_invalid_and_missing_tokens();
#ifndef _WIN32
  rejects_symlinked_assets();
#endif
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

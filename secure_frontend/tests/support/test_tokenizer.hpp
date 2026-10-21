#pragma once

#include "secure_frontend/tokenizer_pack.hpp"

#include "support/test_support.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace test_support {

// GPT-2 byte-alphabet symbol for one byte (the encoding tokenizer packs use):
// bytes 0x21-0x7E, 0xA1-0xAC and 0xAE-0xFF are their own code point; every
// other byte, in ascending order, is code point 256 + n. Returned as UTF-8.
inline std::string byte_symbol(const unsigned char byte) {
  const auto printable = [](const unsigned int value) {
    return (value >= 0x21U && value <= 0x7eU) || (value >= 0xa1U && value <= 0xacU) || (value >= 0xaeU && value <= 0xffU);
  };
  unsigned int code_point = byte;
  if (!printable(byte)) {
    unsigned int shifted_before = 0U;
    for (unsigned int value = 0U; value < byte; ++value) {
      if (!printable(value)) ++shifted_before;
    }
    code_point = 256U + shifted_before;
  }
  if (code_point < 0x80U) return std::string(1U, static_cast<char>(code_point));
  return {static_cast<char>(0xc0U | (code_point >> 6U)), static_cast<char>(0x80U | (code_point & 0x3fU))};
}

// Token id k is the single byte (k + 65) mod 256, so the fake engine's `T 7` decodes to "H"
// (and a '0' byte is id 239: three decimal digits on the GEN line, used by K2 in Task 22).
inline unsigned char byte_for_id(const std::size_t id) { return static_cast<unsigned char>((id + 65U) & 0xffU); }

// Inverse of byte_for_id: the byte pack's id for one byte.
inline std::size_t id_for_byte(const unsigned char byte) { return static_cast<std::size_t>((byte + 256U - 65U) & 0xffU); }

// An ordinary token of kLongTokenBytes 'a' bytes: volume tests reach 1 MiB within
// limits.chat.max_completion_tokens (spec §9.3 dos02_slow_* cases; plan Controller note 4).
inline constexpr std::size_t kLongTokenId = 258U;
inline constexpr std::size_t kLongTokenBytes = 1024U;

// The --token-ids value that makes the fake emit `bytes`, one byte per token.
inline std::string token_ids_for(const std::string_view bytes) {
  std::string csv;
  for (const char character : bytes) {
    if (!csv.empty()) csv += ',';
    csv += std::to_string(id_for_byte(static_cast<unsigned char>(character)));
  }
  return csv;
}

// Every byte as an ordinary token (type 1) plus the Qwen framing controls (type 3).
inline secure_frontend::TokenizerPack byte_tokenizer() {
  secure_frontend::TokenizerPack pack;
  for (std::size_t id = 0; id < 256U; ++id) {
    pack.tokens_by_id.push_back(byte_symbol(byte_for_id(id)));
    pack.token_types.push_back(1);
  }
  pack.tokens_by_id.emplace_back("<|im_start|>");
  pack.token_types.push_back(3);
  pack.tokens_by_id.emplace_back("<|im_end|>");
  pack.token_types.push_back(3);
  pack.tokens_by_id.emplace_back(kLongTokenBytes, 'a');  // id 258 ('a' is its own byte symbol)
  pack.token_types.push_back(1);
  return pack;
}

// SP5 M1 Task 12 (Ruling T12-f): the byte pack with the three Qwen vision markers
// APPENDED (ids 259-261; every existing id stays put). The managed vision e2e's model
// tokenizer is this pack, so the plan's marker runs resolve as single CONTROL ids.
inline secure_frontend::TokenizerPack vision_byte_tokenizer() {
  auto pack = byte_tokenizer();
  for (const char* marker : {"<|vision_start|>", "<|image_pad|>", "<|vision_end|>"}) {
    pack.tokens_by_id.emplace_back(marker);
    pack.token_types.push_back(3);
  }
  return pack;
}

// The same pack as the three files load_local_tokenizer_pack() reads, each
// written 0600 (SP1's fixture rule) into an existing 0700 directory.
inline std::vector<std::pair<std::string, std::string>> tokenizer_pack_files(const secure_frontend::TokenizerPack& pack) {
  std::string vocab = "{";
  for (std::size_t id = 0; id < pack.tokens_by_id.size(); ++id) {
    if (id != 0U) vocab += ',';
    vocab += '"';
    for (const char character : pack.tokens_by_id[id]) {
      if (character == '"' || character == '\\') vocab += '\\';
      vocab += character;
    }
    vocab += "\":" + std::to_string(id);
  }
  vocab += '}';
  std::string types = "[";
  for (std::size_t index = 0; index < pack.token_types.size(); ++index) {
    if (index != 0U) types += ',';
    types += std::to_string(pack.token_types[index]);
  }
  types += ']';
  return {{"vocab.json", vocab}, {"merges.txt", std::string{}}, {"token_type.json", types}};
}

inline void write_tokenizer_pack(const std::filesystem::path& directory) {
  for (const auto& [name, bytes] : tokenizer_pack_files(byte_tokenizer())) {
    secure_frontend_test::write_file(directory / name, bytes, 0600);
  }
}

}  // namespace test_support

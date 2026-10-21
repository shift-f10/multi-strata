#pragma once

#include "secure_frontend/canonical_path.hpp"

#include <cstddef>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace secure_frontend {

// The offline tokenizer assets extracted by upstream/tools/strata_tokenizer.py
// (through our wrapper tools/secure/secure_tokenizer.py for GLM packs).  This
// type intentionally owns all input: loading a pack never keeps a file handle,
// invokes a subprocess, or contacts a network service.
struct TokenizerPack final {
  std::vector<std::string> tokens_by_id;
  std::vector<std::pair<std::string, std::string>> merges_by_rank;
  std::vector<int> token_types;
};

enum class TokenizerPackErrorCode {
  pack_root_unavailable,
  pack_root_not_directory,
  unsafe_pack_path,
  required_file_missing,
  symbolic_link_not_allowed,
  file_read_failed,
  file_too_large,
  invalid_json,
  invalid_vocabulary,
  invalid_merge,
  invalid_token_types,
  token_id_out_of_range,
  undecodable_token,
  decoded_text_not_utf8,
  input_text_not_utf8,
  input_text_too_large,
  unsupported_special_token,
  unencodable_text,
};

struct TokenizerPackError final {
  TokenizerPackErrorCode code;
  std::string message;
};

using TokenizerPackLoadResult = std::variant<TokenizerPack, TokenizerPackError>;
using TokenizerDecodeResult = std::variant<std::string, TokenizerPackError>;
using TokenizerEncodeResult = std::variant<std::vector<std::size_t>, TokenizerPackError>;

// Loads only the fixed local files vocab.json, merges.txt, and token_type.json
// beneath pack_root, each opened by handle with open_beneath (no link is
// followed). All files must be regular, non-symlink files. Vocabulary
// IDs must be unique, contiguous, and zero-based; merges must name vocabulary
// tokens and be unique; token types must have exactly one value per ID.
[[nodiscard]] TokenizerPackLoadResult load_local_tokenizer_pack(const CanonicalRoot& pack_root);
// Opens the root first (open_root: canonical, private, existing).
[[nodiscard]] TokenizerPackLoadResult load_local_tokenizer_pack(const std::filesystem::path& pack_root);

// Decodes byte-level-BPE token IDs using GPT-2's reversible byte alphabet.
// CONTROL (3) and USER_DEFINED (4)
// token types fail closed rather than being silently rendered as plain output.
[[nodiscard]] TokenizerDecodeResult decode_token_ids(const TokenizerPack& pack,
                                                      const std::vector<std::size_t>& ids);

// Raw bytes of ONE ordinary generated token (SP3 streaming). Unlike
// decode_token_ids, the result is not UTF-8 validated: a byte-level token may
// end in the middle of a character, which Utf8StreamDecoder resolves.
// CONTROL (3) and USER_DEFINED (4) types fail closed as in decode_token_ids.
// The pack must outlive the decoder.
class TokenByteDecoder final {
 public:
  explicit TokenByteDecoder(const TokenizerPack& pack);
  [[nodiscard]] TokenizerDecodeResult bytes_for(std::size_t id) const;

 private:
  const TokenizerPack& pack_;
  std::map<std::string, unsigned char> reverse_;
};

// Encodes ordinary UTF-8 text using the GPT-2 byte alphabet and merge ranks in
// this pack. The intentionally small pre-tokenizer preserves runs of ASCII
// letters, digits, whitespace, punctuation, and UTF-8 code points; it is not
// a replacement for model-specific (for example Qwen) regex pre-tokenizers or
// Jinja chat templates. Input containing a CONTROL or USER_DEFINED vocabulary
// literal fails closed, as does text which cannot be expressed by this pack.
[[nodiscard]] TokenizerEncodeResult encode_text(const TokenizerPack& pack,
                                                 std::string_view text);

// Encodes a prompt produced by render_qwen_text_prompt.  This deliberately
// recognizes only the two fixed Qwen ChatML framing literals: <|im_start|>
// and <|im_end|>.  Each must be present in the pack as exactly one CONTROL
// (type 3) token.  Every non-marker span still goes through encode_text(), so
// arbitrary CONTROL or USER_DEFINED literals remain rejected.  This is not a
// general special-token parser and must not be used with untrusted templates.
[[nodiscard]] TokenizerEncodeResult encode_qwen_chatml_prompt(
    const TokenizerPack& pack, std::string_view rendered_prompt);

// Encodes only the fixed literals emitted by render_glm53_text_prompt:
// [gMASK], <sop>, <|system|>, <|user|>, <|assistant|>, and <think>.  Each
// literal must occur exactly once in the vocabulary as a CONTROL (type 3)
// token. Every other span is ordinary text and retains encode_text()'s
// special-token rejection. This is not a general GLM special-token parser.
[[nodiscard]] TokenizerEncodeResult encode_glm53_prompt(
    const TokenizerPack& pack, std::string_view rendered_prompt);

}  // namespace secure_frontend

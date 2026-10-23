#pragma once

#include "secure_frontend/canonical_path.hpp"

#include <cstddef>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace secure_frontend {

// Gemma 4 plan 1 Task 4 (spec §6.2): how a pack's merges are stored and applied. The mode
// is chosen by the engine profile (gemma4 -> spm_bpe, every other -> byte_bpe), never
// inferred from the pack's files: byte_bpe is GPT-2's byte alphabet with merges.txt;
// spm_bpe is SentencePiece-style BPE over raw UTF-8 characters with merges.json.
enum class TokenizerMode { byte_bpe, spm_bpe };

// The offline tokenizer assets extracted by upstream/tools/strata_tokenizer.py
// (through our wrapper tools/secure/secure_tokenizer.py for GLM and Gemma 4 packs).  This
// type intentionally owns all input: loading a pack never keeps a file handle,
// invokes a subprocess, or contacts a network service.
struct TokenizerPack final {
  std::vector<std::string> tokens_by_id;
  std::vector<std::pair<std::string, std::string>> merges_by_rank;
  std::vector<int> token_types;
  TokenizerMode mode{TokenizerMode::byte_bpe};  // the mode it was loaded in (the profile's)
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

// Loads only the fixed local files vocab.json, token_type.json and the mode's merges file
// beneath pack_root, each opened by handle with open_beneath (no link is followed). All
// files must be regular, non-symlink files. Vocabulary IDs must be unique, contiguous, and
// zero-based; merges must name vocabulary tokens and be unique; token types must have
// exactly one value per ID. byte_bpe reads merges.txt (one "left right" per line) and
// refuses a pack that also has merges.json; spm_bpe reads merges.json (a JSON array of
// two-string arrays in rank order, so merges holding newlines, tabs or spaces round-trip) and
// refuses a pack that also has merges.txt (invalid_merge either way).
[[nodiscard]] TokenizerPackLoadResult load_local_tokenizer_pack(const CanonicalRoot& pack_root, TokenizerMode mode);
// Opens the root first (open_root: canonical, private, existing).
[[nodiscard]] TokenizerPackLoadResult load_local_tokenizer_pack(const std::filesystem::path& pack_root, TokenizerMode mode);

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

// The Qwen3 reasoning markers <think> and </think>. Found only when each literal occurs
// exactly once in the vocabulary as a CONTROL (3) or USER_DEFINED (4) token (Qwen3.8 packs
// mark them USER_DEFINED); nullopt otherwise, so a ChatML pack without reasoning keeps the
// plain generation prompt and its output rules.
struct ThinkTokens final {
  std::size_t open;
  std::size_t close;
};
[[nodiscard]] std::optional<ThinkTokens> find_qwen_think_tokens(const TokenizerPack& pack);

// The Qwen end-of-turn tokens <|im_end|> and <|endoftext|> (upstream's stop ids,
// serve/server.py:3770-3771; the engine's default --eos-ids). In serve mode the engine
// prints the end-of-turn token as a T record before DONE ... stop; it ends the reply and
// is never output. Each literal counts only as exactly one CONTROL (3) token; the result
// lists those found, in that order (empty: none).
[[nodiscard]] std::vector<std::size_t> find_qwen_end_of_turn_tokens(const TokenizerPack& pack);

// Encodes a prompt produced by render_qwen_text_prompt.  This deliberately
// recognizes only the two fixed Qwen ChatML framing literals: <|im_start|>
// and <|im_end|>.  Each must be present in the pack as exactly one CONTROL
// (type 3) token.  Every non-marker span still goes through encode_text(), so
// arbitrary CONTROL or USER_DEFINED literals remain rejected.  This is not a
// general special-token parser and must not be used with untrusted templates.
// One exception (issue 19): when the text after the final "<|im_start|>assistant\n"
// is exactly the renderer's reasoning tail ("<think>\n" or
// "<think>\n\n</think>\n\n"), it encodes through find_qwen_think_tokens(); the
// markers anywhere else are rejected as before.
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

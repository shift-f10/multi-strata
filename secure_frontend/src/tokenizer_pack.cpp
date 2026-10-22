#include "secure_frontend/tokenizer_pack.hpp"

#include "glm_pretokenizer_tables.hpp"
#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/json.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace secure_frontend {
namespace {

constexpr std::size_t kMaximumFileBytes = 64U * 1024U * 1024U;
constexpr std::size_t kMaximumVocabularyEntries = 1U * 1024U * 1024U;
constexpr std::size_t kMaximumTokenBytes = 16U * 1024U;
constexpr std::size_t kMaximumDecodedBytes = 8U * 1024U * 1024U;

TokenizerPackError error(const TokenizerPackErrorCode code, const std::string_view message) {
  return TokenizerPackError{code, std::string{message}};
}

bool is_continuation(const unsigned char byte) { return (byte & 0xc0U) == 0x80U; }

bool valid_utf8(const std::string_view value) {
  for (std::size_t i = 0U; i < value.size();) {
    const auto byte = static_cast<unsigned char>(value[i]);
    if (byte <= 0x7fU) { ++i; continue; }
    const auto has = [&](const std::size_t count) { return i + count < value.size(); };
    if (byte >= 0xc2U && byte <= 0xdfU && has(1U) && is_continuation(static_cast<unsigned char>(value[i + 1U]))) {
      i += 2U;
    } else if (byte == 0xe0U && has(2U) && static_cast<unsigned char>(value[i + 1U]) >= 0xa0U &&
               static_cast<unsigned char>(value[i + 1U]) <= 0xbfU && is_continuation(static_cast<unsigned char>(value[i + 2U]))) {
      i += 3U;
    } else if (((byte >= 0xe1U && byte <= 0xecU) || (byte >= 0xeeU && byte <= 0xefU)) && has(2U) &&
               is_continuation(static_cast<unsigned char>(value[i + 1U])) && is_continuation(static_cast<unsigned char>(value[i + 2U]))) {
      i += 3U;
    } else if (byte == 0xedU && has(2U) && static_cast<unsigned char>(value[i + 1U]) >= 0x80U &&
               static_cast<unsigned char>(value[i + 1U]) <= 0x9fU && is_continuation(static_cast<unsigned char>(value[i + 2U]))) {
      i += 3U;
    } else if (byte == 0xf0U && has(3U) && static_cast<unsigned char>(value[i + 1U]) >= 0x90U &&
               static_cast<unsigned char>(value[i + 1U]) <= 0xbfU && is_continuation(static_cast<unsigned char>(value[i + 2U])) &&
               is_continuation(static_cast<unsigned char>(value[i + 3U]))) {
      i += 4U;
    } else if (byte >= 0xf1U && byte <= 0xf3U && has(3U) && is_continuation(static_cast<unsigned char>(value[i + 1U])) &&
               is_continuation(static_cast<unsigned char>(value[i + 2U])) && is_continuation(static_cast<unsigned char>(value[i + 3U]))) {
      i += 4U;
    } else if (byte == 0xf4U && has(3U) && static_cast<unsigned char>(value[i + 1U]) >= 0x80U &&
               static_cast<unsigned char>(value[i + 1U]) <= 0x8fU && is_continuation(static_cast<unsigned char>(value[i + 2U])) &&
               is_continuation(static_cast<unsigned char>(value[i + 3U]))) {
      i += 4U;
    } else { return false; }
  }
  return true;
}

void append_utf8(std::string* out, const std::uint32_t point) {
  if (point <= 0x7fU) out->push_back(static_cast<char>(point));
  else if (point <= 0x7ffU) { out->push_back(static_cast<char>(0xc0U | (point >> 6U))); out->push_back(static_cast<char>(0x80U | (point & 0x3fU))); }
  else if (point <= 0xffffU) { out->push_back(static_cast<char>(0xe0U | (point >> 12U))); out->push_back(static_cast<char>(0x80U | ((point >> 6U) & 0x3fU))); out->push_back(static_cast<char>(0x80U | (point & 0x3fU))); }
  else { out->push_back(static_cast<char>(0xf0U | (point >> 18U))); out->push_back(static_cast<char>(0x80U | ((point >> 12U) & 0x3fU))); out->push_back(static_cast<char>(0x80U | ((point >> 6U) & 0x3fU))); out->push_back(static_cast<char>(0x80U | (point & 0x3fU))); }
}

std::variant<std::string, TokenizerPackError> read_required(const CanonicalRoot& root, const std::string_view name) {
  const auto relative = std::get<RelativePath>(parse_relative_path(name));
  auto opened = open_beneath(root, relative, OpenOptions{.kind = OpenKind::regular_file});
  if (const auto* failure = std::get_if<PathError>(&opened)) {
    switch (failure->code) {
      case PathErrorCode::not_found: return error(TokenizerPackErrorCode::required_file_missing, "required tokenizer pack file is missing");
      case PathErrorCode::symlink_not_allowed: return error(TokenizerPackErrorCode::symbolic_link_not_allowed, "tokenizer pack files must not be symbolic links");
      case PathErrorCode::not_regular_file: return error(TokenizerPackErrorCode::unsafe_pack_path, "tokenizer pack paths must name regular files");
      default: return error(TokenizerPackErrorCode::file_read_failed, "unable to open tokenizer pack file");
    }
  }
  const auto& file = std::get<OpenedFile>(opened);
  if (file.size() > kMaximumFileBytes) return error(TokenizerPackErrorCode::file_too_large, "tokenizer pack file exceeds fixed limit");
  auto text = file.read_all(kMaximumFileBytes);
  if (const auto* failure = std::get_if<PathError>(&text)) {
    return error(failure->code == PathErrorCode::too_large ? TokenizerPackErrorCode::file_too_large : TokenizerPackErrorCode::file_read_failed,
                 "unable to read tokenizer pack file");
  }
  return std::get<std::string>(std::move(text));
}

std::array<std::string, 256U> byte_symbols() {
  std::array<std::string, 256U> values{}; std::array<bool, 256U> printable{};
  for (unsigned int byte = 0x21U; byte <= 0x7eU; ++byte) printable[byte] = true;
  for (unsigned int byte = 0xa1U; byte <= 0xacU; ++byte) printable[byte] = true;
  for (unsigned int byte = 0xaeU; byte <= 0xffU; ++byte) printable[byte] = true;
  std::uint32_t shifted = 256U;
  for (unsigned int byte = 0U; byte < 256U; ++byte) { const auto point = printable[byte] ? byte : shifted++; append_utf8(&values[byte], point); }
  return values;
}

bool ascii_letter(const unsigned char value) {
  return (value >= static_cast<unsigned char>('a') && value <= static_cast<unsigned char>('z')) ||
         (value >= static_cast<unsigned char>('A') && value <= static_cast<unsigned char>('Z'));
}

bool ascii_digit(const unsigned char value) { return value >= static_cast<unsigned char>('0') && value <= static_cast<unsigned char>('9'); }
bool ascii_space(const unsigned char value) { return value == static_cast<unsigned char>(' ') || value == static_cast<unsigned char>('\n') || value == static_cast<unsigned char>('\r') || value == static_cast<unsigned char>('\t'); }

std::size_t utf8_width(const unsigned char value) {
  return value <= 0x7fU ? 1U : value <= 0xdfU ? 2U : value <= 0xefU ? 3U : 4U;
}

// A deliberately conservative approximation of GPT-2's Unicode regex. It is
// sufficient for ordinary text and keeps whitespace boundaries observable; a
// model-specific pre-tokenizer must be added before claiming exact parity.
std::vector<std::string_view> basic_pretokenize(const std::string_view text) {
  std::vector<std::string_view> pieces;
  for (std::size_t begin = 0U; begin < text.size();) {
    const unsigned char initial = static_cast<unsigned char>(text[begin]);
    std::size_t end = begin + utf8_width(initial);
    enum class Kind { spaces, letters, digits, other } kind = ascii_space(initial) ? Kind::spaces : ascii_letter(initial) || initial >= 0x80U ? Kind::letters : ascii_digit(initial) ? Kind::digits : Kind::other;
    while (end < text.size()) {
      const unsigned char current = static_cast<unsigned char>(text[end]);
      const Kind next = ascii_space(current) ? Kind::spaces : ascii_letter(current) || current >= 0x80U ? Kind::letters : ascii_digit(current) ? Kind::digits : Kind::other;
      if (next != kind) break;
      end += utf8_width(current);
    }
    pieces.push_back(text.substr(begin, end - begin));
    begin = end;
  }
  return pieces;
}

// --- the GLM pre-tokenizer of SP6 5.5 -------------------------------------------------------
//
// The transcription of llama.cpp's LLAMA_VOCAB_PRE_TYPE_CHATGLM4 pattern, kept here as the
// text a pack ships so a pack that contradicts the frontend is refused:
//
//   (?:'[sS]|'[tT]|'[rR][eE]|'[vV][eE]|'[mM]|'[lL][lL]|'[dD])
//   |[^\r\n\p{L}\p{N}]?\p{L}+
//   |\p{N}{1,3}
//   | ?[^\s\p{L}\p{N}]+[\r\n]*
//   |\s*[\r\n]+|\s+(?!\S)|\s+
//
// `glm_match_at` below applies it exactly as Python's `regex` does - at each position the
// seven branches are tried IN ORDER and the first that can match wins, each with its own
// greedy quantifiers and its own backtracking.  Two details carry the parity: `\p{L}` here
// EXCLUDES marks (unlike the qwen35 split above), so a combining mark starts a punctuation
// run rather than joining the letter before it; and `\p{N}{1,3}` caps a numeric run at three
// digits.  The classes come from glm_pretokenizer_tables.hpp, generated with the same
// classifier that generated the fixtures.
constexpr std::string_view kGlmPrePattern =
    "(?:'[sS]|'[tT]|'[rR][eE]|'[vV][eE]|'[mM]|'[lL][lL]|'[dD])"
    "|[^\\r\\n\\p{L}\\p{N}]?\\p{L}+"
    "|\\p{N}{1,3}"
    "| ?[^\\s\\p{L}\\p{N}]+[\\r\\n]*"
    "|\\s*[\\r\\n]+|\\s+(?!\\S)|\\s+";

// The names that select it.  `chatglm-bpe` is the older alias tools/secure/secure_tokenizer.py
// has always accepted.
constexpr std::array<std::string_view, 3U> kGlmPreNames{{"glm4", "glm5", "chatglm-bpe"}};
constexpr std::string_view kQwen35PreName = "qwen35";

// Branch 1's contraction literals, in the pattern's own order.
constexpr std::array<std::string_view, 20U> kGlmContractions{{
    "'s", "'S", "'t", "'T", "'re", "'Re", "'rE", "'RE", "'ve", "'Ve", "'vE", "'VE",
    "'m", "'M", "'ll", "'Ll", "'lL", "'LL", "'d", "'D"}};

bool in_ranges(const glm_tables::Range* const table, const std::size_t count, const std::uint32_t point) {
  std::size_t low = 0U;
  std::size_t high = count;
  while (low < high) {
    const std::size_t middle = low + (high - low) / 2U;
    if (table[middle].last < point) low = middle + 1U;
    else if (table[middle].first > point) high = middle;
    else return true;
  }
  return false;
}

bool is_letter(const std::uint32_t point) { return in_ranges(glm_tables::kLetterRanges, glm_tables::kLetterRangesCount, point); }
bool is_number(const std::uint32_t point) { return in_ranges(glm_tables::kNumberRanges, glm_tables::kNumberRangesCount, point); }
bool is_space(const std::uint32_t point) { return in_ranges(glm_tables::kSpaceRanges, glm_tables::kSpaceRangesCount, point); }
bool is_line_break(const std::uint32_t point) { return point == 0x0dU || point == 0x0au; }
bool is_other(const std::uint32_t point) { return !is_space(point) && !is_letter(point) && !is_number(point); }

// The code point at a byte offset of text already known to be valid UTF-8.
std::uint32_t code_point_at(const std::string_view text, const std::size_t at) {
  const auto lead = static_cast<unsigned char>(text[at]);
  const std::size_t width = utf8_width(lead);
  const std::uint32_t mask = width == 1U ? 0x7fU : width == 2U ? 0x1fU : width == 3U ? 0x0fU : 0x07U;
  std::uint32_t point = lead & mask;
  for (std::size_t index = 1U; index < width && at + index < text.size(); ++index) {
    point = (point << 6U) | (static_cast<unsigned char>(text[at + index]) & 0x3fU);
  }
  return point;
}

template <typename Kind>
std::size_t run_of(const std::string_view text, const std::size_t at, const Kind kind) {
  std::size_t index = at;
  while (index < text.size()) {
    const unsigned char lead = static_cast<unsigned char>(text[index]);
    if (!kind(code_point_at(text, index))) break;
    index += utf8_width(lead);
  }
  return index;
}

// Where the leftmost GLM match starting at `at` ends, or nullopt when no branch matches.
std::optional<std::size_t> glm_match_at(const std::string_view text, const std::size_t at) {
  const unsigned char lead_byte = static_cast<unsigned char>(text[at]);
  const std::size_t width = utf8_width(lead_byte);
  const std::uint32_t point = code_point_at(text, at);
  for (const std::string_view literal : kGlmContractions) {
    if (text.size() - at >= literal.size() && text.compare(at, literal.size(), literal) == 0) return at + literal.size();
  }
  // 2. [^\r\n\p{L}\p{N}]?\p{L}+  - a code point that is itself a letter cannot be the lead,
  //    so the two shapes are disjoint and their order does not matter.  The lead class here
  //    holds spaces and marks: " the" and the U+0301 of "a\u0301bc" both arrive with it.
  const std::size_t letters = run_of(text, at, is_letter);
  if (letters > at) return letters;
  if (!is_line_break(point) && !is_letter(point) && !is_number(point)) {
    const std::size_t after_lead = run_of(text, at + width, is_letter);
    if (after_lead > at + width) return after_lead;
  }
  // 3. \p{N}{1,3}
  if (is_number(point)) {
    std::size_t index = at;
    for (std::size_t taken = 0U; taken < 3U && index < text.size(); ++taken) {
      if (!is_number(code_point_at(text, index))) break;
      index += utf8_width(static_cast<unsigned char>(text[index]));
    }
    return index;
  }
  // 4. ` ?[^\s\p{L}\p{N}]+[\r\n]*`  - the optional literal space is greedy, so it is tried
  //    first; without it the branch cannot start at a space at all.
  if (point == 0x20U) {
    const std::size_t others = run_of(text, at + width, is_other);
    if (others > at + width) return run_of(text, others, is_line_break);
  }
  const std::size_t others = run_of(text, at, is_other);
  if (others > at) return run_of(text, others, is_line_break);
  // 5. \s*[\r\n]+   6. \s+(?!\S)   7. \s+   - one whitespace run, three ways.
  if (is_space(point)) {
    const std::size_t run_end = run_of(text, at, is_space);
    std::size_t last_break_end = 0U;      // greedy \s* leaves [\r\n]+ the LAST break cluster
    std::size_t last_codepoint_at = at;   // \s+(?!\S) gives back the run's last code point
    for (std::size_t index = at; index < run_end; ) {
      const std::size_t step = utf8_width(static_cast<unsigned char>(text[index]));
      if (is_line_break(code_point_at(text, index))) last_break_end = run_of(text, index, is_line_break);
      last_codepoint_at = index;
      index += step;
    }
    if (last_break_end != 0U) return last_break_end;
    if (run_end == text.size()) return run_end;
    if (last_codepoint_at > at) return last_codepoint_at;
    return run_end;
  }
  return std::nullopt;
}

std::vector<std::string_view> glm_pretokenize(const std::string_view text) {
  std::vector<std::string_view> pieces;
  for (std::size_t at = 0U; at < text.size();) {
    const auto end = glm_match_at(text, at);
    if (end == std::nullopt || *end <= at) {
      at += utf8_width(static_cast<unsigned char>(text[at]));   // findall moves on
      continue;
    }
    pieces.push_back(text.substr(at, *end - at));
    at = *end;
  }
  return pieces;
}

// tokenizer.json is read with its own limits: it is a metadata object (depth 2 with
// `special_ids`), never a vocabulary.
constexpr JsonLimits kPackMetaLimits{.max_bytes = kMaximumFileBytes, .max_depth = 2U,
                                     .max_container_entries = kMaximumVocabularyEntries + 1U,
                                     .max_string_bytes = kMaximumTokenBytes};

// An optional pack file: a missing copy is not an error, everything else read_required does.
std::variant<std::optional<std::string>, TokenizerPackError> read_optional(const CanonicalRoot& root, const std::string_view name) {
  const auto relative = std::get<RelativePath>(parse_relative_path(name));
  auto opened = open_beneath(root, relative, OpenOptions{.kind = OpenKind::regular_file});
  if (const auto* failure = std::get_if<PathError>(&opened)) {
    switch (failure->code) {
      case PathErrorCode::not_found: return std::optional<std::string>{};
      case PathErrorCode::symlink_not_allowed: return error(TokenizerPackErrorCode::symbolic_link_not_allowed, "tokenizer pack files must not be symbolic links");
      case PathErrorCode::not_regular_file: return error(TokenizerPackErrorCode::unsafe_pack_path, "tokenizer pack paths must name regular files");
      default: return error(TokenizerPackErrorCode::file_read_failed, "unable to open tokenizer pack file");
    }
  }
  const auto& file = std::get<OpenedFile>(opened);
  if (file.size() > kMaximumFileBytes) return error(TokenizerPackErrorCode::file_too_large, "tokenizer pack file exceeds fixed limit");
  auto text = file.read_all(kMaximumFileBytes);
  if (const auto* failure = std::get_if<PathError>(&text)) {
    return error(failure->code == PathErrorCode::too_large ? TokenizerPackErrorCode::file_too_large : TokenizerPackErrorCode::file_read_failed,
                 "unable to read tokenizer pack file");
  }
  return std::get<std::string>(std::move(text));
}

TokenizerEncodeResult encode_piece(const TokenizerPack& pack, const std::string_view piece,
                                   const std::array<std::string, 256U>& symbols,
                                   const std::map<std::string, std::size_t>& ids,
                                   const std::map<std::pair<std::string, std::string>, std::size_t>& ranks) {
  std::vector<std::string> values;
  values.reserve(piece.size());
  for (const unsigned char byte : piece) values.push_back(symbols[byte]);
  // §5.5: llama.cpp's `ignore_merges` for the GLM pre-tokenizers - a pre-token piece that is
  // an exact vocabulary entry is emitted WHOLE, and only the pieces that are not go through
  // BPE.  The lookup runs on the BYTE-MAPPED piece (the vocabulary is stored in the byte-level
  // alphabet), exactly as MAYA's tools/strata_tokenizer.py:249-255 does it: for `x=Δy²` the
  // mapped piece `Â²` is one GLM token while the raw piece `²` is in the vocabulary not at all.
  if (pack.ignore_merges) {
    std::string whole;
    for (const std::string& symbol : values) whole += symbol;
    const auto hit = ids.find(whole);
    if (hit != ids.end()) {
      if (hit->second >= pack.token_types.size() || pack.token_types[hit->second] == 3 || pack.token_types[hit->second] == 4) return error(TokenizerPackErrorCode::unencodable_text, "text cannot be encoded by ordinary vocabulary tokens");
      return std::vector<std::size_t>{hit->second};
    }
  }
  while (values.size() > 1U) {
    std::optional<std::size_t> best_rank;
    std::size_t best_index = 0U;
    for (std::size_t index = 0U; index + 1U < values.size(); ++index) {
      const auto found = ranks.find({values[index], values[index + 1U]});
      if (found != ranks.end() && (!best_rank || found->second < *best_rank)) { best_rank = found->second; best_index = index; }
    }
    if (!best_rank) break;
    values[best_index] += values[best_index + 1U];
    values.erase(values.begin() + static_cast<std::ptrdiff_t>(best_index + 1U));
  }
  std::vector<std::size_t> encoded;
  encoded.reserve(values.size());
  for (const std::string& value : values) {
    const auto found = ids.find(value);
    if (found == ids.end() || found->second >= pack.token_types.size() || pack.token_types[found->second] == 3 || pack.token_types[found->second] == 4) return error(TokenizerPackErrorCode::unencodable_text, "text cannot be encoded by ordinary vocabulary tokens");
    encoded.push_back(found->second);
  }
  return encoded;
}

// One extra entry so an oversized vocabulary still reaches the
// invalid_vocabulary check below with its own error code.
constexpr JsonLimits kPackJsonLimits{.max_bytes = kMaximumFileBytes, .max_depth = 1U,
                                     .max_container_entries = kMaximumVocabularyEntries + 1U,
                                     .max_string_bytes = kMaximumTokenBytes};

std::optional<std::map<std::string, std::size_t>> vocabulary_from(const JsonParseResult& parsed) {
  const auto* root = std::get_if<JsonValue>(&parsed);
  const auto* members = root != nullptr ? root->if_object() : nullptr;
  if (members == nullptr) return std::nullopt;
  std::map<std::string, std::size_t> result;
  for (const auto& member : *members) {
    const auto* id = member.value.if_integer();
    if (id == nullptr || *id < 0) return std::nullopt;
    result.emplace(member.key, static_cast<std::size_t>(*id));
  }
  return result;
}

std::optional<std::vector<int>> token_types_from(const JsonParseResult& parsed) {
  const auto* root = std::get_if<JsonValue>(&parsed);
  const auto* items = root != nullptr ? root->if_array() : nullptr;
  if (items == nullptr || items->size() > kMaximumVocabularyEntries) return std::nullopt;
  std::vector<int> result;
  result.reserve(items->size());
  for (const auto& item : *items) {
    const auto* value = item.if_integer();
    if (value == nullptr || *value < std::numeric_limits<int>::min() || *value > std::numeric_limits<int>::max()) {
      return std::nullopt;
    }
    result.push_back(static_cast<int>(*value));
  }
  return result;
}

}  // namespace

TokenizerPackLoadResult load_local_tokenizer_pack(const std::filesystem::path& pack_root) {
  auto root = open_root(pack_root);
  if (const auto* failure = std::get_if<PathError>(&root)) {
    return error(failure->code == PathErrorCode::not_directory ? TokenizerPackErrorCode::pack_root_not_directory
                                                               : TokenizerPackErrorCode::pack_root_unavailable,
                 "tokenizer pack root must be an existing private directory");
  }
  return load_local_tokenizer_pack(std::get<CanonicalRoot>(root));
}

TokenizerPackLoadResult load_local_tokenizer_pack(const CanonicalRoot& root) {
  const auto vocab_text = read_required(root, "vocab.json"); const auto merges_text = read_required(root, "merges.txt"); const auto types_text = read_required(root, "token_type.json");
  if (const auto* e = std::get_if<TokenizerPackError>(&vocab_text)) return *e;
  if (const auto* e = std::get_if<TokenizerPackError>(&merges_text)) return *e;
  if (const auto* e = std::get_if<TokenizerPackError>(&types_text)) return *e;
  const auto vocabulary = vocabulary_from(parse_json(std::get<std::string>(vocab_text), kPackJsonLimits));
  const auto types = token_types_from(parse_json(std::get<std::string>(types_text), kPackJsonLimits));
  if (!vocabulary) return error(TokenizerPackErrorCode::invalid_json, "vocab.json must be a JSON object of token IDs");
  if (!types) return error(TokenizerPackErrorCode::invalid_json, "token_type.json must be a JSON array of integers");
  if (vocabulary->empty() || vocabulary->size() > kMaximumVocabularyEntries) return error(TokenizerPackErrorCode::invalid_vocabulary, "vocabulary size is outside fixed bounds");
  if (types->size() != vocabulary->size()) return error(TokenizerPackErrorCode::invalid_token_types, "token types must have exactly one value per vocabulary ID");
  TokenizerPack pack; pack.tokens_by_id.resize(vocabulary->size()); pack.token_types = *types;
  for (const auto& [token, id] : *vocabulary) {
    if (token.empty() || token.size() > kMaximumTokenBytes || id >= pack.tokens_by_id.size() || !pack.tokens_by_id[id].empty()) return error(TokenizerPackErrorCode::invalid_vocabulary, "vocabulary IDs must be contiguous, unique, and token strings bounded");
    pack.tokens_by_id[id] = token;
  }
  if (std::any_of(pack.tokens_by_id.begin(), pack.tokens_by_id.end(), [](const std::string& token) { return token.empty(); })) return error(TokenizerPackErrorCode::invalid_vocabulary, "vocabulary IDs must start at zero and be contiguous");
  // The pre-tokenizer the pack declares in tokenizer.json (SP6 §5.5).  A pack with no
  // tokenizer.json, or with no `pre` member, keeps the generic split every such pack has
  // always used; a DECLARED name the frontend has not transcribed is refused, because
  // splitting text the wrong way produces plausible ids and wrong answers.
  const auto meta_text = read_optional(root, "tokenizer.json");
  if (const auto* failure = std::get_if<TokenizerPackError>(&meta_text)) return *failure;
  if (const auto* text = std::get_if<std::optional<std::string>>(&meta_text); text != nullptr && text->has_value()) {
    const auto parsed = parse_json(**text, kPackMetaLimits);
    const auto* document = std::get_if<JsonValue>(&parsed);
    const auto* members = document != nullptr ? document->if_object() : nullptr;
    if (members == nullptr) return error(TokenizerPackErrorCode::invalid_tokenizer_pack, "tokenizer.json must be a JSON object");
    const JsonValue* declared = nullptr;
    const JsonValue* shipped_merges = nullptr;
    const JsonValue* shipped_pattern = nullptr;
    for (const auto& member : *members) {
      if (member.key == "pre") declared = &member.value;
      else if (member.key == "ignore_merges") shipped_merges = &member.value;
      else if (member.key == "pre_pattern") shipped_pattern = &member.value;
    }
    if (declared != nullptr) {
      const auto* name = declared->if_string();
      if (name == nullptr) return error(TokenizerPackErrorCode::invalid_tokenizer_pack, "tokenizer.json pre must be a string");
      if (*name == kQwen35PreName) {
        pack.pre_tokenizer = PreTokenizerScheme::generic;
        pack.ignore_merges = false;
      } else if (std::any_of(kGlmPreNames.begin(), kGlmPreNames.end(), [&](const std::string_view known) { return *name == known; })) {
        pack.pre_tokenizer = PreTokenizerScheme::glm;
        pack.ignore_merges = true;
      } else {
        return error(TokenizerPackErrorCode::invalid_tokenizer_pack, "tokenizer.json declares a pre-tokenizer this frontend has not transcribed");
      }
    }
    // A pack ships the pattern and the flag it was built with (MAYA extract writes both);
    // the frontend uses ITS OWN transcription, so a pack that contradicts it is refused.
    if (shipped_merges != nullptr) {
      const auto* flag = shipped_merges->if_boolean();
      if (flag == nullptr || *flag != pack.ignore_merges) return error(TokenizerPackErrorCode::invalid_tokenizer_pack, "tokenizer.json ignore_merges contradicts the declared pre-tokenizer");
    }
    if (shipped_pattern != nullptr) {
      const auto* pattern = shipped_pattern->if_string();
      // Only the GLM transcription is compared: the generic split above is a documented
      // approximation of the qwen35 regex that the frontend makes no parity claim about.
      if (pattern == nullptr || (pack.pre_tokenizer == PreTokenizerScheme::glm && *pattern != kGlmPrePattern)) return error(TokenizerPackErrorCode::invalid_tokenizer_pack, "tokenizer.json pre_pattern contradicts this frontend's transcription");
    }
  }
  std::set<std::string> known(pack.tokens_by_id.begin(), pack.tokens_by_id.end()); std::set<std::pair<std::string, std::string>> seen;
  std::string_view remaining = std::get<std::string>(merges_text); std::size_t start = 0U;
  while (start <= remaining.size()) {
    const auto end = remaining.find('\n', start); std::string_view line = remaining.substr(start, end == std::string_view::npos ? remaining.size() - start : end - start);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1U);
    if (!line.empty()) {
      const auto split = line.find(' ');
      if (split == std::string_view::npos || split == 0U || split + 1U >= line.size() || line.find(' ', split + 1U) != std::string_view::npos) return error(TokenizerPackErrorCode::invalid_merge, "each merge must be exactly two tokens separated by one space");
      std::pair<std::string, std::string> merge{line.substr(0U, split), line.substr(split + 1U)};
      if (!known.contains(merge.first) || !known.contains(merge.second) || !seen.insert(merge).second || pack.merges_by_rank.size() >= kMaximumVocabularyEntries) return error(TokenizerPackErrorCode::invalid_merge, "merges must be unique bounded pairs of vocabulary tokens");
      pack.merges_by_rank.push_back(std::move(merge));
    }
    if (end == std::string_view::npos) break;
    start = end + 1U;
  }
  return pack;
}

TokenByteDecoder::TokenByteDecoder(const TokenizerPack& pack) : pack_(pack) {
  const auto symbols = byte_symbols();
  for (unsigned int byte = 0U; byte < 256U; ++byte) reverse_.emplace(symbols[byte], static_cast<unsigned char>(byte));
}

TokenizerDecodeResult TokenByteDecoder::bytes_for(const std::size_t id) const {
  if (id >= pack_.tokens_by_id.size()) return error(TokenizerPackErrorCode::token_id_out_of_range, "token ID is outside the loaded vocabulary");
  if (id >= pack_.token_types.size() || pack_.token_types[id] == 3 || pack_.token_types[id] == 4) {
    return error(TokenizerPackErrorCode::undecodable_token, "control and user-defined token types are not ordinary decoded output");
  }
  const std::string_view token = pack_.tokens_by_id[id];
  std::string bytes;
  for (std::size_t offset = 0U; offset < token.size();) {
    const auto lead = static_cast<unsigned char>(token[offset]);
    const std::size_t width = lead <= 0x7fU ? 1U : lead <= 0xdfU ? 2U : lead <= 0xefU ? 3U : 4U;
    if (offset + width > token.size()) return error(TokenizerPackErrorCode::undecodable_token, "token is not composed of byte alphabet symbols");
    const auto it = reverse_.find(std::string{token.substr(offset, width)});
    if (it == reverse_.end()) return error(TokenizerPackErrorCode::undecodable_token, "token is not composed of byte alphabet symbols");
    bytes.push_back(static_cast<char>(it->second));
    offset += width;
  }
  return bytes;
}

TokenizerDecodeResult decode_token_ids(const TokenizerPack& pack, const std::vector<std::size_t>& ids) {
  const TokenByteDecoder decoder(pack);
  std::string bytes;
  for (const std::size_t id : ids) {
    auto piece = decoder.bytes_for(id);
    if (auto* failure = std::get_if<TokenizerPackError>(&piece)) return std::move(*failure);
    const auto& text = std::get<std::string>(piece);
    if (bytes.size() + text.size() > kMaximumDecodedBytes) return error(TokenizerPackErrorCode::decoded_text_not_utf8, "decoded token data exceeds fixed limit");
    bytes += text;
  }
  if (!valid_utf8(bytes)) return error(TokenizerPackErrorCode::decoded_text_not_utf8, "decoded token data is not valid UTF-8");
  return bytes;
}

TokenizerEncodeResult encode_text(const TokenizerPack& pack, const std::string_view text) {
  if (text.size() > kMaximumDecodedBytes) return error(TokenizerPackErrorCode::input_text_too_large, "input text exceeds fixed limit");
  if (!valid_utf8(text)) return error(TokenizerPackErrorCode::input_text_not_utf8, "input text must be valid UTF-8");
  std::map<std::string, std::size_t> ids;
  for (std::size_t id = 0U; id < pack.tokens_by_id.size(); ++id) {
    if (!ids.emplace(pack.tokens_by_id[id], id).second) return error(TokenizerPackErrorCode::invalid_vocabulary, "vocabulary tokens must be unique for encoding");
    if (id < pack.token_types.size() && (pack.token_types[id] == 3 || pack.token_types[id] == 4) && text.find(pack.tokens_by_id[id]) != std::string_view::npos) return error(TokenizerPackErrorCode::unsupported_special_token, "special token literals are not accepted as ordinary input");
  }
  std::map<std::pair<std::string, std::string>, std::size_t> ranks;
  for (std::size_t rank = 0U; rank < pack.merges_by_rank.size(); ++rank) ranks.emplace(pack.merges_by_rank[rank], rank);
  const auto symbols = byte_symbols();
  std::vector<std::size_t> output;
  for (const std::string_view piece : pack.pre_tokenizer == PreTokenizerScheme::glm
                                       ? glm_pretokenize(text) : basic_pretokenize(text)) {
    const auto piece_ids = encode_piece(pack, piece, symbols, ids, ranks);
    if (const auto* failure = std::get_if<TokenizerPackError>(&piece_ids)) return *failure;
    const auto& values = std::get<std::vector<std::size_t>>(piece_ids);
    if (output.size() > kMaximumVocabularyEntries - values.size()) return error(TokenizerPackErrorCode::input_text_too_large, "encoded token count exceeds fixed limit");
    output.insert(output.end(), values.begin(), values.end());
  }
  return output;
}

std::optional<ThinkTokens> find_qwen_think_tokens(const TokenizerPack& pack) {
  // Exactly one entry, typed CONTROL or USER_DEFINED; anything else is no reasoning split.
  const auto find = [&pack](const std::string_view literal) -> std::optional<std::size_t> {
    std::optional<std::size_t> found;
    for (std::size_t id = 0U; id < pack.tokens_by_id.size(); ++id) {
      if (pack.tokens_by_id[id] != literal) continue;
      if (found.has_value() || id >= pack.token_types.size() || (pack.token_types[id] != 3 && pack.token_types[id] != 4)) {
        return std::nullopt;
      }
      found = id;
    }
    return found;
  };
  const auto open = find("<think>");
  const auto close = find("</think>");
  if (!open.has_value() || !close.has_value()) return std::nullopt;
  return ThinkTokens{*open, *close};
}

std::vector<std::string> pretokenizer_pieces(const TokenizerPack& pack, const std::string_view text) {
  std::vector<std::string> pieces;
  for (const std::string_view piece : pack.pre_tokenizer == PreTokenizerScheme::glm
                                           ? glm_pretokenize(text) : basic_pretokenize(text)) {
    pieces.emplace_back(piece);
  }
  return pieces;
}

std::vector<std::size_t> find_qwen_end_of_turn_tokens(const TokenizerPack& pack) {
  std::vector<std::size_t> found;
  for (const std::string_view literal : {"<|im_end|>", "<|endoftext|>"}) {
    std::optional<std::size_t> id_of;
    bool unique = true;
    for (std::size_t id = 0U; id < pack.tokens_by_id.size(); ++id) {
      if (pack.tokens_by_id[id] != literal) continue;
      if (id_of.has_value()) unique = false;
      id_of = id;
    }
    if (id_of.has_value() && unique && *id_of < pack.token_types.size() && pack.token_types[*id_of] == 3) found.push_back(*id_of);
  }
  return found;
}

TokenizerEncodeResult encode_qwen_chatml_prompt(const TokenizerPack& pack,
                                                const std::string_view rendered_prompt) {
  constexpr std::string_view kStartMarker = "<|im_start|>";
  constexpr std::string_view kEndMarker = "<|im_end|>";
  if (pack.tokens_by_id.size() != pack.token_types.size()) {
    return error(TokenizerPackErrorCode::invalid_token_types,
                 "token type entries must match vocabulary entries");
  }

  const auto find_marker = [&pack](const std::string_view marker)
      -> std::variant<std::size_t, TokenizerPackError> {
    std::optional<std::size_t> marker_id;
    for (std::size_t id = 0U; id < pack.tokens_by_id.size(); ++id) {
      if (pack.tokens_by_id[id] != marker) continue;
      if (pack.token_types[id] != 3 || marker_id.has_value()) {
        return error(TokenizerPackErrorCode::unsupported_special_token,
                     "Qwen framing marker must be exactly one CONTROL token");
      }
      marker_id = id;
    }
    if (!marker_id.has_value()) {
      return error(TokenizerPackErrorCode::unsupported_special_token,
                   "Qwen framing marker is unavailable as a CONTROL token");
    }
    return *marker_id;
  };

  const auto start_id = find_marker(kStartMarker);
  if (const auto* failure = std::get_if<TokenizerPackError>(&start_id)) return *failure;
  const auto end_id = find_marker(kEndMarker);
  if (const auto* failure = std::get_if<TokenizerPackError>(&end_id)) return *failure;

  // Issue 19: the Qwen3 reasoning tail (render_qwen_text_prompt with QwenThinking::on or
  // off) is accepted only as the exact text after the final generation header. Its
  // markers are never scanned for anywhere else, so every other span keeps
  // encode_text()'s rejection of special literals.
  constexpr std::string_view kGenerationHeader = "<|im_start|>assistant\n";
  constexpr std::string_view kThinkOpenTail = "<think>\n";
  constexpr std::string_view kThinkClosedTail = "<think>\n\n</think>\n\n";
  std::string_view body = rendered_prompt;
  std::string_view think_tail;
  if (const auto header_at = rendered_prompt.rfind(kGenerationHeader); header_at != std::string_view::npos) {
    const std::size_t tail_at = header_at + kGenerationHeader.size();
    const std::string_view tail = rendered_prompt.substr(tail_at);
    if (tail == kThinkOpenTail || tail == kThinkClosedTail) {
      think_tail = tail;
      body = rendered_prompt.substr(0U, tail_at);
    }
  }

  // SP5 M1 Task 12 (Ruling T12-f): the three Qwen vision markers join the scan ONLY
  // when the rendered prompt actually carries them (a text prompt, and every pack
  // predating images, behave exactly as before). Like the framing markers, each must
  // resolve to exactly one CONTROL token.
  std::vector<std::pair<std::string_view, std::size_t>> markers;
  markers.emplace_back(kStartMarker, std::get<std::size_t>(start_id));
  markers.emplace_back(kEndMarker, std::get<std::size_t>(end_id));
  for (const std::string_view vision_marker : {"<|vision_start|>", "<|image_pad|>", "<|vision_end|>"}) {
    if (body.find(vision_marker) == std::string_view::npos) continue;
    const auto vision_id = find_marker(vision_marker);
    if (const auto* failure = std::get_if<TokenizerPackError>(&vision_id)) return *failure;
    markers.emplace_back(vision_marker, std::get<std::size_t>(vision_id));
  }

  std::vector<std::size_t> output;
  std::size_t offset = 0U;
  while (offset < body.size()) {
    std::size_t marker_at = std::string_view::npos;
    std::size_t marker_index = 0U;
    for (std::size_t candidate = 0U; candidate < markers.size(); ++candidate) {
      const auto at = body.find(markers[candidate].first, offset);
      if (at < marker_at) {
        marker_at = at;
        marker_index = candidate;
      }
    }
    if (marker_at == std::string_view::npos) {
      const auto ordinary = encode_text(pack, body.substr(offset));
      if (const auto* failure = std::get_if<TokenizerPackError>(&ordinary)) return *failure;
      const auto& ids = std::get<std::vector<std::size_t>>(ordinary);
      if (output.size() > kMaximumVocabularyEntries - ids.size()) {
        return error(TokenizerPackErrorCode::input_text_too_large,
                     "encoded token count exceeds fixed limit");
      }
      output.insert(output.end(), ids.begin(), ids.end());
      break;
    }

    const auto ordinary = encode_text(pack, body.substr(offset, marker_at - offset));
    if (const auto* failure = std::get_if<TokenizerPackError>(&ordinary)) return *failure;
    const auto& ids = std::get<std::vector<std::size_t>>(ordinary);
    if (ids.size() >= kMaximumVocabularyEntries ||
        output.size() > kMaximumVocabularyEntries - ids.size() - 1U) {
      return error(TokenizerPackErrorCode::input_text_too_large,
                   "encoded token count exceeds fixed limit");
    }
    output.insert(output.end(), ids.begin(), ids.end());
    output.push_back(markers[marker_index].second);
    offset = marker_at + markers[marker_index].first.size();
  }

  if (think_tail.empty()) return output;
  const auto think = find_qwen_think_tokens(pack);
  if (!think.has_value()) {
    return error(TokenizerPackErrorCode::unsupported_special_token,
                 "Qwen reasoning markers must be exactly one CONTROL or USER_DEFINED token each");
  }
  // The template's spelling: <think> "\n" for the open block, <think> "\n\n" </think> "\n\n" closed.
  const auto append_text = [&pack, &output](const std::string_view text) -> std::optional<TokenizerPackError> {
    const auto ordinary = encode_text(pack, text);
    if (const auto* failure = std::get_if<TokenizerPackError>(&ordinary)) return *failure;
    const auto& ids = std::get<std::vector<std::size_t>>(ordinary);
    if (output.size() > kMaximumVocabularyEntries - ids.size() - 1U) {
      return error(TokenizerPackErrorCode::input_text_too_large, "encoded token count exceeds fixed limit");
    }
    output.insert(output.end(), ids.begin(), ids.end());
    return std::nullopt;
  };
  if (output.size() >= kMaximumVocabularyEntries - 2U) {
    return error(TokenizerPackErrorCode::input_text_too_large, "encoded token count exceeds fixed limit");
  }
  output.push_back(think->open);
  if (think_tail == kThinkOpenTail) {
    if (const auto failure = append_text("\n")) return *failure;
    return output;
  }
  if (const auto failure = append_text("\n\n")) return *failure;
  output.push_back(think->close);
  if (const auto failure = append_text("\n\n")) return *failure;
  return output;
}

TokenizerEncodeResult encode_glm53_prompt(const TokenizerPack& pack,
                                          const std::string_view rendered_prompt) {
  constexpr std::array<std::string_view, 6U> kMarkers = {
      "[gMASK]", "<sop>", "<|system|>", "<|user|>", "<|assistant|>", "<think>"};
  if (pack.tokens_by_id.size() != pack.token_types.size()) {
    return error(TokenizerPackErrorCode::invalid_token_types,
                 "token type entries must match vocabulary entries");
  }

  std::array<std::size_t, kMarkers.size()> marker_ids{};
  for (std::size_t marker_index = 0U; marker_index < kMarkers.size(); ++marker_index) {
    std::optional<std::size_t> marker_id;
    for (std::size_t id = 0U; id < pack.tokens_by_id.size(); ++id) {
      if (pack.tokens_by_id[id] != kMarkers[marker_index]) continue;
      if (pack.token_types[id] != 3 || marker_id.has_value()) {
        return error(TokenizerPackErrorCode::unsupported_special_token,
                     "GLM framing markers must be exactly one CONTROL token");
      }
      marker_id = id;
    }
    if (!marker_id.has_value()) {
      return error(TokenizerPackErrorCode::unsupported_special_token,
                   "GLM framing marker is unavailable as a CONTROL token");
    }
    marker_ids[marker_index] = *marker_id;
  }

  std::vector<std::size_t> output;
  std::size_t offset = 0U;
  while (offset < rendered_prompt.size()) {
    std::size_t marker_at = std::string_view::npos;
    std::size_t marker_index = 0U;
    for (std::size_t index = 0U; index < kMarkers.size(); ++index) {
      const std::size_t found = rendered_prompt.find(kMarkers[index], offset);
      if (found != std::string_view::npos &&
          (marker_at == std::string_view::npos || found < marker_at)) {
        marker_at = found;
        marker_index = index;
      }
    }
    if (marker_at == std::string_view::npos) {
      const auto ordinary = encode_text(pack, rendered_prompt.substr(offset));
      if (const auto* failure = std::get_if<TokenizerPackError>(&ordinary)) return *failure;
      const auto& ids = std::get<std::vector<std::size_t>>(ordinary);
      if (output.size() > kMaximumVocabularyEntries - ids.size()) {
        return error(TokenizerPackErrorCode::input_text_too_large,
                     "encoded token count exceeds fixed limit");
      }
      output.insert(output.end(), ids.begin(), ids.end());
      break;
    }
    const auto ordinary = encode_text(pack, rendered_prompt.substr(offset, marker_at - offset));
    if (const auto* failure = std::get_if<TokenizerPackError>(&ordinary)) return *failure;
    const auto& ids = std::get<std::vector<std::size_t>>(ordinary);
    if (ids.size() >= kMaximumVocabularyEntries ||
        output.size() > kMaximumVocabularyEntries - ids.size() - 1U) {
      return error(TokenizerPackErrorCode::input_text_too_large,
                   "encoded token count exceeds fixed limit");
    }
    output.insert(output.end(), ids.begin(), ids.end());
    output.push_back(marker_ids[marker_index]);
    offset = marker_at + kMarkers[marker_index].size();
  }
  return output;
}

}  // namespace secure_frontend

#include "secure_frontend/tokenizer_pack.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <system_error>

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

class Json final {
 public:
  explicit Json(const std::string_view text) : text_(text) {}
  std::optional<std::map<std::string, std::size_t>> object_of_unsigned() {
    if (!consume('{')) return std::nullopt;
    std::map<std::string, std::size_t> result;
    if (consume('}')) return result;
    while (true) {
      const auto key = string();
      if (!key || !consume(':')) return std::nullopt;
      const auto value = unsigned_number();
      if (!value || !result.emplace(*key, *value).second) return std::nullopt;
      if (consume('}')) break;
      if (!consume(',')) return std::nullopt;
    }
    skip();
    return position_ == text_.size() ? std::optional{std::move(result)} : std::nullopt;
  }
  std::optional<std::vector<int>> array_of_ints() {
    if (!consume('[')) return std::nullopt;
    std::vector<int> result;
    if (consume(']')) return result;
    while (true) {
      const auto value = signed_number();
      if (!value || result.size() >= kMaximumVocabularyEntries) return std::nullopt;
      result.push_back(*value);
      if (consume(']')) break;
      if (!consume(',')) return std::nullopt;
    }
    skip();
    return position_ == text_.size() ? std::optional{std::move(result)} : std::nullopt;
  }
 private:
  void skip() { while (position_ < text_.size() && (text_[position_] == ' ' || text_[position_] == '\n' || text_[position_] == '\r' || text_[position_] == '\t')) ++position_; }
  bool consume(const char expected) { skip(); if (position_ == text_.size() || text_[position_] != expected) return false; ++position_; return true; }
  std::optional<unsigned int> hex(const char value) {
    if (value >= '0' && value <= '9') return static_cast<unsigned int>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<unsigned int>(value - 'a' + 10);
    if (value >= 'A' && value <= 'F') return static_cast<unsigned int>(value - 'A' + 10);
    return std::nullopt;
  }
  std::optional<std::uint32_t> unicode() {
    if (position_ + 4U > text_.size()) return std::nullopt;
    std::uint32_t value = 0U;
    for (unsigned int n = 0U; n < 4U; ++n) { const auto digit = hex(text_[position_++]); if (!digit) return std::nullopt; value = (value << 4U) | *digit; }
    if (value >= 0xd800U && value <= 0xdbffU) {
      if (position_ + 6U > text_.size() || text_[position_++] != '\\' || text_[position_++] != 'u') return std::nullopt;
      const auto low = unicode();
      if (!low || *low < 0xdc00U || *low > 0xdfffU) return std::nullopt;
      return 0x10000U + ((value - 0xd800U) << 10U) + (*low - 0xdc00U);
    }
    if (value >= 0xdc00U && value <= 0xdfffU) return std::nullopt;
    return value;
  }
  std::optional<std::string> string() {
    if (!consume('"')) return std::nullopt;
    std::string out;
    while (position_ < text_.size()) {
      const unsigned char current = static_cast<unsigned char>(text_[position_++]);
      if (current == '"') return valid_utf8(out) ? std::optional{std::move(out)} : std::nullopt;
      if (current < 0x20U) return std::nullopt;
      if (current != '\\') { out.push_back(static_cast<char>(current)); continue; }
      if (position_ == text_.size()) return std::nullopt;
      const char escaped = text_[position_++];
      switch (escaped) {
        case '"': out.push_back('"'); break; case '\\': out.push_back('\\'); break; case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break; case 'f': out.push_back('\f'); break; case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break; case 't': out.push_back('\t'); break;
        case 'u': { const auto point = unicode(); if (!point) return std::nullopt; append_utf8(&out, *point); break; }
        default: return std::nullopt;
      }
      if (out.size() > kMaximumTokenBytes) return std::nullopt;
    }
    return std::nullopt;
  }
  std::optional<std::size_t> unsigned_number() {
    skip(); const std::size_t start = position_;
    if (position_ == text_.size() || text_[position_] < '0' || text_[position_] > '9') return std::nullopt;
    if (text_[position_] == '0') ++position_; else while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') ++position_;
    if (position_ < text_.size() && (text_[position_] == '.' || text_[position_] == 'e' || text_[position_] == 'E')) return std::nullopt;
    std::size_t value = 0U;
    for (std::size_t i = start; i < position_; ++i) { const std::size_t digit = static_cast<std::size_t>(text_[i] - '0'); if (value > (std::numeric_limits<std::size_t>::max() - digit) / 10U) return std::nullopt; value = value * 10U + digit; }
    return value;
  }
  std::optional<int> signed_number() {
    skip(); bool negative = false; if (position_ < text_.size() && text_[position_] == '-') { negative = true; ++position_; }
    const auto number = unsigned_number(); if (!number || *number > static_cast<std::size_t>(std::numeric_limits<int>::max()) + (negative ? 1U : 0U)) return std::nullopt;
    if (negative) return *number == static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1U ? std::numeric_limits<int>::min() : -static_cast<int>(*number);
    return static_cast<int>(*number);
  }
  std::string_view text_; std::size_t position_{0U};
};

std::variant<std::string, TokenizerPackError> read_required(const std::filesystem::path& root, const std::string_view name) {
  const auto path = root / std::string{name};
  std::error_code ec;
  const auto status = std::filesystem::symlink_status(path, ec);
  if (ec || !std::filesystem::exists(status)) return error(TokenizerPackErrorCode::required_file_missing, "required tokenizer pack file is missing");
  if (std::filesystem::is_symlink(status)) return error(TokenizerPackErrorCode::symbolic_link_not_allowed, "tokenizer pack files must not be symbolic links");
  if (!std::filesystem::is_regular_file(status)) return error(TokenizerPackErrorCode::unsafe_pack_path, "tokenizer pack paths must name regular files");
  const auto size = std::filesystem::file_size(path, ec);
  if (ec) return error(TokenizerPackErrorCode::file_read_failed, "unable to inspect tokenizer pack file");
  if (size > kMaximumFileBytes) return error(TokenizerPackErrorCode::file_too_large, "tokenizer pack file exceeds fixed limit");
  std::ifstream input(path, std::ios::binary); if (!input) return error(TokenizerPackErrorCode::file_read_failed, "unable to open tokenizer pack file");
  std::string contents(static_cast<std::size_t>(size), '\0'); input.read(contents.data(), static_cast<std::streamsize>(contents.size()));
  if (!input && !input.eof()) return error(TokenizerPackErrorCode::file_read_failed, "unable to read tokenizer pack file");
  return contents;
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

TokenizerEncodeResult encode_piece(const TokenizerPack& pack, const std::string_view piece,
                                   const std::array<std::string, 256U>& symbols,
                                   const std::map<std::string, std::size_t>& ids,
                                   const std::map<std::pair<std::string, std::string>, std::size_t>& ranks) {
  std::vector<std::string> values;
  values.reserve(piece.size());
  for (const unsigned char byte : piece) values.push_back(symbols[byte]);
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

}  // namespace

TokenizerPackLoadResult load_local_tokenizer_pack(const std::filesystem::path& pack_root) {
  std::error_code ec;
  const auto root = std::filesystem::weakly_canonical(pack_root, ec);
  if (ec) return error(TokenizerPackErrorCode::pack_root_unavailable, "unable to resolve tokenizer pack root");
  if (!std::filesystem::is_directory(root, ec)) return error(ec ? TokenizerPackErrorCode::pack_root_unavailable : TokenizerPackErrorCode::pack_root_not_directory, "tokenizer pack root must be an existing directory");
  const auto vocab_text = read_required(root, "vocab.json"); const auto merges_text = read_required(root, "merges.txt"); const auto types_text = read_required(root, "token_type.json");
  if (const auto* e = std::get_if<TokenizerPackError>(&vocab_text)) return *e;
  if (const auto* e = std::get_if<TokenizerPackError>(&merges_text)) return *e;
  if (const auto* e = std::get_if<TokenizerPackError>(&types_text)) return *e;
  const auto vocabulary = Json(std::get<std::string>(vocab_text)).object_of_unsigned();
  const auto types = Json(std::get<std::string>(types_text)).array_of_ints();
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

TokenizerDecodeResult decode_token_ids(const TokenizerPack& pack, const std::vector<std::size_t>& ids) {
  const auto symbols = byte_symbols(); std::map<std::string, unsigned int> reverse;
  for (unsigned int byte = 0U; byte < 256U; ++byte) reverse.emplace(symbols[byte], byte);
  std::string bytes;
  for (const std::size_t id : ids) {
    if (id >= pack.tokens_by_id.size()) return error(TokenizerPackErrorCode::token_id_out_of_range, "token ID is outside the loaded vocabulary");
    if (id >= pack.token_types.size() || pack.token_types[id] == 3 || pack.token_types[id] == 4) {
      return error(TokenizerPackErrorCode::undecodable_token,
                   "control and user-defined token types are not ordinary decoded output");
    }
    const std::string_view token = pack.tokens_by_id[id];
    for (std::size_t offset = 0U; offset < token.size();) {
      const auto lead = static_cast<unsigned char>(token[offset]); std::size_t width = lead <= 0x7fU ? 1U : lead <= 0xdfU ? 2U : lead <= 0xefU ? 3U : 4U;
      if (offset + width > token.size()) return error(TokenizerPackErrorCode::undecodable_token, "token is not composed of byte alphabet symbols");
      const auto symbol = token.substr(offset, width); const auto it = reverse.find(std::string{symbol});
      if (it == reverse.end()) return error(TokenizerPackErrorCode::undecodable_token, "token is not composed of byte alphabet symbols");
      if (bytes.size() >= kMaximumDecodedBytes) return error(TokenizerPackErrorCode::decoded_text_not_utf8, "decoded token data exceeds fixed limit");
      bytes.push_back(static_cast<char>(it->second)); offset += width;
    }
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
  for (const std::string_view piece : basic_pretokenize(text)) {
    const auto piece_ids = encode_piece(pack, piece, symbols, ids, ranks);
    if (const auto* failure = std::get_if<TokenizerPackError>(&piece_ids)) return *failure;
    const auto& values = std::get<std::vector<std::size_t>>(piece_ids);
    if (output.size() > kMaximumVocabularyEntries - values.size()) return error(TokenizerPackErrorCode::input_text_too_large, "encoded token count exceeds fixed limit");
    output.insert(output.end(), values.begin(), values.end());
  }
  return output;
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

  std::vector<std::size_t> output;
  std::size_t offset = 0U;
  while (offset < rendered_prompt.size()) {
    const auto start_at = rendered_prompt.find(kStartMarker, offset);
    const auto end_at = rendered_prompt.find(kEndMarker, offset);
    const bool has_start = start_at != std::string_view::npos;
    const bool has_end = end_at != std::string_view::npos;
    if (!has_start && !has_end) {
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

    const bool use_start = has_start && (!has_end || start_at < end_at);
    const std::size_t marker_at = use_start ? start_at : end_at;
    const std::string_view marker = use_start ? kStartMarker : kEndMarker;
    const auto ordinary = encode_text(pack, rendered_prompt.substr(offset, marker_at - offset));
    if (const auto* failure = std::get_if<TokenizerPackError>(&ordinary)) return *failure;
    const auto& ids = std::get<std::vector<std::size_t>>(ordinary);
    if (ids.size() >= kMaximumVocabularyEntries ||
        output.size() > kMaximumVocabularyEntries - ids.size() - 1U) {
      return error(TokenizerPackErrorCode::input_text_too_large,
                   "encoded token count exceeds fixed limit");
    }
    output.insert(output.end(), ids.begin(), ids.end());
    output.push_back(std::get<std::size_t>(use_start ? start_id : end_id));
    offset = marker_at + marker.size();
  }
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

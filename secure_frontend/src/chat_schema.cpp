#include "secure_frontend/chat_schema.hpp"

#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <utility>

namespace secure_frontend {
namespace {

constexpr std::size_t kMaximumRequestBytes = 256U * 1024U;
constexpr std::size_t kMaximumMessages = 128U;
constexpr std::size_t kMaximumModelBytes = 256U;
constexpr std::size_t kMaximumMessageBytes = 64U * 1024U;
constexpr std::size_t kMaximumGeneratedBytes = 1024U * 1024U;
constexpr std::size_t kMaximumTokens = 16384U;

bool is_continuation(unsigned char byte) { return (byte & 0xc0U) == 0x80U; }

bool valid_utf8(std::string_view value) {
  for (std::size_t index = 0; index < value.size();) {
    const auto byte = static_cast<unsigned char>(value[index]);
    if (byte <= 0x7fU) {
      ++index;
    } else if (byte >= 0xc2U && byte <= 0xdfU && index + 1U < value.size() &&
               is_continuation(static_cast<unsigned char>(value[index + 1U]))) {
      index += 2U;
    } else if (byte == 0xe0U && index + 2U < value.size() &&
               static_cast<unsigned char>(value[index + 1U]) >= 0xa0U &&
               static_cast<unsigned char>(value[index + 1U]) <= 0xbfU &&
               is_continuation(static_cast<unsigned char>(value[index + 2U]))) {
      index += 3U;
    } else if (((byte >= 0xe1U && byte <= 0xecU) || (byte >= 0xeeU && byte <= 0xefU)) &&
               index + 2U < value.size() && is_continuation(static_cast<unsigned char>(value[index + 1U])) &&
               is_continuation(static_cast<unsigned char>(value[index + 2U]))) {
      index += 3U;
    } else if (byte == 0xedU && index + 2U < value.size() &&
               static_cast<unsigned char>(value[index + 1U]) >= 0x80U &&
               static_cast<unsigned char>(value[index + 1U]) <= 0x9fU &&
               is_continuation(static_cast<unsigned char>(value[index + 2U]))) {
      index += 3U;
    } else if (byte == 0xf0U && index + 3U < value.size() &&
               static_cast<unsigned char>(value[index + 1U]) >= 0x90U &&
               static_cast<unsigned char>(value[index + 1U]) <= 0xbfU &&
               is_continuation(static_cast<unsigned char>(value[index + 2U])) &&
               is_continuation(static_cast<unsigned char>(value[index + 3U]))) {
      index += 4U;
    } else if (byte >= 0xf1U && byte <= 0xf3U && index + 3U < value.size() &&
               is_continuation(static_cast<unsigned char>(value[index + 1U])) &&
               is_continuation(static_cast<unsigned char>(value[index + 2U])) &&
               is_continuation(static_cast<unsigned char>(value[index + 3U]))) {
      index += 4U;
    } else if (byte == 0xf4U && index + 3U < value.size() &&
               static_cast<unsigned char>(value[index + 1U]) >= 0x80U &&
               static_cast<unsigned char>(value[index + 1U]) <= 0x8fU &&
               is_continuation(static_cast<unsigned char>(value[index + 2U])) &&
               is_continuation(static_cast<unsigned char>(value[index + 3U]))) {
      index += 4U;
    } else {
      return false;
    }
  }
  return true;
}

bool contains_remote_scheme(std::string_view value) {
  constexpr std::array<std::string_view, 5> schemes{"http://", "https://", "file://", "data:", "mcp://"};
  std::string lowered;
  lowered.reserve(value.size());
  for (const unsigned char byte : value) lowered.push_back(static_cast<char>(std::tolower(byte)));
  for (const std::string_view scheme : schemes) {
    if (lowered.find(scheme) != std::string::npos) return true;
  }
  return false;
}

bool valid_model(std::string_view value) {
  if (value.empty() || value.size() > kMaximumModelBytes || contains_remote_scheme(value)) return false;
  for (const unsigned char byte : value) {
    if (!(std::isalnum(byte) || byte == '.' || byte == '_' || byte == '-')) return false;
  }
  return true;
}

bool valid_content(std::string_view value) {
  if (value.empty() || value.size() > kMaximumMessageBytes || !valid_utf8(value) || contains_remote_scheme(value)) return false;
  for (const unsigned char byte : value) {
    if (byte < 0x20U && byte != '\n' && byte != '\r' && byte != '\t') return false;
  }
  return true;
}

void append_utf8(std::string* output, std::uint32_t point) {
  if (point <= 0x7fU) {
    output->push_back(static_cast<char>(point));
  } else if (point <= 0x7ffU) {
    output->push_back(static_cast<char>(0xc0U | (point >> 6U)));
    output->push_back(static_cast<char>(0x80U | (point & 0x3fU)));
  } else if (point <= 0xffffU) {
    output->push_back(static_cast<char>(0xe0U | (point >> 12U)));
    output->push_back(static_cast<char>(0x80U | ((point >> 6U) & 0x3fU)));
    output->push_back(static_cast<char>(0x80U | (point & 0x3fU)));
  } else {
    output->push_back(static_cast<char>(0xf0U | (point >> 18U)));
    output->push_back(static_cast<char>(0x80U | ((point >> 12U) & 0x3fU)));
    output->push_back(static_cast<char>(0x80U | ((point >> 6U) & 0x3fU)));
    output->push_back(static_cast<char>(0x80U | (point & 0x3fU)));
  }
}

class Parser final {
 public:
  explicit Parser(std::string_view input) : input_(input) {}

  std::optional<ChatCompletionRequest> parse() {
    if (input_.empty() || input_.size() > kMaximumRequestBytes || !consume('{')) return std::nullopt;
    ChatCompletionRequest request;
    bool model_seen = false;
    bool messages_seen = false;
    bool max_tokens_seen = false;
    bool stream_seen = false;
    skip_ws();
    if (consume('}')) return std::nullopt;
    while (true) {
      const auto key = string();
      if (!key || !consume(':')) return std::nullopt;
      if (*key == "model" && !model_seen) {
        const auto value = string();
        if (!value || !valid_model(*value)) return std::nullopt;
        request.model = *value;
        model_seen = true;
      } else if (*key == "messages" && !messages_seen) {
        const auto values = messages();
        if (!values) return std::nullopt;
        request.messages = *values;
        messages_seen = true;
      } else if (*key == "max_tokens" && !max_tokens_seen) {
        const auto value = unsigned_integer();
        if (!value || *value > kMaximumTokens) return std::nullopt;
        request.max_tokens = *value;
        max_tokens_seen = true;
      } else if (*key == "stream" && !stream_seen) {
        if (!literal("false")) return std::nullopt;
        stream_seen = true;
      } else {
        return std::nullopt;
      }
      skip_ws();
      if (consume('}')) break;
      if (!consume(',')) return std::nullopt;
    }
    skip_ws();
    if (position_ != input_.size() || !model_seen || !messages_seen || request.messages.empty()) return std::nullopt;
    return request;
  }

 private:
  void skip_ws() {
    while (position_ < input_.size() && (input_[position_] == ' ' || input_[position_] == '\n' ||
                                         input_[position_] == '\r' || input_[position_] == '\t')) ++position_;
  }

  bool consume(char expected) {
    skip_ws();
    if (position_ == input_.size() || input_[position_] != expected) return false;
    ++position_;
    return true;
  }

  bool literal(std::string_view expected) {
    skip_ws();
    if (input_.substr(position_, expected.size()) != expected) return false;
    position_ += expected.size();
    return true;
  }

  static std::optional<unsigned int> hex(char value) {
    if (value >= '0' && value <= '9') return static_cast<unsigned int>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<unsigned int>(value - 'a' + 10);
    if (value >= 'A' && value <= 'F') return static_cast<unsigned int>(value - 'A' + 10);
    return std::nullopt;
  }

  std::optional<std::uint32_t> unicode_escape() {
    if (position_ + 4U > input_.size()) return std::nullopt;
    std::uint32_t point = 0;
    for (unsigned int count = 0; count < 4U; ++count) {
      const auto digit = hex(input_[position_++]);
      if (!digit) return std::nullopt;
      point = (point << 4U) | *digit;
    }
    if (point >= 0xd800U && point <= 0xdbffU) {
      if (position_ + 6U > input_.size() || input_[position_] != '\\' || input_[position_ + 1U] != 'u') return std::nullopt;
      position_ += 2U;
      const auto low = unicode_escape();
      if (!low || *low < 0xdc00U || *low > 0xdfffU) return std::nullopt;
      return 0x10000U + ((point - 0xd800U) << 10U) + (*low - 0xdc00U);
    }
    if (point >= 0xdc00U && point <= 0xdfffU) return std::nullopt;
    return point;
  }

  std::optional<std::string> string() {
    if (!consume('"')) return std::nullopt;
    std::string output;
    while (position_ < input_.size()) {
      const unsigned char byte = static_cast<unsigned char>(input_[position_++]);
      if (byte == '"') return valid_utf8(output) ? std::optional<std::string>{std::move(output)} : std::nullopt;
      if (byte < 0x20U) return std::nullopt;
      if (byte != '\\') {
        output.push_back(static_cast<char>(byte));
        continue;
      }
      if (position_ == input_.size()) return std::nullopt;
      switch (input_[position_++]) {
        case '"': output.push_back('"'); break;
        case '\\': output.push_back('\\'); break;
        case '/': output.push_back('/'); break;
        case 'b': output.push_back('\b'); break;
        case 'f': output.push_back('\f'); break;
        case 'n': output.push_back('\n'); break;
        case 'r': output.push_back('\r'); break;
        case 't': output.push_back('\t'); break;
        case 'u': {
          const auto point = unicode_escape();
          if (!point) return std::nullopt;
          append_utf8(&output, *point);
          break;
        }
        default: return std::nullopt;
      }
      if (output.size() > kMaximumRequestBytes) return std::nullopt;
    }
    return std::nullopt;
  }

  std::optional<std::size_t> unsigned_integer() {
    skip_ws();
    if (position_ == input_.size() || input_[position_] < '0' || input_[position_] > '9') return std::nullopt;
    if (input_[position_] == '0' && position_ + 1U < input_.size() && std::isdigit(static_cast<unsigned char>(input_[position_ + 1U]))) return std::nullopt;
    std::size_t value = 0;
    do {
      const std::size_t digit = static_cast<std::size_t>(input_[position_++] - '0');
      if (value > (std::numeric_limits<std::size_t>::max() - digit) / 10U) return std::nullopt;
      value = value * 10U + digit;
    } while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9');
    return value;
  }

  std::optional<std::vector<ChatMessage>> messages() {
    if (!consume('[')) return std::nullopt;
    std::vector<ChatMessage> output;
    skip_ws();
    if (consume(']')) return output;
    while (true) {
      const auto message = message_object();
      if (!message || output.size() == kMaximumMessages) return std::nullopt;
      output.push_back(*message);
      skip_ws();
      if (consume(']')) return output;
      if (!consume(',')) return std::nullopt;
    }
  }

  std::optional<ChatMessage> message_object() {
    if (!consume('{')) return std::nullopt;
    ChatMessage message;
    bool role_seen = false;
    bool content_seen = false;
    skip_ws();
    if (consume('}')) return std::nullopt;
    while (true) {
      const auto key = string();
      if (!key || !consume(':')) return std::nullopt;
      if (*key == "role" && !role_seen) {
        const auto value = string();
        if (!value || (*value != "system" && *value != "user" && *value != "assistant")) return std::nullopt;
        message.role = *value;
        role_seen = true;
      } else if (*key == "content" && !content_seen) {
        const auto value = string();
        if (!value || !valid_content(*value)) return std::nullopt;
        message.content = *value;
        content_seen = true;
      } else {
        return std::nullopt;
      }
      skip_ws();
      if (consume('}')) break;
      if (!consume(',')) return std::nullopt;
    }
    if (!role_seen || !content_seen) return std::nullopt;
    return message;
  }

  std::string_view input_;
  std::size_t position_ = 0;
};

void append_json_string(std::string* output, std::string_view value) {
  static constexpr char kHex[] = "0123456789abcdef";
  output->push_back('"');
  for (const unsigned char byte : value) {
    switch (byte) {
      case '"': output->append("\\\""); break;
      case '\\': output->append("\\\\"); break;
      case '\b': output->append("\\b"); break;
      case '\f': output->append("\\f"); break;
      case '\n': output->append("\\n"); break;
      case '\r': output->append("\\r"); break;
      case '\t': output->append("\\t"); break;
      default:
        if (byte < 0x20U) {
          output->append("\\u00");
          output->push_back(kHex[(byte >> 4U) & 0x0fU]);
          output->push_back(kHex[byte & 0x0fU]);
        } else {
          output->push_back(static_cast<char>(byte));
        }
    }
  }
  output->push_back('"');
}

}  // namespace

std::optional<ChatCompletionRequest> parse_chat_completion_request(std::string_view json) {
  return Parser(json).parse();
}

std::optional<std::string> render_chat_completion_response(const ChatCompletionRequest& request,
                                                           std::string_view generated_text) {
  if (!valid_model(request.model) || generated_text.size() > kMaximumGeneratedBytes || !valid_utf8(generated_text)) {
    return std::nullopt;
  }
  std::string response{"{\"id\":\"chatcmpl-local\",\"object\":\"chat.completion\",\"created\":0,\"model\":"};
  append_json_string(&response, request.model);
  response.append(",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":");
  append_json_string(&response, generated_text);
  response.append("},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":0,\"total_tokens\":0}}\n");
  return response;
}

}  // namespace secure_frontend

// SP6 §4.10: the glm53 output post-processing rules. Every declaration's contract,
// including the three rules and their MAYA sources, is documented in glm_output.hpp.
#include "secure_frontend/glm_output.hpp"

#include <optional>
#include <string_view>

namespace secure_frontend {
namespace {

TokenizerPackError pack_error(const std::string_view message) {
  return TokenizerPackError{TokenizerPackErrorCode::invalid_tokenizer_pack, std::string{message}};
}

// CONTROL (3) or USER_DEFINED (4) as the pack itself declares it; an id with no
// type entry counts as non-control (such out-of-range ids fail closed at decode
// as the corrupt output they are).
bool is_typed_control(const TokenizerPack& pack, const std::size_t id) {
  return id < pack.token_types.size() && (pack.token_types[id] == 3 || pack.token_types[id] == 4);
}

}  // namespace

bool is_glm_end_of_turn_id(const std::size_t id) noexcept {
  for (const std::size_t table_id : kGlmEndOfTurnIds) {
    if (id == table_id) return true;
  }
  return false;
}

std::variant<std::size_t, TokenizerPackError> find_glm53_think_close_id(const TokenizerPack& pack) {
  constexpr std::string_view kClose = "</think>";
  std::optional<std::size_t> found;
  for (std::size_t id = 0U; id < pack.tokens_by_id.size(); ++id) {
    if (pack.tokens_by_id[id] != kClose) continue;
    if (found.has_value())
      return pack_error("the pack carries more than one </think> entry: the close id is ambiguous");
    if (id >= pack.token_types.size() || pack.token_types[id] != 4)
      return pack_error("the </think> entry must be USER_DEFINED (type 4), as MAYA marks it");
    found = id;
  }
  if (!found.has_value()) return pack_error("the pack has no </think> entry");
  return *found;
}

Glm53Split glm53_split_output(const TokenizerPack& pack, const std::vector<std::size_t>& ids,
                              const Glm53OutputRules& rules, const bool finish_stop) {
  std::size_t close_at = ids.size();
  for (std::size_t index = 0U; index < ids.size(); ++index) {
    if (ids[index] == rules.think_close_id) {
      close_at = index;
      break;
    }
  }
  // Rule 2: the content region starts after the FIRST close. Without a close,
  // only a stop turns the whole output into content; length/timeout/cancel leave
  // the reasoning unreturned — and therefore uncounted.
  const std::size_t region_start = close_at < ids.size() ? close_at + 1U : (finish_stop ? 0U : ids.size());
  // Rule 1: on stop exactly ONE trailing end-of-turn id is dropped and never counted.
  const bool drop_trailing = finish_stop && !ids.empty() && is_glm_end_of_turn_id(ids.back());
  Glm53Split split;
  for (std::size_t index = region_start; index < ids.size(); ++index) {
    const std::size_t id = ids[index];
    if (drop_trailing && index + 1U == ids.size()) continue;
    // Rule 3: every other close repeat, end-of-turn id, or type-3/4 id is removed
    // before decoding and counted for the fixed log literal.
    if (id == rules.think_close_id || is_glm_end_of_turn_id(id) || is_typed_control(pack, id))
      ++split.control_tokens_stripped;
    else
      split.content_ids.push_back(id);
  }
  return split;
}

Glm53StreamState::Glm53StreamState(const Glm53OutputRules& rules) : close_id_(rules.think_close_id) {}

Glm53StreamState::Action Glm53StreamState::on_token(const std::size_t id, const bool is_control) {
  last_was_end_of_turn_ = is_glm_end_of_turn_id(id);
  if (id == close_id_) {
    // The first close opens the content region and is itself not counted; every
    // later close is just another stripped control id (rule 3).
    if (!closed_) {
      closed_ = true;
      return Action::think_closed;
    }
    ++stripped_;
    return Action::strip;
  }
  if (is_control || last_was_end_of_turn_) {
    if (closed_) ++stripped_;
    else ++reasoning_stripped_;  // counted only if the never-closed buffer is flushed as content
    return Action::strip;
  }
  return closed_ ? Action::emit : Action::buffer_reasoning;
}

void Glm53StreamState::on_done(const std::string_view finish) {
  if (finish == "stop") {
    // Rule 2: a stop with no close turns the whole (already stripped) buffer into content.
    if (!closed_) {
      flush_buffer_ = true;
      stripped_ += reasoning_stripped_;
    }
    // Rule 1 credit: the one trailing end-of-turn id was dropped, not counted.
    if (last_was_end_of_turn_ && stripped_ > 0U) --stripped_;
  }
  // The fixed log literal's key: a strip in returned text — content-region strips
  // remain, and reasoning-region strips count on the stop-without-close flush.
  emitted_ = stripped_ > 0U || (flush_buffer_ && reasoning_stripped_ > 0U);
}

}  // namespace secure_frontend

// SP6 §4.10 — RED stub: the API and the fixed table exist, the rules do not yet.
#include "secure_frontend/glm_output.hpp"

namespace secure_frontend {

bool is_glm_end_of_turn_id(const std::size_t id) noexcept {
  for (const std::size_t table_id : kGlmEndOfTurnIds) {
    if (id == table_id) return true;
  }
  return false;
}

std::variant<std::size_t, TokenizerPackError> find_glm53_think_close_id(const TokenizerPack& /*pack*/) {
  return TokenizerPackError{TokenizerPackErrorCode::invalid_tokenizer_pack, "stub: lookup not implemented"};
}

Glm53Split glm53_split_output(const TokenizerPack& /*pack*/, const std::vector<std::size_t>& ids,
                              const Glm53OutputRules& /*rules*/, const bool /*finish_stop*/) {
  return Glm53Split{ids, 0U};
}

Glm53StreamState::Glm53StreamState(const Glm53OutputRules& rules) : close_id_(rules.think_close_id) {}

Glm53StreamState::Action Glm53StreamState::on_token(const std::size_t /*id*/, const bool /*is_control*/) {
  return Action::emit;
}

void Glm53StreamState::on_done(const std::string_view /*finish*/) {}

}  // namespace secure_frontend

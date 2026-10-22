#pragma once

// SP6 §4.10: output post-processing for the glm53 chat profile. MAYA prints the
// end-of-turn token and the user-defined </think> id as ordinary T records;
// decode_token_ids fails closed on type 3/4 ids, so the GLM rules below run
// BEFORE decoding. These rules are a separate branch keyed by the plan: the
// Qwen think-token handling (find_qwen_think_tokens, GenerationRunLimits::
// think_tokens) is untouched by anything here. The G53F evaluation probe
// (spec §4.10 last paragraph, Plan 1 Task 4) applies the same rules.

#include "secure_frontend/tokenizer_pack.hpp"

#include <array>
#include <cstddef>
#include <string_view>
#include <variant>
#include <vector>

namespace secure_frontend {

// Rule 1: MAYA's GLM end-of-turn ids (`glm_eos`, generate.cpp:1081 at the pin)
// as a fixed frontend table; the §5.2 layout check (SP6 Plan 2) refuses a pack
// whose token_type.json or tokenizer.json disagrees with it. Membership is by
// value, independent of the vocabulary.
inline constexpr std::array<std::size_t, 3> kGlmEndOfTurnIds{154820U, 154827U, 154829U};

[[nodiscard]] bool is_glm_end_of_turn_id(std::size_t id) noexcept;

// Rule 2: the </think> id, looked up once from the pack's vocabulary by its
// literal: exactly one entry, and it is USER_DEFINED (type 4) as MAYA marks it.
// Anything else is invalid_tokenizer_pack. Deliberately NOT the Qwen lookup:
// that one is lenient (type 3 or 4, both markers, fail-soft nullopt); a GLM
// pack that contradicts this rule must fail closed.
struct Glm53OutputRules final {
  std::size_t think_close_id;
};
[[nodiscard]] std::variant<std::size_t, TokenizerPackError> find_glm53_think_close_id(const TokenizerPack& pack);

// The complete output of one glm53 generation: the ids that decode to content,
// and how many type-3/4 ids were stripped inside the content region (rule 3;
// the fixed log literal `engine emitted control token` counts them). The one
// trailing end-of-turn id dropped by rule 1 (finish_stop) is not counted.
struct Glm53Split final {
  std::vector<std::size_t> content_ids;
  std::size_t control_tokens_stripped{0};
};

// The batch form, for the non-streaming decode site (ChatExecutionService::
// execute). finish_stop is the DONE row's finish == "stop".
[[nodiscard]] Glm53Split glm53_split_output(const TokenizerPack& pack, const std::vector<std::size_t>& ids,
                                            const Glm53OutputRules& rules, bool finish_stop);

// The incremental form, one T record at a time (the SP3 pump, and the probe).
// Feed every generated id in order with its control flag (type 3 or 4), then
// on_done with the DONE finish. The reasoning text is BUFFERED, never emitted:
// a stop without </think> flushes the whole buffer as one content chunk, any
// other end drops it (empty content, the SP3 finish mapping stays as is).
class Glm53StreamState final {
 public:
  enum class Action {
    buffer_reasoning,  // ordinary id before the close: decode for the buffer, emit nothing
    think_closed,      // the FIRST </think>: the buffer is discarded, content starts
    emit,              // ordinary id in the content region
    strip,             // any control id: never decoded, never emitted
  };
  explicit Glm53StreamState(const Glm53OutputRules& rules);
  [[nodiscard]] Action on_token(std::size_t id, bool is_control);
  void on_done(std::string_view finish);
  // Rule 3: the stripped content-region control ids, the trailing rule-1 drop
  // credited back. Closed at on_done.
  [[nodiscard]] std::size_t control_tokens_stripped() const noexcept { return stripped_; }
  // True exactly when the buffered reasoning must be sent as one content chunk:
  // finish == stop and no </think> was ever seen.
  [[nodiscard]] bool flushes_buffer_on_stop() const noexcept { return flush_buffer_; }

 private:
  std::size_t close_id_;
  bool closed_{false};
  bool last_was_end_of_turn_{false};
  std::size_t stripped_{0};
  std::size_t reasoning_stripped_{0};
  bool flush_buffer_{false};
};

}  // namespace secure_frontend

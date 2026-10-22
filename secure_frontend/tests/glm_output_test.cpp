// SP6 §4.10: the glm53 output post-processing rules — the fixed end-of-turn table,
// the fail-closed </think> lookup, the batch split (the M1 non-streaming decode site)
// and the incremental state machine (the shared pump and the Task-4 probe).
#include "secure_frontend/glm_output.hpp"

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

// A tiny ordinary pack: ids 0..3 are single-byte text, then the control fixtures.
secure_frontend::TokenizerPack make_pack() {
  secure_frontend::TokenizerPack pack;
  for (const char* literal : {"A", "B", "C", "D"}) pack.tokens_by_id.emplace_back(literal);
  pack.token_types.assign(pack.tokens_by_id.size(), 1);
  return pack;
}

// The close id sits beyond the text ids; callers look it up, never hardcode it.
void add_close(secure_frontend::TokenizerPack& pack, const int type) {
  pack.tokens_by_id.emplace_back("</think>");
  pack.token_types.push_back(type);
}

std::size_t id_of(const secure_frontend::TokenizerPack& pack, const std::string_view literal) {
  for (std::size_t index = 0U; index < pack.tokens_by_id.size(); ++index) {
    if (pack.tokens_by_id[index] == literal) return index;
  }
  return pack.tokens_by_id.size();
}

secure_frontend::Glm53OutputRules rules_for(const secure_frontend::TokenizerPack& pack) {
  const auto found = secure_frontend::find_glm53_think_close_id(pack);
  const auto* id = std::get_if<std::size_t>(&found);
  expect(id != nullptr, "the fixture pack must answer the close lookup");
  return id != nullptr ? secure_frontend::Glm53OutputRules{*id} : secure_frontend::Glm53OutputRules{0U};
}

std::string content_text(const secure_frontend::TokenizerPack& pack, const std::vector<std::size_t>& ids) {
  const auto decoded = secure_frontend::decode_token_ids(pack, ids);
  const auto* text = std::get_if<std::string>(&decoded);
  return text != nullptr ? *text : std::string{"<decode-failed>"};
}

// §4.10 rule 2: the </think> id is looked up once, fail closed. Qwen's lenient
// lookup (type 3 OR 4, nullopt on absence) must not be reused here.
void glm53_think_close_lookup_is_fail_closed() {
  auto pack = make_pack();
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(secure_frontend::find_glm53_think_close_id(pack)),
         "no </think> entry: invalid_tokenizer_pack");

  add_close(pack, 4);
  const auto good = secure_frontend::find_glm53_think_close_id(pack);
  expect(std::holds_alternative<std::size_t>(good), "exactly one type-4 </think>: the id");

  auto typed3 = make_pack();
  add_close(typed3, 3);
  const auto wrong = secure_frontend::find_glm53_think_close_id(typed3);
  const auto* wrong_error = std::get_if<secure_frontend::TokenizerPackError>(&wrong);
  expect(wrong_error != nullptr && wrong_error->code == secure_frontend::TokenizerPackErrorCode::invalid_tokenizer_pack,
         "a CONTROL-typed </think> contradicts MAYA's USER_DEFINED marking: invalid_tokenizer_pack");

  auto ordinary = make_pack();
  add_close(ordinary, 1);
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(secure_frontend::find_glm53_think_close_id(ordinary)),
         "an ordinary-typed </think> is invalid_tokenizer_pack");

  auto twice = make_pack();
  add_close(twice, 4);
  add_close(twice, 4);
  expect(std::holds_alternative<secure_frontend::TokenizerPackError>(secure_frontend::find_glm53_think_close_id(twice)),
         "a duplicated </think> is ambiguous: invalid_tokenizer_pack");
}

// §4.10 rule 1: on stop exactly ONE trailing end-of-turn id (fixed table,
// membership by value) is dropped and NOT counted; anywhere else it is rule 3.
void glm53_split_drops_one_trailing_end_of_turn_at_stop() {
  const auto pack = make_pack();
  const auto rules = rules_for(pack);
  const auto close = rules.think_close_id;
  constexpr std::size_t kEos0 = 154820;  // the table, by value: a pack may carry them beyond its vocabulary

  const auto single = secure_frontend::glm53_split_output(pack, {close, 0U, kEos0}, rules, true);
  expect(content_text(pack, single.content_ids) == "A", "the trailing end-of-turn id is dropped: [" + content_text(pack, single.content_ids) + "]");
  expect(single.control_tokens_stripped == 0U, "the one trailing end-of-turn id is not counted");

  const auto two = secure_frontend::glm53_split_output(pack, {close, 0U, 154827U, 154829U}, rules, true);
  expect(content_text(pack, two.content_ids) == "A", "exactly ONE trailing id is dropped");
  expect(two.control_tokens_stripped == 1U, "the other end-of-turn id is rule 3: counted");

  const auto mid = secure_frontend::glm53_split_output(pack, {close, kEos0, 0U}, rules, true);
  expect(content_text(pack, mid.content_ids) == "A", "an end-of-turn id elsewhere is stripped, not a turn end");
  expect(mid.control_tokens_stripped == 1U, "an end-of-turn id elsewhere is counted");

  const auto not_stop = secure_frontend::glm53_split_output(pack, {close, 0U, kEos0}, rules, false);
  expect(content_text(pack, not_stop.content_ids) == "A", "finish != stop: the trailing id is not the rule-1 drop");
  expect(not_stop.control_tokens_stripped == 1U, "finish != stop: that end-of-turn id is counted");
}

// §4.10 rule 3: any other type-3/4 id after </think> is removed before decoding
// and counted; decoding never fails because of such ids.
void glm53_split_strips_content_control_ids_and_counts() {
  auto pack = make_pack();
  add_close(pack, 4);
  pack.tokens_by_id.emplace_back("<|tool_call>");
  pack.token_types.push_back(4);  // MAYA marks tool tags type 4 (strata_tokenizer.py:120)
  const auto rules = rules_for(pack);
  const auto close = rules.think_close_id;
  const auto tool = id_of(pack, "<|tool_call>");

  const auto split = secure_frontend::glm53_split_output(pack, {close, 0U, tool, 1U}, rules, true);
  expect(content_text(pack, split.content_ids) == "AB", "the type-4 id is removed before decoding: [" + content_text(pack, split.content_ids) + "]");
  expect(split.control_tokens_stripped == 1U, "the removed id is counted with the fixed log literal");

  const auto repeat = secure_frontend::glm53_split_output(pack, {close, 0U, close, 1U}, rules, true);
  expect(content_text(pack, repeat.content_ids) == "AB", "only the FIRST close flips the phase");
  expect(repeat.control_tokens_stripped == 1U, "a repeated close id is a stripped control token");
}

// §4.10 rule 2, stop row: without </think> the WHOLE output (after rules 1 and 3)
// is the content — never an empty 200. length/timeout/cancel: empty content.
void glm53_split_stop_without_close_returns_the_whole_output() {
  auto pack = make_pack();
  add_close(pack, 4);  // a valid pack whose generation never emits the close
  const auto rules = rules_for(pack);

  const auto whole = secure_frontend::glm53_split_output(pack, {0U, 1U, 154827U}, rules, true);
  expect(content_text(pack, whole.content_ids) == "AB", "stop without </think>: the whole decoded output is the content");
  expect(whole.control_tokens_stripped == 0U, "the trailing end-of-turn id is the rule-1 drop, not counted");

  const auto empty = secure_frontend::glm53_split_output(pack, {0U, 1U, 154827U}, rules, false);
  expect(empty.content_ids.empty(), "length without </think>: empty content");
  expect(empty.control_tokens_stripped == 0U, "never-returned reasoning ids are not counted");
}

// The stream state machine (shared by the SP3 pump and the Task-4 probe): the
// same three rules, token by token, with the count closed at DONE.
void glm53_stream_state_mirrors_the_split_rules() {
  auto pack = make_pack();
  add_close(pack, 4);
  pack.tokens_by_id.emplace_back("<|tool_call>");
  pack.token_types.push_back(4);
  const auto rules = rules_for(pack);
  const auto close = rules.think_close_id;
  const auto tool = id_of(pack, "<|tool_call>");
  constexpr std::size_t kEos2 = 154829;

  secure_frontend::Glm53StreamState state(rules);
  using Action = secure_frontend::Glm53StreamState::Action;
  expect(state.on_token(0U, false) == Action::buffer_reasoning, "the prompt opened the think block: reasoning is buffered, not emitted");
  expect(state.on_token(kEos2, false) == Action::strip, "an end-of-turn id inside the reasoning region is stripped");
  expect(state.on_token(close, false) == Action::think_closed, "the first </think> ends the reasoning region");
  expect(state.on_token(1U, false) == Action::emit, "the ids after the close are content");
  expect(state.on_token(tool, true) == Action::strip, "a type-4 id in content is stripped before decoding");
  expect(state.on_token(154827U, false) == Action::strip, "an end-of-turn id in content is stripped");
  state.on_done("stop");
  // stripped in content: tool + 154827 + the trailing 154829 credited back to rule 1? No: the
  // trailing id is the LAST emitted id — here 154827 trails the content, so the credit is one,
  // and the reasoning-region 154829 was stripped inside never-returned text: not counted.
  expect(state.control_tokens_stripped() == 1U, "content strips: tool + trailing end-of-turn, minus the rule-1 credit");

  secure_frontend::Glm53StreamState never_closed(rules);
  (void)never_closed.on_token(0U, false);
  (void)never_closed.on_token(1U, false);
  never_closed.on_done("stop");
  expect(never_closed.flushes_buffer_on_stop(), "stop without </think>: the buffered text goes out as one content chunk");

  secure_frontend::Glm53StreamState cut(rules);
  (void)cut.on_token(0U, false);
  cut.on_done("length");
  expect(!cut.flushes_buffer_on_stop(), "length without </think>: nothing is flushed");
}

void table_is_the_fixed_glm_end_of_turn_set() {
  const std::vector<std::size_t> ids(secure_frontend::kGlmEndOfTurnIds.begin(), secure_frontend::kGlmEndOfTurnIds.end());
  expect(ids == std::vector<std::size_t>{154820U, 154827U, 154829U}, "kGlmEndOfTurnIds is MAYA's glm_eos set (generate.cpp:1081)");
}

}  // namespace

int main(int argc, char** argv) {
  const std::vector<std::pair<const char*, void (*)()>> cases{
      {"glm53_think_close_lookup_is_fail_closed", glm53_think_close_lookup_is_fail_closed},
      {"glm53_split_drops_one_trailing_end_of_turn_at_stop", glm53_split_drops_one_trailing_end_of_turn_at_stop},
      {"glm53_split_strips_content_control_ids_and_counts", glm53_split_strips_content_control_ids_and_counts},
      {"glm53_split_stop_without_close_returns_the_whole_output", glm53_split_stop_without_close_returns_the_whole_output},
      {"glm53_stream_state_mirrors_the_split_rules", glm53_stream_state_mirrors_the_split_rules},
      {"table_is_the_fixed_glm_end_of_turn_set", table_is_the_fixed_glm_end_of_turn_set},
  };
  if (argc == 3 && std::strcmp(argv[1], "--case") == 0) {
    for (const auto& [name, run] : cases) {
      if (std::strcmp(name, argv[2]) == 0) {
        run();
        return failures == 0 ? 0 : 1;
      }
    }
    std::cerr << "unknown case: " << argv[2] << '\n';
    return 2;
  }
  for (const auto& [name, run] : cases) run();
  return failures == 0 ? 0 : 1;
}

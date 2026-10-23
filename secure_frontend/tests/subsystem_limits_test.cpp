#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/config_file.hpp"
#include "secure_frontend/subsystem_limits.hpp"
#include "support/config_json.hpp"
#include "support/test_support.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <variant>

namespace {
int failures = 0;
void expect(const bool condition, const std::string& message) {
  if (!condition) { ++failures; std::cerr << "FAILED: " << message << '\n'; }
}

std::shared_ptr<const secure_frontend::FrontendConfig> config_with(const std::map<std::string, std::string>& extra) {
  secure_frontend_test::ConfigFixture f;
  auto literals = f.literals;
  for (const auto& [k, v] : extra) literals[k] = v;
  auto draft = secure_frontend::parse_config_text(secure_frontend_test::render_config_json(literals), f.dir);
  auto result = secure_frontend::validate(std::get<secure_frontend::FrontendConfigDraft>(draft));
  return std::get<secure_frontend::ValidatedConfig>(result).shared();
}

void ready_timeout_defaults_to_900_seconds() {
  expect(secure_frontend::ChatExecutionLimits{}.ready_timeout == std::chrono::seconds(900),
         "ChatExecutionLimits{} waits 900 s for READY (upstream STRATA_ENGINE_READY_S)");
  expect(secure_frontend::chat_execution_limits(*config_with({})).ready_timeout == std::chrono::seconds(900),
         "the default config derives 900 s");
}

void subsystem_limits_follow_config() {
  const auto config = config_with({{"limits.http.max_request_bytes", "262144"},
                                   {"limits.http.max_header_bytes", "8192"},
                                   {"limits.http.max_headers", "32"},
                                   {"limits.http.request_deadline_ms", "1500"},
                                   // SP3 §5.1: header_deadline_ms (default 10000) must not exceed it.
                                   {"limits.http.header_deadline_ms", "1500"},
                                   {"listener.backlog", "64"},
                                   {"limits.chat.max_body_bytes", "131072"},
                                   {"limits.chat.default_max_tokens", "64"},
                                   {"limits.engine.ready_timeout_s", "7"}});
  const auto http = secure_frontend::connection_limits(*config);
  expect(http.head.max_request_bytes == 262144U && http.head.max_header_bytes == 8192U && http.head.max_headers == 32U &&
             http.head.max_request_line_bytes == 4096U && http.request_deadline == std::chrono::milliseconds(1500) &&
             http.header_deadline == std::chrono::milliseconds(1500),
         "connection and parser limits come from the config");
  expect(http.write_stall == std::chrono::milliseconds(10000) && http.response_write_deadline == std::chrono::milliseconds(60000),
         "write_stall and response_write_deadline default to 10 s and 60 s");
  // Pre-flight T8b(e)/V17: ConnectionLimits has no backlog; bind() takes it from the listener config.
  expect(config->listener.backlog == 64U, "the listener backlog comes from the config");
  const auto schema = secure_frontend::chat_schema_limits(*config);
  expect(schema.max_body_bytes == 131072U, "chat body limit comes from the config");
  const auto chat = secure_frontend::chat_execution_limits(*config);
  expect(chat.ready_timeout == std::chrono::seconds(7) && chat.default_max_tokens == 64U, "chat execution limits");
}

void supervisor_policy_follows_config() {
  const auto config = config_with({{"limits.engine.ready_timeout_s", "7"}});
  const secure_frontend::SupervisorConfig supervisor = secure_frontend::supervisor_config(*config);
  expect(supervisor.policy.ready_timeout == std::chrono::seconds(7), "limits.engine.ready_timeout_s drives RestartPolicy::ready_timeout");
  expect(supervisor.chat_limits.ready_timeout == std::chrono::seconds(7), "and the chat limits agree");
  const secure_frontend::RestartPolicy defaults{};
  expect(defaults.ready_timeout == std::chrono::seconds(secure_frontend::config_defaults::kEngineReadyTimeoutS),
         "the policy default is SP1's 900 s constant, not a second copy");
  expect(supervisor.policy.max_consecutive_failures == secure_frontend::config_defaults::kMaxConsecutiveFailures &&
             supervisor.policy.backoff_initial == secure_frontend::config_defaults::kBackoffInitial,
         "the other policy values come from config_defaults.hpp");
}

// SP5 M2 Task 7 (Ruling R-T5-b): the glm53 profile speaks Project Maya v1.1.21's wire
// dialect (Task 5), not the uncharacterized lighttransport one; the qwen profile is
// unchanged. The same selection stands at the bootstrap site (server_bootstrap.cpp).
void supervisor_flavor_is_the_maya_dialect_for_glm53() {
  const auto glm = config_with({{"engine.profile", "\"glm53\""}});
  const secure_frontend::SupervisorConfig supervisor = secure_frontend::supervisor_config(*glm);
  expect(supervisor.profile == secure_frontend::NativeChatProfile::glm53, "the chat profile stays glm53");
  expect(supervisor.flavor == secure_frontend::EngineProtocolFlavor::maya_118,
         "glm53 selects the maya_118 dialect at the selection site");
  const secure_frontend::SupervisorConfig plain = secure_frontend::supervisor_config(*config_with({}));
  expect(plain.flavor == secure_frontend::EngineProtocolFlavor::strata_0143, "the qwen profile keeps the strata dialect");
}

// Gemma 4 plan 1 Task 3 (spec §6.1): gemma4 is its own chat profile on the strata_0143
// wire and the strata environment family; the selection functions are exhaustive switches
// that the bootstrap shares (server_bootstrap.cpp), so a third profile never takes glm's.
void supervisor_profile_and_flavor_for_gemma4() {
  using secure_frontend::EngineProfile;
  const secure_frontend::SupervisorConfig gemma = secure_frontend::supervisor_config(*config_with({{"engine.profile", "\"gemma4\""}}));
  expect(gemma.profile == secure_frontend::NativeChatProfile::gemma4, "gemma4 selects NativeChatProfile::gemma4");
  expect(gemma.flavor == secure_frontend::EngineProtocolFlavor::strata_0143, "gemma4 speaks strata_0143 (spec §4.7)");
  expect(secure_frontend::native_chat_profile_for(EngineProfile::qwen) == secure_frontend::NativeChatProfile::qwen &&
             secure_frontend::native_chat_profile_for(EngineProfile::glm53) == secure_frontend::NativeChatProfile::glm53 &&
             secure_frontend::native_chat_profile_for(EngineProfile::gemma4) == secure_frontend::NativeChatProfile::gemma4,
         "each profile selects its own chat profile");
  expect(secure_frontend::protocol_flavor_for(EngineProfile::qwen) == secure_frontend::EngineProtocolFlavor::strata_0143 &&
             secure_frontend::protocol_flavor_for(EngineProfile::glm53) == secure_frontend::EngineProtocolFlavor::maya_118 &&
             secure_frontend::protocol_flavor_for(EngineProfile::gemma4) == secure_frontend::EngineProtocolFlavor::strata_0143,
         "the wire flavor per profile");
  expect(secure_frontend::engine_family_for(EngineProfile::qwen) == secure_frontend::EngineFamily::strata &&
             secure_frontend::engine_family_for(EngineProfile::glm53) == secure_frontend::EngineFamily::glm &&
             secure_frontend::engine_family_for(EngineProfile::gemma4) == secure_frontend::EngineFamily::strata,
         "the environment family per profile (gemma4: the strata allowlist)");
  expect(secure_frontend::per_request_reasoning_effort_for(EngineProfile::qwen) &&
             !secure_frontend::per_request_reasoning_effort_for(EngineProfile::glm53) &&
             secure_frontend::per_request_reasoning_effort_for(EngineProfile::gemma4),
         "reasoning_effort per request: qwen and gemma4, never glm53 (spec §6.6)");
}
// Gemma 4 plan 1 Task 4 (Review Focus 2): the bootstrap loads the pack in the profile's mode.
void tokenizer_mode_follows_the_profile() {
  using secure_frontend::EngineProfile;
  using secure_frontend::TokenizerMode;
  expect(secure_frontend::tokenizer_mode_for(EngineProfile::qwen) == TokenizerMode::byte_bpe, "qwen packs are byte_bpe");
  expect(secure_frontend::tokenizer_mode_for(EngineProfile::glm53) == TokenizerMode::byte_bpe, "glm53 packs are byte_bpe");
  expect(secure_frontend::tokenizer_mode_for(EngineProfile::gemma4) == TokenizerMode::spm_bpe, "gemma4 packs are spm_bpe");
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"ready_timeout_defaults_to_900_seconds", ready_timeout_defaults_to_900_seconds},
      {"subsystem_limits_follow_config", subsystem_limits_follow_config},
      {"supervisor_policy_follows_config", supervisor_policy_follows_config},
      {"supervisor_flavor_is_the_maya_dialect_for_glm53", supervisor_flavor_is_the_maya_dialect_for_glm53},
      {"supervisor_profile_and_flavor_for_gemma4", supervisor_profile_and_flavor_for_gemma4},
      {"tokenizer_mode_follows_the_profile", tokenizer_mode_follows_the_profile},
  }, failures);
}

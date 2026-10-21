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
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"ready_timeout_defaults_to_900_seconds", ready_timeout_defaults_to_900_seconds},
      {"subsystem_limits_follow_config", subsystem_limits_follow_config},
      {"supervisor_policy_follows_config", supervisor_policy_follows_config},
  }, failures);
}

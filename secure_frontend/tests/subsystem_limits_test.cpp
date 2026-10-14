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
                                   {"listener.backlog", "64"},
                                   {"limits.chat.max_body_bytes", "131072"},
                                   {"limits.chat.default_max_tokens", "64"},
                                   {"limits.engine.ready_timeout_s", "7"}});
  const auto http = secure_frontend::http_socket_server_limits(*config);
  expect(http.max_request_bytes == 262144U && http.max_header_bytes == 8192U && http.max_headers == 32U &&
             http.request_deadline == std::chrono::milliseconds(1500) && http.backlog == 64,
         "listener and parser limits come from the config");
  const auto schema = secure_frontend::chat_schema_limits(*config);
  expect(schema.max_body_bytes == 131072U, "chat body limit comes from the config");
  const auto chat = secure_frontend::chat_execution_limits(*config);
  expect(chat.ready_timeout == std::chrono::seconds(7) && chat.default_max_tokens == 64U, "chat execution limits");
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"ready_timeout_defaults_to_900_seconds", ready_timeout_defaults_to_900_seconds},
      {"subsystem_limits_follow_config", subsystem_limits_follow_config},
  }, failures);
}

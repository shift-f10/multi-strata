#include "secure_frontend/subsystem_limits.hpp"

#include <chrono>

namespace secure_frontend {

HttpSocketServerLimits http_socket_server_limits(const FrontendConfig& c) {
  HttpSocketServerLimits limits;
  limits.request_deadline = c.limits.http.request_deadline;
  limits.max_request_bytes = c.limits.http.max_request_bytes;
  limits.max_header_bytes = c.limits.http.max_header_bytes;
  limits.max_headers = c.limits.http.max_headers;
  limits.max_request_line_bytes = c.limits.http.max_request_line_bytes;
  limits.backlog = static_cast<int>(c.listener.backlog);
  return limits;
}

ChatSchemaLimits chat_schema_limits(const FrontendConfig& c) {
  ChatSchemaLimits limits;
  limits.max_body_bytes = c.limits.chat.max_body_bytes;
  limits.max_messages = c.limits.chat.max_messages;
  limits.max_message_bytes = c.limits.chat.max_message_bytes;
  limits.max_completion_tokens = c.limits.chat.max_completion_tokens;
  limits.max_generated_bytes = c.limits.chat.max_generated_bytes;
  return limits;
}

ChatExecutionLimits chat_execution_limits(const FrontendConfig& c) {
  ChatExecutionLimits limits;
  limits.maximum_prompt_tokens = c.limits.chat.max_prompt_tokens;
  limits.maximum_output_tokens = c.limits.chat.max_completion_tokens;
  limits.default_max_tokens = c.limits.chat.default_max_tokens;
  limits.ready_timeout = c.limits.engine.ready_timeout;
  limits.generation_timeout = c.limits.engine.generation_timeout;
  limits.stop_drain_timeout = c.limits.engine.stop_drain_timeout;
  return limits;
}

SupervisorConfig supervisor_config(const FrontendConfig& config) {
  SupervisorConfig supervisor;
  supervisor.chat_limits = chat_execution_limits(config);
  supervisor.policy.ready_timeout = std::chrono::duration_cast<std::chrono::milliseconds>(config.limits.engine.ready_timeout);
  supervisor.profile = config.engine.profile == EngineProfile::glm53 ? NativeChatProfile::glm53 : NativeChatProfile::qwen;
  supervisor.flavor = config.engine.profile == EngineProfile::glm53 ? EngineProtocolFlavor::lighttransport_glm53
                                                                     : EngineProtocolFlavor::strata_0143;
  return supervisor;
}

}  // namespace secure_frontend

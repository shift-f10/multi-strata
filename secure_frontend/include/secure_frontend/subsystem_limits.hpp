#pragma once

#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/http_socket_server.hpp"

namespace secure_frontend {

// Derived once from the validated configuration, before bind/spawn, and
// passed by value into each subsystem's private const state.
[[nodiscard]] HttpSocketServerLimits http_socket_server_limits(const FrontendConfig& config);
[[nodiscard]] ChatSchemaLimits chat_schema_limits(const FrontendConfig& config);
[[nodiscard]] ChatExecutionLimits chat_execution_limits(const FrontendConfig& config);

}  // namespace secure_frontend

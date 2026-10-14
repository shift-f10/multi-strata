#pragma once

#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/engine_supervisor.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/connection_handler.hpp"

namespace secure_frontend {

// Derived once from the validated configuration, before bind/spawn, and
// passed by value into each subsystem's private const state.
// Per-connection bounds (spec §2.2); the listen backlog is listener.backlog, passed to HttpSocketServer::bind.
[[nodiscard]] ConnectionLimits connection_limits(const FrontendConfig& config);
[[nodiscard]] ChatSchemaLimits chat_schema_limits(const FrontendConfig& config);
[[nodiscard]] ChatExecutionLimits chat_execution_limits(const FrontendConfig& config);
// The supervisor's configuration from the validated config: chat limits as
// chat_execution_limits(), READY deadline from limits.engine.ready_timeout_s,
// every other policy value from config_defaults.hpp.
[[nodiscard]] SupervisorConfig supervisor_config(const FrontendConfig& config);

}  // namespace secure_frontend

#pragma once

#include "secure_frontend/chat_execution.hpp"
#include "secure_frontend/chat_schema.hpp"
#include "secure_frontend/engine_supervisor.hpp"
#include "secure_frontend/frontend_config.hpp"
#include "secure_frontend/connection_handler.hpp"
#include "secure_frontend/engine_environment.hpp"

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

// Gemma 4 plan 1 Task 3 (spec §6.1): what each engine profile selects, as exhaustive
// switches shared by supervisor_config() and the bootstrap (server_bootstrap.cpp), so a new
// profile cannot silently take another profile's branch.
[[nodiscard]] NativeChatProfile native_chat_profile_for(EngineProfile profile);
[[nodiscard]] EngineProtocolFlavor protocol_flavor_for(EngineProfile profile);
[[nodiscard]] EngineFamily engine_family_for(EngineProfile profile);
// Whether the schema admits reasoning_effort per request (qwen and gemma4; glm53 refuses it).
[[nodiscard]] bool per_request_reasoning_effort_for(EngineProfile profile);

}  // namespace secure_frontend

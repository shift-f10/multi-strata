#pragma once

#include "secure_frontend/http_request_handler.hpp"

#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace secure_frontend {

// Metadata returned by the local model inventory. The router copies provider
// output into a JSON response and never exposes the provider itself to callers.
struct ApiModel final {
  std::string id;
  std::string owned_by;
};

// These providers are injected at construction time. They are intentionally
// narrow: route dispatch has no engine, filesystem, process, or network access.
using HealthStatusProvider = std::function<bool()>;
using ModelListProvider = std::function<std::vector<ApiModel>()>;
// Optional engine state for /health. It must return one of the fixed literals
// "starting", "ready", "generating", "failed"; any other value fails closed
// (503, no engine field) so the body never echoes dynamic text.
using EngineStateProvider = std::function<std::string_view()>;

// Dispatches only the authenticated API surface currently implemented. The
// HTTP boundary must authenticate and validate request headers before calling
// this class. Requests for unsupported methods or targets receive a generic
// 404 so this layer does not advertise future endpoints.
class ApiRouter final {
 public:
  // /health returns {"status":"ok"|"unavailable"} and, when engine_state is
  // set, also "engine":"<state>". The status code is 200 only when
  // health_status returns true.
  ApiRouter(HealthStatusProvider health_status, ModelListProvider model_list, EngineStateProvider engine_state = {});

  [[nodiscard]] HttpResponse dispatch(std::string_view method, std::string_view target) const;

 private:
  const HealthStatusProvider health_status_;
  const ModelListProvider model_list_;
  const EngineStateProvider engine_state_;
};

}  // namespace secure_frontend

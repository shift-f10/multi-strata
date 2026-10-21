#pragma once

#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/request_router.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace secure_frontend {

// One SP2 snapshot rendered as the /health body. engine/recovery are SP2's
// fixed literals (health_for); recovery empty = absent. Any other value, or
// recovery with a healthy engine or a state other than "failed", fails closed
// (503 engine_unavailable) so the body never echoes dynamic text.
struct HealthView final {
  bool healthy;
  std::string_view engine;
  std::string_view recovery;
};
// Called exactly once per authenticated GET /health.
using HealthProvider = std::function<HealthView()>;
// A chat handler returns a complete response or (M2) a StreamHandler.
using ChatHandler = std::function<RouteResult(std::string_view body, const RequestContext& context)>;

struct ApiRouterConfig final {
  HttpPolicy policy;
  BearerTokenValidator validator;
  std::string model_id;   // the one served id; /v1/models lists only it (spec §3.6, E9)
  std::string owned_by;
  // SP5 M1 Task 8 (model.aliases; runconfig.py:34 "lists and answers to"): /v1/models
  // lists the served id and these aliases, and GET /v1/models/<alias> finds the model.
  std::vector<std::string> aliases{};
  std::size_t chat_body_limit;
  HealthProvider health;
  ChatHandler chat;
};

// application/json, optionally followed by `; charset=utf-8`; ASCII
// case-insensitive, optional whitespace around each part (spec §4.2). Never allocates.
[[nodiscard]] bool is_json_content_type(std::string_view value) noexcept;

// The header-first router (spec §4.1 steps 3-7): Host, Origin, preflight,
// bearer token, kRouteTable, then the chat route's Content-Type and body
// limit. Nothing about routes, models or the engine is revealed before the
// token is accepted. Every response after a CORS-approved origin carries
// Access-Control-Allow-Origin and Vary: Origin, a 401 included.
class ApiRouter final : public RequestRouter {
 public:
  explicit ApiRouter(ApiRouterConfig config);
  [[nodiscard]] RouteDecision authorize(const RequestHead& head) override;
  [[nodiscard]] RouteResult handle(const RequestHead& head, std::string_view body, const RouteDecision& decision,
                                   const RequestContext& context) override;

 private:
  ApiRouterConfig config_;
};

}  // namespace secure_frontend

#include "secure_frontend/api_router.hpp"

#include "secure_frontend/api_constants.hpp"
#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/http_request_head.hpp"
#include "secure_frontend/json.hpp"
#include "secure_frontend/web_ui.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace secure_frontend {
namespace {

HttpResponse json_response(int status, std::string body) {
  return {.status = status, .headers = {{"Content-Type", "application/json; charset=utf-8"}}, .body = std::move(body)};
}

// Spec §3.9: copied unchanged only after validation — 1..kMaxModelFieldBytes
// bytes of valid UTF-8 with no C0 control or DEL.
bool valid_field(std::string_view value) {
  return !value.empty() && value.size() <= api_constants::kMaxModelFieldBytes && is_valid_utf8(value) &&
         std::none_of(value.begin(), value.end(), [](char c) { return static_cast<unsigned char>(c) < 0x20U || c == 0x7f; });
}

// SP2's fixed /health literals (health_for); recovery only with a failed, unhealthy engine.
bool valid_health(const HealthView& view) {
  const std::string_view e = view.engine;
  if (e != "starting" && e != "ready" && e != "generating" && e != "failed") return false;
  if (view.recovery.empty()) return true;
  return !view.healthy && e == "failed" && (view.recovery == "restarting" || view.recovery == "exhausted");
}

std::string model_object(std::string_view id, std::string_view owned_by) {
  std::string body{"{\"id\":"};
  append_json_string(&body, id);
  body.append(",\"object\":\"model\",\"created\":0,\"owned_by\":");
  append_json_string(&body, owned_by);
  body.push_back('}');
  return body;
}

void add_cors(HttpResponse* response, const std::optional<std::string>& allow_origin) {
  if (!allow_origin.has_value()) return;
  response->headers.emplace_back("Access-Control-Allow-Origin", *allow_origin);
  response->headers.emplace_back("Vary", "Origin");
}

}  // namespace

bool is_json_content_type(const std::string_view value) noexcept {
  constexpr std::string_view kType = "application/json";
  const std::string_view text = trim_ows(value);
  if (text.size() < kType.size() || !ascii_iequal(text.substr(0, kType.size()), kType)) return false;
  const std::string_view rest = trim_ows(text.substr(kType.size()));
  if (rest.empty()) return true;
  if (rest.front() != ';') return false;
  return ascii_iequal(trim_ows(rest.substr(1U)), "charset=utf-8");
}

ApiRouter::ApiRouter(ApiRouterConfig config) : config_(std::move(config)) {}

RouteDecision ApiRouter::authorize(const RequestHead& head) {
  RouteDecision decision;
  const auto early = [&decision](HttpResponse response) {
    add_cors(&response, decision.allow_origin);
    decision.early = std::move(response);
    return decision;
  };
  // Step 3: Host and Origin policy.
  const PolicyVerdict host = check_host(config_.policy, head.values("host"));
  if (host != PolicyVerdict::allowed) {
    return early(make_error_response(host == PolicyVerdict::malformed ? ApiError::invalid_request : ApiError::forbidden));
  }
  const OriginDecision origin = check_origin(config_.policy, head.values("origin"));
  if (origin.verdict != PolicyVerdict::allowed) return early(make_error_response(ApiError::forbidden));
  // Step 4: CORS preflight, before authentication; it carries its own CORS headers.
  if (auto preflight = evaluate_preflight(config_.policy, head)) {
    decision.early = std::move(*preflight);
    return decision;
  }
  decision.allow_origin = origin.allow_origin;

  // The built-in page (listener.web_ui): its bundled files are public — they hold no secret
  // and reach no route. Exact GET targets only, after Host and Origin; anything else goes on
  // to the key check like every API request.
  if (config_.web_ui && head.method == "GET" && find_web_asset(head.target) != nullptr) {
    decision.route = RouteId::web;
    decision.expect_continue = head.expect_continue;
    decision.body_limit = head.content_length.value_or(0U);
    return decision;
  }

  // Step 5: exactly one `Bearer <non-empty>` the validator accepts — unless this is the
  // keyless loopback listener (listener.loopback_without_key; require_key false).
  if (config_.require_key) {
    const auto authorizations = head.values("authorization");
    if (authorizations.size() > 1U) return early(make_error_response(ApiError::invalid_request));
    constexpr std::string_view kBearer = "Bearer ";
    bool authorized = false;
    if (authorizations.size() == 1U && authorizations.front().size() > kBearer.size() &&
        authorizations.front().substr(0, kBearer.size()) == kBearer) {
      try {
        authorized = config_.validator && config_.validator(authorizations.front().substr(kBearer.size()));
      } catch (...) {
        authorized = false;
      }
    }
    if (!authorized) return early(make_error_response(ApiError::invalid_api_key));
  }

  // Step 6: kRouteTable, byte-exact; a prefix route needs a non-empty rest.
  const RouteEntry* matched = nullptr;
  std::string_view allow;
  const std::string_view target = head.target;
  for (const auto& entry : kRouteTable) {
    const bool path_match = entry.prefix
                                ? (target.size() > entry.path.size() && target.substr(0, entry.path.size()) == entry.path)
                                : target == entry.path;
    if (!path_match) continue;
    allow = entry.method;
    if (head.method == entry.method) matched = &entry;
  }
  if (matched == nullptr) {
    if (allow.empty()) return early(make_error_response(ApiError::not_found));
    return early(make_error_response(ApiError::method_not_allowed, {.allow = allow}));
  }
  decision.route = matched->id;
  // Step 7: the chat route's header checks.
  if (decision.route == RouteId::chat) {
    const auto types = head.values("content-type");
    if (types.size() != 1U || !is_json_content_type(types.front())) return early(make_error_response(ApiError::unsupported_media_type));
    if (head.content_length.value_or(0U) > config_.chat_body_limit) return early(make_error_response(ApiError::request_too_large));
  }
  decision.expect_continue = head.expect_continue;
  decision.body_limit = head.content_length.value_or(0U);
  return decision;
}

RouteResult ApiRouter::handle(const RequestHead& head, const std::string_view body, const RouteDecision& decision,
                              const RequestContext& context) {
  HttpResponse response = make_error_response(ApiError::internal_error);
  try {
    switch (decision.route) {
      case RouteId::health: {
        if (!config_.health) {
          response = make_error_response(ApiError::engine_unavailable);
          break;
        }
        const HealthView view = config_.health();   // exactly once per request
        if (!valid_health(view)) {
          response = make_error_response(ApiError::engine_unavailable);
          break;
        }
        std::string text{view.healthy ? "{\"status\":\"ok\",\"engine\":" : "{\"status\":\"unavailable\",\"engine\":"};
        append_json_string(&text, view.engine);
        if (!view.recovery.empty()) {
          text.append(",\"recovery\":");
          append_json_string(&text, view.recovery);
        }
        text.append("}\n");
        response = json_response(view.healthy ? 200 : 503, std::move(text));
        break;
      }
      case RouteId::models:
        if (!valid_field(config_.model_id) || !valid_field(config_.owned_by)) break;   // internal_error
        if (!std::all_of(config_.aliases.begin(), config_.aliases.end(), [](const std::string& alias) { return valid_field(alias); }))
          break;  // internal_error: an alias is schema-checked; a router fed a bad one is a bug
        {
          std::string data = model_object(config_.model_id, config_.owned_by);
          for (const auto& alias : config_.aliases) data += "," + model_object(alias, config_.owned_by);
          response = json_response(200, "{\"object\":\"list\",\"data\":[" + std::move(data) + "]}\n");
        }
        break;
      case RouteId::model: {
        constexpr std::string_view kPrefix = "/v1/models/";
        const std::string_view target = head.target;
        if (!valid_field(config_.model_id) || !valid_field(config_.owned_by) || target.size() <= kPrefix.size()) break;
        const std::string_view wanted = target.substr(kPrefix.size());
        // SP5 M1 Task 8: an alias names the same model.
        const bool named = wanted == config_.model_id ||
                           std::find(config_.aliases.begin(), config_.aliases.end(), std::string{wanted}) != config_.aliases.end();
        response = named ? json_response(200, model_object(config_.model_id, config_.owned_by) + "\n")
                         : make_error_response(ApiError::model_not_found);
        break;
      }
      case RouteId::chat: {
        RouteResult result =
            config_.chat ? config_.chat(body, context) : RouteResult{make_error_response(ApiError::engine_unavailable)};
        // A StreamHandler gets the CORS headers from deliver_route_result (Task 8b), which adds them to its head.
        if (auto* complete = std::get_if<HttpResponse>(&result)) add_cors(complete, decision.allow_origin);
        return result;
      }
      case RouteId::web: {
        const WebAsset* asset = find_web_asset(head.target);
        if (asset == nullptr) break;  // internal_error: authorize matched it
        response = HttpResponse{.status = 200,
                                .headers = {{"Content-Type", std::string{asset->content_type}},
                                            {"Cross-Origin-Opener-Policy", "same-origin"}},
                                .body = std::string{asset->body},
                                .content_security_policy = kWebUiContentSecurityPolicy};
        break;
      }
      case RouteId::other:
        response = make_error_response(ApiError::not_found);
        break;
    }
  } catch (...) {
    response = make_error_response(decision.route == RouteId::health ? ApiError::engine_unavailable : ApiError::internal_error);
  }
  add_cors(&response, decision.allow_origin);
  return response;
}

}  // namespace secure_frontend

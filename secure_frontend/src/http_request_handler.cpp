#include "secure_frontend/http_request_handler.hpp"

#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/http_policy.hpp"
#include "secure_frontend/request_router.hpp"
#include "secure_frontend/secret_bytes.hpp"

#include <utility>

namespace secure_frontend {

std::optional<std::string_view> HttpResponse::header_value(const std::string_view name) const {
  for (const auto& [header_name, value] : headers) {
    if (ascii_iequal(header_name, name)) return value;
  }
  return std::nullopt;
}

// Kept (pre-flight P24/V8): the socket server tests and the handler tests still use it.
bool constant_time_token_equals(std::string_view candidate, std::string_view expected) {
  return detail::fixed_window_equals(candidate, expected, nullptr);
}

HttpResponse handle_http_request(const std::string_view request, RequestRouter& router, const HeadLimits& limits) {
  const HeadScanResult scan = scan_request_head(request, limits);
  if (scan.state == HeadScan::line_too_long) return make_error_response(ApiError::request_line_too_long);
  if (scan.state == HeadScan::header_too_large) return make_error_response(ApiError::header_too_large);
  if (scan.state != HeadScan::complete) return make_error_response(ApiError::invalid_request);
  const HeadParseResult parsed = parse_request_head(request.substr(0, scan.head_bytes), limits);
  if (const auto* error = std::get_if<ApiError>(&parsed)) return make_error_response(*error);
  const RequestHead& head = std::get<RequestHead>(parsed);
  RouteDecision decision = router.authorize(head);
  if (decision.early.has_value()) return std::move(*decision.early);
  const std::string_view body = request.substr(scan.head_bytes);
  if (body.size() != head.content_length.value_or(0U)) return make_error_response(ApiError::invalid_request);
  RouteResult result = router.handle(head, body, decision, RequestContext{});
  if (auto* complete = std::get_if<HttpResponse>(&result)) return std::move(*complete);
  return make_error_response(ApiError::internal_error);
}

namespace {

// Adapts the SP0/SP1 dispatcher to RequestRouter for the serial server until Task 9.
class DispatcherRouter final : public RequestRouter {
 public:
  DispatcherRouter(HttpPolicy policy, BearerTokenValidator validator, RequestDispatcher dispatch)
      : policy_(std::move(policy)), validator_(std::move(validator)), dispatch_(std::move(dispatch)) {}

  RouteDecision authorize(const RequestHead& head) override {
    RouteDecision decision;
    const PolicyVerdict host = check_host(policy_, head.values("host"));
    if (host != PolicyVerdict::allowed) {
      decision.early = make_error_response(host == PolicyVerdict::malformed ? ApiError::invalid_request : ApiError::forbidden);
      return decision;
    }
    const OriginDecision origin = check_origin(policy_, head.values("origin"));
    if (origin.verdict != PolicyVerdict::allowed) {
      decision.early = make_error_response(ApiError::forbidden);
      return decision;
    }
    if (auto preflight = evaluate_preflight(policy_, head)) {
      decision.early = std::move(*preflight);
      return decision;
    }
    const auto auth = head.values("authorization");
    if (auth.size() > 1U) {
      decision.early = make_error_response(ApiError::invalid_request);
      return decision;
    }
    bool ok = false;
    if (auth.size() == 1U && auth.front().rfind("Bearer ", 0) == 0 && auth.front().size() > 7U) {
      try {
        ok = validator_ && validator_(auth.front().substr(7U));
      } catch (...) {
        ok = false;
      }
    }
    if (!ok) decision.early = make_error_response(ApiError::invalid_api_key);
    decision.body_limit = head.content_length.value_or(0U);
    decision.allow_origin = origin.allow_origin;
    return decision;
  }

  RouteResult handle(const RequestHead& head, std::string_view body, const RouteDecision& decision,
                     const RequestContext&) override {
    HttpResponse response = make_error_response(ApiError::engine_unavailable);
    try {
      if (dispatch_) response = dispatch_(head.method, head.target, body);
    } catch (...) {
      response = make_error_response(ApiError::engine_unavailable);
    }
    if (decision.allow_origin) {
      response.headers.emplace_back("Access-Control-Allow-Origin", *decision.allow_origin);
      response.headers.emplace_back("Vary", "Origin");
    }
    return response;
  }

 private:
  HttpPolicy policy_;
  BearerTokenValidator validator_;
  RequestDispatcher dispatch_;
};

}  // namespace

HttpResponse handle_http_request(const std::string_view request, const HttpPolicy& policy, const BearerTokenValidator& validator,
                                 const RequestDispatcher& dispatch, const HttpParserLimits& limits) {
  DispatcherRouter router(policy, validator, dispatch);
  return handle_http_request(request, router,
                             HeadLimits{limits.max_request_line_bytes, limits.max_header_bytes, limits.max_headers,
                                        limits.max_request_bytes});
}

std::unique_ptr<RequestRouter> make_dispatcher_router(HttpPolicy policy, BearerTokenValidator validator, RequestDispatcher dispatch) {
  return std::make_unique<DispatcherRouter>(std::move(policy), std::move(validator), std::move(dispatch));
}

}  // namespace secure_frontend

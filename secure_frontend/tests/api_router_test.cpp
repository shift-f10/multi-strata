#include "secure_frontend/api_router.hpp"
#include "secure_frontend/token_verifier.hpp"
#include "support/test_support.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

secure_frontend::ApiRouter router(bool healthy = true) {
  return secure_frontend::ApiRouter(
      [healthy] { return healthy; },
      [] {
        return std::vector<secure_frontend::ApiModel>{
            {.id = "local-model", .owned_by = "local"},
            {.id = "quote-\\\"and-newline\\n", .owned_by = "owner\\\\name"},
        };
      });
}

void dispatches_exact_health_route() {
  const auto response = router().dispatch("GET", "/health");
  expect(response.status == 200, "GET /health should be successful when provider is healthy");
  expect(response.header_value("Content-Type") == "application/json; charset=utf-8",
         "health must use JSON content type");
  expect(response.body == "{\"status\":\"ok\"}\n", "health response should be stable JSON");

  const auto unavailable = router(false).dispatch("GET", "/health");
  expect(unavailable.status == 503, "unhealthy provider should be unavailable");
  expect(unavailable.body == "{\"status\":\"unavailable\"}\n",
         "unhealthy response should not leak provider details");
}

void dispatches_models_with_json_escaping() {
  const auto response = router().dispatch("GET", "/v1/models");
  expect(response.status == 200, "GET /v1/models should be successful");
  expect(response.body ==
             "{\"object\":\"list\",\"data\":[{\"id\":\"local-model\",\"object\":\"model\",\"owned_by\":\"local\"},{\"id\":\"quote-\\\\\\\"and-newline\\\\n\",\"object\":\"model\",\"owned_by\":\"owner\\\\\\\\name\"}]}\n",
         "model metadata must be serialized as escaped JSON, never interpolated raw");
}

void rejects_non_exact_routes() {
  for (const auto& [method, target] : std::vector<std::pair<std::string, std::string>>{
           {"POST", "/health"}, {"GET", "/health?verbose=1"}, {"GET", "/health/"},
           {"GET", "/v1/models/"}, {"GET", "/v1/chat/completions"}, {"OPTIONS", "/v1/models"},
       }) {
    const auto response = router().dispatch(method, target);
    expect(response.status == 404, "only exact GET routes should be exposed");
    expect(response.body == "{\"error\":\"Not Found\"}\n", "404 must be generic JSON");
  }
}

void fails_closed_when_provider_throws_or_returns_invalid_model() {
  secure_frontend::ApiRouter throwing_router(
      [] { return true; }, []() -> std::vector<secure_frontend::ApiModel> { throw std::runtime_error("private"); });
  const auto thrown = throwing_router.dispatch("GET", "/v1/models");
  expect(thrown.status == 503, "model provider exceptions should fail closed");
  expect(thrown.body == "{\"error\":\"Service Unavailable\"}\n", "errors must not leak exception details");

  secure_frontend::ApiRouter invalid_router(
      [] { return true; }, [] { return std::vector<secure_frontend::ApiModel>{{.id = "", .owned_by = "local"}}; });
  const auto invalid = invalid_router.dispatch("GET", "/v1/models");
  expect(invalid.status == 503, "invalid model metadata must not be emitted");
}
void health_includes_engine_state_when_provided() {
  const secure_frontend::ApiRouter with_state(
      [] { return true; }, [] { return std::vector<secure_frontend::ApiModel>{}; },
      []() -> std::string_view { return "ready"; });
  const auto response = with_state.dispatch("GET", "/health");
  expect(response.status == 200, "healthy provider with engine state must be 200");
  expect(response.body == "{\"status\":\"ok\",\"engine\":\"ready\"}\n", "health must carry \"engine\":\"ready\"");
  const secure_frontend::ApiRouter generating(
      [] { return true; }, [] { return std::vector<secure_frontend::ApiModel>{}; },
      []() -> std::string_view { return "generating"; });
  expect(generating.dispatch("GET", "/health").body == "{\"status\":\"ok\",\"engine\":\"generating\"}\n",
         "generating is reported as healthy");
}

void health_is_503_with_engine_state_when_unavailable() {
  const secure_frontend::ApiRouter failed(
      [] { return false; }, [] { return std::vector<secure_frontend::ApiModel>{}; },
      []() -> std::string_view { return "failed"; });
  const auto response = failed.dispatch("GET", "/health");
  expect(response.status == 503, "unavailable provider with engine state must be 503");
  expect(response.body == "{\"status\":\"unavailable\",\"engine\":\"failed\"}\n",
         "503 body carries only status and the engine literal");
  const secure_frontend::ApiRouter bogus(
      [] { return true; }, [] { return std::vector<secure_frontend::ApiModel>{}; },
      []() -> std::string_view { return "/secret/path\"x"; });
  const auto rejected = bogus.dispatch("GET", "/health");
  expect(rejected.status == 503, "an engine state outside the fixed literals fails closed");
  expect(rejected.body == "{\"status\":\"unavailable\"}\n", "an unknown engine state is never echoed");
}

void health_samples_status_before_state_once_each() {
  std::string calls;
  std::string_view snapshot{"failed"};
  const secure_frontend::ApiRouter snapshotting(
      [&] { calls += 'b'; snapshot = "starting"; return true; },
      [] { return std::vector<secure_frontend::ApiModel>{}; },
      [&]() -> std::string_view { calls += 's'; return snapshot; });
  const auto response = snapshotting.dispatch("GET", "/health");
  expect(calls == "bs", "health must call the bool provider once, then the state provider once; saw: " + calls);
  expect(response.status == 200 && response.body == "{\"status\":\"ok\",\"engine\":\"starting\"}\n",
         "a starting engine that is not failed is reported 200 with engine=starting");
}

void auth01_every_route_rejects_missing_malformed_wrong_token() {
  secure_frontend::SecretBytes secret;
  (void)secret.assign("auth01-token-0123456789abcdefghijklmnopq");
  const auto validator = secure_frontend::make_bearer_validator(
      std::make_shared<const secure_frontend::TokenVerifier>(std::move(secret)));
  const auto routes_under_test = router();
  const secure_frontend::RequestDispatcher dispatch = [&routes_under_test](std::string_view method, std::string_view target,
                                                                           std::string_view) {
    return routes_under_test.dispatch(method, target);
  };
  const secure_frontend::HttpPolicy policy{.allowed_hosts = {"127.0.0.1:8080"},
                                           .same_origin_origins = {"http://127.0.0.1:8080"},
                                           .cors_allowed_origins = {}, .cors_enabled = false};
  const std::string token = "auth01-token-0123456789abcdefghijklmnopq";
  const std::pair<std::string, int> variants[] = {
      {"", 401},                                                           // missing
      {"Authorization: bearer " + token + "\r\n", 401},                    // lowercase scheme
      {"Authorization: Bearer \r\n", 401},                                 // Bearer + empty
      {"Authorization: Bearer\t" + token + "\r\n", 401},                   // tab separator
      {"Authorization: Basic " + token + "\r\n", 401},                     // other scheme
      {"Authorization: Bearer " + token + "\r\nAuthorization: Bearer " + token + "\r\n", 400},  // duplicate
      {"Authorization: Bearer wrong-token-0123456789abcdefghijklmn\r\n", 401}};
  const std::pair<const char*, const char*> routes[] = {
      {"GET", "/health"}, {"GET", "/v1/models"}, {"POST", "/v1/chat/completions"}, {"GET", "/does-not-exist"}};
  for (const auto& [method, target] : routes) {
    for (const auto& [headers, status] : variants) {
      std::string request = std::string{method} + " " + target + " HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n" + headers;
      request += std::string{method} == "POST" ? "Content-Length: 2\r\n\r\n{}" : "\r\n";
      const auto response = secure_frontend::handle_http_request(request, policy, validator, dispatch);
      expect(response.status == status, std::string{method} + " " + target + " must answer " + std::to_string(status));
      expect(response.body.find("local-model") == std::string::npos && response.body.find("status") == std::string::npos,
             "a rejected request carries no route or model data");
    }
  }
  const auto allowed = secure_frontend::handle_http_request(
      "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAuthorization: Bearer " + token + "\r\n\r\n", policy, validator,
      dispatch);
  expect(allowed.status == 200 && allowed.body.find("local-model") != std::string::npos,
         "the same route answers with the right token (the negatives are not vacuous)");
}
}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"health_samples_status_before_state_once_each", health_samples_status_before_state_once_each},
      {"health_includes_engine_state_when_provided", health_includes_engine_state_when_provided},
      {"health_is_503_with_engine_state_when_unavailable", health_is_503_with_engine_state_when_unavailable},
      {"dispatches_exact_health_route", dispatches_exact_health_route},
      {"dispatches_models_with_json_escaping", dispatches_models_with_json_escaping},
      {"rejects_non_exact_routes", rejects_non_exact_routes},
      {"fails_closed_when_provider_throws_or_returns_invalid_model", fails_closed_when_provider_throws_or_returns_invalid_model},
      {"auth01_every_route_rejects_missing_malformed_wrong_token", auth01_every_route_rejects_missing_malformed_wrong_token},
  }, failures);
}

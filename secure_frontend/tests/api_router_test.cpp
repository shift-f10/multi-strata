#include "secure_frontend/api_router.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
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

}  // namespace

int main() {
  dispatches_exact_health_route();
  dispatches_models_with_json_escaping();
  rejects_non_exact_routes();
  fails_closed_when_provider_throws_or_returns_invalid_model();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

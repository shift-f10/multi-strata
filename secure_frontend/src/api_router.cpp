#include "secure_frontend/api_router.hpp"

#include <cstddef>
#include <string>
#include <utility>

namespace secure_frontend {
namespace {

constexpr std::size_t kMaximumModelFields = 1024U;

HttpResponse json_response(int status, std::string body) {
  return {.status = status,
          .headers = {{"Content-Type", "application/json; charset=utf-8"}, {"Cache-Control", "no-store"}},
          .body = std::move(body)};
}

HttpResponse not_found() { return json_response(404, "{\"error\":\"Not Found\"}\n"); }

HttpResponse unavailable() {
  return json_response(503, "{\"error\":\"Service Unavailable\"}\n");
}

bool is_engine_state_literal(std::string_view state) {
  return state == "starting" || state == "ready" || state == "generating" || state == "failed";
}

HttpResponse health_response(bool healthy, const EngineStateProvider& engine_state) {
  if (!engine_state) {
    return healthy ? json_response(200, "{\"status\":\"ok\"}\n") : json_response(503, "{\"status\":\"unavailable\"}\n");
  }
  const std::string_view state = engine_state();
  if (!is_engine_state_literal(state)) return json_response(503, "{\"status\":\"unavailable\"}\n");
  std::string body{healthy ? "{\"status\":\"ok\",\"engine\":\"" : "{\"status\":\"unavailable\",\"engine\":\""};
  body.append(state);
  body.append("\"}\n");
  return json_response(healthy ? 200 : 503, std::move(body));
}

bool is_valid_model_field(std::string_view value) {
  if (value.empty() || value.size() > kMaximumModelFields) return false;
  for (const unsigned char character : value) {
    if (character < 0x20U || character == 0x7fU) return false;
  }
  return true;
}

void append_json_string(std::string* output, std::string_view value) {
  static constexpr char kHex[] = "0123456789abcdef";
  output->push_back('\"');
  for (const unsigned char character : value) {
    switch (character) {
      case '\"': output->append("\\\""); break;
      case '\\': output->append("\\\\"); break;
      case '\b': output->append("\\b"); break;
      case '\f': output->append("\\f"); break;
      case '\n': output->append("\\n"); break;
      case '\r': output->append("\\r"); break;
      case '\t': output->append("\\t"); break;
      default:
        if (character < 0x20U || character >= 0x80U) {
          output->append("\\u00");
          output->push_back(kHex[(character >> 4U) & 0x0fU]);
          output->push_back(kHex[character & 0x0fU]);
        } else {
          output->push_back(static_cast<char>(character));
        }
    }
  }
  output->push_back('\"');
}

HttpResponse model_list_response(const std::vector<ApiModel>& models) {
  std::string body{"{\"object\":\"list\",\"data\":["};
  bool first = true;
  for (const ApiModel& model : models) {
    if (!is_valid_model_field(model.id) || !is_valid_model_field(model.owned_by)) return unavailable();
    if (!first) body.push_back(',');
    first = false;
    body.append("{\"id\":");
    append_json_string(&body, model.id);
    body.append(",\"object\":\"model\",\"owned_by\":");
    append_json_string(&body, model.owned_by);
    body.push_back('}');
  }
  body.append("]}\n");
  return json_response(200, std::move(body));
}

}  // namespace

ApiRouter::ApiRouter(HealthStatusProvider health_status, ModelListProvider model_list, EngineStateProvider engine_state)
    : health_status_(std::move(health_status)),
      model_list_(std::move(model_list)),
      engine_state_(std::move(engine_state)) {}

HttpResponse ApiRouter::dispatch(std::string_view method, std::string_view target) const {
  if (method != "GET") return not_found();
  try {
    if (target == "/health") {
      const bool healthy = health_status_ && health_status_();  // first, by contract
      return health_response(healthy, engine_state_);
    }
    if (target == "/v1/models") {
      if (!model_list_) return unavailable();
      return model_list_response(model_list_());
    }
  } catch (...) {
    return unavailable();
  }
  return not_found();
}

}  // namespace secure_frontend

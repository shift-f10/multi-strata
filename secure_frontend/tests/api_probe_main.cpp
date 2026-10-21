// strata-api-probe: test-only client for the SP3 GPU validation kit (docs/validation/sp3-api-kit.md).
// Built in every preset, never installed. Talks only to a loopback address.
#include "secure_frontend/api_client.hpp"
#include "secure_frontend/config.hpp"
#include "secure_frontend/json.hpp"
#include "secure_frontend/utf8_stream_decoder.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
using secure_frontend::ChatExchangeEnd;
using secure_frontend::ChatExchangeResult;

struct Probe final {
  secure_frontend::LoopbackAddress address;
  std::uint16_t port;
  std::string token;
  std::string model;
};

long long ms_since(const Clock::time_point start) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
}

std::string json_text(const std::string& text) {
  std::string out;
  secure_frontend::append_json_string(&out, text);
  return out;
}

std::string body(const Probe& probe, const std::string& prompt, const std::string& extra) {
  return R"({"model":)" + json_text(probe.model) + R"(,"messages":[{"role":"user","content":)" + json_text(prompt) + "}]" +
         (extra.empty() ? "" : "," + extra) + "}";
}

std::optional<secure_frontend::JsonValue> parse(const std::string& text) {
  auto parsed = secure_frontend::parse_json(text, {.max_bytes = 16U << 20U, .max_depth = 8U, .max_container_entries = 4096U, .max_string_bytes = 16U << 20U});
  if (auto* value = std::get_if<secure_frontend::JsonValue>(&parsed)) return std::move(*value);
  return std::nullopt;
}

const secure_frontend::JsonValue* member(const secure_frontend::JsonValue* object, const std::string_view key) {
  const auto* members = object != nullptr ? object->if_object() : nullptr;
  if (members == nullptr) return nullptr;
  for (const auto& entry : *members) {
    if (entry.key == key) return &entry.value;
  }
  return nullptr;
}

const secure_frontend::JsonValue* first_choice(const secure_frontend::JsonValue* root) {
  const auto* choices = member(root, "choices");
  return choices != nullptr && choices->if_array() != nullptr && !choices->if_array()->empty() ? &choices->if_array()->front() : nullptr;
}

std::string string_of(const secure_frontend::JsonValue* value) { return value != nullptr && value->if_string() ? *value->if_string() : ""; }

struct StreamFacts final {
  std::string text;
  std::string finish;
  std::size_t content_events{0};
  long long first_content_ms{-1};
};

StreamFacts facts_of(const ChatExchangeResult& result) {
  StreamFacts facts;
  for (const auto& item : result.items) {
    if (item.kind != secure_frontend::SseItemKind::data || item.text == "[DONE]") continue;
    const auto root = parse(item.text);
    const auto* choice = first_choice(root ? &*root : nullptr);
    const auto* content = member(member(choice, "delta"), "content");
    if (content != nullptr && content->if_string() && !content->if_string()->empty()) {
      facts.text += *content->if_string();
      ++facts.content_events;
    }
    const auto finish = string_of(member(choice, "finish_reason"));
    if (!finish.empty()) facts.finish = finish;
  }
  return facts;
}

std::string complete_text(const ChatExchangeResult& result) {
  const auto root = parse(result.body);
  return string_of(member(member(first_choice(root ? &*root : nullptr), "message"), "content"));
}

ChatExchangeResult send(const Probe& probe, const std::string& json, secure_frontend::ChatRequestOptions options = {}) {
  if (options.timeout == std::chrono::seconds(30)) options.timeout = 600s;  // real prefill can be long
  return secure_frontend::post_chat_completion(probe.address, probe.port, probe.token, json, options);
}

int pass(const std::string& mode, const std::string& facts) {
  std::cout << "PASS " << mode << ' ' << facts << '\n';
  return 0;
}
int fail(const std::string& mode, const std::string& reason) {
  std::cout << "FAIL " << mode << ' ' << reason << '\n';
  return 1;
}

bool complete_stream(const ChatExchangeResult& result) {
  return result.end == ChatExchangeEnd::complete && result.streamed && result.done_seen && result.terminal_chunk_seen;
}

// After a cancel: how long until a one-token request is served (STOP -> DONE ... cancel -> next lease).
long long next_request_ms(const Probe& probe) {
  const auto start = Clock::now();
  const auto next = send(probe, body(probe, "Say OK.", R"("max_tokens":1)"));
  return next.head.status == 200 ? ms_since(start) : -1;
}

int run_mode(const Probe& probe, const std::string& mode) {
  if (mode == "stream") {
    const auto start = Clock::now();
    const auto result = send(probe, body(probe, "Say hello in five words.", R"("max_tokens":64,"stream":true)"));
    const auto facts = facts_of(result);
    if (!complete_stream(result) || facts.finish.empty()) return fail(mode, "stream not complete (needs [DONE] and the terminal chunk)");
    return pass(mode, "events=" + std::to_string(facts.content_events) + " bytes=" + std::to_string(facts.text.size()) +
                          " finish=" + facts.finish + " total_ms=" + std::to_string(ms_since(start)));
  }
  if (mode == "nonstream") {
    const auto result = send(probe, body(probe, "Say hello in five words.", R"("max_tokens":64)"));
    if (result.end != ChatExchangeEnd::complete || result.head.status != 200) return fail(mode, "status " + std::to_string(result.head.status));
    return pass(mode, "bytes=" + std::to_string(complete_text(result).size()));
  }
  if (mode.rfind("cancel-after=", 0) == 0) {
    const int after = std::stoi(mode.substr(13));
    int seen = 0;
    secure_frontend::ChatRequestOptions options;
    options.on_item = [&seen, after](const secure_frontend::SseItem& item) {
      seen += item.text.find(R"("delta":{"content")") != std::string::npos;
      return seen < after;
    };
    const auto result = send(probe, body(probe, "Count from 1 to 500.", R"("max_tokens":2048,"stream":true)"), options);
    if (result.end != ChatExchangeEnd::cancelled) return fail(mode, "the stream ended before the cancel");
    const auto next = next_request_ms(probe);
    if (next < 0) return fail(mode, "the next request failed after the cancel");
    return pass(mode, "next_request_ms=" + std::to_string(next) + " (compare with limits.engine.stop_drain_timeout_s)");
  }
  if (mode == "cancel-during-prefill") {
    std::string prompt;
    while (prompt.size() < 40000U) prompt += "Summarize this sentence carefully. ";
    secure_frontend::ChatRequestOptions options;
    options.on_item = [](const secure_frontend::SseItem&) { return false; };  // close at the role chunk
    (void)send(probe, body(probe, prompt, R"("max_tokens":16,"stream":true)"), options);
    const auto next = next_request_ms(probe);
    if (next < 0) return fail(mode, "the next request failed after a cancel during prefill");
    return pass(mode, "next_request_ms=" + std::to_string(next) + " (risk R4: STOP latency during prefill)");
  }
  if (mode.rfind("concurrent=", 0) == 0) {
    const int count = std::stoi(mode.substr(11));
    std::mutex lock;
    std::vector<int> finished;
    std::vector<std::thread> clients;
    for (int index = 0; index < count; ++index) {
      clients.emplace_back([&, index] {
        const auto result = send(probe, body(probe, "Say OK.", R"("max_tokens":16)"));
        std::lock_guard guard(lock);
        finished.push_back(result.head.status == 200 ? index : -1 - index);
      });
      std::this_thread::sleep_for(100ms);  // admission order = start order
    }
    for (auto& client : clients) client.join();
    for (int index = 0; index < count; ++index) {
      if (finished[static_cast<std::size_t>(index)] != index) return fail(mode, "completion order is not admission order (FIFO)");
    }
    return pass(mode, "fifo=yes clients=" + std::to_string(count));
  }
  if (mode == "utf8") {
    const std::string prompt = "Repeat exactly: 東京 и 🌍 — ok";
    const auto streamed = send(probe, body(probe, prompt, R"("max_tokens":64,"seed":7,"temperature":0,"stream":true)"));
    const auto complete = send(probe, body(probe, prompt, R"("max_tokens":64,"seed":7,"temperature":0)"));
    const auto facts = facts_of(streamed);
    secure_frontend::Utf8StreamDecoder check;
    const bool valid = check.push(facts.text) == facts.text && check.finish(false).empty();
    if (!complete_stream(streamed) || !valid) return fail(mode, "stream incomplete or not valid UTF-8");
    if (facts.text != complete_text(complete)) return fail(mode, "stream text differs from non-stream text at a fixed seed");
    return pass(mode, "bytes=" + std::to_string(facts.text.size()));
  }
  if (mode == "seed") {
    const auto first = send(probe, body(probe, "Write one sentence about rivers.", R"("max_tokens":48,"seed":42,"temperature":0.7)"));
    const auto second = send(probe, body(probe, "Write one sentence about rivers.", R"("max_tokens":48,"seed":42,"temperature":0.7)"));
    if (first.head.status != 200 || complete_text(first) != complete_text(second)) return fail(mode, "the same seed gave different text");
    return pass(mode, "same_text=yes");
  }
  return -1;
}

}  // namespace

int main(int argc, char* argv[]) {
  std::optional<std::uint16_t> port;
  std::string token_file;
  std::string model;
  std::string host = "127.0.0.1";
  std::string mode;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    const bool has_value = index + 1 < argc;
    if (argument == "--port" && has_value) port = static_cast<std::uint16_t>(std::stoi(argv[++index]));
    else if (argument == "--token-file" && has_value) token_file = argv[++index];
    else if (argument == "--model" && has_value) model = argv[++index];
    else if (argument == "--host" && has_value) host = argv[++index];
    else mode = argument;
  }
  const auto ip = secure_frontend::parse_listener_address(host);
  auto address = ip ? secure_frontend::LoopbackAddress::from(*ip) : std::nullopt;
  std::ifstream file(token_file, std::ios::binary);
  std::string token((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  while (!token.empty() && (token.back() == '\n' || token.back() == '\r')) token.pop_back();
  if (!port || !address || token.empty() || model.empty() || mode.empty()) {
    std::cerr << "usage: strata-api-probe --port <n> --token-file <path> --model <id> [--host 127.0.0.1|::1] "
                 "<stream|nonstream|cancel-after=<n>|cancel-during-prefill|concurrent=<k>|utf8|seed>\n";
    return 2;
  }
  const Probe probe{std::move(*address), *port, std::move(token), std::move(model)};
  const int result = run_mode(probe, mode);
  if (result < 0) {
    std::cerr << "unknown mode\n";
    return 2;
  }
  return result;
}

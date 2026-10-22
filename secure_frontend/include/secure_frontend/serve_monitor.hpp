#pragma once

// The Monitor (listener.monitor; owner request 2026-10-22, session log step 16): what
// GET /metrics tells a key holder, in upstream's /metrics shape (serve/server.py metrics()) so
// the page's Monitor tab reads like upstream's. The engine's state and the queue, the last
// requests' token counts and the engine's own timings, and this machine's CPU, RAM and GPU
// readings with a minute of history. Never a prompt, an answer, a client address or a key.
// In memory only and bounded (kMonitorKeptRequests requests, kMonitorHistorySamples samples
// per series); gone when the server stops.

#include "secure_frontend/engine_protocol_client.hpp"
#include "secure_frontend/generation_run.hpp"
#include "secure_frontend/host_readings.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace secure_frontend {

inline constexpr std::size_t kMonitorKeptRequests = 100;
inline constexpr std::size_t kMonitorHistorySamples = 60;  // one a second: a minute

struct HostSample final {
  std::optional<double> cpu_percent{};
  std::optional<MemoryReading> memory{};
  std::optional<GpuReading> gpu{};
  std::string gpu_note{};  // why there is no GPU reading (GpuSampler::note); empty when there is
};

// What the route adds at the moment of each request.
struct MonitorView final {
  std::string_view model;   // the served name
  std::string_view engine;  // the /health literal: starting | ready | generating | failed
  std::size_t queued;       // GenerationGate::waiting()
};

// The finish a generation ended with, as the Monitor names it (upstream's badges):
// stop | length | cancel | disconnect | error.
[[nodiscard]] std::string_view monitor_finish(RunEnd end, RunCancel cancel) noexcept;

class ServeMonitor final : public GenerationMeter {
 public:
  using SteadyNow = std::function<std::chrono::steady_clock::time_point()>;
  using UnixNow = std::function<std::int64_t()>;
  // Empty clocks are the real ones; tests pass their own.
  explicit ServeMonitor(std::size_t kept_requests = kMonitorKeptRequests, SteadyNow steady = {}, UnixNow unix_seconds = {});

  // ChatRoute, around one generation (the gate admits one at a time). A start while another
  // is open ends that one as error first.
  void generation_started(std::size_t prompt_tokens, std::size_t max_tokens, std::size_t context_tokens);
  void generation_ended(std::string_view finish);  // one of monitor_finish's literals
  void on_token(std::size_t generated) override;
  void on_done(const DoneFigures& figures) override;

  // The sampler, once a second.
  void add_host_sample(const HostSample& sample);

  [[nodiscard]] std::string render_json(const MonitorView& view) const;

 private:
  struct Live final {
    std::size_t prompt_tokens{0};
    std::size_t max_tokens{0};
    std::size_t generated{0};
    std::chrono::steady_clock::time_point started{};
    std::optional<std::chrono::steady_clock::time_point> first_token{};
    std::optional<std::chrono::steady_clock::time_point> last_token{};
    std::optional<DoneFigures> figures{};
  };
  struct Finished final {
    std::int64_t time{0};
    std::string_view finish;  // a static literal (monitor_finish)
    std::size_t prompt_tokens{0};
    std::size_t output_tokens{0};
    std::optional<std::size_t> reused{};
    std::optional<double> prompt_ms{};
    std::optional<double> decode_ms{};
    std::optional<double> decode_tok_s{};
    double duration_s{0.0};
  };
  struct Series final {
    std::deque<std::optional<double>> values;
    void push(std::optional<double> value, std::size_t cap);
  };

  void end_locked(std::string_view finish);
  [[nodiscard]] std::optional<double> live_tok_s_locked() const;

  const std::size_t kept_;
  SteadyNow steady_;
  UnixNow unix_;
  const std::int64_t since_;
  mutable std::mutex mutex_;
  std::optional<Live> live_;
  std::deque<Finished> requests_;  // newest first
  std::size_t context_tokens_{0};
  // Totals since start.
  std::size_t total_requests_{0};
  std::size_t total_prompt_tokens_{0};
  std::size_t total_output_tokens_{0};
  std::size_t total_reused_{0};
  double total_prompt_ms_{0.0};
  double total_decode_ms_{0.0};
  // The newest host reading and its history.
  HostSample host_{};
  std::string gpu_name_;  // the last GPU name seen
  Series tok_s_, gpu_util_, gpu_mem_used_, gpu_temp_, gpu_power_, cpu_;
};

}  // namespace secure_frontend

#pragma once

// Model downloads (plan docs/superpowers/plans/2026-10-23-model-downloads.md Task 4): the server
// side of the Models tab's download cards. The server holds no network code: every transfer is
// `strata --config <this config> pull --manifest <m> --trust-manifest sha256:<d> --yes
// --progress-lines`, and a pasted link's lookup `strata ... hf-info <link>`, each a supervised
// child (no shell, fixed argv, closed environment, the Job), read line by line. The manifests are
// made by hf_source (owner rule O4: Hugging Face and .gguf only). After a Qwen download the
// prepare step (upstream's pack tools through tools/secure/prepare_download.py, the owner's D7)
// builds the pack, and a model card is written for the launcher.

#include "secure_frontend/download_catalog.hpp"
#include "secure_frontend/engine_process.hpp"
#include "secure_frontend/hf_source.hpp"
#include "secure_frontend/http_request_handler.hpp"
#include "secure_frontend/request_router.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace secure_frontend {

// One supervised child read line by line (production: EngineStdioProcess).
class LineChild {
 public:
  virtual ~LineChild() = default;
  // The next stdout line, or nullopt on timeout or when the child has ended (then ended() is true).
  [[nodiscard]] virtual std::optional<std::string> next_line(std::chrono::milliseconds timeout) = 0;
  [[nodiscard]] virtual bool ended() = 0;
  [[nodiscard]] virtual int exit_code() = 0;  // after ended()
  virtual void kill() = 0;
};

struct DiskSpace final {
  std::uint64_t free_bytes{0};
  std::uint64_t total_bytes{0};
};

struct DownloadSeams final {
  // Starts a child; nullptr when it could not start.
  std::function<std::unique_ptr<LineChild>(const EngineCommand&)> spawn{};
  std::function<std::optional<DiskSpace>(const std::filesystem::path&)> disk{};
};

// What a prepared Qwen download's card is made of: the engine settings of an existing qwen card.
struct DownloadCardTemplate final {
  std::string engine_executable;               // UTF-8, absolute
  std::vector<std::string> engine_lib_dirs;
  std::optional<std::string> engine_gpu;
};

// The card a prepared download becomes (the launcher adds it).
using CardWriter = std::function<bool(const std::string& name, const std::filesystem::path& card_file)>;

struct DownloadSettings final {
  DownloadCatalog catalog;
  std::filesystem::path strata_executable;     // `strata` beside the server
  std::filesystem::path config_file;           // the server's own config (strata reads it)
  std::filesystem::path downloads_root;        // models.downloads_root (the store)
  std::filesystem::path work_dir;              // <roots.state>/downloads: manifests, links, temp
  std::filesystem::path cards_dir;             // <roots.state>/cards: the cards prepared downloads become
  std::optional<std::filesystem::path> prepare_python;
  std::optional<std::filesystem::path> prepare_tools;   // upstream's tools folder
  std::optional<std::filesystem::path> prepare_script;  // tools/secure/prepare_download.py
  std::optional<DownloadCardTemplate> card_template;
  std::map<std::string, std::string, std::less<>> child_environment;  // the closed environment
  std::uint64_t margin_bytes{std::uint64_t{2} << 30U};                // free space a start leaves
  CardWriter on_card{};                        // a card was written: the launcher loads it
  std::function<void(std::string_view)> log{};
  DownloadSeams seams{};
};

class DownloadManager final {
 public:
  explicit DownloadManager(DownloadSettings settings);
  ~DownloadManager();
  DownloadManager(const DownloadManager&) = delete;
  DownloadManager& operator=(const DownloadManager&) = delete;

  struct Refusal final {
    int status;              // the HTTP status the route answers
    std::string_view code;   // an ApiError code name
  };
  // GET /v1/strata/downloads (the plan's JSON shape).
  [[nodiscard]] std::string list_json();
  // Starts (queues) a catalog or custom card.
  [[nodiscard]] std::optional<Refusal> start(std::string_view id);
  // A pasted link (O3): the lookup through `strata hf-info`; the confirm object, or a refusal and
  // a fixed reason for the page.
  struct LinkAnswer final {
    std::optional<std::string> confirm_json;
    std::optional<Refusal> refusal;
    std::string reason;
  };
  // url is the pasted link; profile matches it to a family this server runs (empty: unmatched, a
  // download-only custom card as before); extra_urls are the other shards of a multipart GGUF (at
  // most five), all pulled to the one location.
  [[nodiscard]] LinkAnswer check_link(std::string_view url, std::string_view profile = {},
                                      const std::vector<std::string>& extra_urls = {});
  // Starts the download a check_link confirmed (the same link, within ten minutes).
  [[nodiscard]] std::optional<Refusal> start_link(std::string_view url);
  // Stops a running, queued or paused download and discards its partial files (409 when none is).
  [[nodiscard]] std::optional<Refusal> cancel(std::string_view id);
  // Stops a running or queued download and keeps its partial files: a later start resumes it.
  [[nodiscard]] std::optional<Refusal> pause(std::string_view id);
  void shutdown();

  // Test seam: wait until nothing is queued or running.
  [[nodiscard]] bool wait_idle(std::chrono::milliseconds timeout);

 private:
  enum class State { available, queued, downloading, verifying, preparing, installed, ready, failed, cancelled, paused };
  struct Card final {
    DownloadEntry entry;
    State state{State::available};
    std::uint64_t bytes{0};
    std::uint64_t total{0};
    std::string error;
    std::string current_file;
    double rate_bps{0.0};
  };
  struct PendingLink final {
    DownloadEntry entry;
    std::chrono::steady_clock::time_point at;
  };
  void run();
  void run_card(std::size_t index);
  [[nodiscard]] bool resolve_main(Card& card, std::string& error);
  [[nodiscard]] bool pull(std::size_t index, const HfDownload& download, std::string& error);
  [[nodiscard]] bool prepare(std::size_t index, const HfDownload& download, std::string& error);
  [[nodiscard]] std::optional<std::string> hf_info(std::string_view url, std::string& error);
  void discard_partials(std::string_view id);
  [[nodiscard]] std::unique_ptr<LineChild> spawn(std::vector<std::string> arguments, const std::filesystem::path& executable);
  [[nodiscard]] std::optional<DiskSpace> disk() const;
  [[nodiscard]] std::uint64_t total_of(const DownloadEntry& entry) const;
  [[nodiscard]] std::optional<std::size_t> find(std::string_view id) const;
  void set_state(std::size_t index, State state, std::string error = {});
  void log(std::string_view line) const;
  [[nodiscard]] static std::string_view state_name(State state) noexcept;
  void load_custom();
  void save_custom();
  void refresh_installed();

  DownloadSettings settings_;
  std::mutex mutex_;
  std::condition_variable changed_;
  std::deque<Card> cards_;                 // stable addresses: cards are only appended
  std::deque<std::size_t> queue_;
  std::optional<std::size_t> active_;
  std::unique_ptr<LineChild>* active_child_{nullptr};
  bool cancel_requested_{false};   // stop the active transfer now (pause or cancel)
  bool pause_requested_{false};    // ... and keep its partial files
  bool stopping_{false};
  std::map<std::string, PendingLink, std::less<>> links_;
  std::thread worker_;
};

// The download routes' answers (kModelDownloadRoutes) over one manager: the plan's JSON
// contract, every refusal an ApiError row.
[[nodiscard]] HttpResponse download_route_answer(DownloadManager& manager, RouteId route, std::string_view body);

// `strata` beside this process's own executable (the server's): the downloads' child. Empty
// when the executable's path cannot be read.
[[nodiscard]] std::filesystem::path strata_beside_this_executable();

// The production seams: EngineStdioProcess children (the Job / process group) and
// std::filesystem::space.
[[nodiscard]] DownloadSeams production_download_seams();

}  // namespace secure_frontend

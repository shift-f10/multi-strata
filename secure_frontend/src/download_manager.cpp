#include "secure_frontend/download_manager.hpp"

#include "secure_frontend/api_errors.hpp"
#include "secure_frontend/canonical_path.hpp"
#include "secure_frontend/config_file.hpp"
#include "secure_frontend/engine_stdio_process.hpp"
#include "secure_frontend/json.hpp"
#include "secure_frontend/model_index_store.hpp"
#include "secure_frontend/sha256.hpp"
#include "secure_frontend/token_store.hpp"

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#endif

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <utility>

namespace secure_frontend {
namespace {

// Every download lands in the store as <id>:download (one tag: a card is one model).
constexpr std::string_view kStoreTag = "download";
constexpr auto kLinkValidFor = std::chrono::minutes(10);
constexpr JsonLimits kChildJsonLimits{.max_bytes = 1U << 20U, .max_depth = 8U, .max_container_entries = 65536U,
                                      .max_string_bytes = 4096U, .allow_fractions = false};

const JsonValue* member(const JsonValue& object, const std::string_view key) {
  const auto* members = object.if_object();
  if (members == nullptr) return nullptr;
  for (const auto& m : *members) {
    if (m.key == key) return &m.value;
  }
  return nullptr;
}

// Decimal GB with one decimal, as the page writes sizes.
std::string decimal_gb(const std::uint64_t bytes) {
  char text[32];
  (void)std::snprintf(text, sizeof text, "%.1f", static_cast<double>(bytes) / 1e9);
  return text;
}

std::string json_text(const std::string_view text) {
  std::string out;
  append_json_string(&out, text);
  return out;
}

std::optional<std::uint64_t> number(const std::string_view text) {
  std::uint64_t value = 0;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || end != text.data() + text.size()) return std::nullopt;
  return value;
}

std::vector<std::string_view> words(const std::string_view line) {
  std::vector<std::string_view> out;
  std::size_t start = 0;
  while (start < line.size()) {
    const auto end = line.find(' ', start);
    out.push_back(line.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start));
    if (end == std::string_view::npos) break;
    start = end + 1U;
  }
  return out;
}

// Owner 2026-10-23: "for custom download from huggingface, the downloads must be matched to a
// current settings we have available like qwen 3.8 flash next, swift, gemma4, qwen3.6 etc." A
// pasted GGUF is matched to one of these families. The qwen ones all run on the qwen engine by its
// own GGUF-direct path (--native, the tokenizer built from the GGUF): for a pasted single GGUF
// there is no iq_pack to download, so they share one recipe and differ only in the context they
// open with. Gemma 4 is a separate engine whose tokenizer the download tools cannot build from a
// bare GGUF (strata_tokenizer.py wants a qwen35 byte-level BPE vocabulary), so it is offered but
// stays download-only until a Gemma tokenizer step exists.
struct CustomProfile final {
  std::string_view key;      // the matched card's family and the page's value
  std::string_view display;  // the page's label
  std::string_view engine;   // "qwen" | "gemma4"
  bool prepares;             // a runnable card is written after the download
  std::uint64_t context_default;
  std::uint64_t context_min;
  std::uint64_t context_max;
};
constexpr std::array<CustomProfile, 7> kCustomProfiles{{
    {"qwen", "Qwen3.8-Flash-Next", "qwen", true, 131072U, 4096U, 1048576U},
    {"unsloth", "Qwen3.8-Flash-Next (Unsloth)", "qwen", true, 131072U, 4096U, 1048576U},
    {"coder", "Qwen3.8-Flash-Next-Coder", "qwen", true, 131072U, 4096U, 1048576U},
    {"gyro", "Qwen3.8-Flash-Next-Gyro", "qwen", true, 131072U, 4096U, 1048576U},
    {"swift", "Swift-1.5", "qwen", true, 131072U, 4096U, 1048576U},
    {"qwen36", "Qwen3.6-35B-A3B", "qwen", true, 32768U, 4096U, 262144U},
    {"gemma4", "Gemma 4", "gemma4", false, 262144U, 4096U, 262144U},
}};
const CustomProfile* custom_profile(const std::string_view key) {
  for (const auto& profile : kCustomProfiles) {
    if (profile.key == key) return &profile;
  }
  return nullptr;
}

// A served name for a card: the display name with every character outside [A-Za-z0-9._-] as '-'.
std::string card_name_for(const DownloadEntry& entry) {
  std::string name;
  for (const char c : entry.name) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    name.push_back(ok ? c : '-');
  }
  while (!name.empty() && (name.front() == '-' || name.front() == '.' || name.front() == '_')) name.erase(name.begin());
  if (name.size() > 64U) name.resize(64U);
  return name.empty() ? entry.id : name;
}

// A custom card's id from its repository and file: lowercase [a-z0-9._-], at most 64.
std::string custom_id(const std::string_view repo, const std::string_view path) {
  std::string base = "hf-" + std::string{repo.substr(repo.find('/') + 1U)} + "-" +
                     std::string{path.substr(path.rfind('/') == std::string_view::npos ? 0 : path.rfind('/') + 1U)};
  std::string id;
  for (char c : base) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    id.push_back(ok ? c : '-');
  }
  if (id.size() > 5U && id.substr(id.size() - 5U) == ".gguf") id.resize(id.size() - 5U);
  if (id.size() > 64U) id.resize(64U);
  return id;
}

class StdioLineChild final : public LineChild {
 public:
  explicit StdioLineChild(std::unique_ptr<EngineStdioProcess> process) : process_(std::move(process)) {}
  ~StdioLineChild() override {
    if (!ended()) (void)process_->terminate(std::chrono::milliseconds(250));
  }
  std::optional<std::string> next_line(const std::chrono::milliseconds timeout) override {
    if (closed_) return std::nullopt;
    auto read = process_->read_line(timeout);
    if (read.kind == EngineReadKind::line) return std::move(read.line);
    if (read.kind == EngineReadKind::closed || read.kind == EngineReadKind::failure) closed_ = true;
    return std::nullopt;
  }
  bool ended() override {
    if (!closed_) return false;
    if (!status_) status_ = process_->try_reap();
    if (!status_ && !process_->running()) status_ = process_->exit_status();
    return status_.has_value() || !process_->running();
  }
  int exit_code() override { return status_ && !status_->signaled ? static_cast<int>(status_->value) : -1; }
  void kill() override {
    (void)process_->terminate(std::chrono::milliseconds(250));
    closed_ = true;
  }

 private:
  std::unique_ptr<EngineStdioProcess> process_;
  bool closed_{false};
  std::optional<ExitStatus> status_;
};

}  // namespace

namespace {

HttpResponse json_answer(const int status, std::string body) {
  return HttpResponse{.status = status, .headers = {{"Content-Type", "application/json; charset=utf-8"}}, .body = std::move(body)};
}

// A manager refusal as its ApiError row (the manager names only rows of the table).
ApiError error_for(const DownloadManager::Refusal& refusal) {
  for (const auto& row : api_error_table()) {
    if (row.code == refusal.code && row.status == refusal.status) return row.error;
  }
  return ApiError::internal_error;
}

HttpResponse refusal_answer(const DownloadManager::Refusal& refusal) { return make_error_response(error_for(refusal)); }

// {"state": "<state>", "id": "<id>"}: what the request did (the list shows how it goes).
HttpResponse accepted(const std::string_view state, const std::string_view id) {
  return json_answer(202, "{\"state\":" + json_text(state) + ",\"id\":" + json_text(id) + "}\n");
}

constexpr JsonLimits kRouteBodyLimits{.max_bytes = kModelControlBodyLimit, .max_depth = 2U, .max_container_entries = 8U,
                                      .max_string_bytes = 2048U, .allow_fractions = false};

}  // namespace

HttpResponse download_route_answer(DownloadManager& manager, const RouteId route, const std::string_view body) {
  if (route == RouteId::strata_downloads) return json_answer(200, manager.list_json());
  if (route != RouteId::strata_download_start && route != RouteId::strata_download_pause && route != RouteId::strata_download_cancel &&
      route != RouteId::strata_download_link) {
    return make_error_response(ApiError::internal_error);
  }
  // {"id": "<card>"} | {"url": "<link>"} | {"url": "<link>", "confirm": true}; the link check also
  // takes {"profile": "<family>"} and {"extra_urls": ["<part>", ...]} (the multipart shards).
  const auto parsed = parse_json(body, kRouteBodyLimits);
  const auto* root = std::get_if<JsonValue>(&parsed);
  if (root == nullptr) return make_error_response(ApiError::invalid_json);
  const auto* members = root->if_object();
  if (members == nullptr) return make_error_response(ApiError::invalid_request);
  const std::string* id = nullptr;
  const std::string* url = nullptr;
  const std::string* profile = nullptr;
  std::vector<std::string> extra_urls;
  bool have_extra = false;
  bool confirm = false;
  for (const auto& item : *members) {
    if (item.key == "id" && item.value.if_string() != nullptr) id = item.value.if_string();
    else if (item.key == "url" && item.value.if_string() != nullptr) url = item.value.if_string();
    else if (item.key == "confirm" && item.value.if_boolean() != nullptr) confirm = *item.value.if_boolean();
    else if (item.key == "profile" && item.value.if_string() != nullptr) profile = item.value.if_string();
    else if (item.key == "extra_urls" && item.value.if_array() != nullptr) {
      have_extra = true;
      for (const auto& part : *item.value.if_array()) {
        if (part.if_string() == nullptr) return make_error_response(ApiError::invalid_request);
        extra_urls.push_back(*part.if_string());
      }
    } else {
      return make_error_response(ApiError::invalid_request);
    }
  }
  // profile and extra_urls belong to the link check only.
  if (route != RouteId::strata_download_link && (profile != nullptr || have_extra)) {
    return make_error_response(ApiError::invalid_request);
  }
  if (route == RouteId::strata_download_link) {
    if (url == nullptr || id != nullptr || confirm) return make_error_response(ApiError::invalid_request);
    const auto checked = manager.check_link(*url, profile != nullptr ? std::string_view{*profile} : std::string_view{}, extra_urls);
    if (checked.confirm_json) return json_answer(200, *checked.confirm_json);
    const auto refusal = checked.refusal.value_or(DownloadManager::Refusal{500, "internal_error"});
    // The fixed reason (O4's rule that refused the link, or what went wrong asking Hugging Face).
    std::string text = render_error_body(error_for(refusal));
    while (!text.empty() && (text.back() == '\n' || text.back() == '}')) text.pop_back();
    text += "}";
    if (!checked.reason.empty()) text += ",\"reason\":" + json_text(checked.reason);
    HttpResponse response = make_error_response(error_for(refusal));
    response.body = text + "}\n";
    return response;
  }
  if (route == RouteId::strata_download_start && url != nullptr) {
    if (id != nullptr || !confirm) return make_error_response(ApiError::invalid_request);  // a link starts once confirmed
    const auto link = parse_hf_link(*url);
    const auto* file = std::get_if<HfFileLink>(&link);
    if (file == nullptr) return make_error_response(ApiError::invalid_request);
    if (const auto refused = manager.start_link(*url)) return refusal_answer(*refused);
    // The card's id is its first shard's (a multipart paste's shards share one card).
    return accepted("queued", custom_id(file->repo, gguf_shard_set(file->path).front()));
  }
  if (id == nullptr || url != nullptr || confirm) return make_error_response(ApiError::invalid_request);
  if (route == RouteId::strata_download_start) {
    if (const auto refused = manager.start(*id)) return refusal_answer(*refused);
    return accepted("queued", *id);
  }
  if (route == RouteId::strata_download_pause) {
    if (const auto refused = manager.pause(*id)) return refusal_answer(*refused);
    return accepted("paused", *id);
  }
  if (const auto refused = manager.cancel(*id)) return refusal_answer(*refused);
  return accepted("cancelled", *id);
}

std::filesystem::path strata_beside_this_executable() {
#if defined(_WIN32)
  std::wstring buffer(32768, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size()) return {};
  buffer.resize(length);
  return std::filesystem::path(buffer).parent_path() / L"strata.exe";
#else
  std::error_code ec;
  const auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
  return ec ? std::filesystem::path{} : self.parent_path() / "strata";
#endif
}

DownloadSeams production_download_seams() {
  DownloadSeams seams;
  seams.spawn = [](const EngineCommand& command) -> std::unique_ptr<LineChild> {
    auto process = std::make_unique<EngineStdioProcess>();
    if (process->start(command)) return nullptr;
    process->close_stdin();
    return std::make_unique<StdioLineChild>(std::move(process));
  };
  seams.disk = [](const std::filesystem::path& path) -> std::optional<DiskSpace> {
    std::error_code ec;
    const auto space = std::filesystem::space(path, ec);
    if (ec) return std::nullopt;
    return DiskSpace{space.available, space.capacity};
  };
  return seams;
}

DownloadManager::DownloadManager(DownloadSettings settings) : settings_(std::move(settings)) {
  if (!settings_.seams.spawn || !settings_.seams.disk) {
    const auto production = production_download_seams();
    if (!settings_.seams.spawn) settings_.seams.spawn = production.spawn;
    if (!settings_.seams.disk) settings_.seams.disk = production.disk;
  }
  for (const auto& entry : settings_.catalog.entries) {
    Card card;
    card.entry = entry;
    card.total = total_of(entry);
    cards_.push_back(std::move(card));
  }
  load_custom();
  refresh_installed();
  worker_ = std::thread([this] { run(); });
}

DownloadManager::~DownloadManager() { shutdown(); }

void DownloadManager::log(const std::string_view line) const {
  if (settings_.log) {
    settings_.log(line);
    return;
  }
  std::cerr << line << '\n' << std::flush;
}

std::string_view DownloadManager::state_name(const State state) noexcept {
  switch (state) {
    case State::available: return "available";
    case State::queued: return "queued";
    case State::downloading: return "downloading";
    case State::verifying: return "verifying";
    case State::preparing: return "preparing";
    case State::installed: return "installed";
    case State::ready: return "ready";
    case State::failed: return "failed";
    case State::cancelled: return "cancelled";
    case State::paused: return "paused";
  }
  return "available";
}

std::uint64_t DownloadManager::total_of(const DownloadEntry& entry) const {
  std::uint64_t total = 0;
  for (const auto& file : entry.files) total += file.size.value_or(0);
  return total;
}

std::optional<DiskSpace> DownloadManager::disk() const {
  return settings_.seams.disk(settings_.downloads_root);
}

std::optional<std::size_t> DownloadManager::find(const std::string_view id) const {
  for (std::size_t i = 0; i < cards_.size(); ++i) {
    if (cards_[i].entry.id == id) return i;
  }
  return std::nullopt;
}

void DownloadManager::set_state(const std::size_t index, const State state, std::string error) {
  {
    std::lock_guard lock(mutex_);
    cards_[index].state = state;
    cards_[index].error = std::move(error);
  }
  changed_.notify_all();
}

// The store says which downloads are installed; the cards folder which became cards.
void DownloadManager::refresh_installed() {
  auto root = open_root(settings_.downloads_root);
  std::optional<ModelIndex> index;
  if (const auto* opened = std::get_if<CanonicalRoot>(&root)) {
    auto read = read_model_index(*opened);
    if (auto* found = std::get_if<ModelIndex>(&read)) index = std::move(*found);
  }
  std::lock_guard lock(mutex_);
  for (auto& card : cards_) {
    std::error_code ec;
    if (std::filesystem::exists(settings_.cards_dir / (card.entry.id + ".json"), ec)) {
      card.state = State::ready;
      card.bytes = card.total;
      continue;
    }
    if (!index) continue;
    const auto installed = find_installed(*index, ModelReference{card.entry.id, std::string{kStoreTag}});
    if (std::holds_alternative<IndexEntry>(installed)) {
      card.state = State::installed;
      card.bytes = card.total;
    }
  }
}

void DownloadManager::load_custom() {
  std::ifstream in(settings_.work_dir / "custom.json", std::ios::binary);
  if (!in) return;
  std::ostringstream text;
  text << in.rdbuf();
  auto catalog = parse_download_catalog(text.str());
  for (auto& entry : catalog.entries) {
    if (find(entry.id)) continue;
    entry.source = "custom";
    Card card;
    card.entry = std::move(entry);
    card.total = total_of(card.entry);
    cards_.push_back(std::move(card));
  }
}

// custom.json in the catalog's own format, so the same reader (and its rules) reads it back.
void DownloadManager::save_custom() {
  std::string text = "{\"schema_version\":1,\"models\":[";
  bool first = true;
  for (const auto& card : cards_) {
    if (card.entry.source != "custom") continue;
    const auto& e = card.entry;
    text += first ? "" : ",";
    first = false;
    text += "{\"id\":" + json_text(e.id) + ",\"name\":" + json_text(e.name) + ",\"source\":\"custom\",\"family\":" + json_text(e.family) +
            ",\"engine\":" + json_text(e.engine) + ",\"about\":" + json_text(e.about) + ",\"repo\":" + json_text(e.repo) + ",\"revision\":" + json_text(e.revision) +
            ",\"prepare\":" + json_text(e.prepare) + ",\"files\":[";
    for (std::size_t i = 0; i < e.files.size(); ++i) {
      text += (i ? "," : "") + std::string{"{\"path\":"} + json_text(e.files[i].path) + ",\"size\":" +
              std::to_string(e.files[i].size.value_or(0)) + ",\"sha256\":" + json_text(e.files[i].sha256) + "}";
    }
    text += "]}";
  }
  text += "]}\n";
  auto root = open_root(settings_.work_dir);
  const auto name = parse_relative_path("custom.json");
  if (std::holds_alternative<CanonicalRoot>(root) && std::holds_alternative<RelativePath>(name)) {
    (void)write_private_file(std::get<CanonicalRoot>(root), std::get<RelativePath>(name), text, TokenStoreMode::replace);
  }
}

std::string DownloadManager::list_json() {
  const auto space = disk();
  std::lock_guard lock(mutex_);
  std::string out = "{\"object\":\"list\",\"disk\":{\"root\":";
  std::string root_label = settings_.downloads_root.root_name().string();
  if (root_label.empty()) root_label = settings_.downloads_root.root_path().string();
  out += json_text(root_label) + ",\"free_bytes\":" + std::to_string(space ? space->free_bytes : 0) +
         ",\"total_bytes\":" + std::to_string(space ? space->total_bytes : 0) + "},\"active\":";
  if (active_) {
    const auto& card = cards_[*active_];
    out += "{\"id\":" + json_text(card.entry.id) + ",\"file\":" + json_text(card.current_file) + ",\"bytes\":" + std::to_string(card.bytes) +
           ",\"total\":" + std::to_string(card.total) + ",\"rate_bps\":" + std::to_string(static_cast<std::uint64_t>(card.rate_bps)) +
           ",\"eta_s\":" +
           std::to_string(card.rate_bps > 1.0 && card.total > card.bytes
                              ? static_cast<std::uint64_t>(static_cast<double>(card.total - card.bytes) / card.rate_bps)
                              : 0U) +
           "}";
  } else {
    out += "null";
  }
  out += ",\"data\":[";
  for (std::size_t i = 0; i < cards_.size(); ++i) {
    const auto& card = cards_[i];
    const auto& e = card.entry;
    const std::uint64_t remaining = card.total > card.bytes ? card.total - card.bytes : 0U;
    const std::uint64_t needed = remaining + settings_.margin_bytes;
    const bool fits = !space || space->free_bytes >= needed || card.state == State::ready || card.state == State::installed;
    // Qwen3.6-35B-A3B (OWN_PATH) and a profile-matched custom paste both read the GGUF itself, so no
    // iq_pack - only the tokenizer is prepared, then a card is written (prepare is "none" but it runs).
    // A matched custom paste carries its profile as its family; an unmatched one stays "custom".
    const bool matched_custom = e.source == "custom" && e.family != "custom";
    const bool gguf_direct = e.engine == "qwen" && (e.family == "qwen36" || matched_custom);
    const bool qwen_ready = e.engine == "qwen" && (e.prepare == "iq_pack" || gguf_direct) && settings_.prepare_python &&
                            settings_.prepare_tools && settings_.prepare_script && settings_.card_template;
    std::string note;
    if (e.engine == "glm53") note = "download only: the GLM-5.3 engine is not built here yet";
    else if (matched_custom && e.engine != "qwen")
      note = "download only: the Gemma engine needs a tokenizer pack that is not built from a pasted GGUF yet";
    else if (e.source == "custom" && e.family == "custom")
      note = "download only: pick the model family it matches (its Download button) so a card can be made";
    else if (!qwen_ready) note = "download only: the prepare step is not configured (models.prepare_python, models.prepare_tools)";
    else if (gguf_direct) note = "after the download its tokenizer is prepared (a few seconds) and a card appears in Models";
    else note = "after the download the pack is built (a few minutes) and a card appears in Models";
    out += i != 0U ? "," : "";
    out += "{\"id\":" + json_text(e.id) + ",\"name\":" + json_text(e.name) + ",\"source\":" + json_text(e.source) + ",\"family\":" +
           json_text(e.family) + ",\"about\":" + json_text(e.about) + ",\"repo\":" + json_text(e.repo) + ",\"size_bytes\":" +
           std::to_string(card.total) + ",\"files\":" + std::to_string(e.files.size()) + ",\"state\":" + json_text(state_name(card.state)) +
           ",\"bytes\":" + std::to_string(card.bytes) + ",\"total\":" + std::to_string(card.total) + ",\"error\":" +
           (card.error.empty() ? std::string{"null"} : json_text(card.error)) + ",\"needed_bytes\":" + std::to_string(needed) +
           ",\"fits\":" + (fits ? "true" : "false") + ",\"runnable\":" + (qwen_ready ? "true" : "false") + ",\"note\":" + json_text(note) +
           "}";
  }
  // The families a pasted GGUF can be matched to (the page's profile picker). "runnable" is whether
  // a card is written after the download; Gemma 4 is listed but stays download-only (no tokenizer).
  out += "],\"profiles\":[";
  for (std::size_t i = 0; i < kCustomProfiles.size(); ++i) {
    const auto& p = kCustomProfiles[i];
    out += (i != 0U ? "," : "") + std::string{"{\"key\":"} + json_text(p.key) + ",\"display\":" + json_text(p.display) +
           ",\"engine\":" + json_text(p.engine) + ",\"runnable\":" + (p.prepares ? "true" : "false") + "}";
  }
  out += "]}\n";
  return out;
}

std::optional<DownloadManager::Refusal> DownloadManager::start(const std::string_view id) {
  const auto space = disk();
  {
    std::lock_guard lock(mutex_);
    if (stopping_) return Refusal{503, "server_shutting_down"};
    const auto index = find(id);
    if (!index) return Refusal{404, "model_not_found"};
    auto& card = cards_[*index];
    if (card.state == State::queued || card.state == State::downloading || card.state == State::verifying ||
        card.state == State::preparing) {
      return Refusal{409, "download_in_progress"};
    }
    if (card.state == State::ready) return Refusal{409, "download_in_progress"};
    // O2: the missing bytes and the margin must fit on the store's drive (Maya's sizes are known
    // only at start; the pull checks the space again while it writes).
    const std::uint64_t remaining = card.total > card.bytes ? card.total - card.bytes : 0U;
    if (space && space->free_bytes < remaining + settings_.margin_bytes) return Refusal{507, "insufficient_storage"};
    card.state = State::queued;
    card.error.clear();
    queue_.push_back(*index);
  }
  log("[strata] downloads: queued " + std::string{id});
  changed_.notify_all();
  return std::nullopt;
}

std::optional<DownloadManager::Refusal> DownloadManager::cancel(const std::string_view id) {
  bool discard = false;
  {
    std::lock_guard lock(mutex_);
    const auto index = find(id);
    if (!index) return Refusal{404, "model_not_found"};
    const auto queued = std::find(queue_.begin(), queue_.end(), *index);
    if (queued != queue_.end() || cards_[*index].state == State::paused) {
      if (queued != queue_.end()) queue_.erase(queued);
      cards_[*index].state = State::cancelled;
      cards_[*index].bytes = 0;
      discard = true;
    } else if (active_ == index && cards_[*index].state != State::preparing) {
      cancel_requested_ = true;
      pause_requested_ = false;
    } else {
      return Refusal{409, "download_not_active"};  // nothing running, queued or paused to cancel
    }
  }
  log("[strata] downloads: cancel " + std::string{id});
  if (discard) discard_partials(id);
  changed_.notify_all();
  return std::nullopt;
}

DownloadManager::LinkAnswer DownloadManager::check_link(const std::string_view url, const std::string_view profile,
                                                        const std::vector<std::string>& extra_urls) {
  // Owner 2026-10-23: a pasted GGUF is matched to a family (profile) so a runnable card can be made,
  // and a multipart GGUF's other shards are pasted too (at most five more), all to the one location.
  const CustomProfile* matched = profile.empty() ? nullptr : custom_profile(profile);
  if (!profile.empty() && matched == nullptr) {
    return LinkAnswer{std::nullopt, Refusal{400, "invalid_request"}, "That model family is not one this server runs."};
  }
  if (extra_urls.size() > 5U) {
    return LinkAnswer{std::nullopt, Refusal{400, "invalid_request"}, "At most five more part links can be added."};
  }
  // The primary link names the shard set (a single GGUF is a set of one).
  const auto parsed_primary = parse_hf_link(url);
  if (const auto* why = std::get_if<std::string_view>(&parsed_primary)) {
    return LinkAnswer{std::nullopt, Refusal{400, "invalid_request"}, std::string{*why}};
  }
  const auto& primary_link = std::get<HfFileLink>(parsed_primary);
  const auto shard_names = gguf_shard_set(primary_link.path);

  // Resolve one pasted link through `strata hf-info`: its repo, commit and .gguf file(s).
  struct Resolved final {
    std::string repo;
    std::string commit;
    std::vector<CatalogFile> files;
  };
  std::string reason;
  int fail_status = 400;
  const auto resolve = [this, &reason, &fail_status](const std::string_view link_url) -> std::optional<Resolved> {
    const auto parsed = parse_hf_link(link_url);
    if (const auto* why = std::get_if<std::string_view>(&parsed)) {
      reason = std::string{*why};
      fail_status = 400;
      return std::nullopt;
    }
    std::string error;
    const auto answer = hf_info(link_url, error);
    if (!answer) {
      reason = error;
      fail_status = 502;
      return std::nullopt;
    }
    const auto json = parse_json(*answer, kChildJsonLimits);
    const auto* root = std::get_if<JsonValue>(&json);
    const auto* commit = root ? member(*root, "commit") : nullptr;
    const auto* repo = root ? member(*root, "repo") : nullptr;
    const auto* files = root ? member(*root, "files") : nullptr;
    if (commit == nullptr || commit->if_string() == nullptr || !is_hf_commit(*commit->if_string()) || repo == nullptr ||
        repo->if_string() == nullptr || files == nullptr || files->if_array() == nullptr || files->if_array()->empty()) {
      reason = "Hugging Face answered in an unexpected shape.";
      fail_status = 502;
      return std::nullopt;
    }
    Resolved out;
    out.repo = *repo->if_string();
    out.commit = *commit->if_string();
    for (const auto& item : *files->if_array()) {
      const auto* path = member(item, "path");
      const auto* size = member(item, "size");
      const auto* sha = member(item, "sha256");
      if (path == nullptr || path->if_string() == nullptr || !is_hf_gguf_path(*path->if_string()) || size == nullptr ||
          size->if_integer() == nullptr || *size->if_integer() <= 0 || sha == nullptr || sha->if_string() == nullptr) {
        reason = "Hugging Face answered in an unexpected shape.";
        fail_status = 502;
        return std::nullopt;
      }
      out.files.push_back(CatalogFile{*path->if_string(), static_cast<std::uint64_t>(*size->if_integer()), *sha->if_string()});
    }
    return out;
  };
  const auto refuse = [&reason, &fail_status]() {
    return LinkAnswer{std::nullopt, Refusal{fail_status, fail_status == 400 ? "invalid_request" : "upstream_unavailable"}, reason};
  };

  const auto primary = resolve(url);
  if (!primary) return refuse();
  // Every provided file is placed at its position in the shard set; parts share repo and revision.
  std::map<std::size_t, CatalogFile> parts;
  const auto place = [&](const Resolved& r) -> std::optional<std::string> {
    if (r.repo != primary->repo || r.commit != primary->commit) {
      return std::string{"Every part must be from the same repository and revision."};
    }
    for (const auto& file : r.files) {
      const auto at = std::find(shard_names.begin(), shard_names.end(), file.path);
      if (at == shard_names.end()) return "That link is not a shard of this model (" + file.path + ").";
      const auto index = static_cast<std::size_t>(at - shard_names.begin());
      if (parts.count(index) != 0U) return "The same part was pasted twice (" + file.path + ").";
      parts.emplace(index, file);
    }
    return std::nullopt;
  };
  if (const auto err = place(*primary)) return LinkAnswer{std::nullopt, Refusal{400, "invalid_request"}, *err};
  for (const auto& extra : extra_urls) {
    const auto resolved = resolve(extra);
    if (!resolved) return refuse();
    if (const auto err = place(*resolved)) return LinkAnswer{std::nullopt, Refusal{400, "invalid_request"}, *err};
  }

  const std::string& first_shard = shard_names.front();
  DownloadEntry entry;
  entry.id = custom_id(primary->repo, first_shard);
  const auto slash = first_shard.rfind('/');
  entry.name = std::string{primary->repo.substr(primary->repo.find('/') + 1U)} + " " +
               first_shard.substr(slash == std::string::npos ? 0 : slash + 1U);
  if (entry.name.size() > 128U) entry.name.resize(128U);
  entry.source = "custom";
  entry.family = matched ? std::string{matched->key} : std::string{"custom"};
  entry.engine = matched ? std::string{matched->engine} : std::string{"qwen"};
  entry.prepare = "none";
  entry.about = "Pasted link: " + primary->repo + (matched ? " (matched to " + std::string{matched->display} + ")" : std::string{});
  entry.repo = primary->repo;
  entry.revision = primary->commit;
  for (const auto& [index, file] : parts) entry.files.push_back(file);  // shard order (map is sorted)

  const std::size_t parts_total = shard_names.size();
  const std::size_t parts_have = parts.size();
  const bool complete = parts_have == parts_total;
  const std::uint64_t total = total_of(entry);
  const auto space = disk();
  const std::uint64_t needed = total + settings_.margin_bytes;
  std::string confirm = "{\"confirm\":{\"id\":" + json_text(entry.id) + ",\"name\":" + json_text(entry.name) + ",\"repo\":" +
                        json_text(entry.repo) + ",\"commit\":" + json_text(entry.revision) + ",\"family\":" + json_text(entry.family) +
                        ",\"engine\":" + json_text(entry.engine) + ",\"runnable\":" + ((matched && matched->prepares) ? "true" : "false") +
                        ",\"multipart\":{\"parts\":" + std::to_string(parts_total) + ",\"have\":" + std::to_string(parts_have) +
                        ",\"complete\":" + (complete ? "true" : "false") + ",\"missing\":[";
  bool first_missing = true;
  for (std::size_t k = 0; k < shard_names.size(); ++k) {
    if (parts.count(k) != 0U) continue;
    confirm += (first_missing ? "" : ",") + json_text(shard_names[k]);
    first_missing = false;
  }
  confirm += "]},\"files\":[";
  for (std::size_t i = 0; i < entry.files.size(); ++i) {
    confirm += (i ? "," : "") + std::string{"{\"path\":"} + json_text(entry.files[i].path) + ",\"size\":" +
               std::to_string(entry.files[i].size.value_or(0)) + ",\"sha256\":" + json_text(entry.files[i].sha256) + "}";
  }
  confirm += "],\"size_bytes\":" + std::to_string(total) + ",\"needed_bytes\":" + std::to_string(needed) +
             ",\"fits\":" + (!space || space->free_bytes >= needed ? "true" : "false") + "}}\n";
  {
    std::lock_guard lock(mutex_);
    links_[std::string{url}] = PendingLink{std::move(entry), std::chrono::steady_clock::now()};
  }
  return LinkAnswer{confirm, std::nullopt, {}};
}

std::optional<DownloadManager::Refusal> DownloadManager::start_link(const std::string_view url) {
  std::string id;
  {
    std::lock_guard lock(mutex_);
    const auto found = links_.find(url);
    if (found == links_.end() || std::chrono::steady_clock::now() - found->second.at > kLinkValidFor) {
      return Refusal{400, "invalid_request"};  // check the link first (its confirmation expired or never happened)
    }
    DownloadEntry entry = found->second.entry;
    // A multipart paste starts only once every shard has been pasted (the set derived from any one
    // shard names them all); otherwise the download could never complete.
    if (!entry.files.empty() && gguf_shard_set(entry.files.front().path).size() != entry.files.size()) {
      return Refusal{400, "invalid_request"};
    }
    links_.erase(found);
    id = entry.id;
    if (const auto existing = find(id)) {
      cards_[*existing].entry = std::move(entry);
      cards_[*existing].total = total_of(cards_[*existing].entry);
    } else {
      Card card;
      card.entry = std::move(entry);
      card.total = total_of(card.entry);
      cards_.push_back(std::move(card));
    }
    save_custom();
  }
  return start(id);
}

// Owner: "Have a download pause and resume functionality". A pause keeps the partial files
// (SP4's pull resumes from them on the next start of the same manifest); a queued card simply
// leaves the queue.
std::optional<DownloadManager::Refusal> DownloadManager::pause(const std::string_view id) {
  {
    std::lock_guard lock(mutex_);
    const auto index = find(id);
    if (!index) return Refusal{404, "model_not_found"};
    const auto queued = std::find(queue_.begin(), queue_.end(), *index);
    if (queued != queue_.end()) {
      queue_.erase(queued);
      cards_[*index].state = State::paused;
    } else if (active_ == index && cards_[*index].state != State::preparing) {
      cancel_requested_ = true;
      pause_requested_ = true;
    } else {
      return Refusal{409, "download_not_active"};  // nothing running or queued to pause
    }
  }
  log("[strata] downloads: pause " + std::string{id});
  changed_.notify_all();
  return std::nullopt;
}

// `strata rm --partials <id>:download`: the staged partial files of a cancelled download.
void DownloadManager::discard_partials(const std::string_view id) {
  auto child = spawn({"--config", path_to_utf8(settings_.config_file), "rm", "--partials", std::string{id} + ":" + std::string{kStoreTag}},
                     settings_.strata_executable);
  if (!child) return;
  const auto until = std::chrono::steady_clock::now() + std::chrono::minutes(1);
  while (std::chrono::steady_clock::now() < until) {
    if (!child->next_line(std::chrono::milliseconds(100)) && child->ended()) return;
  }
  child->kill();
}

void DownloadManager::shutdown() {
  {
    std::lock_guard lock(mutex_);
    stopping_ = true;
    cancel_requested_ = true;
  }
  changed_.notify_all();
  if (worker_.joinable()) worker_.join();
}

bool DownloadManager::wait_idle(const std::chrono::milliseconds timeout) {
  std::unique_lock lock(mutex_);
  return changed_.wait_for(lock, timeout, [this] { return queue_.empty() && !active_; });
}

void DownloadManager::run() {
  for (;;) {
    std::size_t index = 0;
    {
      std::unique_lock lock(mutex_);
      changed_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
      if (stopping_) return;
      index = queue_.front();
      queue_.pop_front();
      active_ = index;
      cancel_requested_ = false;
      pause_requested_ = false;
    }
    run_card(index);
    {
      std::lock_guard lock(mutex_);
      active_.reset();
    }
    changed_.notify_all();
  }
}

std::unique_ptr<LineChild> DownloadManager::spawn(std::vector<std::string> arguments, const std::filesystem::path& executable) {
  EngineCommand command;
  command.executable = executable;
  command.arguments = std::move(arguments);
  command.environment = settings_.child_environment;
  command.working_directory = settings_.work_dir;
  command.no_new_privileges = true;
  command.insert_serve = false;
  return settings_.seams.spawn(command);
}

std::optional<std::string> DownloadManager::hf_info(const std::string_view url, std::string& error) {
  auto child = spawn({"--config", path_to_utf8(settings_.config_file), "hf-info", std::string{url}}, settings_.strata_executable);
  if (!child) {
    error = "The downloader could not start.";
    return std::nullopt;
  }
  std::optional<std::string> answer;
  std::string code;
  const auto until = std::chrono::steady_clock::now() + std::chrono::minutes(2);
  while (std::chrono::steady_clock::now() < until) {
    auto line = child->next_line(std::chrono::milliseconds(200));
    if (line) {
      if (line->rfind("ERROR ", 0) == 0) code = line->substr(6);
      else if (!line->empty() && line->front() == '{') answer = std::move(*line);
      continue;
    }
    if (child->ended()) break;
  }
  if (!child->ended()) child->kill();
  if (answer) return answer;
  error = code == "link_refused"       ? "The link is not a Hugging Face .gguf file."
          : code == "file_not_found"   ? "The file (or one of its shards) is not at that revision."
          : code == "not_lfs"          ? "The file has no size and SHA-256 on Hugging Face."
          : code.empty()               ? "Hugging Face could not be reached."
                                       : "Hugging Face could not be reached or answered unexpectedly (" + code + ").";
  return std::nullopt;
}

// Maya's entries name "main" and pin each shard's SHA-256: ask Hugging Face for the commit and the
// sizes, and go on only when every reported SHA-256 is the pinned one.
bool DownloadManager::resolve_main(Card& card, std::string& error) {
  const std::string url = "https://huggingface.co/" + card.entry.repo + "/resolve/main/" + card.entry.files.front().path;
  const auto answer = hf_info(url, error);
  if (!answer) return false;
  const auto json = parse_json(*answer, kChildJsonLimits);
  const auto* root = std::get_if<JsonValue>(&json);
  const auto* commit = root ? member(*root, "commit") : nullptr;
  const auto* files = root ? member(*root, "files") : nullptr;
  if (commit == nullptr || commit->if_string() == nullptr || files == nullptr || files->if_array() == nullptr) {
    error = "Hugging Face answered in an unexpected shape.";
    return false;
  }
  for (auto& pinned : card.entry.files) {
    bool matched = false;
    for (const auto& item : *files->if_array()) {
      const auto* path = member(item, "path");
      const auto* size = member(item, "size");
      const auto* sha = member(item, "sha256");
      if (path == nullptr || path->if_string() == nullptr || *path->if_string() != pinned.path) continue;
      if (sha == nullptr || sha->if_string() == nullptr || *sha->if_string() != pinned.sha256 || size == nullptr ||
          size->if_integer() == nullptr || *size->if_integer() <= 0) {
        error = "The files on Hugging Face no longer match the pinned SHA-256; the download was not started.";
        return false;
      }
      pinned.size = static_cast<std::uint64_t>(*size->if_integer());
      matched = true;
    }
    if (!matched) {
      error = "A pinned file is not on Hugging Face's main revision.";
      return false;
    }
  }
  card.entry.revision = *commit->if_string();
  return true;
}

void DownloadManager::run_card(const std::size_t index) {
  Card card;
  {
    std::lock_guard lock(mutex_);
    card = cards_[index];
  }
  std::string error;
  if (card.entry.revision == "main") {
    if (!resolve_main(card, error)) {
      set_state(index, State::failed, error);
      log("[strata] downloads: " + card.entry.id + " failed: " + error);
      return;
    }
    std::uint64_t remaining = 0;
    {
      std::lock_guard lock(mutex_);
      cards_[index].entry.files = card.entry.files;
      cards_[index].entry.revision = card.entry.revision;  // a resume pulls this commit: the same partial files
      cards_[index].total = total_of(card.entry);
      remaining = cards_[index].total > cards_[index].bytes ? cards_[index].total - cards_[index].bytes : 0U;
    }
    // O2: the sizes are known only now, so the free space is checked again before any pull.
    if (const auto space = disk(); space && space->free_bytes < remaining + settings_.margin_bytes) {
      error = "Insufficient disk space on the data drive for this download: " + decimal_gb(remaining + settings_.margin_bytes) +
              " GB needed, " + decimal_gb(space->free_bytes) + " GB free";
      set_state(index, State::failed, error);
      log("[strata] downloads: " + card.entry.id + " failed: " + error);
      return;
    }
  }
  HfDownload download;
  download.name = card.entry.id;
  download.tag = std::string{kStoreTag};
  download.profile = card.entry.engine == "glm53" ? "glm53" : "gguf";
  download.repo = card.entry.repo;
  download.commit = card.entry.revision;
  download.license_url = "https://huggingface.co/" + card.entry.repo;
  for (const auto& file : card.entry.files) download.files.push_back(HfFile{file.path, file.size.value_or(0), file.sha256, false});
  if (!pull(index, download, error)) {
    bool stopped = false;
    bool paused = false;
    {
      std::lock_guard lock(mutex_);
      stopped = cancel_requested_;
      paused = pause_requested_;
    }
    if (stopped && paused) {
      set_state(index, State::paused);
      log("[strata] downloads: " + card.entry.id + " paused (the partial files are kept)");
      return;
    }
    if (stopped) {
      discard_partials(card.entry.id);
      {
        std::lock_guard lock(mutex_);
        cards_[index].bytes = 0;
      }
      set_state(index, State::cancelled);
      log("[strata] downloads: " + card.entry.id + " cancelled (the partial files are discarded)");
      return;
    }
    set_state(index, State::failed, error);
    log("[strata] downloads: " + card.entry.id + " failed: " + error);
    return;
  }
  log("[strata] downloads: " + card.entry.id + " installed");
  // A qwen card prepares when it has a pack to build (iq_pack), is Qwen3.6, or is a profile-matched
  // custom paste (all GGUF-direct); a custom paste never has an iq_pack.
  const bool can_prepare = card.entry.engine == "qwen" &&
                           (card.entry.prepare == "iq_pack" || card.entry.family == "qwen36" ||
                            (card.entry.source == "custom" && card.entry.family != "custom")) &&
                           settings_.prepare_python && settings_.prepare_tools && settings_.prepare_script && settings_.card_template;
  if (!can_prepare) {
    set_state(index, State::installed);
    return;
  }
  set_state(index, State::preparing);
  if (!prepare(index, download, error)) {
    set_state(index, State::failed, "the download is installed, but preparing it failed: " + error);
    log("[strata] downloads: " + card.entry.id + " prepare failed: " + error);
    return;
  }
  set_state(index, State::ready);
  log("[strata] downloads: " + card.entry.id + " is ready (a model card was added)");
}

bool DownloadManager::pull(const std::size_t index, const HfDownload& download, std::string& error) {
  const auto manifest = hf_manifest_json(download, "2026.10.23.1");
  if (const auto* reason = std::get_if<std::string_view>(&manifest)) {
    error = std::string{"the download could not be described: "} + std::string{*reason};
    return false;
  }
  const std::string& text = std::get<std::string>(manifest);
  const std::string digest = to_hex(sha256(text));
  const std::string file_name = download.name + ".manifest.json";
  auto root = open_root(settings_.work_dir);
  const auto relative = parse_relative_path(file_name);
  if (!std::holds_alternative<CanonicalRoot>(root) || !std::holds_alternative<RelativePath>(relative) ||
      write_private_file(std::get<CanonicalRoot>(root), std::get<RelativePath>(relative), text, TokenStoreMode::replace)) {
    error = "the download's manifest could not be written";
    return false;
  }
  set_state(index, State::downloading);
  auto child = spawn({"--config", path_to_utf8(settings_.config_file), "pull", "--manifest", path_to_utf8(settings_.work_dir / file_name),
                      "--trust-manifest", "sha256:" + digest, "--yes", "--progress-lines"},
                     settings_.strata_executable);
  if (!child) {
    error = "the downloader could not start";
    return false;
  }
  std::map<std::string, std::uint64_t, std::less<>> sizes;
  std::uint64_t finished = 0;
  std::string result;
  auto last_at = std::chrono::steady_clock::now();
  std::uint64_t last_bytes = 0;  // a resume's rate counts from the bytes it kept
  {
    std::lock_guard lock(mutex_);
    last_bytes = cards_[index].bytes;
  }
  for (;;) {
    {
      std::lock_guard lock(mutex_);
      if (cancel_requested_) {
        child->kill();
        error = "cancelled";
        return false;
      }
    }
    auto line = child->next_line(std::chrono::milliseconds(200));
    if (!line) {
      if (child->ended()) break;
      continue;
    }
    const auto w = words(*line);
    if (w.empty()) continue;
    if (w[0] == "FILE" && w.size() == 3U) {
      if (const auto size = number(w[2])) sizes[std::string{w[1]}] = *size;
      std::lock_guard lock(mutex_);
      cards_[index].current_file = std::string{w[1]};
      cards_[index].state = State::downloading;
    } else if (w[0] == "BYTES" && w.size() == 4U) {
      const auto done = number(w[2]);
      const auto total = number(w[3]);
      if (!done || !total) continue;
      const auto now = std::chrono::steady_clock::now();
      std::lock_guard lock(mutex_);
      auto& c = cards_[index];
      c.bytes = finished + *done;
      const double seconds = std::chrono::duration<double>(now - last_at).count();
      if (seconds >= 1.0) {
        c.rate_bps = c.bytes > last_bytes ? static_cast<double>(c.bytes - last_bytes) / seconds : 0.0;
        last_at = now;
        last_bytes = c.bytes;
      }
      c.state = *done == *total ? State::verifying : State::downloading;
    } else if (w[0] == "FINISHED" && w.size() == 3U) {
      if (w[2] == "ok") {
        const auto size = sizes.find(w[1]);
        finished += size == sizes.end() ? 0U : size->second;
        std::lock_guard lock(mutex_);
        cards_[index].bytes = finished;
      }
    } else if (w[0] == "RESULT" && w.size() == 2U) {
      result = std::string{w[1]};
    }
  }
  if (result == "ok" && child->exit_code() == 0) {
    std::lock_guard lock(mutex_);
    cards_[index].bytes = cards_[index].total;
    cards_[index].rate_bps = 0.0;
    return true;
  }
  error = result == "disk_space"            ? "insufficient disk space on the data drive"
          : result == "digest_mismatch"     ? "a file did not match its SHA-256 (it was deleted)"
          : result.empty()                  ? "the downloader ended unexpectedly"
                                            : "the download failed (" + result + ")";
  return false;
}

bool DownloadManager::prepare(const std::size_t index, const HfDownload& download, std::string& error) {
  DownloadEntry entry;
  {
    std::lock_guard lock(mutex_);
    entry = cards_[index].entry;
  }
  // The installed version directory (the store's own index).
  auto root = open_root(settings_.downloads_root);
  if (!std::holds_alternative<CanonicalRoot>(root)) {
    error = "the model store cannot be opened";
    return false;
  }
  auto read = read_model_index(std::get<CanonicalRoot>(root));
  const auto* index_file = std::get_if<ModelIndex>(&read);
  const auto installed = index_file ? find_installed(*index_file, ModelReference{download.name, download.tag})
                                    : std::variant<IndexEntry, AcquireError>{AcquireError{AcquireReason::model_unknown, ""}};
  const auto* found = std::get_if<IndexEntry>(&installed);
  if (found == nullptr) {
    error = "the installed download is not in the store's index";
    return false;
  }
  const std::filesystem::path version = settings_.downloads_root / download.name / download.tag / found->dir;
  const std::string first = gguf_shard_set(entry.files.front().path).front();
  const std::filesystem::path shard = version / path_from_utf8(first);
  const std::filesystem::path pack = settings_.downloads_root / "packs" / entry.id;
  // Qwen3.6 and a profile-matched custom paste are GGUF-direct: tokenizer only, the engine reads the
  // GGUF itself (--native). A custom paste never has an iq_pack, so any custom qwen card is direct.
  const bool gguf_direct = entry.engine == "qwen" && (entry.family == "qwen36" || entry.source == "custom");
  std::vector<std::string> args{"-I", path_to_utf8(*settings_.prepare_script), "--gguf", path_to_utf8(shard), "--out", path_to_utf8(pack),
                                "--tools", path_to_utf8(*settings_.prepare_tools)};
  if (gguf_direct) args.emplace_back("--tokenizer-only");
  else for (const auto& arg : entry.pack_args) args.push_back("--pack-arg=" + arg);
  auto child = spawn(std::move(args), *settings_.prepare_python);
  if (!child) {
    error = "the prepare step could not start";
    return false;
  }
  std::string last;
  const auto until = std::chrono::steady_clock::now() + std::chrono::hours(2);
  while (std::chrono::steady_clock::now() < until) {
    {
      std::lock_guard lock(mutex_);
      if (stopping_) {
        child->kill();
        error = "the server is stopping";
        return false;
      }
    }
    auto line = child->next_line(std::chrono::milliseconds(500));
    if (line) {
      last = *line;
      continue;
    }
    if (child->ended()) break;
  }
  if (last != "DONE" || child->exit_code() != 0) {
    error = last.rfind("ERROR ", 0) == 0 ? "the pack tools said " + last.substr(6) : "the pack tools ended without finishing";
    return false;
  }
  // prepared.json: the pack, its tokenizer and the PLE table's shard.
  std::ifstream in(pack / "prepared.json", std::ios::binary);
  std::ostringstream text;
  text << in.rdbuf();
  const auto parsed = parse_json(text.str(), kChildJsonLimits);
  const auto* prepared = std::get_if<JsonValue>(&parsed);
  const auto* ple = prepared ? member(*prepared, "ple") : nullptr;
  const auto& tmpl = *settings_.card_template;
  const std::filesystem::path models_root = shard.parent_path();
  std::string model_id = path_to_utf8(shard.filename());
  if (model_id.size() > 5U) model_id.resize(model_id.size() - 5U);  // the inventory id is the stem
  std::string args_json;
  if (gguf_direct) {
    args_json = "[\"--mtp\",\"2\"]";  // Unsloth's qwen35moe GGUFs carry the MTP block; 2 drafts (upstream OWN_PATH_FAMILIES)
  } else {
    args_json = "[\"--pack\"," + json_text(path_to_utf8(pack));
    if (ple != nullptr && ple->if_string() != nullptr && !ple->if_string()->empty()) args_json += ",\"--ple-gguf\"," + json_text(*ple->if_string());
    if (entry.expert_profile) {
      args_json += ",\"--expert-profile\"," + json_text(path_to_utf8(settings_.prepare_tools->parent_path() / "data" / *entry.expert_profile));
    }
    args_json += "]";
  }
  std::string lib_dirs = "[";
  for (std::size_t i = 0; i < tmpl.engine_lib_dirs.size(); ++i) lib_dirs += (i ? "," : "") + json_text(tmpl.engine_lib_dirs[i]);
  lib_dirs += "]";
  // The GGUF-direct options follow the matched family's context; MTP drafting is on for a catalog
  // Qwen3.6 (its GGUFs carry the MTP block) and off for a custom paste (most finetune GGUFs have no
  // MTP layer), with the card's toggle to turn it on.
  const CustomProfile* prof = custom_profile(entry.family);
  const std::uint64_t ctx_default = prof ? prof->context_default : 32768U;
  const std::uint64_t ctx_min = prof ? prof->context_min : 4096U;
  const std::uint64_t ctx_max = prof ? prof->context_max : 262144U;
  const bool mtp_default = entry.source != "custom";
  const std::string card_name = card_name_for(entry);
  const std::string card = "{\"schema_version\":1,\"name\":" + json_text(card_name) + ",\"profile\":\"qwen\",\"config\":{\"engine\":{" +
                           "\"executable\":" + json_text(tmpl.engine_executable) + ",\"model_id\":" + json_text(model_id) +
                           ",\"lib_dirs\":" + lib_dirs + (tmpl.engine_gpu ? ",\"gpu\":" + json_text(*tmpl.engine_gpu) : std::string{}) +
                           ",\"args\":" + args_json + "},\"roots\":{\"models\":" + json_text(path_to_utf8(models_root)) +
                           ",\"tokenizer_pack\":" + json_text(path_to_utf8(pack / "tokenizer")) +
                           "},\"limits\":{\"chat\":{\"max_prompt_tokens\":1048576,\"max_completion_tokens\":1048576}}}," +
                           (gguf_direct
                                ? std::string{"\"options\":{\"max_context\":{\"default\":"} + std::to_string(ctx_default) +
                                      ",\"min\":" + std::to_string(ctx_min) + ",\"max\":" + std::to_string(ctx_max) + "},\"mtp\":{\"default\":" +
                                      (mtp_default ? "true" : "false") + "},\"prefill\":{\"default\":\"auto\"},\"thinking\":{\"default\":\"high\"}}}\n"
                                : std::string{"\"options\":{\"max_context\":{\"default\":131072,\"min\":4096,\"max\":1048576},\"kv\":{\"default\":\"int8\"},"} +
                                      "\"kv_resident\":{\"default\":32768,\"max\":262144},\"spec\":{\"default\":4},\"expert_cache\":{\"default\":\"auto\"}," +
                                      "\"prefill\":{\"default\":\"auto\"},\"thinking\":{\"default\":\"high\"}}}\n");
  auto cards_root = open_root(settings_.cards_dir);
  const auto card_file = parse_relative_path(entry.id + ".json");
  if (!std::holds_alternative<CanonicalRoot>(cards_root) || !std::holds_alternative<RelativePath>(card_file) ||
      write_private_file(std::get<CanonicalRoot>(cards_root), std::get<RelativePath>(card_file), card, TokenStoreMode::replace)) {
    error = "the model card could not be written";
    return false;
  }
  if (settings_.on_card && !settings_.on_card(card_name, settings_.cards_dir / (entry.id + ".json"))) {
    error = "the model card was written but the launcher refused it (see the server log)";
    return false;
  }
  return true;
}

}  // namespace secure_frontend

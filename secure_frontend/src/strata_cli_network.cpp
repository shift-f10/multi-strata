// SP4 Task 27: the strata network verbs — pull, run (D6/C6), update --models, doctor —
// with §8.3 interrupts and §7.3 acquire.log records.
#include "secure_frontend/catalog.hpp"
#include "secure_frontend/downloader.hpp"
#include "secure_frontend/engine_gate.hpp"
#include "secure_frontend/strata_cli.hpp"
#include "strata_cli_internal.hpp"

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <ostream>
#include <system_error>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#endif

namespace secure_frontend {
namespace {

using namespace strata_cli_detail;

std::atomic<bool> g_interrupted{false};

#if defined(_WIN32)
BOOL WINAPI on_console_event(DWORD) {
  g_interrupted.store(true);
  return TRUE;  // handled: run_pull winds down, the downloader terminates its Job, exit 8
}
#else
void on_signal(int) { g_interrupted.store(true); }
#endif

// §8.3: SIGINT/SIGTERM (Windows: console Ctrl-C/Ctrl-Break/close) stop cleanly. Active for the
// whole network verb. At a pending [y/N] the handler (no SA_RESTART) ends the blocked read, and
// do_pull reports `interrupted` (exit 8) rather than `declined` (§8.2); during a transfer the
// downloader sees the flag, kills its process group / Job, and run_pull returns `interrupted`
// with the resume hint.
class InterruptScope final {
 public:
  InterruptScope() {
    g_interrupted.store(false);
#if defined(_WIN32)
    SetConsoleCtrlHandler(on_console_event, TRUE);
#else
    struct sigaction action {};
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, &old_int_);
    sigaction(SIGTERM, &action, &old_term_);
#endif
  }
  ~InterruptScope() {
#if defined(_WIN32)
    SetConsoleCtrlHandler(on_console_event, FALSE);
#else
    sigaction(SIGINT, &old_int_, nullptr);
    sigaction(SIGTERM, &old_term_, nullptr);
#endif
  }
  InterruptScope(const InterruptScope&) = delete;
  InterruptScope& operator=(const InterruptScope&) = delete;

 private:
#if !defined(_WIN32)
  struct sigaction old_int_ {};
  struct sigaction old_term_ {};
#endif
};

struct NetworkKit final {
  std::unique_ptr<ConfinedDownloader> downloader;
  std::unique_ptr<HopTransport> transport_owned;
  std::unique_ptr<DownloaderProbe> probe_owned;
  std::unique_ptr<Resolver> resolver;
  std::unique_ptr<LoadedVersions> loaded;
  SystemClock system_clock;
  HopTransport* transport{nullptr};
  DownloaderProbe* probe{nullptr};
  AcquireClock* clock{nullptr};
  const std::atomic<bool>* interrupted{nullptr};
};

std::vector<ProtectedPath> protected_paths(const FrontendConfig& config, const std::filesystem::path& config_file) {
  std::vector<ProtectedPath> paths;
  std::error_code ec;
  const auto canonical_config = std::filesystem::canonical(config_file, ec);
  if (!ec) paths.push_back({"config file", canonical_config.generic_string()});
  paths.push_back({"roots.models", config.roots.models.path().generic_string()});
  if (config.roots.secret) paths.push_back({"roots.secret", config.roots.secret->path().generic_string()});
  return paths;
}

// Spec §3.2 cwd row (ruling B1): every downloader spawn — probe or transfer, also for
// pull --bundle and doctor --downloader — runs in roots.models/.staging/.cwd, so it must exist.
std::optional<AcquireError> ensure_downloader_cwd(const CanonicalRoot& models) {
  if (auto failure = ensure_directory(models, must_rel(std::string{kStagingDirName}))) return failure;
  return make_read_only_directory(models, must_rel(std::string{kStagingDirName} + "/" + std::string{kStagingCwdName}));
}

// `will_spawn`: the verb may run the downloader (a pull, doctor --downloader); plain doctor
// only asks for the confinement label and writes nothing.
std::optional<AcquireError> fill_kit(NetworkKit& kit, const FrontendConfig& config, const std::filesystem::path& config_file,
                                     CliServices& services, const bool will_spawn) {
  kit.interrupted = services.interrupted != nullptr ? services.interrupted : &g_interrupted;
  if (services.transport && services.probe) {
    kit.transport_owned = services.transport(config);
    kit.probe_owned = services.probe(config);
    kit.transport = kit.transport_owned.get();
    kit.probe = kit.probe_owned.get();
  } else {
    if (will_spawn) {
      if (auto failure = ensure_downloader_cwd(config.roots.models)) return failure;
    }
    DownloaderOptions options;
    options.executable = config.pull.downloader;
    options.protected_paths = protected_paths(config, config_file);
    options.cwd = config.roots.models.path() / std::string{kStagingDirName} / std::string{kStagingCwdName};
    if (config.pull.proxy) options.proxy_port = config.pull.proxy->port;
    options.interrupted = kit.interrupted;
#if defined(SECURE_FRONTEND_TEST_HOOKS)
    options.record_file = services.test_record_file;
    options.test_force_no_landlock = services.test_force_no_landlock;
#endif
    kit.downloader = std::make_unique<ConfinedDownloader>(std::move(options));
    kit.transport = kit.downloader.get();
    kit.probe = kit.downloader.get();
  }
  kit.resolver = services.resolver ? services.resolver() : std::make_unique<SystemResolver>();
  kit.loaded = loaded_for(config, services);
  kit.clock = services.clock != nullptr ? services.clock : &kit.system_clock;
  return std::nullopt;
}

std::string utc_now() {
  const std::time_t now = std::time(nullptr);
  std::tm parts{};
#if defined(_WIN32)
  gmtime_s(&parts, &now);
#else
  gmtime_r(&now, &parts);
#endif
  char buffer[32];
  std::strftime(buffer, sizeof buffer, "%Y-%m-%dT%H:%M:%SZ", &parts);
  return buffer;
}

// §7.3: one record per transferred file in <roots.logs>/acquire.log when roots.logs is set
// (off by default). Fixed fields only: relative path, size, digest, host, result, confinement —
// never a URL, address, proxy or config value. A log failure never fails the pull (I14).
class LoggingProgress final : public ProgressSink {
 public:
  LoggingProgress(StreamProgress& inner, const FrontendConfig& config, std::string verb, std::string confinement)
      : inner_(inner), config_(config), verb_(std::move(verb)), confinement_(std::move(confinement)) {}
  void notice(const std::string_view line) override { inner_.notice(line); }
  void manifest_selected(const std::string_view name_tag, const std::string_view sha256) override {
    model_ = std::string{name_tag};
    manifest_ = std::string{sha256};
  }
  void file_started(const std::string_view path, const std::uint64_t total) override { inner_.file_started(path, total); }
  void file_bytes(const std::string_view path, const std::uint64_t done, const std::uint64_t total) override {
    inner_.file_bytes(path, done, total);
  }
  void file_finished(const std::string_view path, const std::uint64_t size, const std::string_view sha256, const std::string_view host,
                     const std::string_view result) override {
    if (!config_.roots.logs) return;
    auto root = open_root(*config_.roots.logs, RootPolicy::create_private);
    if (!std::holds_alternative<CanonicalRoot>(root)) return;
    const auto& logs = std::get<CanonicalRoot>(root);
    const StoreEnvironment env;
    const auto file = must_rel("acquire.log");
    auto opened = open_part_file(logs, file, exists_within(logs, file) ? PartOpen::open_existing : PartOpen::create_new, env);
    if (!std::holds_alternative<PartFile>(opened)) return;
    const std::string line = utc_now() + " verb=" + verb_ + " model=" + model_ + " manifest=" + manifest_ + " path=" + std::string{path} +
                             " size=" + std::to_string(size) + " sha256=" + std::string{sha256} + " host=" + std::string{host} +
                             " result=" + std::string{result} + " confinement=" + confinement_ + "\n";
    (void)std::get<PartFile>(opened).append(line);
  }

 private:
  StreamProgress& inner_;
  const FrontendConfig& config_;
  std::string verb_;
  std::string confinement_;
  std::string model_;
  std::string manifest_;
};

int do_pull(PullRequest request, const std::string& verb, const FrontendConfig& config, const std::filesystem::path& config_file,
            CliStreams& io, CliServices& services) {
#if defined(SECURE_FRONTEND_TEST_HOOKS)
  request.test_cacert = services.test_cacert;  // F-51 / ruling R1: a test config only; never a CLI option
#endif
  NetworkKit kit;
  if (auto failure = fill_kit(kit, config, config_file, services, true)) return report(io, *failure);
  StreamConfirmer ui(io);
  StreamProgress stream(io);
  LoggingProgress progress(stream, config, verb, kit.probe->confinement());
  PullServices pull_services{*kit.transport, *kit.probe, *kit.resolver, *kit.clock, store_for(services), *kit.loaded, ui, progress,
                             *kit.interrupted};
  const auto outcome = run_pull(request, config.roots.models, config.pull, pull_services);
  if (outcome.error && outcome.error->reason == AcquireReason::declined && kit.interrupted->load()) {
    // §8.2 (controller ruling): a signal at a pending [y/N] is an interrupt, never a No. EOF
    // (Ctrl-D) leaves the flag clear and stays `declined` (exit 2). Nothing was spawned: the
    // probe runs only after a yes.
    return report(io, AcquireError{AcquireReason::interrupted, outcome.error->detail});
  }
  if (outcome.error) return report(io, *outcome.error);
  return exit_code_value(outcome.exit);
}

int verb_pull(const FrontendConfig& config, const std::filesystem::path& config_file, const std::span<const std::string> rest,
              CliStreams& io, CliServices& services) {
  const auto args = parse_args(rest, {"--yes", "--allow-downgrade", "--verify", "--discard-partial"}, {"--bundle", "--manifest", "--trust-manifest"});
  if (!args) return usage(io, "pull: unknown or incomplete option");
  bool bad = false;
  PullRequest request;
  request.trust_digest = trust_option(*args, io, bad);
  if (bad) return exit_code_value(ExitCode::usage);
  request.yes = args->flags.contains("--yes");
  request.allow_downgrade = args->flags.contains("--allow-downgrade");
  request.verify = args->flags.contains("--verify");
  request.discard_partial = args->flags.contains("--discard-partial");
  if (const auto it = args->options.find("--bundle"); it != args->options.end()) request.bundle_dir = path_from_utf8(it->second);
  if (const auto it = args->options.find("--manifest"); it != args->options.end()) {
    if (!args->positional.empty()) return usage(io, "pull --manifest takes no <name[:tag]>");
    request.manifest_file = path_from_utf8(it->second);
  } else {
    if (args->positional.size() != 1) return usage(io, "pull takes one <name[:tag]>");
    request.reference = args->positional[0];
  }
  return do_pull(std::move(request), "pull", config, config_file, io, services);
}

// The tail both run branches share: the engine gate, then where to start the server.
int model_ready(const FrontendConfig& config, const std::filesystem::path& config_file, const IndexEntry& entry, CliStreams& io) {
  auto model = load_installed(config.roots.models, entry);
  if (auto* failure = std::get_if<AcquireError>(&model)) return report(io, *failure);
  if (auto gate = engine_gate(std::get<InstalledModel>(model).manifest.manifest)) return report(io, *gate);
  io.out << "model ready: " << model_ref_text(entry.name, entry.tag) << "\nstart the server with: strata-secure-server --config "
         << path_to_utf8(config_file) << '\n';
  return 0;
}

int verb_run(const FrontendConfig& config, const std::filesystem::path& config_file, const std::span<const std::string> rest,
             CliStreams& io, CliServices& services) {
  const auto args = parse_args(rest, {"--yes"}, {});
  if (!args || args->positional.size() != 1) return usage(io, "run takes one <name[:tag]>");
  const std::string& text = args->positional[0];
  const auto reference = parse_model_reference(text);
  if (!reference) return usage(io, "run takes <name[:tag]>");
  auto found = find_installed_text(config.roots.models, text);
  if (auto* entry = std::get_if<IndexEntry>(&found)) return model_ready(config, config_file, *entry, io);
  const auto& missing = std::get<AcquireError>(found);
  if (missing.reason != AcquireReason::model_unknown) return report(io, missing);
  // D6/C6: the same in-process pull flow after the same confirmation.
  const auto* catalog = find_catalog_entry(reference->name, reference->tag.value_or("default"));
  if (catalog == nullptr) {
    const int code = report(io, AcquireError{AcquireReason::model_unknown, text});  // ruling R11
    io.err << "strata: it is not installed and not in this release's catalog; install it with strata import <bundle> "
              "or strata pull --manifest <file> --trust-manifest sha256:<hex>\n";
    return code;
  }
  const std::string ref = model_ref_text(catalog->name, catalog->tag);
  io.out << ref << " is not installed.\n";
  PullRequest request;
  request.reference = ref;
  request.yes = args->flags.contains("--yes");
  if (const int pulled = do_pull(std::move(request), "run", config, config_file, io, services); pulled != 0) return pulled;
  auto reread = read_model_index(config.roots.models);
  if (auto* failure = std::get_if<AcquireError>(&reread)) return report(io, *failure);
  const auto* installed = find_model(std::get<ModelIndex>(reread), catalog->name, catalog->tag);
  if (installed == nullptr) return report(io, AcquireError{AcquireReason::index_inconsistent, ref});
  return model_ready(config, config_file, *installed, io);
}

int verb_update_models(const FrontendConfig& config, const std::filesystem::path& config_file, const std::span<const std::string> rest,
                       CliStreams& io, CliServices& services) {
  const auto args = parse_args(rest, {"--models", "--yes"}, {});
  if (!args || !args->flags.contains("--models")) {
    return usage(io, "update --models [<name:tag> ...] [--yes]; plain 'strata update' is the program update");
  }
  auto read = read_model_index(config.roots.models);
  if (auto* failure = std::get_if<AcquireError>(&read)) return report(io, *failure);
  std::vector<std::string> targets;
  for (const auto& entry : std::get<ModelIndex>(read).models) {
    const std::string ref = model_ref_text(entry.name, entry.tag);
    const bool named = args->positional.empty() || std::find(args->positional.begin(), args->positional.end(), ref) != args->positional.end();
    // §6.1: answered offline from the catalog compiled into this binary.
    const auto* newer = entry.origin == ModelOrigin::catalog ? find_catalog_entry(entry.name, entry.tag) : nullptr;
    if (named && newer != nullptr && newer->sequence > entry.sequence) targets.push_back(ref);
  }
  if (targets.empty()) {
    io.out << "nothing to update (third-party models update only with strata pull --manifest ... --trust-manifest ...)\n";
    return 0;
  }
  int first_failure = 0;
  for (const auto& ref : targets) {
    PullRequest request;
    request.reference = ref;
    request.yes = args->flags.contains("--yes");
    const int code = do_pull(std::move(request), "update", config, config_file, io, services);
    if (code != 0 && first_failure == 0) first_failure = code;
    if (code == exit_code_value(ExitCode::interrupted)) break;
  }
  return first_failure;
}

bool variable_present(const char* name) {
#if defined(_WIN32)
  const std::wstring wide = path_from_utf8(name).wstring();
  return GetEnvironmentVariableW(wide.c_str(), nullptr, 0) != 0;
#else
  return std::getenv(name) != nullptr;  // presence only: the value is never read further, printed or stored
#endif
}

int verb_doctor(const FrontendConfig& config, const std::filesystem::path& config_file, const std::span<const std::string> rest,
                CliStreams& io, CliServices& services) {
  const auto args = parse_args(rest, {"--downloader"}, {});
  if (!args || !args->positional.empty()) return usage(io, "doctor [--downloader]");
  const bool probe = args->flags.contains("--downloader");
  NetworkKit kit;
  if (auto failure = fill_kit(kit, config, config_file, services, probe)) return report(io, *failure);
#if !defined(_WIN32)
  const int abi = landlock_abi();
  io.out << (abi > 0 ? "landlock: ABI " + std::to_string(abi) : std::string{"landlock: unavailable"}) << '\n';
#endif
  io.out << "confinement: " << kit.probe->confinement() << '\n';
  // §3.8: presence only.
  if (!config.pull.proxy && (variable_present("HTTPS_PROXY") || variable_present("https_proxy") || variable_present("ALL_PROXY"))) {
    io.out << "hint: a proxy variable is set in this environment; strata never reads it. Set pull.proxy to use a proxy.\n";
  }
  auto read = read_model_index(config.roots.models);
  if (auto* failure = std::get_if<AcquireError>(&read)) return report(io, *failure);
  if (const int code = print_store_usage(config.roots.models, std::get<ModelIndex>(read), io); code != 0) return code;
  if (!probe) return 0;  // plain doctor spawns nothing (§3.2)
  if (auto failure = kit.probe->probe()) return report(io, *failure);
  if (kit.downloader && kit.downloader->probe_result()) {
    const auto& result = *kit.downloader->probe_result();
    io.out << "downloader: curl " << result.major << "." << result.minor << "." << result.patch << " (" << result.tls_backend << ")\n";
  }
  if (config.pull.downloader != default_downloader_path()) {
    io.out << "note: a custom pull.downloader that reads its CA bundle from SSL_CERT_FILE fails with tls_failed under the empty environment\n";
  }
  return 0;
}

}  // namespace

int run_network_verb(const std::string& verb, const FrontendConfig& config, const std::filesystem::path& config_file,
                     const std::span<const std::string> rest, CliStreams& io, CliServices& services) {
  const InterruptScope scope;  // the whole verb: prompts, every update --models target, run's re-read
  if (verb == "pull") return verb_pull(config, config_file, rest, io, services);
  if (verb == "run") return verb_run(config, config_file, rest, io, services);
  if (verb == "doctor") return verb_doctor(config, config_file, rest, io, services);
  return verb_update_models(config, config_file, rest, io, services);
}

}  // namespace secure_frontend

#include "secure_frontend/strata_cli.hpp"

#include "secure_frontend/bundle_io.hpp"
#include "secure_frontend/catalog.hpp"
#include "secure_frontend/config_file.hpp"
#include "secure_frontend/engine_gate.hpp"
#include "secure_frontend/test_hooks.hpp"
#include "strata_cli_internal.hpp"

#include <istream>
#include <ostream>
#include <system_error>

namespace secure_frontend {
namespace strata_cli_detail {

const std::string_view kUsage =
    "strata --config <file> <verb> ...\n"
    "  import <bundle> [--trust-manifest sha256:<hex>] [--yes] [--allow-downgrade]\n"
    "  verify <bundle> [--trust-manifest sha256:<hex>]\n"
    "  export <name[:tag]> <dir>\n"
    "  list [--all] [--outdated]\n"
    "  show <name[:tag]> [--digests]\n"
    "  rm <name[:tag]> [--force] | rm --retired | rm --partials <name:tag>\n"
    "  pull <name[:tag]> | pull --manifest <file> --trust-manifest sha256:<hex>\n"
    "       [--yes] [--bundle <dir>] [--allow-downgrade] [--verify] [--discard-partial]\n"
    "  update --models [<name:tag> ...] [--yes]\n"
    "  run <name[:tag]> [--yes]\n"
    "  doctor [--downloader]\n"
    "strata update        (program update: not available until SP7, exit 12)";

std::optional<Args> parse_args(const std::span<const std::string> args, const std::set<std::string>& flags,
                               const std::set<std::string>& options) {
  Args out;
  for (std::size_t i = 0; i < args.size(); ++i) {
    const auto& arg = args[i];
    if (flags.contains(arg)) {
      out.flags.insert(arg);
    } else if (options.contains(arg)) {
      if (i + 1 >= args.size()) return std::nullopt;
      out.options[arg] = args[++i];
    } else if (arg.starts_with("--")) {
      return std::nullopt;
    } else {
      out.positional.push_back(arg);
    }
  }
  return out;
}

int usage(CliStreams& io, const std::string_view problem) {
  io.err << "strata: " << problem << "\nusage: " << kUsage << '\n';
  return exit_code_value(ExitCode::usage);
}

int report(CliStreams& io, const AcquireError& error) {
  io.err << format_error(error) << '\n';
  // Task 19 carry: publish never replaces a directory. A version directory the index does not
  // name and whose manifest.json differs (so it was not adopted) blocks this manifest's publish.
  constexpr std::string_view kTargetExists = ": target exists";
  if (error.reason == AcquireReason::publish_failed && error.detail.ends_with(kTargetExists)) {
    io.err << "strata: roots.models/" << std::string_view{error.detail}.substr(0, error.detail.size() - kTargetExists.size())
           << " is a version directory the index does not name; strata never loads, replaces or deletes it. "
              "Check it with strata list --all (orphaned), delete it by hand, then retry.\n";
  }
  return exit_code_value(exit_class(error.reason));
}

std::optional<std::string> trust_option(const Args& args, CliStreams& io, bool& bad) {
  const auto it = args.options.find("--trust-manifest");
  if (it == args.options.end()) return std::nullopt;
  auto digest = parse_trust_argument(it->second);
  if (!digest) {
    bad = true;
    io.err << "strata: --trust-manifest must be sha256:<64 lowercase hex>\n";
  }
  return digest;
}

std::unique_ptr<LoadedVersions> loaded_for(const FrontendConfig& config, CliServices& services) {
  if (services.loaded) return services.loaded(config);
  return std::make_unique<NoServerDiscovery>();  // Controller note 5: no server discovery until SP2
}

const StoreEnvironment& store_for(const CliServices& services) {
  static const StoreEnvironment real;
  return services.store != nullptr ? *services.store : real;
}

ManifestRules rules_for(const FrontendConfig& config) {
  ManifestRules rules;
  rules.max_total_bytes = config.pull.max_total_bytes;
  return rules;
}

std::variant<IndexEntry, AcquireError> find_installed_text(const CanonicalRoot& models, const std::string_view text) {
  const auto reference = parse_model_reference(text);
  if (!reference) return AcquireError{AcquireReason::usage_error, "expected <name[:tag]>"};
  auto read = read_model_index(models);
  if (auto* failure = std::get_if<AcquireError>(&read)) return *failure;
  return find_installed(std::get<ModelIndex>(read), *reference);
}

}  // namespace strata_cli_detail

namespace {

using namespace strata_cli_detail;

int verb_import(const FrontendConfig& config, const Args& args, CliStreams& io, CliServices& services) {
  if (args.positional.size() != 1) return usage(io, "import takes one <bundle> directory");
  bool bad = false;
  const auto trust = trust_option(args, io, bad);
  if (bad) return exit_code_value(ExitCode::usage);
  StreamProgress progress(io);
  StreamConfirmer ui(io);
  auto opened = open_bundle(path_from_utf8(args.positional[0]), trust, rules_for(config), progress);
  if (auto* failure = std::get_if<AcquireError>(&opened)) return report(io, *failure);
  const auto& bundle = std::get<OpenedBundle>(opened);
  const auto& m = bundle.manifest.parsed.manifest;
  const std::string ref = model_ref_text(m.name, m.tag);
  ui.say("model: " + ref + " version " + m.version + " (sequence " + std::to_string(m.sequence) + ", " +
         std::string{origin_name(bundle.manifest.origin)} + ")");
  ui.say("manifest sha256: " + bundle.manifest.parsed.sha256);
  // Terminal only; nothing here is written to acquire.log (Task 10 carry).
  ui.say("license: " + m.license.id + " " + m.license.url);
  if (!m.license.notice.empty()) ui.say("notice: " + m.license.notice);
  ui.say("files: " + std::to_string(m.files.size()) + ", total " + format_gb(total_bytes(m)));
  // §2.3: accepted and recorded, but said before anything is copied.
  if (engine_gate(m)) ui.say("note: this release cannot run it (" + engine_state_text(m) + ")");
  // Final review C1: import_bundle decides under .lock first ("already installed" asks nothing),
  // then prints the manifest diff and asks the §6.1 questions as pull does.
  auto loaded = loaded_for(config, services);
  auto outcome = import_bundle(bundle, config.roots.models, args.flags.contains("--allow-downgrade"), *loaded, store_for(services), progress,
                               ui, args.flags.contains("--yes"));
  if (auto* failure = std::get_if<AcquireError>(&outcome)) return report(io, *failure);
  const auto& result = std::get<InstallOutcome>(outcome);
  ui.say(result.already_installed ? "already installed: " + ref : "installed " + ref + "; start it with: strata run " + ref);
  return 0;
}

int verb_verify(const FrontendConfig& config, const Args& args, CliStreams& io) {
  if (args.positional.size() != 1) return usage(io, "verify takes one <bundle> directory");
  bool bad = false;
  const auto trust = trust_option(args, io, bad);
  if (bad) return exit_code_value(ExitCode::usage);
  StreamProgress progress(io);
  auto opened = open_bundle(path_from_utf8(args.positional[0]), trust, rules_for(config), progress);
  if (auto* failure = std::get_if<AcquireError>(&opened)) return report(io, *failure);
  if (auto failure = verify_bundle_files(std::get<OpenedBundle>(opened), progress)) return report(io, *failure);
  io.out << "bundle verified: " << std::get<OpenedBundle>(opened).manifest.parsed.sha256 << '\n';
  return 0;
}

bool is_empty_directory(const std::filesystem::path& path) {
  std::error_code ec;
  const bool empty = std::filesystem::is_directory(path, ec) && std::filesystem::is_empty(path, ec);
  return !ec && empty;
}

int verb_export(const FrontendConfig& config, const Args& args, CliStreams& io, CliServices& services) {
  if (args.positional.size() != 2) return usage(io, "export takes <name[:tag]> <dir>");
  auto entry = find_installed_text(config.roots.models, args.positional[0]);
  if (auto* failure = std::get_if<AcquireError>(&entry)) return report(io, *failure);
  auto model = load_installed(config.roots.models, std::get<IndexEntry>(entry));
  if (auto* failure = std::get_if<AcquireError>(&model)) return report(io, *failure);
  const auto target = path_from_utf8(args.positional[1]);
  std::error_code ec;
  const bool absent_before = !std::filesystem::exists(std::filesystem::symlink_status(target, ec));
  const bool empty_before = !absent_before && is_empty_directory(target);
  StreamProgress progress(io);
  if (auto failure = export_model(config.roots.models, std::get<InstalledModel>(model), target, store_for(services), progress)) {
    const int code = report(io, *failure);
    // Task 20 carry: export never deletes what it wrote (the target is outside roots.models).
    // Only a directory this run created or filled is named; a refused non-empty target is not ours.
    const bool left_behind = absent_before ? std::filesystem::exists(std::filesystem::symlink_status(target, ec))
                                           : empty_before && !is_empty_directory(target);
    if (left_behind) {
      io.err << "strata: export stopped part-way and left the target directory behind; "
                "remove the target directory (or empty it) before retrying\n";
    }
    return code;
  }
  io.out << "exported " << model_ref_text(std::get<IndexEntry>(entry).name, std::get<IndexEntry>(entry).tag) << '\n';
  return 0;
}

int verb_list(const FrontendConfig& config, const Args& args, CliStreams& io) {
  if (!args.positional.empty()) return usage(io, "list takes no operands");
  const auto& models = config.roots.models;
  auto read = read_model_index(models);
  if (auto* failure = std::get_if<AcquireError>(&read)) return report(io, *failure);
  const auto& index = std::get<ModelIndex>(read);
  for (const auto& entry : index.models) {
    if (args.flags.contains("--outdated")) {
      // §6.1: answered offline from the catalog compiled into this binary.
      const auto* newer = entry.origin == ModelOrigin::catalog ? find_catalog_entry(entry.name, entry.tag) : nullptr;
      if (newer != nullptr && newer->sequence > entry.sequence) {
        io.out << model_ref_text(entry.name, entry.tag) << " sequence " << entry.sequence << " -> " << newer->sequence << '\n';
      }
      continue;
    }
    auto model = load_installed(models, entry);  // re-hashes manifest.json only (fails closed)
    if (auto* failure = std::get_if<AcquireError>(&model)) return report(io, *failure);
    const auto& m = std::get<InstalledModel>(model).manifest.manifest;
    io.out << model_ref_text(entry.name, entry.tag) << "  " << entry.version << "  " << format_gb(total_bytes(m)) << "  "
           << origin_name(entry.origin) << "  " << engine_state_text(m) << '\n';
  }
  if (!args.flags.contains("--all")) return 0;
  return print_store_usage(models, index, io);
}

int verb_show(const FrontendConfig& config, const Args& args, CliStreams& io) {
  if (args.positional.size() != 1) return usage(io, "show takes <name[:tag]>");
  auto entry = find_installed_text(config.roots.models, args.positional[0]);
  if (auto* failure = std::get_if<AcquireError>(&entry)) return report(io, *failure);
  auto loaded = load_installed(config.roots.models, std::get<IndexEntry>(entry));
  if (auto* failure = std::get_if<AcquireError>(&loaded)) return report(io, *failure);
  const auto& model = std::get<InstalledModel>(loaded);
  const auto& m = model.manifest.manifest;
  if (args.flags.contains("--digests")) {  // sha256sum -c format, relative to the version directory
    for (const auto& f : m.files) io.out << f.sha256 << "  " << f.path << '\n';
    io.out << model.manifest.sha256 << "  " << kVersionManifestName << '\n';
    return 0;
  }
  io.out << "model: " << model_ref_text(m.name, m.tag) << " version " << m.version << " sequence " << m.sequence << '\n'
         << "manifest sha256: " << model.manifest.sha256 << "\nprofile: " << profile_name(m.profile) << "; engine "
         << family_name(m.family) << " >= " << render_engine_version(m.min_version) << " (" << engine_state_text(m) << ")\n"
         << "license: " << m.license.id << " " << m.license.url << "\nversion directory: " << model.version_dir.generic() << '\n';
  for (const auto& f : m.files) io.out << "  " << f.size << "  " << role_name(f.role) << "  " << f.path << '\n';
  io.out << "engine arguments: " << implied_engine_arguments(model) << '\n';
  return 0;
}

int rm_partials(const CanonicalRoot& models, const std::string& reference_text, CliStreams& io) {
  const auto reference = parse_model_reference(reference_text);
  if (!reference || !reference->tag) return usage(io, "rm --partials takes <name:tag>");
  const auto staging_root = must_rel(std::string{kStagingDirName});
  if (!exists_within(models, staging_root)) return 0;  // nothing staged
  auto listed = list_directory(models, staging_root);
  if (std::holds_alternative<PathError>(listed)) {
    return report(io, AcquireError{AcquireReason::publish_failed, std::string{kStagingDirName} + ": cannot be listed"});
  }
  ManifestRules any;  // the staged MANIFEST is matched by name:tag only; nothing is trusted or installed from it
  any.max_total_bytes = ~std::uint64_t{0};
  for (const auto& entry : std::get<std::vector<DirectoryEntry>>(listed)) {
    if (entry.type != EntryType::directory || !is_staging_key_name(entry.name)) continue;
    const auto dir = join_rel(staging_root, entry.name);
    auto bytes = read_small_file(models, join_rel(dir, kStagingManifestName), kManifestMaxBytes);
    if (!std::holds_alternative<std::string>(bytes)) continue;
    auto parsed = parse_manifest(std::get<std::string>(bytes), any);
    if (const auto* manifest = std::get_if<ParsedManifest>(&parsed);
        manifest != nullptr && manifest->manifest.name == reference->name && manifest->manifest.tag == *reference->tag) {
      if (auto failure = remove_tree_within(models, dir)) return report(io, *failure);
      io.out << "deleted partial download " << entry.name << '\n';
    }
  }
  return 0;
}

int verb_rm(const FrontendConfig& config, const Args& args, CliStreams& io, CliServices& services) {
  const auto& models = config.roots.models;
  const bool retired = args.flags.contains("--retired");
  const auto partials = args.options.find("--partials");
  // Operand checks first: a usage error never takes the lock.
  if (retired && (!args.positional.empty() || partials != args.options.end() || args.flags.contains("--force"))) {
    return usage(io, "rm --retired takes no operands");
  }
  if (partials != args.options.end() && (!args.positional.empty() || args.flags.contains("--force"))) {
    return usage(io, "rm --partials takes <name:tag>");
  }
  if (!retired && partials == args.options.end() && args.positional.size() != 1) return usage(io, "rm takes <name[:tag]>");
  auto lock = lock_models_root(models);  // §4.8: held for the whole verb
  if (auto* failure = std::get_if<AcquireError>(&lock)) return report(io, *failure);
  if (partials != args.options.end()) return rm_partials(models, partials->second, io);
  auto loaded = loaded_for(config, services);
  if (retired) {
    if (auto failure = delete_unheld_retired(models, *loaded, store_for(services))) return report(io, *failure);
    io.out << "deleted unheld retired versions\n";
    return 0;
  }
  auto entry = find_installed_text(models, args.positional[0]);
  if (auto* failure = std::get_if<AcquireError>(&entry)) return report(io, *failure);
  const auto& e = std::get<IndexEntry>(entry);
  auto removed = remove_installed(models, e.name, e.tag, *loaded, args.flags.contains("--force"), store_for(services));
  if (auto* failure = std::get_if<AcquireError>(&removed)) return report(io, *failure);
  io.out << "removed " << model_ref_text(e.name, e.tag) << '\n';
  return 0;
}

std::variant<ValidatedConfig, int> load_config(const std::string& file, CliStreams& io) {
  auto draft = read_config_file(path_from_utf8(file));
  if (auto* issues = std::get_if<ConfigErrors>(&draft)) {
    for (const auto& issue : *issues) io.err << "strata: config: " << format_issue(issue) << '\n';
    return exit_code_value(ExitCode::usage);
  }
  auto validated = validate(std::get<FrontendConfigDraft>(draft));
  if (auto* issues = std::get_if<ConfigErrors>(&validated)) {
    for (const auto& issue : *issues) io.err << "strata: config: " << format_issue(issue) << '\n';
    return exit_code_value(ExitCode::usage);
  }
  return std::get<ValidatedConfig>(std::move(validated));
}

}  // namespace

int print_store_usage(const CanonicalRoot& models, const ModelIndex& index, CliStreams& io) {
  auto scanned = scan_model_root(models);
  if (std::holds_alternative<PathError>(scanned)) return report(io, AcquireError{AcquireReason::publish_failed, "roots.models cannot be scanned"});
  const auto& scan = std::get<ModelRootScan>(scanned);
  std::set<std::string> live;
  for (const auto& e : index.models) live.insert(e.name + "/" + e.tag + "/" + e.dir);
  std::map<std::string, std::uint64_t> retired;
  for (const auto& e : index.retired) retired[e.name + "/" + e.tag + "/" + e.dir] = 0;
  std::map<std::string, std::uint64_t> orphaned;
  std::map<std::string, std::uint64_t> staging;
  for (const auto& file : scan.files) {
    if (file.path.starts_with(std::string{kStagingDirName} + "/")) {
      const auto rest = file.path.substr(kStagingDirName.size() + 1);
      const auto key = rest.substr(0, rest.find('/'));
      if (is_staging_key_name(key)) staging[key] += file.size;
      continue;
    }
    const auto first = file.path.find('/');
    const auto second = first == std::string::npos ? std::string::npos : file.path.find('/', first + 1);
    const auto third = second == std::string::npos ? std::string::npos : file.path.find('/', second + 1);
    if (third == std::string::npos) continue;  // index.json, .lock and other top-level files
    const auto version = file.path.substr(0, third);
    if (live.contains(version)) continue;
    if (retired.contains(version)) retired[version] += file.size;
    else orphaned[version] += file.size;
  }
  for (const auto& [dir, bytes] : retired) io.out << "retired " << dir << " " << bytes << " bytes\n";
  for (const auto& [dir, bytes] : orphaned) io.out << "orphaned " << dir << " " << bytes << " bytes\n";
  if (!orphaned.empty()) {
    io.out << "  orphaned versions are never loaded; a pull or import of the same manifest adopts one, "
              "otherwise delete it by hand (it also blocks publishing a manifest whose directory name it takes)\n";
  }
  for (const auto& [key, bytes] : staging) io.out << "staging " << key << " " << bytes << " bytes\n";
  if (scan.skipped != 0) {
    io.out << "skipped " << scan.skipped << (scan.skipped == 1 ? " entry" : " entries")
           << " under roots.models that strata never follows (links, junctions, devices, non-portable names)\n";
  }
  return 0;
}

void StreamConfirmer::say(const std::string_view line) { io_.out << line << '\n'; }

bool StreamConfirmer::confirm(const std::string_view question, const bool yes_applies) {
  io_.out << question << ' ';
  if (yes_applies) {
    io_.out << "yes (--yes)\n";
    return true;
  }
  if (!io_.interactive) {
    io_.out << "no (not interactive; pass --yes)\n";
    return false;
  }
  io_.out.flush();
  std::string answer;
  if (!std::getline(io_.in, answer)) {
    io_.out << '\n';
    return false;  // EOF is No
  }
  return parse_confirmation(answer);
}

void StreamProgress::notice(const std::string_view line) {
  if (line != "verifying") io_.err << line << '\n';
}

void StreamProgress::file_started(const std::string_view path, const std::uint64_t total) {
  last_reported_ = 0;
  io_.err << path << ": " << total << " bytes\n";
}

void StreamProgress::file_bytes(const std::string_view path, const std::uint64_t done, const std::uint64_t total) {
  constexpr std::uint64_t kStep = std::uint64_t{1} << 30U;
  if (done == total || done / kStep != last_reported_ / kStep) io_.err << path << ": " << done << " / " << total << " bytes\n";
  last_reported_ = done;
}

std::string implied_engine_arguments(const InstalledModel& model) {
  const auto& launch = model.manifest.manifest.launch;
  const std::string base = model.version_dir.generic() + "/";
  std::string text;
  if (launch.native) text += "--native " + base + *launch.native;
  if (launch.pack) text += " --pack " + base + *launch.pack;
  if (launch.ple_gguf) text += " --ple-gguf " + base + *launch.ple_gguf;
  if (launch.tokenizer_pack) text += "; frontend --tokenizer-pack " + base + *launch.tokenizer_pack;
  return text;
}

int run_strata(const std::span<const std::string> args, CliStreams& io, CliServices& services) {
#if defined(SECURE_FRONTEND_TEST_HOOKS)
  io.err << "warning: test hooks compiled in (" << kTestHooksMarker << "); never ship this binary\n";
#endif
  if (args.empty() || args[0] == "--help" || args[0] == "-h") {
    io.out << "usage: " << kUsage << '\n';
    return args.empty() ? exit_code_value(ExitCode::usage) : 0;
  }
  // §6.2 / Controller note 16 / C7: program updates need SP7's signature verification. No network
  // access: no transport, probe or resolver is created.
  const auto program_update = [&io] {
    io.out << "program update not available in this release; install the new release manually\n";
    return exit_code_value(ExitCode::program_update);
  };
  if (args[0] == "update" && args.size() == 1) return program_update();
  // The documented form under note 2 (--config on every verb): `update` with no operands is the
  // program part too, exactly like the bare form (the config is not read). `update --models …`
  // (and any other operand) goes to the network verbs (Task 27).
  if (args.size() == 3 && args[0] == "--config" && args[2] == "update") return program_update();
  if (args[0] != "--config" || args.size() < 3) return usage(io, "--config <file> is required before the verb (no default location yet)");
  auto loaded = load_config(args[1], io);
  if (auto* code = std::get_if<int>(&loaded)) return *code;
  const auto& config = std::get<ValidatedConfig>(loaded).get();
  const std::string verb = args[2];
  const auto rest = args.subspan(3);
  if (verb == "pull" || verb == "run" || verb == "doctor" || verb == "update") {
    return run_network_verb(verb, config, path_from_utf8(args[1]), rest, io, services);
  }
  struct Grammar final {
    std::set<std::string> flags;
    std::set<std::string> options;
  };
  static const std::map<std::string, Grammar> grammar{
      {"import", {{"--yes", "--allow-downgrade"}, {"--trust-manifest"}}},
      {"verify", {{}, {"--trust-manifest"}}},
      {"export", {{}, {}}},
      {"list", {{"--all", "--outdated"}, {}}},
      {"show", {{"--digests"}, {}}},
      {"rm", {{"--force", "--retired"}, {"--partials"}}},
  };
  const auto it = grammar.find(verb);
  if (it == grammar.end()) return usage(io, "unknown verb");
  const auto parsed = parse_args(rest, it->second.flags, it->second.options);
  if (!parsed) return usage(io, "unknown or incomplete option");
  if (verb == "import") return verb_import(config, *parsed, io, services);
  if (verb == "verify") return verb_verify(config, *parsed, io);
  if (verb == "export") return verb_export(config, *parsed, io, services);
  if (verb == "list") return verb_list(config, *parsed, io);
  if (verb == "show") return verb_show(config, *parsed, io);
  return verb_rm(config, *parsed, io, services);
}

// Until Task 27 adds strata_cli_network.cpp (and deletes this stub).
int run_network_verb(const std::string& verb, const FrontendConfig&, const std::filesystem::path&, std::span<const std::string>,
                     CliStreams& io, CliServices&) {
  io.err << "strata: " << verb << " is not available in this build yet\n";
  return exit_code_value(ExitCode::usage);
}

}  // namespace secure_frontend

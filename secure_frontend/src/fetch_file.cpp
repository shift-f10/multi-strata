#include "secure_frontend/fetch_file.hpp"

#include "secure_frontend/acquire_url.hpp"
#include "secure_frontend/download_response.hpp"

#include <utility>
#include <variant>

namespace secure_frontend {
namespace {

// Per manifest file, across every attempt and source of this run.
struct FileState final {
  bool restarted_after_ignored_range{false};  // §3.4: a 200 to a range restarts from 0 once per file
  bool refetched_after_mismatch{false};       // §3.7: one refetch from 0 after a mismatch on resumed bytes
  std::uint64_t written_since_check{0};       // §4.6 free-space re-check counter
};

struct AttemptResult final {
  std::optional<AcquireError> error;
  bool status_transient{false};  // 429 / 5xx (§3.4); the reason table decides the rest
  bool done{false};
  bool retry_now{false};
};

AttemptResult fail(const AcquireReason reason, std::string detail, const bool status_transient = false) {
  return AttemptResult{AcquireError{reason, std::move(detail)}, status_transient, false, false};
}

AttemptResult fail_with(AcquireError error) { return AttemptResult{std::move(error), false, false, false}; }

std::optional<AcquireError> reset(FetchTarget& target) {
  if (auto failure = target.file.truncate_to_zero()) return failure;
  target.hasher = Sha256{};
  return std::nullopt;
}

// §3.7: the bytes on disk are complete; verify, then publish into the staging name.
// `resumed`: the bytes did not all arrive in one from-zero transfer of this attempt.
AttemptResult verify_and_finish(FetchContext& ctx, const ManifestFile& file, FetchTarget& target, FileState& state, const bool resumed) {
  if (to_hex(Sha256{target.hasher}.finish()) != file.sha256) {
    if (resumed && !state.refetched_after_mismatch) {
      state.refetched_after_mismatch = true;
      if (auto failure = reset(target)) return fail_with(std::move(*failure));
      return AttemptResult{std::nullopt, false, false, true};
    }
    return fail(AcquireReason::digest_mismatch, file.path);
  }
  if (auto failure = target.file.sync()) return fail_with(std::move(*failure));
  target.file.close();
  if (auto failure = rename_within(ctx.root, target.part, target.final_path, ctx.store)) return fail_with(std::move(*failure));
  return AttemptResult{std::nullopt, false, true, false};
}

// One attempt: the manifest source URL plus at most kMaxRedirectHops of our own redirects.
AttemptResult run_attempt(FetchContext& ctx, const AcquireManifest& manifest, const ManifestFile& file, const std::string& source,
                          const std::vector<std::string>& redirect_allowed, FetchTarget& target, FileState& state) {
  auto parsed_source = parse_source_url(source);
  if (!std::holds_alternative<HttpsUrl>(parsed_source)) return fail(AcquireReason::manifest_invalid, file.path);
  HttpsUrl current = std::get<HttpsUrl>(std::move(parsed_source));
  if (!host_in(manifest.hosts, current.host)) return fail(AcquireReason::host_not_allowed, current.host);
  if (target.file.size() > file.size) {
    if (auto failure = reset(target)) return fail_with(std::move(*failure));
  }
  // §3.7 "L == size is hashed": nothing left to transfer (a --range would only earn a 416).
  if (target.file.size() == file.size) return verify_and_finish(ctx, file, target, state, true);
  for (int hop = 0;; ++hop) {
    if (ctx.interrupted.load()) return fail(AcquireReason::interrupted, file.path);
    const auto remaining = ctx.budget.remaining_seconds(ctx.clock.now());
    if (!remaining) return fail(AcquireReason::time_budget_exceeded, "pull.max_duration_s");
    TransferRequest request = hop_request(current, ctx.settings, *remaining);
    if (!ctx.settings.proxy) {
      // §3.5: resolve and check before every hop; any denied answer rejects it.
      const auto answers = ctx.resolver.resolve(current.host);
      if (!answers || answers->empty()) return fail(AcquireReason::dns_failed, current.host);
      const auto verdict = choose_pinned_address(*answers, ctx.settings.allow_private_addresses);
      // denied, and (F-13) an IPv6-only answer while the IPv6 pin is unverified.
      if (verdict.kind != AddressVerdictKind::pinned) return fail(AcquireReason::address_not_allowed, current.host);
      request.pin = verdict.pinned;
    }  // else: the proxy resolves the target; §3.5 cannot see it (§13.2)
    if (target.file.size() > 0) request.range_from = target.file.size();

    ResponseHeadParser parser;
    std::optional<HeadDecision> decision;
    std::optional<AcquireError> body_error;
    bool writing = false;
    bool resumed = false;
    const auto on_bytes = [&](std::string_view bytes) -> bool {
      if (ctx.interrupted.load()) {
        body_error = AcquireError{AcquireReason::interrupted, file.path};
        return false;
      }
      if (!decision) {
        const auto fed = parser.feed(bytes);
        if (fed.state == ResponseHeadParser::State::malformed) {
          body_error = AcquireError{AcquireReason::response_malformed, current.host};
          return false;
        }
        if (fed.state == ResponseHeadParser::State::need_more) return true;
        decision = classify_head(parser.head(), HopExpectation{file.size, request.range_from});
        bytes.remove_prefix(fed.consumed);
        if (decision->action == HeadAction::restart_from_zero) {
          if (state.restarted_after_ignored_range) {
            body_error = AcquireError{AcquireReason::range_mismatch, current.host};
            return false;
          }
          state.restarted_after_ignored_range = true;
          if (auto failure = reset(target)) {
            body_error = std::move(failure);
            return false;
          }
          writing = true;
        } else if (decision->action == HeadAction::write_body) {
          writing = true;
          resumed = request.range_from.has_value();  // 206: appended to bytes already on disk
        } else {
          return false;  // redirect or failure: the body is not needed
        }
      }
      if (!writing || bytes.empty()) return true;
      if (target.file.size() + bytes.size() > file.size) {
        body_error = AcquireError{AcquireReason::size_exceeded, file.path};
        return false;
      }
      if (auto failure = target.file.append(bytes)) {
        body_error = std::move(failure);
        return false;
      }
      target.hasher.update(bytes);
      state.written_since_check += bytes.size();
      if (state.written_since_check >= ctx.store.recheck_interval_bytes()) {
        state.written_since_check = 0;
        const auto space = ctx.store.free_bytes(ctx.root);
        if (!std::holds_alternative<std::uint64_t>(space) || std::get<std::uint64_t>(space) < kFreeSpaceMarginBytes) {
          body_error = AcquireError{AcquireReason::disk_space, file.path};
          return false;
        }
      }
      ctx.progress.file_bytes(file.path, target.file.size(), file.size);
      return true;
    };
    const HopExit exit = ctx.transport.run(request, on_bytes);
    if (exit.failure) return fail_with(*exit.failure);
    if (body_error) return fail_with(std::move(*body_error));
    if (ctx.interrupted.load()) return fail(AcquireReason::interrupted, file.path);
    const bool budget_gone = !ctx.budget.remaining_seconds(ctx.clock.now());
    if (!decision) {
      // No complete header block: the exit code says why (0 = curl ended without a response).
      const AcquireReason reason = !exit.curl_exit     ? AcquireReason::transport_failed
                                   : *exit.curl_exit == 0 ? AcquireReason::response_malformed
                                                          : map_curl_exit(*exit.curl_exit, budget_gone).value_or(AcquireReason::transport_failed);
      return fail(reason, current.host);
    }
    if (decision->action == HeadAction::redirect) {
      // §3.4: Location grammar (<= 8 KiB) and hosts ∪ redirect_hosts; the value is never printed.
      auto location = parse_location(decision->location, current.host);
      if (!std::holds_alternative<HttpsUrl>(location)) return fail(AcquireReason::redirect_not_allowed, current.host);
      auto next = std::get<HttpsUrl>(std::move(location));
      if (!host_in(redirect_allowed, next.host)) return fail(AcquireReason::redirect_not_allowed, current.host);
      if (hop + 1 > kMaxRedirectHops) return fail(AcquireReason::redirect_limit, current.host);
      current = std::move(next);
      continue;
    }
    if (decision->action == HeadAction::fail) {
      std::string detail = current.host;
      if (decision->reason == AcquireReason::http_status) detail += " HTTP " + std::to_string(decision->status);
      return fail(decision->reason, std::move(detail), decision->transient);
    }
    if (exit.curl_exit.value_or(-1) != 0) {
      const AcquireReason reason = exit.curl_exit ? map_curl_exit(*exit.curl_exit, budget_gone).value_or(AcquireReason::transport_failed)
                                                  : AcquireReason::transport_failed;
      return fail(reason, current.host);
    }
    if (target.file.size() < file.size) return fail(AcquireReason::size_short, current.host);
    return verify_and_finish(ctx, file, target, state, resumed);
  }
}

std::string source_host(const std::string& source) {
  const auto parsed = parse_source_url(source);
  const auto* url = std::get_if<HttpsUrl>(&parsed);
  return url == nullptr ? std::string{} : url->host;
}

}  // namespace

bool is_run_fatal(const AcquireReason reason) noexcept {
  switch (reason) {
    case AcquireReason::interrupted:
    case AcquireReason::disk_space:
    case AcquireReason::time_budget_exceeded:
    case AcquireReason::publish_failed:
    case AcquireReason::downloader_missing:
    case AcquireReason::downloader_version:
    case AcquireReason::downloader_untrusted_path:
    case AcquireReason::downloader_unsupported:
    case AcquireReason::downloader_confinement_failed:
      return true;
    default:
      return false;
  }
}

TransferRequest hop_request(const HttpsUrl& url, const FetchSettings& settings, const std::uint64_t max_time_s) {
  TransferRequest request;
  request.url = render_url(url);
  request.host = url.host;
  request.connect_timeout_s = settings.connect_timeout_s;
  request.stall_timeout_s = settings.stall_timeout_s;
  request.max_time_s = max_time_s;
  request.proxy = settings.proxy;
#if defined(SECURE_FRONTEND_TEST_HOOKS)
  request.test_cacert = settings.test_cacert;
#endif
  return request;
}

std::optional<AcquireError> fetch_file(FetchContext& ctx, const AcquireManifest& manifest, const std::size_t file_index, FetchTarget& target) {
  const auto& file = manifest.files[file_index];
  if (file.sources.empty()) return AcquireError{AcquireReason::manifest_requires_bundle, file.path};
  std::vector<std::string> redirect_allowed = manifest.hosts;
  redirect_allowed.insert(redirect_allowed.end(), manifest.redirect_hosts.begin(), manifest.redirect_hosts.end());
  SourceSchedule schedule(file.sources.size());
  FileState state;
  ctx.progress.file_started(file.path, file.size);
  while (true) {
    const std::string& source = file.sources[schedule.source()];
    const std::string host = source_host(source);
    if (ctx.interrupted.load()) {
      ctx.progress.file_finished(file.path, file.size, file.sha256, host, reason_name(AcquireReason::interrupted));
      return AcquireError{AcquireReason::interrupted, file.path};
    }
    // §3.6: each attempt starts again at the manifest's source URL.
    auto result = run_attempt(ctx, manifest, file, source, redirect_allowed, target, state);
    if (result.done) {
      ctx.progress.file_finished(file.path, file.size, file.sha256, host, "ok");
      return std::nullopt;
    }
    if (result.retry_now) continue;  // §3.7: refetch once from byte 0, same source, no back-off
    const AcquireError error = std::move(*result.error);
    if (is_run_fatal(error.reason)) {
      ctx.progress.file_finished(file.path, file.size, file.sha256, host, reason_name(error.reason));
      return AcquireError{error.reason, file.path + ": " + error.detail};
    }
    const auto same = reason_info(error.reason).same_source;
    if (same == SameSource::restart_file || same == SameSource::next_source_file_deleted) {
      if (auto failure = reset(target)) return failure;
    }
    // Task 7 carry: the reason table decides, plus 429/5xx from the status line.
    const auto step = schedule.record_failure(error.reason, is_transient(error.reason) || result.status_transient);
    if (step.kind == SourceSchedule::Step::Kind::exhausted) {
      if (exit_class(error.reason) == ExitCode::verification) {
        target.file.close();
        (void)remove_file_within(ctx.root, target.part);
      }
      ctx.progress.file_finished(file.path, file.size, file.sha256, host, reason_name(error.reason));
      return AcquireError{error.reason, file.path + ": " + error.detail};
    }
    if (step.wait.count() > 0) ctx.clock.sleep_for(step.wait);
  }
}

}  // namespace secure_frontend

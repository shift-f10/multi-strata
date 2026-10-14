#include "secure_frontend/downloader.hpp"

namespace secure_frontend {

std::optional<AcquireError> ConfinedDownloader::probe() {
  auto valid = validate_downloader(options_.executable);
  if (auto* failure = std::get_if<AcquireError>(&valid)) return *failure;
  validated_ = std::get<std::filesystem::path>(valid);
  std::string output;
  const auto result = spawn(build_probe_argv(validated_->string()), {}, [&output](const std::string_view bytes) {
    output.append(bytes);
    return output.size() <= 65536;
  });
  if (result.failure) return result.failure;
  if (result.exit.value_or(-1) != 0) return AcquireError{AcquireReason::downloader_unsupported, "the probe exited non-zero"};
  const auto parsed = parse_probe_output(output);
  if (!parsed) return AcquireError{AcquireReason::downloader_unsupported, "not a curl with a TLS backend"};
  if (!meets_version_floor(*parsed, kThisDownloaderPlatform)) {
    return AcquireError{AcquireReason::downloader_version, "curl " + std::to_string(parsed->major) + "." + std::to_string(parsed->minor) +
                                                               "." + std::to_string(parsed->patch) + " is below the floor"};
  }
  probe_result_ = parsed;
  return std::nullopt;
}

HopExit ConfinedDownloader::run(const TransferRequest& request, const std::function<bool(std::string_view)>& on_bytes) {
  if (!validated_) {
    auto valid = validate_downloader(options_.executable);
    if (auto* failure = std::get_if<AcquireError>(&valid)) return HopExit{std::nullopt, *failure, false};
    validated_ = std::get<std::filesystem::path>(valid);
  }
  const auto result = spawn(build_transfer_argv(validated_->string(), request), build_config_stdin(request), on_bytes);
  return HopExit{result.exit, result.failure, result.killed};
}

}  // namespace secure_frontend

#include "secure_frontend/engine_process.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

std::filesystem::path current_executable() {
#if defined(_WIN32)
  std::vector<wchar_t> buffer(32768);
  const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  return std::filesystem::path(std::wstring(buffer.data(), length));
#else
  std::vector<char> buffer(4096);
  const auto length = readlink("/proc/self/exe", buffer.data(), buffer.size());
  return std::filesystem::path(std::string(buffer.data(), static_cast<std::size_t>(length)));
#endif
}

int run_fake_engine(const int argc, char** argv) {
  if (argc != 3 || std::string(argv[2]) != "literal; exit 73") {
    return 41;
  }
  const char* const allowed = std::getenv("STRATA_ALLOWED_TEST");
  return allowed != nullptr && std::string(allowed) == "present" && std::getenv("HOME") == nullptr ? 0 : 42;
}

void starts_without_a_shell_and_uses_only_allowlisted_environment() {
  secure_frontend::EngineProcess process;
  const secure_frontend::EngineCommand command{
      .executable = current_executable(),
      .arguments = {"--fake-engine", "literal; exit 73"},
      .environment = {{"STRATA_ALLOWED_TEST", "present"}},
  };
  const auto error = process.start(command);
  expect(!error.has_value(), "a valid fake engine should start");
  const auto result = process.wait_for(std::chrono::seconds(2));
  expect(result.has_value() && *result == 0,
         "arguments must reach the child literally, without a shell, and environment must be allowlisted");
}

void rejects_empty_executable() {
  secure_frontend::EngineProcess process;
  const auto error = process.start({.executable = {}, .arguments = {}, .environment = {}});
  expect(error.has_value() && error->code == secure_frontend::ProcessErrorCode::invalid_command,
         "an empty executable must be rejected before process creation");
}

void rejects_malformed_allowlist_entry() {
  secure_frontend::EngineProcess process;
  const auto error = process.start(
      {.executable = current_executable(), .arguments = {}, .environment = {{"BAD=NAME", "value"}}});
  expect(error.has_value() && error->code == secure_frontend::ProcessErrorCode::invalid_command,
         "environment allowlist names must not permit an embedded equals sign");
}

void rejects_embedded_nul_in_exec_boundary() {
  secure_frontend::EngineProcess process;
  const auto executable_error = process.start(
      {.executable = std::filesystem::path{std::string{"ignored\0truncated", 17}},
       .arguments = {},
       .environment = {}});
  expect(executable_error.has_value() &&
             executable_error->code == secure_frontend::ProcessErrorCode::invalid_command,
         "executable paths must not allow embedded NUL truncation");

  const auto argument_error = process.start(
      {.executable = current_executable(),
       .arguments = {std::string{"--fake-engine\0--fake-sleeper", 28}},
       .environment = {}});
  expect(argument_error.has_value() &&
             argument_error->code == secure_frontend::ProcessErrorCode::invalid_command,
         "argv values must not allow embedded NUL truncation");
}

void termination_cleans_up_a_process_group() {
  secure_frontend::EngineProcess process;
  const secure_frontend::EngineCommand command{
      .executable = current_executable(), .arguments = {"--fake-sleeper"}, .environment = {}};
  expect(!process.start(command).has_value(), "sleeper should start");
  expect(process.terminate(std::chrono::milliseconds(200)), "termination should reap the child process group");
  const auto result = process.wait_for(std::chrono::milliseconds(1));
  expect(result.has_value(), "terminated child should have an observable exit result");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc >= 2 && std::string(argv[1]) == "--fake-engine") {
    return run_fake_engine(argc, argv);
  }
  if (argc >= 2 && std::string(argv[1]) == "--fake-sleeper") {
    std::this_thread::sleep_for(std::chrono::seconds(30));
    return 0;
  }

  starts_without_a_shell_and_uses_only_allowlisted_environment();
  rejects_empty_executable();
  rejects_malformed_allowlist_entry();
  rejects_embedded_nul_in_exec_boundary();
  termination_cleans_up_a_process_group();
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

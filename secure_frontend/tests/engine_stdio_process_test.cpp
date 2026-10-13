#include "secure_frontend/engine_protocol_client.hpp"
#include "secure_frontend/engine_stdio_process.hpp"

#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void expect(const bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

int fake_engine() {
  // A real engine may emit human diagnostics on stderr before protocol READY.
  // Those bytes must never enter the strict stdout protocol stream.
  std::cerr << "diagnostic: private engine startup\n" << std::flush;
  std::cout << "READY 4096 stop\n" << std::flush;
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.rfind("GEN ", 0) == 0) {
      std::cout << "T 7\nDONE stop\n" << std::flush;
    } else if (line == "QUIT") {
      return 0;
    }
  }
  return 0;
}

void test_round_trip(const std::filesystem::path& self) {
  secure_frontend::EngineStdioProcess transport;
  secure_frontend::EngineCommand command{.executable = self,
                                         .arguments = {"--fake-engine"},
                                         .environment = {}};
  const auto start_error = transport.start(command);
  expect(!start_error.has_value(), "fake engine must start");
  secure_frontend::EngineProtocolClient client(transport);
  secure_frontend::EngineReady ready{};
  expect(!client.await_ready(std::chrono::seconds(2), ready).has_value(), "READY must parse");
  expect(ready.max_context_tokens == 4096 && ready.supports_stop, "READY capabilities must survive transport");
  // E4: the GEN line for a full context is far beyond 8 KiB; the write cap must allow it.
  // Raw write while the client is idle, then consume the fake's two reply lines so
  // the protocol client continues from a clean stream.
  std::string big(100000U, '1'); std::string werr;
  const bool big_written = transport.write_line("GEN 1 " + big, werr);
  expect(big_written, "a 100 KB GEN line must be writable: " + werr);
  const auto reply_token = transport.read_line(std::chrono::seconds(2));
  const auto reply_done = transport.read_line(std::chrono::seconds(2));
  expect(reply_token.kind == secure_frontend::EngineReadKind::line && reply_token.line == "T 7" &&
             reply_done.kind == secure_frontend::EngineReadKind::line && reply_done.line == "DONE stop",
         "the fake engine must answer the 100 KB GEN line");
  expect(!client.begin_generation(2, {1, 2, 3}).has_value(), "GEN must write through transport");
  secure_frontend::EngineGeneration generation{};
  expect(!client.read_generation(std::chrono::seconds(2), generation).has_value(), "generation must read through transport");
  expect(generation.token_ids == std::vector<std::uint32_t>{7}, "token must survive transport");
  expect(!client.quit().has_value(), "QUIT must write through transport");
  expect(transport.terminate(std::chrono::milliseconds(250)), "child cleanup must succeed");
}

void test_invalid_record() {
  secure_frontend::EngineStdioProcess transport;
  std::string error;
  expect(!transport.write_line("bad\nline", error), "multiline writes must be rejected");
}

}  // namespace

int main(const int argc, char* argv[]) {
  for (int index = 1; index < argc; ++index) {
    if (std::string(argv[index]) == "--fake-engine") return fake_engine();
  }
  try {
    test_round_trip("/proc/self/exe");
    test_invalid_record();
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

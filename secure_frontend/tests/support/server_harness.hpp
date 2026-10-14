#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace test_support {

inline constexpr std::string_view kHarnessTokenEnv = "STRATA_HARNESS_TOKEN";
// 43 base64url characters (32 random-looking bytes' worth): SP1 rejects tokens under 32 bytes.
inline constexpr std::string_view kHarnessToken = "SP2harnessToken_0123456789-abcdefghijklmnop";
inline constexpr std::string_view kHealthStarting = "{\"status\":\"unavailable\",\"engine\":\"starting\"}\n";
inline constexpr std::string_view kHealthReady = "{\"status\":\"ok\",\"engine\":\"ready\"}\n";
inline constexpr std::string_view kGeneric503 = "{\"error\":\"Service Unavailable\"}\n";
inline constexpr std::string_view kBadRequest = "{\"error\":\"Bad Request\"}\n";
inline constexpr std::string_view kChatBody = R"({"model":"fake-model","messages":[{"role":"user","content":"Hi"}],"max_tokens":2})";

// POSIX: the direct children of `pid` (from every thread's /proc/<pid>/task/<tid>/children). Windows: empty.
std::vector<long> children_of(long pid);
// POSIX: every descendant of `pid`, breadth first. Windows: empty.
std::vector<long> descendants_of(long pid);
// Windows: TokenElevation of process `pid` (true when it cannot be read). POSIX: false.
bool process_token_elevated(long pid);
// A loopback TCP port that was free a moment ago.
std::uint16_t pick_free_port();

struct HttpResult final {
  int status{0};
  std::string body;
};

// One authenticated HTTP/1.1 request to 127.0.0.1:<port>; nullopt if no complete status line arrived in time.
std::optional<HttpResult> http_request(std::uint16_t port, std::string_view method, std::string_view target, std::string_view body,
                                       std::chrono::milliseconds timeout);
bool port_refuses(std::uint16_t port);

// Every member has a default initializer, so designated initializers that name
// only some of them keep compiling when later tasks add members (Task 18: state_dir).
struct ServerOptions final {
  std::vector<std::string> engine_args{};            // each passed as --engine-arg <value>
  std::vector<std::string> extra_args{};             // appended verbatim
  std::map<std::string, std::string> extra_env{};    // added to the server's own environment
  std::optional<std::filesystem::path> engine{};     // default: the fake engine
};

// strata-secure-server as a test child: fixture models (fake-model.gguf, 0600)
// and the byte tokenizer pack in 0700 directories, a free port, token from
// kHarnessTokenEnv; stdout/stderr go to <root>/stdout.log and <root>/stderr.log.
// Windows: started suspended with a non-elevated (LUA-restricted) token in its
// own console process group (so CTRL_BREAK_EVENT can target it) inside a
// kill-on-close harness Job used to count descendants and to clean up.
// Linux: the test process becomes a child subreaper, so descendants orphaned
// by a server that died are re-parented here and reaped by the destructor.
class ServerProcess final {
 public:
  enum class Stop { term, interrupt, kill, ctrl_break };

  static std::unique_ptr<ServerProcess> start(const ServerOptions& options);
  ~ServerProcess();
  ServerProcess(const ServerProcess&) = delete;
  ServerProcess& operator=(const ServerProcess&) = delete;

  [[nodiscard]] long pid() const noexcept { return pid_; }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] const std::filesystem::path& root() const noexcept { return root_; }
  [[nodiscard]] std::optional<HttpResult> get(std::string_view target,
                                              std::chrono::milliseconds timeout = std::chrono::seconds(5)) const;
  [[nodiscard]] std::optional<HttpResult> post_chat(std::string_view body,
                                                    std::chrono::milliseconds timeout = std::chrono::seconds(5)) const;
  [[nodiscard]] bool wait_until_listening(std::chrono::milliseconds timeout);
  [[nodiscard]] bool wait_for_health(std::string_view body, std::chrono::milliseconds timeout) const;
  // POSIX: SIGTERM / SIGINT / SIGKILL (ctrl_break sends SIGINT). Windows: CTRL_BREAK_EVENT to the
  // server's console group for term/interrupt/ctrl_break, TerminateProcess for kill.
  void stop(Stop how);
  // Exit code; POSIX 128 + signal for a signal death.
  [[nodiscard]] std::optional<int> wait_exit(std::chrono::milliseconds timeout);
  [[nodiscard]] bool port_refuses() const;
  [[nodiscard]] std::string stderr_text() const;
  // POSIX: every descendant. Windows: every process in the harness Job except the server.
  [[nodiscard]] std::vector<long> descendants() const;
  // Windows: the harness Job's ActiveProcesses. POSIX: 1 + descendants() while the server lives, else 0.
  [[nodiscard]] unsigned long active_processes();

 private:
  ServerProcess() = default;
  bool launch(const std::vector<std::string>& arguments, const std::map<std::string, std::string>& environment);
  // POSIX: adds the server's current descendants to known_descendants_ (the destructor kills them all).
  void remember_descendants() const;

  std::filesystem::path root_;
  std::uint16_t port_{0};
  long pid_{-1};
  std::optional<int> exit_code_;
  mutable std::set<long> known_descendants_;
#if defined(_WIN32)
  void* process_{nullptr};
  void* job_{nullptr};
#endif
};

}  // namespace test_support

#pragma once

namespace secure_frontend {

// Process-wide defaults every frontend executable (and every test binary
// that opens sockets) installs first thing in main(): a peer that closes a
// socket early must produce an error return from send(), never a SIGPIPE
// that terminates the service. Idempotent. No effect on Windows.
void install_process_defaults() noexcept;

}  // namespace secure_frontend

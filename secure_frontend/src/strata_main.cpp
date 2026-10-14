#include "secure_frontend/strata_cli.hpp"

#include <iostream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

int main(int argc, char** argv) {
  const std::vector<std::string> args(argv + 1, argv + argc);
#if defined(_WIN32)
  const bool interactive = _isatty(_fileno(stdin)) != 0;
#else
  const bool interactive = ::isatty(STDIN_FILENO) == 1;
#endif
  secure_frontend::CliStreams streams{std::cin, std::cout, std::cerr, interactive};
  secure_frontend::CliServices services;
  return secure_frontend::run_strata(args, streams, services);
}

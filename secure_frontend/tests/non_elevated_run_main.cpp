// Windows test launcher: secure_frontend_non_elevated_run <strata-secure-server> <argument>...
//
// Runs the server through the shared non-elevated launch (spec G4: the server
// refuses an elevated token; plan Global Constraint "Elevation in tests (no
// override flag)"), with this process's stdout/stderr, and exits with the
// server's exit code. CTest's PASS/FAIL_REGULAR_EXPRESSION then see the
// server's own output. Exit 125: the launch itself failed.

#if !defined(_WIN32)
#error "secure_frontend_non_elevated_run is Windows-only; Linux CTest runs strata-secure-server directly"
#endif

#include "secure_frontend/win32_prelude.hpp"
#include <shellapi.h>

#include "support/non_elevated_launch.hpp"

#include <cwchar>
#include <iostream>
#include <string>

namespace {

// CommandLineToArgvW quoting rules.
std::wstring quote(const std::wstring& argument) {
  if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) return argument;
  std::wstring out = L"\"";
  for (auto it = argument.begin();; ++it) {
    std::size_t backslashes = 0;
    while (it != argument.end() && *it == L'\\') { ++it; ++backslashes; }
    if (it == argument.end()) { out.append(backslashes * 2, L'\\'); break; }
    if (*it == L'"') { out.append(backslashes * 2 + 1, L'\\'); out.push_back(L'"'); }
    else { out.append(backslashes, L'\\'); out.push_back(*it); }
  }
  out.push_back(L'"');
  return out;
}

}  // namespace

int main() {
  int argc = 0;
  wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);  // UTF-16, no -municode
  if (argv == nullptr || argc < 2) {
    std::cerr << "usage: secure_frontend_non_elevated_run <strata-secure-server> <argument>...\n";
    return 125;
  }
  std::wstring command = quote(argv[1]);
  for (int index = 2; index < argc; ++index) command += L" " + quote(argv[index]);
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  for (HANDLE handle : {startup.hStdInput, startup.hStdOutput, startup.hStdError}) {
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) (void)SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
  }
  PROCESS_INFORMATION info{};
  const std::wstring executable = argv[1];
  LocalFree(argv);
  if (!secure_frontend_test::create_non_elevated_process(executable, command, 0, nullptr, startup, info, "non_elevated_run")) {
    std::cerr << "non_elevated_run: could not launch the server\n";
    return 125;
  }
  (void)ResumeThread(info.hThread);
  CloseHandle(info.hThread);
  (void)WaitForSingleObject(info.hProcess, INFINITE);
  DWORD code = 125;
  (void)GetExitCodeProcess(info.hProcess, &code);
  CloseHandle(info.hProcess);
  return static_cast<int>(code);
}

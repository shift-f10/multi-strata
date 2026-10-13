# Secure frontend portability CI

`secure_frontend` is built as an independent CMake project. This is
deliberate: portability checks must not configure the legacy inference engine,
select a CUDA/HIP/SYCL backend, or need a GPU. The top-level Strata build
includes it only with `-DSTRATA_BUILD_SECURE_FRONTEND=ON` (default `OFF`).

The checked-in presets (`secure_frontend/CMakePresets.json`):

| Preset | Platform and compiler | Role |
| --- | --- | --- |
| `linux-gcc` | Linux, GCC, Ninja | Blocking CI; primary local preset |
| `linux-clang` | Linux, Clang, Ninja | Blocking CI |
| `windows-llvm-mingw-cross` | Linux host, llvm-mingw cross to Windows x86_64 | Blocking CI (compile + link with `-Werror`); locally, `ctest` runs the `.exe` files under wine as a smoke test only |
| `windows-msys2-clang` | Windows, MSYS2 CLANG64 clang | Blocking CI; the only job that runs the tests on real Windows |
| `windows-msvc` | Windows, Visual Studio 2022/MSVC x64 | Informational, non-blocking (`continue-on-error`) |

The Windows toolchain is open source: llvm-mingw and MSYS2 clang. MSVC is kept
only as an informational job. Caveat: CUDA engine builds on Windows still need
MSVC as the nvcc host compiler; that concerns the engine (`src/`), not this
frontend.

## Building locally (Linux)

    scripts/dev/bootstrap-linux.sh          # once; creates .venv-dev (cmake/ninja pinned in requirements.txt; pytest pinned in scripts/dev/requirements-dev.txt)
    export PATH=$PWD/.venv-dev/bin:$PATH
    cd secure_frontend
    cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc

The venv needs no root. The script installs `-r requirements.txt -r
scripts/dev/requirements-dev.txt`: cmake 4.4.3 and ninja 1.13.2 are pinned in
`requirements.txt`; pytest 9.1.1 and its dependencies are pinned in
`scripts/dev/requirements-dev.txt`. Offline use (`STRATA_WHEEL_DIR` set) needs
every wheel those files name **plus** a pip wheel (`pip-*.whl`); on a fresh venv
the pip bootstrap takes pip from `STRATA_WHEEL_DIR` too, so nothing is fetched.

Windows cross build from the same Linux host:

    scripts/dev/bootstrap-llvm-mingw.sh     # pinned llvm-mingw 20261006, sha256 checked
    cd secure_frontend
    cmake --preset windows-llvm-mingw-cross
    cmake --build --preset windows-llvm-mingw-cross
    ctest --preset windows-llvm-mingw-cross # under wine; WINEPREFIX=secure_frontend/out/wineprefix

Windows binaries are cross-compiled with llvm-mingw and smoke-tested under
wine on Linux. wine does not implement Job Objects or protected-file DACLs
faithfully; Windows runtime behavior is validated only by the `windows-msys2-clang`
CI job on a real Windows runner. The `windows-msvc` job is informational.

The cross build produces 20 `.exe` files (three executables, seventeen test
binaries) and `ctest` registers 19 entries on Windows against 20 on Linux:
`secure_frontend_token_reader_tests` is the only UNIX-only target, so the Windows
protected-file reader has no runtime test even in the `windows-msys2-clang` job
yet. `secure_frontend_http_socket_server_tests` is portable and runs the Windows
listener in that job. `engine_process_tests` and `engine_stdio_process_tests`
start and terminate through the Job on MSYS2; the grandchild assertion
(`job_object_terminates_grandchild`) runs only there (it also passes under wine,
which is not authoritative for Job Objects). `secure_frontend_http_socket_server_tests`
and `secure_frontend_engine_stdio_process_tests` carry a 300 s ctest `TIMEOUT`, and
every CI job has `timeout-minutes: 60`.

## Python tests

`pytest -q` from the repository root runs only `tools/` (see `pytest.ini`) and
takes about 20.6 s on the dev host; the owner's pre-push hook runs it. `pytest.ini` ignores
`tools/test_iq_pack.py` (needs llama.cpp's `gguf` module) and
`tools/test_setup_engine_hash.py` (reaches GitHub), and deselects three
`tools/test_setup_choices.py` vision tests that fail against the current
upstream `setup.py`. After merging an upstream Strata update, also run
`pytest serve` explicitly (about 4.5 minutes; the upstream service suite).
`conftest.py` skips numpy-dependent upstream tests when the interpreter running pytest lacks numpy, so the pre-push hook passes with a system pytest; the full set runs in `.venv-dev`.

## Workflow

`.github/workflows/secure-frontend.yml` defines these jobs:

| Job | Runs on | Blocking |
| --- | --- | --- |
| `linux` (matrix `linux-gcc`, `linux-clang`) | ubuntu-latest; `linux-gcc` also runs `pytest -q` | yes |
| `windows-cross` (`windows-llvm-mingw-cross`) | ubuntu-latest; uploads the `.exe` files | yes |
| `windows-msys2` (`windows-msys2-clang`) | windows-latest, MSYS2 CLANG64; runs `ctest` | yes |
| `windows-msvc` | windows-latest | no |
| `top-level-integration` | ubuntu-latest; root CMake with `STRATA_BUILD_SECURE_FRONTEND=ON`, `STRATA_NATIVE_EXPERTS=OFF`, CUDA/HIP off (no llama.cpp clone) | yes |

Network fetches are limited to the GitHub actions, the pip wheels for
`requirements.txt` (cmake/ninja pinned) and `scripts/dev/requirements-dev.txt`
(pytest and its dependencies pinned) and, on a fresh venv, pip itself, MSYS2 packages through `msys2/setup-msys2`, and the pinned,
sha256-checked llvm-mingw tarball. No model is downloaded and no GPU backend is
enabled. Do not change the frontend jobs to configure the repository root: that
would exercise the upstream engine rather than the isolated,
security-sensitive portable frontend.

Status (2026-10-13): all blocking jobs green on run `38458255140` (branch
`ci/windows-runtime-fixes`), after the first real run (`38456682352`) found three
Windows-only failures; see `AGENT_HANDOFF.md` "Verification performed". The
`windows-msys2-clang` preset links with `-static`, so a child started with the
allowlisted environment (no `PATH`) needs no MSYS2 runtime DLL. `windows-msvc`
currently fails at configure (the image ships Visual Studio 2026, the preset
names 2022); it is non-blocking.

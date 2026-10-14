# Secure frontend portability CI

`secure_frontend` is built as an independent CMake project. This is
deliberate: portability checks must not configure the inference engine, select
a CUDA/HIP/SYCL backend, or need a GPU. Upstream Strata (the engine) is the git
submodule `upstream/`; the presets below never read it. Our root
`CMakeLists.txt` builds `secure_frontend/` together with the engine from
`upstream/` (see "Root build").

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
MSVC as the nvcc host compiler; that concerns the engine (`upstream/src/`), not
this frontend.

## Getting the code

    git clone --recurse-submodules https://github.com/shift-f10/multi-strata.git
    # or, after a plain clone:
    git submodule update --init

The presets need no submodule. `pytest -q` and the root build do; both stop
with "run `git submodule update --init`" when `upstream/` is empty.

After a `git pull` that moves the gitlink, run `git submodule update --init`
again (or set `git config submodule.recurse true` once). A `+` at the start of
the `git submodule status` line means the checked-out `upstream/` commit differs
from the recorded gitlink (behind, ahead or elsewhere).

## Building locally (Linux)

    scripts/dev/bootstrap-linux.sh          # once; creates .venv-dev from scripts/dev/requirements-dev.txt
    export PATH=$PWD/.venv-dev/bin:$PATH
    cd secure_frontend
    cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc

The venv needs no root. The script installs `-r
scripts/dev/requirements-dev.txt` only: cmake 4.4.3, ninja 1.13.2, regex
2026.9.10, pytest 9.1.1 and pytest's dependencies. Upstream's
`upstream/requirements.txt` is not installed. Offline use (`STRATA_WHEEL_DIR`
set) needs every wheel that file names **plus** a pip wheel (`pip-*.whl`); on a
fresh venv the pip bootstrap takes pip from `STRATA_WHEEL_DIR` too, so nothing
is fetched.

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

## Root build

    cmake -S . -B out/root -G Ninja
    cmake --build out/root
    ctest --test-dir out/root

Our root `CMakeLists.txt` adds `secure_frontend/` first, then `upstream/`
unmodified. It seeds `STRATA_ENABLE_CUDA=OFF`, `STRATA_ENABLE_HIP=OFF` and
`STRATA_NATIVE_EXPERTS=OFF` as cache defaults (a `-D` overrides them), so the
default build needs no GPU SDK and fetches nothing (no `out/root/_deps`). It
defaults `CMAKE_BUILD_TYPE` to `Release` before upstream sees it and declares
`SECURE_FRONTEND_WERROR=ON`, so `-DSTRATA_WERROR=OFF` does not drop the
frontend's `-Werror`. `-DSECURE_STRATA_BUILD_ENGINE=OFF` builds only the
frontend and works with an empty `upstream/`. From clean: 94 Ninja steps, 0
warnings, `ctest` 20/20 (the frontend's tests; upstream registers none at
`v0.1.43` because `STRATA_BUILD_TESTS` is `OFF`).

## Python tests

`pytest -q` from the repository root runs only `tools/secure/` (see
`pytest.ini`): the GLM tokenizer wrapper tests and the secure distribution
check tests, 13 in all; the owner's pre-push hook runs it. `conftest.py` stops
the run with "run `git submodule update --init`" when `upstream/` is empty.
Upstream's own suites run only after a submodule bump ("Updating upstream").

## Updating upstream

The order and the exact commands are in `docs/PROVENANCE.md`, "Updating the
baseline" (the single source of truth); in short:

1. `git -C upstream fetch --tags origin`, then
   `git -C upstream checkout --detach <tag>`.
2. Run the gates, each with its working directory:

       pytest -q                                   # repo root
       ( cd secure_frontend && cmake --preset linux-gcc && cmake --build --preset linux-gcc \
         && ctest --preset linux-gcc )             # subshell: the shell stays at the repo root
       # in secure_frontend/: the windows-llvm-mingw-cross build (and wine ctest), above
       cmake -S . -B out/root -G Ninja && cmake --build out/root \
         && ctest --test-dir out/root && test ! -e out/root/_deps   # repo root, fresh dir

   Then upstream's own suites in a separate venv (upstream's pins win there).
   `python3 -m venv` may lack `ensurepip`, so create it without pip and fill
   it with the dev venv's pip (repo root):

       python3 -m venv --without-pip out/venv-upstream
       .venv-dev/bin/pip --python out/venv-upstream/bin/python install \
         -r scripts/dev/requirements-dev.txt -r upstream/requirements.txt

   and run them **from `upstream/`** (four `tools/` tests resolve `tools/...`
   against the working directory; our root `pytest.ini` stays the rootdir, so
   the `--deselect` ids keep the `upstream/tools/` prefix):

       ( cd upstream && ../out/venv-upstream/bin/pytest -q tools \
         --ignore=tools/test_iq_pack.py \
         --ignore=tools/test_setup_engine_hash.py \
         --deselect upstream/tools/test_setup_choices.py::HipVision::test_the_cpu_encoder_is_built_once \
         --deselect upstream/tools/test_setup_choices.py::HipVision::test_without_images_nothing_changes \
         --deselect upstream/tools/test_setup_choices.py::CudaVision::test_the_encoder_is_built_native \
         && ../out/venv-upstream/bin/pytest -q serve )   # about 4.5 minutes; subshell keeps the cwd

   At `v0.1.43`: `616 passed, 2 skipped, 3 deselected` and `695 passed, 11
   skipped`. The two ignores need llama.cpp's `gguf` module and GitHub
   respectively; the three deselects are recorded upstream drift against its
   `setup.py`. Drop an exclusion once the new tag no longer needs it.

   Re-audit upstream's top-level CMake assumptions (layout spec §3 table):
   new `FetchContent`, option defaults, a `tests/CMakeLists.txt` that would
   flip `STRATA_BUILD_TESTS`. Re-check the SP5 pass-through table against the
   new engine's flags and protocol, and the upstream internals
   `tools/secure/secure_tokenizer.py` relies on (listed in its module
   docstring: `Tokenizer._re`, the `__init__` argument order, the `extract()`
   output path `tokenizer/tokenizer.json`, which `extract()` now refuses to
   create if upstream did not write it).
3. `git -C upstream status --porcelain` is empty and `git submodule status`
   shows no `-`/`U` (`+` is expected until the pointer is staged).
4. Update `docs/PROVENANCE.md` "Baseline", then run
   `git grep -n '<old tag>\|<old short sha>' -- ':!docs/superpowers' ':!upstream'`
   and update every current-pin hit; leave verification history (rows that
   record what was verified at an older pin) untouched. The authoritative
   list of pin sites is `docs/PROVENANCE.md` step 4.
5. `git add upstream docs/PROVENANCE.md` plus every file touched in step 4;
   one commit: `upstream: bump to <tag>`.

## Offline checkout

An offline box cannot fetch the submodule. The offline kit carries a git bundle
of the pinned upstream commit next to the bundle of our repository:

    git -C upstream bundle create ../out/upstream-v0.1.43-7695859a.bundle v0.1.43
    git bundle verify out/upstream-v0.1.43-7695859a.bundle

On the offline box, after cloning our repository from its bundle:

    git submodule init
    git config submodule.upstream.url /path/to/upstream-v0.1.43-7695859a.bundle
    git -c protocol.file.allow=always submodule update
    git submodule status   # 7695859aa13afb248bdb4d36f9b2e95707db079d upstream (v0.1.43)

The bundle holds tag `v0.1.43` (tag object
`16374b3e6dfe452a163c3a961ae5faa3b4aec84b`, commit
`7695859aa13afb248bdb4d36f9b2e95707db079d`).

## Workflow

`.github/workflows/secure-frontend.yml` defines these jobs:

| Job | Runs on | Submodule | Blocking |
| --- | --- | --- | --- |
| `linux` (matrix `linux-gcc`, `linux-clang`) | ubuntu-latest; `linux-gcc` also checks that `pytest -q` collects `tools/secure/` only and runs it | yes (pytest) | yes |
| `windows-cross` (`windows-llvm-mingw-cross`) | ubuntu-latest; uploads the `.exe` files | no | yes |
| `windows-msys2` (`windows-msys2-clang`) | windows-latest, MSYS2 CLANG64; runs `ctest` | no | yes |
| `windows-msvc` | windows-latest | no | no |
| `top-level-integration` | ubuntu-latest; first configures **our** root with no `-D` flags (`out/root-defaults`, configure only) and asserts `STRATA_NATIVE_EXPERTS`/`STRATA_ENABLE_CUDA`/`STRATA_ENABLE_HIP` `OFF`, `CMAKE_BUILD_TYPE=Release` and no `_deps`; then configures it with CUDA/HIP/native experts off, builds `strata-secure-server`, `secure_frontend_config_tests`, `strata-plan`, runs `ctest -R secure_frontend_config_tests`, checks no `out/root/_deps` | yes | yes |

The jobs that check out the submodule end with the step "upstream submodule
pinned and unmodified": `git submodule status` must show no `+`/`-`/`U` prefix
and `git -C upstream status --porcelain` must be empty. The
`top-level-integration` display name is now "top-level-integration (our root
CMake + upstream/ engine)"; a branch-protection rule that names the old check
("root CMake with STRATA_BUILD_SECURE_FRONTEND=ON") must be updated.

Network fetches are limited to the GitHub actions, the upstream submodule at
depth 1 in `linux` and `top-level-integration` (about a 19.7 MB pack, 50.7 MB
and 2,976 files checked out), the pip wheels pinned in
`scripts/dev/requirements-dev.txt` and, on a fresh venv, pip itself, MSYS2
packages through `msys2/setup-msys2`, and the pinned, sha256-checked
llvm-mingw tarball. No model is downloaded and no GPU backend is enabled. Do
not change the frontend preset jobs to configure the repository root: that
would exercise the upstream engine rather than the isolated,
security-sensitive portable frontend.

Path filters: the workflow runs on changes to `secure_frontend/**`,
`CMakeLists.txt`, `scripts/**`, `pytest.ini`, `conftest.py`, `tools/**`,
`upstream` (the gitlink), `.gitmodules` and the workflow file. `tools/**` is
kept because our own `tools/secure/` tests live there (layout spec U10).

Status (2026-10-13): all blocking jobs green on run `38458255140` (branch
`ci/windows-runtime-fixes`), before the submodule layout, and on run
`38478775552` (branch `layout/upstream-submodule` @ `4aa742c9`), the first run
after it: all five blocking jobs green, `top-level-integration` building our
root with the `upstream/` engine. The
`windows-msys2-clang` preset links with `-static`, so a child started with the
allowlisted environment (no `PATH`) needs no MSYS2 runtime DLL. `windows-msvc`
currently fails at configure (the image ships Visual Studio 2026, the preset
names 2022); it is non-blocking.

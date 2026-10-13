# Secure frontend portability CI

`secure_frontend` is built as an independent CMake project. This is
deliberate: portability checks must not configure the legacy inference engine,
select a CUDA/HIP/SYCL backend, fetch dependencies, or need a GPU.

The checked-in presets cover the supported native toolchains:

| Preset | Platform and compiler |
| --- | --- |
| `linux-gcc` | Linux, GCC |
| `linux-clang` | Linux, Clang |
| `windows-msvc` | Windows, Visual Studio 2022/MSVC x64 |

Run a preset from the `secure_frontend` directory:

```sh
cmake --preset linux-gcc
cmake --build --preset linux-gcc --parallel
ctest --preset linux-gcc
```

Use `linux-clang` or `windows-msvc` in place of `linux-gcc` for the other
toolchains. The Windows preset is intended for a Visual Studio developer
environment (including the GitHub Actions Windows runner).

## Building locally (Linux)

    scripts/dev/bootstrap-linux.sh          # once; creates .venv-dev with pinned cmake/ninja/pytest
    export PATH=$PWD/.venv-dev/bin:$PATH
    cd secure_frontend
    cmake --preset linux-gcc && cmake --build --preset linux-gcc && ctest --preset linux-gcc

The venv needs no root. For an offline machine, pre-download the wheels from
`requirements.txt` into a directory and run the script with
`STRATA_WHEEL_DIR=/path/to/wheels`.

`pytest -q` from the repository root runs only `tools/` (see `pytest.ini`).
After merging an upstream Strata update, also run `pytest serve` explicitly.

The `Secure frontend portability` workflow runs this exact matrix. It checks
out the repository but downloads no build dependencies; the CMake project is
dependency-free and the workflow installs no packages. Do not change it to
configure the repository root: that would exercise the upstream engine rather
than the isolated, security-sensitive portable frontend.

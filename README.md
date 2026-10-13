# Secure Strata (multi-strata)

This repository (`shift-f10/multi-strata`) builds a security- and privacy-first frontend around [Niko1221/Strata](https://github.com/Niko1221/Strata/tree/v0.1.43) and is a mixture of the sources below. Upstream Strata is not copied into this tree: it is the git submodule [`upstream/`](upstream/), pinned at `v0.1.43` and never modified. The repository root holds only our code.

Get the code with the submodule: `git clone --recurse-submodules https://github.com/shift-f10/multi-strata.git`, or run `git submodule update --init` after a plain clone.

## Sources and credits

| Source | What we took from it | Revision | License |
| --- | --- | --- | --- |
| [Niko1221/Strata](https://github.com/Niko1221/Strata/tree/v0.1.43) | The engine, Python server, installer and docs, used unmodified from the git submodule `upstream/`. This project started as a fork of it. | tag `v0.1.43`, commit `7695859aa13afb248bdb4d36f9b2e95707db079d` (the `upstream` gitlink) | MIT, Copyright (c) 2026 Niko1221 and the Strata contributors ([`upstream/LICENSE`](upstream/LICENSE); the line is retained in our [`LICENSE`](LICENSE)) |
| [robertkarl/UnbiasedStrata](https://github.com/robertkarl/UnbiasedStrata/tree/46c46ecfc11d2315512f21f7549b0a7792ccd2ae) | Security-design ideas only (smaller, offline-verifiable runtime; reduced service attack surface). No code copied. | commit `46c46ecfc11d2315512f21f7549b0a7792ccd2ae` | MIT (per the GitHub license API, 2026-10-13; see [`docs/PROVENANCE.md`](docs/PROVENANCE.md)); no code taken, so it governs nothing here |
| [lighttransport/Strata](https://github.com/lighttransport/Strata/tree/glm53f) | GLM-5.3 compatibility reference: the native GLM-5.3 serving profile and `glm4` / `chatglm-bpe` tokenizer handling were implemented against its observable contracts (the tokenizer regex was transcribed from its `tools/strata_tokenizer.py` into our wrapper [`tools/secure/secure_tokenizer.py`](tools/secure/secure_tokenizer.py)). Its engine and kernels are not ported yet. | branch `glm53f`, commit `4894c9967f5754a2052d7b05f10a01b6071bb6e4` | MIT, Copyright (c) 2026 Niko1221 and the Strata contributors (per the GitHub API, 2026-10-13; see [`docs/PROVENANCE.md`](docs/PROVENANCE.md)) |
| [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp) / ggml | Comes with upstream Strata, unchanged by us: `upstream/third_party/ggml` and the pinned llama.cpp checkout its build fetches (only with `STRATA_NATIVE_EXPERTS=ON`). | commit `3cf03257f219afbe7334045ff7c6a06ac68c627d` | MIT ([`upstream/third_party/ggml/LICENSE`](upstream/third_party/ggml/LICENSE)) |
| [mstorsjo/llvm-mingw](https://github.com/mstorsjo/llvm-mingw) | Build tool only: the open-source Windows cross toolchain, fetched by `scripts/dev/bootstrap-llvm-mingw.sh` with a pinned sha256. Nothing from it is in this tree. | release `20261006` | GitHub API reports `NOASSERTION` (Other); its `LICENSE` puts the llvm-mingw scripts under ISC, bundled components keep their own licenses (see [`docs/PROVENANCE.md`](docs/PROVENANCE.md)) |

## What is different here

- **Exists:** a dependency-free native C++20 security frontend that owns the listener and starts the unmodified upstream engine as a private child process over standard I/O. It does not yet replace the upstream Python service in a release. See [`secure_frontend/`](secure_frontend/).
- **Exists:** a bearer token is required on every listener, including loopback; the default bind is loopback, and remote and wildcard binds need separate opt-ins. See [`docs/security/threat-model.md`](docs/security/threat-model.md).
- **Planned:** the token is generated for the user and used by the client automatically, so it is never typed. Today it must be supplied. See the [product spec](docs/superpowers/specs/2026-10-13-product-experience-and-upstream-tracking-design.md).
- **Planned:** no telemetry, no update checks, no automatic downloads; network use only in an explicit, digest-verified `pull` or `update`. The native frontend has no download or outbound code today, but the upstream Python service is still in the `upstream/` submodule, so nothing here is privacy-hardened yet. See [`docs/AGENT_HANDOFF.md`](docs/AGENT_HANDOFF.md).
- **Exists:** Linux and Windows builds with an open-source Windows toolchain (llvm-mingw, MSYS2 clang) and CI on real Windows. Nothing has run on a GPU or against a real engine yet. See [`docs/secure-frontend-ci.md`](docs/secure-frontend-ci.md).
- **Exists:** security acceptance tests specified by ID, to run hermetically. Most are not automated yet. See [`tests/security/README.md`](tests/security/README.md).
- **Exists:** upstream stays trackable: it is a pinned, unmodified git submodule, and an update is a pointer bump plus the gates. See [`docs/PROVENANCE.md`](docs/PROVENANCE.md).
- **Exists:** a fixed GLM-5.3 serving profile and GLM tokenizer handling. The GLM engine port is planned. See [`docs/AGENT_HANDOFF.md`](docs/AGENT_HANDOFF.md).
- **Planned:** an Ollama-style `strata` CLI (`pull`, `run`, `serve`, `list`). It does not exist yet. See the [product spec](docs/superpowers/specs/2026-10-13-product-experience-and-upstream-tracking-design.md).

Nothing here is released. The full attribution record is [`docs/PROVENANCE.md`](docs/PROVENANCE.md); current status is in [`docs/AGENT_HANDOFF.md`](docs/AGENT_HANDOFF.md).

---

Upstream Strata's README: [`upstream/README.md`](upstream/README.md).

# Privacy migration inventory

## Purpose

This is a deliberately narrow inventory of known network-capable paths in the
Strata `v0.2.1.3` baseline. It prevents the native frontend migration from
accidentally retaining an implicit outbound behavior. It is not an assertion
that these paths are malicious: several are normal, user-visible installer or
optional image/MCP features. They are incompatible with the secure release
profile until replaced by a reviewed explicit action.

## Secure-release rule

The default build and normal service lifecycle must not make an outbound
connection or DNS lookup. A release may include no analytics, telemetry upload,
crash upload, update check, remote configuration, advertising, or automatic
download client.

The only allowed future network operation is the user-invoked `acquire`
command specified in [`threat-model.md`](threat-model.md). It must be separate
from the server and its HTTP API.

## Baseline paths to quarantine or replace

| Baseline area | Current capability | Secure migration action |
| --- | --- | --- |
| `upstream/START-HERE.bat` | May download Python from `python.org`. | Do not use in secure packaging. Ship a native executable or make dependency acquisition a separate explicit action. |
| `upstream/setup.py` | Downloads models, engine releases, llama.cpp, Python packages, and GPU support assets; performs network probes. | Replace with offline local-artifact inventory plus the explicit digest-verified `acquire` command. Do not reuse its startup flow. |
| `upstream/update.sh`, `upstream/UPDATE.bat` | Updates from GitHub/git or a ZIP. | Exclude from secure distribution until a separately designed, signed, user-invoked updater exists. No automatic update check. |
| `upstream/serve/server.py` image handling | Can fetch HTTP(S) image URLs supplied in requests. | Native API accepts local/base64 image bytes only in the first secure release. Reject remote image URLs. |
| `upstream/serve/mcp.py` | Can contact configured MCP HTTP endpoints and launch tool servers. | Exclude from default native build. MCP, tools, and plugins remain disabled. |
| `upstream/serve/telemetry.py`, `upstream/serve/prometheus.py` | Local hardware/request monitoring and metrics surfaces. | These are not evidence of outbound analytics, but the native release must make local metrics opt-in, token-protected, and documented. |
| `upstream/serve/web/` | Browser UI includes static external links. | Do not ship a web UI in the initial native boundary; if reintroduced, use only bundled assets and no third-party runtime resources. |
| `upstream/setup.sh` (macOS branch, since `v0.1.44`) | Downloads a standalone Python from `github.com/astral-sh/python-build-standalone` (SHA-256 pinned). | Same as `START-HERE.bat`: not used in secure packaging. |
| `upstream/metal/setup_mac.py` (new in `v0.1.44`, run by `setup.py` on macOS) | Downloads Apple's metal-cpp zip, model shards and the vision mmproj; builds the engine. | Same as `setup.py`. macOS is not a target of this project. |
| Image generation (`upstream/tools/image/`, `upstream/serve/images.py`, `setup.py --images`, new in `v0.1.44`) | Setup downloads stable-diffusion.cpp/ggml zips (GitHub), the LunarG Vulkan SDK and image models (Hugging Face); the server adds `POST /v1/images/generations` and `GET /v1/images/files/<id>` and runs a local `sd-cli` subprocess when the config has an `images` section. | Exclude from the native build; no image generation in the first secure release. |

## Verification work required before release

1. Add hermetic tests for `PRIV-01` through `PRIV-04` in
   [`../../tests/security/README.md`](../../tests/security/README.md).
2. Monitor socket creation and DNS resolution around startup, inference,
   failure/restart, and shutdown on Windows and Linux.
3. Produce a release manifest that lists every linked component with potential
   network capability and states whether it is compiled in, reachable, and
   user-triggered.
4. Review the final executable's imports/dependencies and configuration surface
   for telemetry, update, crash-reporting, and remote-configuration clients.
5. Keep legacy Python installer/service files out of the secure package until
   their replacement has passed these checks.

## Evidence baseline

The current inventory was derived from direct source review on 2026-10-11
Pacific time, re-reviewed against `v0.1.44.1` on 2026-10-14 (three rows added),
and re-reviewed against `v0.2.1.3` on 2026-10-20 (no row changed: every named
reference still exists; upstream added `apps/desktop` and `apps/host`, which
are not part of any package we stage — SP7 packaging must exclude them).
Representative network-capable references include
`upstream/START-HERE.bat`, `upstream/setup.py`, `upstream/UPDATE.bat`, `upstream/update.sh`, `upstream/serve/server.py`, and
`upstream/serve/mcp.py` (the baseline is the `upstream/` submodule). Future agents must update this inventory when adding or
removing a network-capable code path.

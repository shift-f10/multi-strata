# Privacy migration inventory

## Purpose

This is a deliberately narrow inventory of known network-capable paths in the
Strata `v0.1.43` baseline. It prevents the native frontend migration from
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
| `START-HERE.bat` | May download Python from `python.org`. | Do not use in secure packaging. Ship a native executable or make dependency acquisition a separate explicit action. |
| `setup.py` | Downloads models, engine releases, llama.cpp, Python packages, and GPU support assets; performs network probes. | Replace with offline local-artifact inventory plus the explicit digest-verified `acquire` command. Do not reuse its startup flow. |
| `update.sh`, `UPDATE.bat` | Updates from GitHub/git or a ZIP. | Exclude from secure distribution until a separately designed, signed, user-invoked updater exists. No automatic update check. |
| `serve/server.py` image handling | Can fetch HTTP(S) image URLs supplied in requests. | Native API accepts local/base64 image bytes only in the first secure release. Reject remote image URLs. |
| `serve/mcp.py` | Can contact configured MCP HTTP endpoints and launch tool servers. | Exclude from default native build. MCP, tools, and plugins remain disabled. |
| `serve/telemetry.py`, `serve/prometheus.py` | Local hardware/request monitoring and metrics surfaces. | These are not evidence of outbound analytics, but the native release must make local metrics opt-in, token-protected, and documented. |
| `serve/web/` | Browser UI includes static external links. | Do not ship a web UI in the initial native boundary; if reintroduced, use only bundled assets and no third-party runtime resources. |

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
Pacific time. Representative network-capable references include
`START-HERE.bat`, `setup.py`, `UPDATE.bat`, `update.sh`, `serve/server.py`, and
`serve/mcp.py`. Future agents must update this inventory when adding or
removing a network-capable code path.

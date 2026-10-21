# Owner-box validation index

Everything in this repository that **cannot** be proven on the Linux dev host lives here,
in one place, with its current status. Agents prove only the local gates
(`linux-gcc`, release preset, `windows-llvm-mingw-cross` compile-only, pytest, TSan);
every claim below waits for the owner's own hardware (owner rulings 2026-10-20/21).

## Windows runtime

- **What:** the `windows-runtime`-labelled ctest cases (300+ registered in the cross
  preset; excluded from Linux suites) plus the SP3/SP4 real-Windows proofs.
- **How:** native build on a Windows box per `docs/AGENT_HANDOFF.md` ("Update upstream"
  and CI-era job definitions, which remain runbooks though Actions are disabled).
- **Status:** last CI-authorized proof: green `windows-msys2-clang` at `7bddb9e1`
  (v0.2.1.3 pin). Newer `windows-runtime` cases added by SP3 M2 (two named cases with
  write-stall volume risk) and SP5 M1 (idle-unload/lifecycle, serve foreground, vision)
  have **no runtime proof yet**.

## GPU validation kits

1. **SP3 API kit** — `docs/validation/sp3-api-kit.md` + `strata-api-probe`
   (modes `stream`, `nonstream`, `cancel-after=<n>`, `cancel-during-prefill`,
   `concurrent=<k>`, `utf8`, `seed`). Status: defined, **not yet run**.
2. **SP5 parity acceptance kit** — `docs/validation/sp5-parity-kit.md` + probe corpus
   mode (delivered by SP5 M2 Task 9). Runs the same corpus against plain upstream
   `serve` (v0.2.1.3 engine) and `strata serve`, plus the Maya `v1.1.8` side vs our
   `glm53` profile; results file is hashed into `docs/PROVENANCE.md` as the SP5
   acceptance entry. Status: pending SP5 M2 merge; **run is owner-side**.
3. **SP6 GLM eval kit** — `tools/glm-eval/*` per the SP6 design; blocked on the
   owner's decision sheet (`docs/superpowers/handoff/2026-10-16-controller-resume.md` §5.1).

## Parked for the owner (decisions, not runs)

- `secure_frontend_api_server_tests.log_line_format_and_rate_limit` — pre-existing M1
  token-bucket timing flake: fails only under heavy suite/TSan load; 10/10 in isolation
  every time measured (lane baseline, M1 merge battery, M2 battery, and again 10/10 on
  2026-10-22 during SP5 M2). Fix or accept.
- SP6 decision sheet (S1–S7, M1–M7), presented 2026-10-14, unanswered.

## How to record results

Run a kit, keep its results file, and commit a `docs/PROVENANCE.md` row: kit name, date,
host, commit sha tested, results file SHA-256, verdict. Agents then cite that row as the
authority for the claim — never the run output itself.

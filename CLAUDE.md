# Secure Strata — agent entry point

**Before doing anything in this repository, read, in this order:**

1. `docs/superpowers/handoff/2026-10-16-controller-resume.md` — the orchestration-level state: what is built, the owner's binding rules, how work is run (sub-controllers, briefs, the merge gate), decisions already taken, what waits on the owner, the exact resume procedure, and the first GPU-box checklist. The project is **stopped by the owner** until he says otherwise; do not start work on your own.
2. `docs/AGENT_HANDOFF.md` — the code-level truth: every deliverable, its proof status, known gaps. It is updated as part of every change.
3. `docs/PROVENANCE.md` and `docs/security/threat-model.md` before touching code.

Sub-controllers and implementers also read `docs/superpowers/handoff/briefs/subcontroller-common.md` and their lane brief.

## Non-negotiable rules (full text in the resume document, §2)

- Touch only what the owner names. No paid services. `upstream/` is never modified.
- Agents never push, merge, rebase, switch branches, or install outside `.venv-dev/` and `.toolchains/`.
- Commit author `shift-f10 <testdaflow.tv@gmail.com>`; two literal trailer lines in every commit (`Co-Authored-By: <model> <noreply@anthropic.com>` and the `Claude-Session:` URL of the current session). Existing trailers are never rewritten.
- No `rm -rf`, `git clean -fd*`, or bypass flags. Retire worktrees by moving them out, then `git worktree prune`.
- `-Werror` everywhere; TDD with RED evidence; a test is never weakened to pass.
- Windows claims come only from the `windows-msys2-clang` CI job; GPU claims only from the owner's box. Update `docs/AGENT_HANDOFF.md` with every change.

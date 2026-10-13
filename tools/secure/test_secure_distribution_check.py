"""scripts/secure_distribution_check.py: quarantined content is rejected at any depth.

Hermetic: every case builds a throwaway staging directory under tmp_path.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "secure_distribution_check", ROOT / "scripts" / "secure_distribution_check.py")
check = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check)


def stage(tmp_path: Path, *files: str) -> Path:
    root = tmp_path / "stage"
    root.mkdir()
    for relative in files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
    return root


def flagged(errors: list[str], relative: str) -> bool:
    return any(error.startswith(relative.lower() + ":") for error in errors)


def test_nested_upstream_requirements_is_rejected(tmp_path):
    errors = check.inspect(stage(tmp_path, "upstream/requirements.txt"), False)
    assert flagged(errors, "upstream/requirements.txt"), errors


def test_nested_upstream_serve_asset_is_rejected(tmp_path):
    errors = check.inspect(stage(tmp_path, "upstream/serve/index.html", "upstream/setup.sh"), False)
    assert flagged(errors, "upstream/serve/index.html"), errors
    assert flagged(errors, "upstream/setup.sh"), errors


def test_forbidden_file_below_the_root_is_rejected(tmp_path):
    files = ["vendor/strata/requirements.txt", "vendor/strata/docs/MCP_SERVER.md", "opt/START-HERE.bat"]
    errors = check.inspect(stage(tmp_path, *files), False)
    for relative in files:
        assert flagged(errors, relative), (relative, errors)


def test_forbidden_directory_below_the_root_is_rejected(tmp_path):
    files = ["pkg/serve/index.html", "pkg/sycl/serve/app.js", "pkg/.strata-mcp/state.json"]
    errors = check.inspect(stage(tmp_path, *files), False)
    for relative in files:
        assert flagged(errors, relative), (relative, errors)


def test_native_only_stage_passes(tmp_path):
    assert check.inspect(stage(tmp_path, "bin/strata-secure-server"), False) == []


def test_lookalike_names_pass(tmp_path):
    files = ["share/doc/upstream-notes.txt", "bin/requirements.txt.sig", "bin/observe/index.html"]
    assert check.inspect(stage(tmp_path, *files), False) == []

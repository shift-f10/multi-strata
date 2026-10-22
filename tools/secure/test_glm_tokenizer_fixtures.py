r"""The committed GLM fixtures and Unicode class tables are exactly what the generator writes.

SP6 §5.5 pins the frontend's GLM split with two generated files:
  secure_frontend/tests/fixtures/glm-tokenize.txt
  secure_frontend/src/glm_pretokenizer_tables.hpp
Both come from tools/secure/gen_glm_tokenizer_fixtures.py, which classifies with the venv's
`regex` module.  This guard regenerates them and refuses drift: a `regex` upgrade changes
what `\p{L}`, `\p{N}` and `\s` mean, and that must not silently move what the frontend's C++
tokenizer accepts - it has to arrive as a regenerated, reviewed, committed diff.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURE = ROOT / "secure_frontend" / "tests" / "fixtures" / "glm-tokenize.txt"
TABLES = ROOT / "secure_frontend" / "src" / "glm_pretokenizer_tables.hpp"


def test_committed_fixture_and_tables_are_up_to_date(tmp_path):
    fixture = tmp_path / "glm-tokenize.txt"
    tables = tmp_path / "glm_pretokenizer_tables.hpp"
    subprocess.run([sys.executable, str(HERE / "gen_glm_tokenizer_fixtures.py"),
                    "--fixture", str(fixture), "--tables", str(tables)],
                   check=True, cwd=tmp_path)
    assert fixture.read_bytes() == FIXTURE.read_bytes(), \
        "tests/fixtures/glm-tokenize.txt is stale: rerun tools/secure/gen_glm_tokenizer_fixtures.py"
    assert tables.read_bytes() == TABLES.read_bytes(), \
        "src/glm_pretokenizer_tables.hpp is stale: rerun tools/secure/gen_glm_tokenizer_fixtures.py"


def test_the_fixture_carries_its_declared_pack_and_case_count():
    """A structural read of the committed fixture: the C++ case depends on this shape."""
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    body = [line for line in lines if line and not line.startswith("#")]
    tags = [line.split(" ", 1)[0] for line in body]
    assert body[0] == "PRE glm4", "the fixture declares the scheme it was generated under, first"
    assert tags.count("CASE") == 200 and tags.count("PIECES") == 200 and tags.count("IDS") == 200
    assert tags.count("VOCAB") > 256, "the pack carries the 256 byte symbols plus its whole pieces"
    assert tags.count("MERGE") == 6, "the pack carries merge ranks: the leftovers of ignore_merges"

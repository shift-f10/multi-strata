"""SP5 M1 Task 15: the README parity blocks mirror the parity table for the whole
generated option inventory (plan Task 15 Step 1) — every inventory name lands in the
block for its disposition, and the mirror is proven non-vacuous by row count."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROW = re.compile(r'^\s*\{"([^"]+)", (kTyped|kRejected|kMapped), ([a-z_]+), "(.*)"\},?$', re.M)
ARRAY = re.compile(r"kUpstream(?:ConfigKeys|EnvKnobs)\[\] = \{(.*?)\};", re.S)
NAME = re.compile(r'"([^"]+)"')
BLOCK = {"kTyped": "parity-typed", "kRejected": "parity-rejected", "kMapped": "parity-mapped"}


def region(readme: str, marker: str) -> str:
    begin, end = f"<!-- {marker}:begin -->", f"<!-- {marker}:end -->"
    start, stop = readme.index(begin), readme.index(end)
    assert start < stop, f"{marker}: end before begin"
    return readme[start + len(begin):stop]


def test_parity_readme_coverage() -> None:
    table = (REPO / "secure_frontend/src/parity_table.cpp").read_text(encoding="utf-8")
    rows = ROW.findall(table)
    assert len(rows) == 121, f"the parity table shape changed ({len(rows)} rows parsed) — update this gate and the README"

    inventory = (REPO / "secure_frontend/tests/parity_keys_upstream.hpp").read_text(encoding="utf-8")
    names = [name for body in ARRAY.findall(inventory) for name in NAME.findall(body)]
    assert len(names) == 118, f"the generated inventory changed ({len(names)} names) — re-run the pin greps"
    row_names = {row[0] for row in rows}
    missing_rows = [name for name in names if name not in row_names]
    assert not missing_rows, f"inventory names with no parity row: {missing_rows}"

    readme = (REPO / "secure_frontend/README.md").read_text(encoding="utf-8")
    blocks = {marker: region(readme, marker) for marker in BLOCK.values()}
    found = 0
    missing = []
    for name, disposition, _destination, _citation in rows:
        if re.search(rf'^\| `{re.escape(name)}` \|', blocks[BLOCK[disposition]], re.M):
            found += 1
        else:
            missing.append(f"{name} ({disposition})")
    assert not missing, f"parity rows absent from the README block for their disposition: {missing}"
    assert found >= 80, f"the README mirror counts only {found} rows — too few to be real"

    # The auto-rendered config table (gate: the C++ readme_config_table_matches_schema)
    # must also be present here as a real table; the floor catches a truncated paste.
    assert len(re.findall(r"^\| `", region(readme, "config-keys"), re.M)) >= 100, "the config table looks truncated"

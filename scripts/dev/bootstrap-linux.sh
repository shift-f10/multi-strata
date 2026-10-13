#!/usr/bin/env bash
# Creates the project-local developer environment for the secure frontend on
# Linux without root: a venv holding the pinned cmake/ninja/pytest wheels from
# requirements.txt. Idempotent. Works offline when the wheels are already in
# the pip cache or in $STRATA_WHEEL_DIR.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
venv="$repo/.venv-dev"
python="${PYTHON:-python3}"

if [[ ! -x "$venv/bin/python" ]]; then
  "$python" -m venv --without-pip "$venv"
fi
if [[ ! -x "$venv/bin/pip" ]]; then
  # Debian/Ubuntu images often lack ensurepip; bootstrap pip from the system pip.
  if "$python" -m pip --version >/dev/null 2>&1; then
    "$python" -m pip download --no-deps -q -d "$venv/.pip-bootstrap" pip
    "$venv/bin/python" "$venv/.pip-bootstrap"/pip-*.whl/pip install --no-index --find-links "$venv/.pip-bootstrap" pip
  else
    echo "bootstrap-linux: neither ensurepip nor a system pip is available" >&2
    exit 1
  fi
fi
pip_args=(-q -r "$repo/requirements.txt" pytest)
if [[ -n "${STRATA_WHEEL_DIR:-}" ]]; then
  pip_args=(--no-index --find-links "$STRATA_WHEEL_DIR" "${pip_args[@]}")
fi
"$venv/bin/pip" install "${pip_args[@]}"
echo "bootstrap-linux: ready. Use: export PATH=$venv/bin:\$PATH"
"$venv/bin/cmake" --version | head -1
"$venv/bin/ninja" --version

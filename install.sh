#!/bin/sh
set -eu

GOVP_PACKAGE='govp==0.1.11'

printf '%s\n' 'Installing stable GOVP verifier from PyPI:'
printf '  %s\n' "$GOVP_PACKAGE"

if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'Python 3.10 or newer is required.' >&2
  exit 2
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
  printf '%s\n' 'Python 3.10 or newer is required.' >&2
  exit 2
fi

if command -v pipx >/dev/null 2>&1; then
  pipx install --force "$GOVP_PACKAGE"
  pipx run --spec "$GOVP_PACKAGE" govp self-test
  pipx run --spec "$GOVP_PACKAGE" govp conformance --run
else
  printf '%s\n' 'pipx was not found; installing into the current Python user environment.'
  python3 -m pip install --user "$GOVP_PACKAGE"
  python3 -m govp self-test
  python3 -m govp conformance --run
fi

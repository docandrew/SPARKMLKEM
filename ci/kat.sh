#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/tests/kat"

export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

echo "== known-answer tests =="
bash fetch.sh
alr -n --no-tty build
bin/kat_tests

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

mapfile -t UNITS < <(
  find src -maxdepth 1 -type f \( -name '*.adb' -o -name '*.ads' \) \
    -printf '%f\n' | sort
)

#  Parallelism is capped: every prover may take --memlimit (2000 MB), and
#  -j0 on a 128-thread host is more than the machine's memory.
alr gnatprove \
  -j"${PROVE_JOBS:-32}" \
  --counterexamples=off \
  --output=oneline \
  --output-header \
  -u "${UNITS[@]}" 2>&1 | tee gnatprove-run.txt

OUT="obj/gnatprove/gnatprove.out"

if grep -nE 'mlkem.*:.*(medium|high):|not proved' "$OUT" gnatprove-run.txt; then
  echo "SPARKMLKEM proof failed: see $OUT and gnatprove-run.txt" >&2
  exit 1
fi
echo "SPARKMLKEM proof clean"

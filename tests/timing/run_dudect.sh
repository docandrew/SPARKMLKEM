#!/usr/bin/env bash
set +e

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/bin"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

echo "Rebuilding library + timing harnesses in optimize mode..."
( cd "$DIR" && SPARKMLKEM_BUILD_MODE=optimize alr -n --no-tty build >/dev/null 2>&1 ) \
  || { echo "Rebuild failed; aborting"; exit 2; }

echo "=== dudect statistical timing analysis (ML-KEM-768) ==="
echo ""

#  run_one NAME [canary]
run_one() {
  local name="$1" mode="${2:-clean}" exe="$BIN/$1" out status
  if [ ! -x "$exe" ]; then echo "  $name: BINARY MISSING ($exe)"; return 1; fi
  echo "--- $name ---"
  out=$("$exe" 2>&1); status=$?
  echo "$out"; echo ""
  if [ "$mode" = "canary" ]; then
    echo "$out" | grep -q "TIMING DEPENDS ON SECRET INPUT" && return 0
    echo "  FAIL  $name: planted leak was NOT flagged; the lane has lost its teeth"; return 1
  fi
  echo "$out" | grep -q "TIMING DEPENDS ON SECRET INPUT" && return 1
  return "$status"
}

fail=0
run_one dudect_negative_control canary || fail=1
run_one dudect_keygen        || fail=1
run_one dudect_encaps        || fail=1
run_one dudect_decaps_keys   || fail=1
run_one dudect_decaps_reject || fail=1

if [ "$fail" -eq 0 ]; then echo "=== ALL dudect checks pass ==="
else echo "=== DUDECT TIMING REGRESSION ==="; fi
exit "$fail"

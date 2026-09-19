#!/usr/bin/env bash
set +e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/../.."
BIN="$DIR/bin"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

if ! command -v valgrind >/dev/null 2>&1; then
  echo "valgrind not installed; aborting"
  exit 2
fi

echo "Rebuilding library + timing harnesses in ctgrind mode..."
build_log="$(mktemp)"
( cd "$DIR" && SPARKMLKEM_BUILD_MODE=ctgrind alr -n --no-tty build >"$build_log" 2>&1 )
if [ $? -ne 0 ]; then
  echo "Rebuild failed; aborting"; cat "$build_log"; rm -f "$build_log"; exit 2
fi
rm -f "$build_log"

if [ -n "${NIX_CC:-}" ] && [ -f "$NIX_CC/nix-support/dynamic-linker" ]; then
  nix_ld="$(cat "$NIX_CC/nix-support/dynamic-linker")"
  command -v patchelf >/dev/null 2>&1 || { echo "patchelf not installed; aborting"; exit 2; }
  for exe in "$BIN"/*; do
    [ -x "$exe" ] && [ -f "$exe" ] && patchelf --set-interpreter "$nix_ld" "$exe"
  done
fi

#  run_one NAME MODE [COUNT]
#    clean   : must report no errors
#    canary  : must report at least one (negative control)
#    exact N : must report exactly N distinct error sites (classified)
run_one() {
  local name="$1" mode="$2" want="${3:-}"
  local exe="$BIN/$name"
  if [ ! -x "$exe" ]; then echo "  $name: BINARY MISSING ($exe)"; return 1; fi
  local out status errs
  out=$(valgrind --tool=memcheck --error-exitcode=1 --track-origins=yes --quiet "$exe" 2>&1)
  status=$?
  errs=$(echo "$out" | grep -E -c "Use of uninitiali[sz]ed|Conditional jump.*uninitiali[sz]ed")
  case "$mode" in
    clean)
      if [ "$status" -eq 0 ] && [ "$errs" -eq 0 ]; then echo "  PASS  $name (0 errors)"
      else echo "  FAIL  $name (valgrind status $status, $errs errors)"; echo "$out" | sed 's/^/      /' | head -30; return 1; fi ;;
    canary)
      if [ "$status" -ne 0 ] || [ "$errs" -gt 0 ]; then echo "  PASS  $name ($errs errors from expected canary leak)"
      else echo "  FAIL  $name (0 errors; canary should have leaked)"; return 1; fi ;;
    exact)
      if [ "$errs" -eq "$want" ]; then echo "  PASS  $name ($errs errors; exactly the classified sites)"
      else echo "  FAIL  $name ($errs errors; expected exactly $want classified sites)"; echo "$out" | sed 's/^/      /' | head -40; return 1; fi ;;
    *) echo "  $name: unknown mode '$mode'"; return 1 ;;
  esac
}

echo "=== ctgrind constant-time analysis (ML-KEM-768) ==="
echo ""
fail=0
run_one ct_negative_control canary || fail=1
run_one ct_encaps            clean  || fail=1
run_one ct_decaps            clean  || fail=1
run_one ct_decaps_reject     clean  || fail=1
#  ct_keygen: exactly TWO classified sites, both in XOF_Then_SampleNTT
#  (the two "candidate < q" tests of the A-matrix rejection sampling).
#  rho is derived from the tainted seed d, so Valgrind cannot know it is
#  public (it is published in the encapsulation key). Enforced in both
#  directions: more means a new seed-dependent branch elsewhere in
#  KeyGen; fewer means the taint stopped reaching the sampler. See
#  ct_keygen.adb. (Three sites until 2026-09-18: the three-bytes-per-
#  Extract loop shape compiled one of the tests as a fused compare; the
#  block-wise sampler compiles to one site per test.)
run_one ct_keygen            exact "${CT_KEYGEN_SITES:-2}" || fail=1

echo ""
if [ "$fail" -eq 0 ]; then echo "=== ALL constant-time checks pass ==="; rc=0
else echo "=== CONSTANT-TIME REGRESSION ==="; rc=1; fi

echo "Restoring optimize build..."
( cd "$ROOT" && SPARKMLKEM_BUILD_MODE=optimize alr -n --no-tty build >/dev/null 2>&1 ) \
  || echo "Warning: failed to restore optimize build" >&2
exit "$rc"

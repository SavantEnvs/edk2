#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the oracle that mayhem/build.sh already built (never compiles).
# exit 0 = pass. Asserts BEHAVIOR: known answers from mayhem/build/oracle/OracleBmp, a normal-flags
# (no sanitizer, no libFuzzer) build of MdeModulePkg/Library/BaseBmpSupportLib linked against the
# same EDK II host library stack the fuzz targets use:
#   * 29 built-in cases: hand-built 24-bit and 8-bit palette BMPs must decode to exact pixels/size,
#     malformed headers must be rejected with the specific status, and TranslateGopBltToBmp output
#     must have the exact header/bottom-up layout and round-trip.
#   * golden status/size/FNV-1a-of-pixels for each seed BMP (mayhem/oracle/golden.txt).
#   * every fuzz target's standalone reproducer must replay its own seeds without crashing.
#   * TestPartition and TestUdf must reach the UDF parser from seeds that fit Mayhem's 8 KiB input cap
#     (libFuzzer `-runs=0 -max_len=8192` over the seeds reports at least 100 coverage counters; the
#     same seeds as whole 512 KiB / 1 MiB images, cut to 8 KiB, covered 25 and 70).
# A run that produces no oracle output (a no-op or exit(0) "fix") counts the missing cases as failed.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

ORACLE="$SRC/mayhem/build/oracle/OracleBmp"
BUILTIN_CASES=29
GOLDEN="$SRC/mayhem/oracle/golden.txt"
SEEDS="$SRC/mayhem/TestBmpSupportLib/testsuite"

if [ ! -x "$ORACLE" ]; then
  echo "oracle missing: $ORACLE (mayhem/build.sh must build it)" >&2
  emit_ctrf "edk2-bmp-oracle" 0 1 0
  exit 1
fi

passed=0; failed=0

out=$("$ORACLE" 2>&1) || true
echo "$out"
p=$(printf '%s\n' "$out" | grep -c '^PASS ') || true
f=$(printf '%s\n' "$out" | grep -c '^FAIL ') || true
missing=$(( BUILTIN_CASES - p - f )); [ "$missing" -gt 0 ] || missing=0
passed=$(( passed + p )); failed=$(( failed + f + missing ))

res=$(cd "$SEEDS" && "$ORACLE" $(ls | LC_ALL=C sort) 2>&1) || true
while IFS= read -r want; do
  [ -n "$want" ] || continue
  if printf '%s\n' "$res" | grep -Fxq -- "$want"; then
    passed=$((passed + 1))
  else
    echo "FAIL golden: expected '$want'"; failed=$((failed + 1))
  fi
done < "$GOLDEN"

for seedset in "$SRC"/mayhem/Test*/testsuite; do
  t=$(basename "$(dirname "$seedset")")
  bad=0
  for f in "$seedset"/*; do
    timeout 120 "$SRC/$t-standalone" "$f" >/dev/null 2>&1 || { echo "FAIL replay: $t $(basename "$f")"; bad=1; }
  done
  if [ "$bad" -eq 0 ]; then passed=$((passed + 1)); echo "PASS replay $t"; else failed=$((failed + 1)); fi
done

for t in TestPartition TestUdf; do
  cov=$(timeout 300 "$SRC/$t" -runs=0 -max_len=8192 "$SRC/mayhem/$t/testsuite" 2>&1 | sed -n 's/.*INITED cov: \([0-9]*\).*/\1/p') || true
  if [ "${cov:-0}" -ge 100 ]; then passed=$((passed + 1)); echo "PASS seed coverage $t cov=$cov"; else failed=$((failed + 1)); echo "FAIL seed coverage $t cov=${cov:-none} (< 100)"; fi
done

emit_ctrf "edk2-bmp-oracle" "$passed" "$failed" 0

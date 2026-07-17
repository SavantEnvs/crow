#!/usr/bin/env bash
#
# crow/mayhem/test.sh — RUN crow's OWN Catch2 unit-test binary (built by mayhem/build.sh with
# normal flags against the apt catch2 package) and emit a CTRF summary. exit 0 iff no test failed.
#
# PATCH-grade oracle: these are crow's real upstream unit tests (tests/unittest.cpp +
# query_string/json/mustache/utility/http_response) — routing, HTTP method dispatch, query-string
# parsing, JSON round-trips, mustache rendering, static-file serving, etc. They assert concrete
# expected values, so a no-op / "return early" patch cannot pass. This script only RUNS the
# pre-built binary (it never compiles) and must run from the repo root because the send_file test
# loads tests/img/cat.jpg by relative path.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

TEST_BIN="$SRC/mayhem-build/crow_unittest"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

if [ ! -x "$TEST_BIN" ]; then
  echo "missing $TEST_BIN — run mayhem/build.sh first" >&2
  emit_ctrf "catch2" 0 1 0; exit 2
fi

echo "=== running crow unit tests ($TEST_BIN) ==="
# Catch2 leak/UB noise is irrelevant here (normal-flags build, no sanitizers), but keep ASan quiet
# just in case the base default flows in.
out="$(ASAN_OPTIONS=detect_leaks=0 "$TEST_BIN" --reporter compact 2>&1)"; rc=$?
echo "$out"

# Catch2 compact summary line:  "Passed N test cases with M assertions." (all-pass) OR
#   "test cases: A | B passed | C failed" style is the console reporter; compact prints:
#   "Failed N test cases, passed M test cases. ..." — parse defensively, fall back to exit code.
# Pull the assertion-level tallies from a console-style run for a robust count.
detail="$(ASAN_OPTIONS=detect_leaks=0 "$TEST_BIN" 2>&1 | tail -20)"
# "test cases: 105 | 104 passed | 1 failed"
CASES_TOTAL=$(printf '%s\n' "$detail" | sed -n 's/^test cases:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | tail -1)
CASES_FAILED=$(printf '%s\n' "$detail" | sed -n 's/.*|[[:space:]]*\([0-9][0-9]*\)[[:space:]]*failed.*/\1/p' | tail -1)
# "All tests passed (836 assertions in 105 test cases)"
ALLPASS=$(printf '%s\n' "$detail" | sed -n 's/.*All tests passed (\([0-9][0-9]*\) assertions in \([0-9][0-9]*\) test cases).*/\2/p' | tail -1)

if [ -n "$ALLPASS" ]; then
  emit_ctrf "catch2" "$ALLPASS" 0 0
elif [ -n "$CASES_TOTAL" ]; then
  : "${CASES_FAILED:=0}"
  emit_ctrf "catch2" "$(( CASES_TOTAL - CASES_FAILED ))" "$CASES_FAILED" 0
else
  echo "could not parse Catch2 summary; using exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "catch2" 1 0 0; exit 0; }
  emit_ctrf "catch2" 0 1 0; exit 1
fi

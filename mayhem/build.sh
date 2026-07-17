#!/usr/bin/env bash
#
# crow/mayhem/build.sh — build CrowCpp/Crow's five OSS-Fuzz harnesses as sanitized libFuzzer
# targets (+ standalone reproducers) AND crow's own Catch2 unit-test binary for mayhem/test.sh.
#
# Crow is a HEADER-ONLY C++17 web framework; the fuzzed surface is its HTTP-request handling and
# the helpers an HTTP request pulls in:
#   http_fuzzer     — drives crow::HTTPParser<>::feed()/done() on raw bytes (the HTTP/1.x request
#                     parser — method/url/header/body) then app.handle_full() on the parsed request.
#                     This is the core attacker-controlled request parser.
#   request_fuzzer  — spins up a real crow::SimpleApp on 127.0.0.1:18080 in a thread and sends the
#                     fuzz bytes (prefixed "GET / HTTP/1.1\r\n") over a TCP socket — end-to-end
#                     accept->parse->route->body-param path.
#   json_fuzzer     — crow::json::load() on the bytes, then walks the parsed object/list (crow's
#                     JSON parser, reached from request bodies).
#   template_fuzzer — crow::mustache::compile()/render_string() on the bytes (the templating engine).
#   b64_fuzzer      — round-trips crow::utility::base64encode/decode (header auth / websocket helper).
#
# Crow is included with -DCROW_USE_BOOST so it uses Boost.Asio (apt libboost-dev) rather than
# standalone Asio; boost_system + boost_date_time are linked. We compile the harnesses WITH
# $SANITIZER_FLAGS so all of crow's (header-only) code is instrumented.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN/OUT).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: DWARF ≤ 3 required by Mayhem triage (clang-19 defaults to DWARF-5; be explicit).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${SRC:=/mayhem}"
: "${OUT:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN SRC OUT MAYHEM_JOBS

cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
# Header-only Crow with Boost.Asio backend. NDEBUG matches the OSS-Fuzz CMake (assertions off).
COMMON="-std=c++17 -DNDEBUG -DCROW_USE_BOOST -I$SRC/include"
LINK="-lboost_system -lboost_date_time -lpthread"

BUILD="$SRC/mayhem-build"
mkdir -p "$BUILD"

# Standalone run-once driver: compile the org's StandaloneFuzzTargetMain.c AS C (-x c) so its
# `extern int LLVMFuzzerTestOneInput(...)` keeps C linkage matching the harnesses' extern "C".
$CC ${SANITIZER_FLAGS} ${DEBUG_FLAGS} -c -x c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

HARNESSES="http_fuzzer request_fuzzer json_fuzzer template_fuzzer b64_fuzzer"
for harness in $HARNESSES; do
  # libFuzzer target -> $OUT/<name>
  $CXX $COMMON $SANITIZER_FLAGS ${DEBUG_FLAGS} \
      "$HARNESS_DIR/$harness.cpp" $LIB_FUZZING_ENGINE $LINK \
      -o "$OUT/$harness"

  # standalone reproducer (no libFuzzer runtime) -> $OUT/<name>-standalone
  $CXX $COMMON $SANITIZER_FLAGS ${DEBUG_FLAGS} \
      "$HARNESS_DIR/$harness.cpp" "$BUILD/standalone_main.o" $LINK \
      -o "$OUT/$harness-standalone"

  echo "built $harness (+ standalone)"
done

# ── Crow's OWN Catch2 unit-test binary (run by mayhem/test.sh). Built with NORMAL flags (no
#    sanitizers) against the apt `catch2` (Catch2 v3) package — header-only Crow, so a single
#    translation unit links the framework. We compile the self-contained subset of tests/ that
#    needs no network fixtures: the framework-routing/json/mustache/utility/query-string tests. ──
TEST_BIN="$BUILD/crow_unittest"
CATCH_MAIN_FLAGS="$(pkg-config --cflags catch2-with-main 2>/dev/null || true)"
CATCH_MAIN_LIBS="$(pkg-config --libs catch2-with-main 2>/dev/null || echo '-lCatch2Main -lCatch2')"
TEST_SRCS="tests/unittest.cpp tests/query_string_tests.cpp \
           tests/unit_tests/test_json.cpp tests/unit_tests/test_mustache.cpp \
           tests/unit_tests/test_utility.cpp tests/unit_tests/test_http_response.cpp"
if $CXX -std=c++17 -DCROW_USE_BOOST -I"$SRC/include" $CATCH_MAIN_FLAGS \
       $TEST_SRCS $CATCH_MAIN_LIBS $LINK -o "$TEST_BIN" 2> "$BUILD/test_build.log"; then
  echo "built crow unit-test binary -> $TEST_BIN"
else
  echo "WARNING: crow unit-test build failed (see $BUILD/test_build.log) — mayhem/test.sh will fail loudly" >&2
  sed -n '1,40p' "$BUILD/test_build.log" >&2 || true
fi

echo "build.sh complete:"
for harness in $HARNESSES; do
  ls -la "$OUT/$harness" "$OUT/$harness-standalone" 2>&1 || true
done

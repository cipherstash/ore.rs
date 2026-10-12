#!/usr/bin/env bash
# Run the Valgrind taint harness (packages/ct-taint) over the v2 encryptors.
#
#   scripts/ct-taint.sh          # gate: fail on any report not in valgrind.supp
#   scripts/ct-taint.sh --gen    # print every report as a suppression, for triage
#
# Needs Linux and valgrind on PATH. On macOS run it inside an arm64 container:
#   docker run --rm --platform linux/arm64 -v "$PWD":/src -w /src rust:bookworm \
#     bash -c 'apt-get update -qq && apt-get install -y -qq valgrind && scripts/ct-taint.sh'
#
# Each mode marks the key and plaintext undefined and runs one encryptor; every
# memcheck report is a secret-dependent branch ("Cond") or a secret-indexed
# address ("Value*"). The reports that are accepted, and why, are the entries
# of packages/ct-taint/valgrind.supp.
#
# The gate refuses to pass vacuously. CT_TAINT_GATE makes every mode fail if a
# taint request does nothing or if its output comes out fully defined (the
# taint never reached it), and the `canary` mode, which branches on a tainted
# byte, must fail.
set -euo pipefail

cd "$(dirname "$0")/../packages/ct-taint"

cargo build --release --quiet
bin="${CARGO_TARGET_DIR:-target}/release/ct-taint"
modes=(
    bit6-encrypt bit6-encrypt-left bit6-encrypt-i64 bit6-encrypt-f64 bit6-encrypt-u32
    bit6-encrypt-raw bit6-encrypt-left-raw
    chained-encrypt chained-encrypt-left chained-encrypt-raw chained-encrypt-left-raw
)
status=0
export CT_TAINT_GATE=1

if [ "${1:-}" != "--gen" ]; then
    echo "== canary (must fail)"
    canary=0
    valgrind -q --tool=memcheck --leak-check=no --error-exitcode=99 \
        --suppressions=valgrind.supp "$bin" canary >/dev/null 2>&1 || canary=$?
    if [ "$canary" -eq 99 ]; then
        echo "   ok: memcheck reported the tainted branch"
    else
        echo "   FAIL: canary exited $canary, not 99; the gate cannot see a tainted branch"
        status=1
    fi
fi

for mode in "${modes[@]}"; do
    echo "== $mode"
    if [ "${1:-}" = "--gen" ]; then
        valgrind -q --tool=memcheck --leak-check=no --gen-suppressions=all \
            "$bin" "$mode" || true
    elif valgrind -q --tool=memcheck --leak-check=no --error-exitcode=99 \
            --suppressions=valgrind.supp "$bin" "$mode"; then
        echo "   ok"
    else
        echo "   FAIL: unexpected secret-dependent branch or access (see above)"
        status=1
    fi
done

exit $status

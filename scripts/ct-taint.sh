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
set -euo pipefail

cd "$(dirname "$0")/../packages/ct-taint"

cargo build --release --quiet
bin="${CARGO_TARGET_DIR:-target}/release/ct-taint"
modes=(bit6-encrypt bit6-encrypt-left chained-encrypt chained-encrypt-left)
status=0

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

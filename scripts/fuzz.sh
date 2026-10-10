#!/usr/bin/env bash
# Build and run the ore-rs fuzz targets (packages/ore-rs/fuzz, a detached
# cargo-fuzz crate; needs the nightly toolchain and cargo-fuzz).
#
#   scripts/fuzz.sh                 # every target, 60 s each
#   scripts/fuzz.sh 300             # every target, 300 s each
#   scripts/fuzz.sh 60 bit6_parse   # one target
#
# The targets assert that the ciphertext parsers and raw comparators never
# panic on arbitrary bytes and that accepted bytes re-encode to themselves.
# A crash leaves its input under packages/ore-rs/fuzz/artifacts/<target>/.
#
# Each target is built and run on its own, so a single-target run (one CI
# matrix job) compiles only that target, and a crash in one target does not
# stop the others: every target runs, and the script fails at the end if
# any of them did.
set -euo pipefail

seconds="${1:-60}"
cd "$(dirname "$0")/../packages/ore-rs/fuzz"

if [ $# -ge 2 ]; then
    targets=("$2")
else
    # Every target cargo-fuzz knows, so a new target needs no edit here. A
    # plain assignment, so `set -e` stops the script if the listing fails.
    list="$(cargo +nightly fuzz list)"
    targets=()
    while IFS= read -r t; do
        [ -n "$t" ] && targets+=("$t")
    done <<<"$list"
fi
if [ ${#targets[@]} -eq 0 ]; then
    echo "no fuzz targets found" >&2
    exit 1
fi

failed=()
for target in "${targets[@]}"; do
    echo "== $target (${seconds}s)"
    if ! cargo +nightly fuzz build "$target" ||
        ! cargo +nightly fuzz run "$target" -- -max_total_time="$seconds"; then
        echo "   FAIL: $target"
        failed+=("$target")
    fi
done

if [ ${#failed[@]} -gt 0 ]; then
    echo "failed: ${failed[*]}"
    exit 1
fi

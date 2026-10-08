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
set -euo pipefail

seconds="${1:-60}"
cd "$(dirname "$0")/../packages/ore-rs/fuzz"

if [ $# -ge 2 ]; then
    targets=("$2")
else
    targets=(chained_parse chained_compare bit6_parse bit8_parse)
fi

cargo +nightly fuzz build
for target in "${targets[@]}"; do
    echo "== $target (${seconds}s)"
    cargo +nightly fuzz run "$target" -- -max_total_time="$seconds"
done

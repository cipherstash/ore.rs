#!/usr/bin/env bash
# Reproducibility harness for the Trail of Bits constant-time-analysis tool.
#
# Prereqs:
#   - The constant-time-analysis tool checked out somewhere on disk.
#     Pass its analyzer.py path as $CT_ANALYZER, or as $1.
#   - rustc / cargo for the project's pinned toolchain.
#
# Usage:
#   ./run.sh /path/to/ct_analyzer/analyzer.py
#
# Or with env var:
#   CT_ANALYZER=/path/to/analyzer.py ./run.sh
#
# Output goes to ct-analysis/analyzer-output/.

set -euo pipefail

ANALYZER="${1:-${CT_ANALYZER:-}}"
if [[ -z "$ANALYZER" ]]; then
  echo "ERROR: pass the analyzer.py path as \$1 or set \$CT_ANALYZER." >&2
  exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

OUT="packages/ore-rs/ct-analysis/analyzer-output"
mkdir -p "$OUT"

# The analyzer is host-arch sensitive. Default to the host triple; allow override.
HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
TARGET="${CT_TARGET:-$HOST_TRIPLE}"

# Map rustc target -> analyzer arch flag. Extend as needed.
case "$TARGET" in
  aarch64-*) ANALYZER_ARCH=arm64 ;;
  x86_64-*)  ANALYZER_ARCH=x86_64 ;;
  *) echo "ERROR: unsupported target $TARGET" >&2; exit 2 ;;
esac

emit_asm () {
  local profile="$1"  # "release" or "dev"
  local opt_label="$2" # "O2" or "O0"
  local rustflags=()
  if [[ "$profile" == "release" ]]; then
    rustflags+=(-C opt-level=2)
  else
    rustflags+=(-C opt-level=0)
  fi
  echo "==> Building ct_extract example with $opt_label ($TARGET)..."
  RUSTFLAGS="${rustflags[*]}" cargo rustc \
    --manifest-path packages/ore-rs/Cargo.toml \
    --target "$TARGET" \
    $([[ "$profile" == "release" ]] && echo --release) \
    --example ct_extract \
    -- --emit=asm
  # Locate the emitted .s. Cargo names it with a hash suffix.
  local asm
  asm=$(find target/"$TARGET"/$([[ "$profile" == "release" ]] && echo release || echo debug)/examples \
        -maxdepth 1 -name 'ct_extract-*.s' -print -quit)
  cp "$asm" "$OUT/ct_extract.$opt_label.s"
}

emit_asm release O2
emit_asm dev O0

echo "==> Running analyzer (-O2)..."
uv run --quiet "$ANALYZER" --assembly --arch "$ANALYZER_ARCH" --warnings \
  "$OUT/ct_extract.O2.s" | tee "$OUT/analyzer.O2.log"

echo "==> Running analyzer (-O0)..."
uv run --quiet "$ANALYZER" --assembly --arch "$ANALYZER_ARCH" --warnings \
  "$OUT/ct_extract.O0.s" | tee "$OUT/analyzer.O0.log"

echo
echo "Output written to: $OUT/"

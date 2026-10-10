#!/usr/bin/env bash
# Run one ct-dudect bench continuously and report the *uncropped* Welch t
# next to dudect's own figure.
#
#   scripts/dudect-uncropped.sh prp_build_const_vs_random        # 150 s
#   CT_DUDECT_DIT=1 scripts/dudect-uncropped.sh <bench> 300
#
# dudect reports the largest |t| over 101 tests, 100 of which first drop
# every sample above a percentile of the runtime distribution. When the two
# classes differ in spread, dropping the slow tail removes more of one class
# than the other, and the cropped tests can report a large t with no
# difference in mean. On Apple Silicon the timer is a 24 MHz counter (41.67
# ns ticks), so the percentiles also fall exactly on tick values. This
# script records every sample (streamed through a FIFO into per-class
# histograms, so a long run stays small) and prints the plain Welch t, the
# per-class means and spreads, and the share of samples in each tick bin.
#
# Needs python3. dudect-bencher writes every sample with class 0; the classes
# are recovered from the row order (it writes Left, Right pairs).
set -euo pipefail

bench="${1:?usage: dudect-uncropped.sh <bench> [seconds]}"
seconds="${2:-150}"
cd "$(dirname "$0")/../packages/ct-dudect"

cargo +stable build --release --locked --quiet
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkfifo "$tmp/samples"

awk -F, 'NR > 1 && NF == 3 && $3 ~ /^[0-9]+$/ {
            k++; h[(k % 2 == 1 ? "L" : "R") " " $3]++
         }
         END { for (x in h) print x, h[x] }' "$tmp/samples" >"$tmp/hist" &
timeout "$seconds" ./target/release/ct-dudect --continuous "$bench" \
    --out "$tmp/samples" >"$tmp/dudect.log" 2>&1 || true
wait

echo "dudect: $(grep 'max t' "$tmp/dudect.log" | tail -1 | sed -E 's/.*: (n ==.*)/\1/')"
python3 - "$tmp/hist" <<'EOF'
import math, sys
from collections import defaultdict

h = {"L": defaultdict(int), "R": defaultdict(int)}
for line in open(sys.argv[1]):
    c, v, k = line.split()
    h[c][float(v)] += int(k)

def moments(d):
    n = sum(d.values())
    m = sum(v * c for v, c in d.items()) / n
    var = sum(c * (v - m) ** 2 for v, c in d.items()) / (n - 1)
    return n, m, var

(nl, ml, vl), (nr, mr, vr) = moments(h["L"]), moments(h["R"])
t = (ml - mr) / math.sqrt(vl / nl + vr / nr)
print(f"uncropped: n = {nl / 1e6:.1f} M + {nr / 1e6:.1f} M, "
      f"t = {t:+.2f}, tau = {t / math.sqrt(nl + nr):+.5f}")
print(f"mean Left {ml:.2f}, Right {mr:.2f} (diff {ml - mr:+.3f}); "
      f"sd Left {math.sqrt(vl):.1f}, Right {math.sqrt(vr):.1f}")
print("bin      Left share  Right share  z")
top = sorted(set(h["L"]) | set(h["R"]), key=lambda v: -(h["L"][v] + h["R"][v]))[:8]
for b in sorted(top):
    pl, pr = h["L"][b] / nl, h["R"][b] / nr
    p = (h["L"][b] + h["R"][b]) / (nl + nr)
    se = math.sqrt(p * (1 - p) * (1 / nl + 1 / nr)) or 1.0
    print(f"{b:7.0f}  {pl:10.5f}  {pr:11.5f}  {(pl - pr) / se:+6.1f}")
EOF

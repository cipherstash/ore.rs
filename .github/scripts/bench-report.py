#!/usr/bin/env python3
"""Render criterion's base-vs-head comparison as a Markdown PR comment.

bench.yml runs every benchmark twice on the same runner: once at the PR's
base commit (`--save-baseline base`), then at its head
(`--baseline-lenient base`). Criterion then leaves, per benchmark, under
target/criterion/<id>/:

- base/estimates.json  : the base commit's timings
- new/estimates.json   : the head commit's timings
- change/estimates.json: the relative change with a 95% confidence interval

A benchmark counts as slower or faster only when its median moves by
more than the threshold AND the confidence interval excludes zero, so run-to-
run noise on a shared runner isn't reported as a change.

Usage: bench-report.py CRITERION_DIR BASE_SHA HEAD_SHA THRESHOLD_PCT OUTPUT
"""

import json
import sys
from pathlib import Path

MARKER = "<!-- ore-rs-bench-report -->"


def load(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def fmt_time(ns):
    if ns is None:
        return "–"
    for unit, scale in (("s", 1e9), ("ms", 1e6), ("µs", 1e3)):
        if ns >= scale:
            return f"{ns / scale:.2f} {unit}"
    return f"{ns:.1f} ns"


def fmt_pct(fraction):
    return f"{fraction * 100:+.1f}%"


def collect(root):
    """One row per benchmark id, from whichever of base/new exists."""
    rows = {}
    for meta in root.glob("**/benchmark.json"):
        run_dir = meta.parent  # .../<id>/{base,new}
        if run_dir.name not in ("base", "new"):
            continue
        bench_dir = run_dir.parent
        full_id = load(meta)["full_id"]
        if full_id in rows:
            continue

        def median(name):
            est = load(bench_dir / name / "estimates.json")
            return est["median"]["point_estimate"] if est else None

        change = load(bench_dir / "change" / "estimates.json")
        rows[full_id] = {
            "id": full_id,
            "base": median("base"),
            "head": median("new"),
            "change": change["median"] if change else None,
        }
    return sorted(rows.values(), key=lambda r: r["id"])


def classify(row, threshold):
    if row["base"] is None:
        return "new"
    if row["head"] is None:
        return "removed"
    change = row["change"]
    if change is None:
        return "unchanged"
    point = change["point_estimate"]
    ci = change["confidence_interval"]
    if point > threshold and ci["lower_bound"] > 0:
        return "slower"
    if point < -threshold and ci["upper_bound"] < 0:
        return "faster"
    return "unchanged"


STATUS = {
    "slower": "🔴 slower",
    "faster": "🟢 faster",
    "unchanged": "no change",
    "new": "new",
    "removed": "removed",
}


def table(rows):
    lines = [
        "| Benchmark | Base | PR | Change (95% CI) | |",
        "|---|---:|---:|---:|---|",
    ]
    for row in rows:
        change = row["change"]
        if change and row["base"] is not None and row["head"] is not None:
            ci = change["confidence_interval"]
            delta = (
                f"{fmt_pct(change['point_estimate'])} "
                f"({fmt_pct(ci['lower_bound'])} … {fmt_pct(ci['upper_bound'])})"
            )
        else:
            delta = "–"
        lines.append(
            f"| `{row['id']}` | {fmt_time(row['base'])} | {fmt_time(row['head'])} "
            f"| {delta} | {STATUS[row['status']]} |"
        )
    return "\n".join(lines)


def main():
    root, base_sha, head_sha, threshold_pct, output = sys.argv[1:6]
    threshold = float(threshold_pct) / 100
    rows = collect(Path(root))
    for row in rows:
        row["status"] = classify(row, threshold)

    counts = {s: sum(r["status"] == s for r in rows) for s in STATUS}
    flagged = [r for r in rows if r["status"] in ("slower", "faster", "new", "removed")]

    out = [MARKER, "## ⏱ Benchmarks", ""]
    if not rows:
        out.append("No benchmark results were produced. Check the job log.")
    else:
        if counts["slower"]:
            headline = f"**{counts['slower']} slower**"
        else:
            headline = "**No regressions**"
        parts = [headline]
        if counts["faster"]:
            parts.append(f"{counts['faster']} faster")
        parts.append(f"{counts['unchanged']} unchanged")
        if counts["new"]:
            parts.append(f"{counts['new']} new")
        if counts["removed"]:
            parts.append(f"{counts['removed']} removed")
        out.append(", ".join(parts) + f" (of {len(rows)}).")
        out.append("")
        if flagged:
            out.append(table(flagged))
            out.append("")
        out.append("<details><summary>All benchmarks</summary>")
        out.append("")
        out.append(table(rows))
        out.append("")
        out.append("</details>")
    out.append("")
    out.append(
        f"Base `{base_sha[:7]}` vs PR `{head_sha[:7]}`, both run on the same "
        f"runner. Times are medians. A benchmark is flagged only when it moves "
        f"by more than {threshold_pct}% and the 95% confidence interval "
        f"excludes zero. Shared runners are noisy, so treat a small flagged "
        f"change as a prompt to re-run or measure locally, not as proof."
    )
    Path(output).write_text("\n".join(out) + "\n")


if __name__ == "__main__":
    main()

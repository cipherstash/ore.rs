#!/usr/bin/env python3
"""Fail if library code can panic through an assertion macro.

The crates deny clippy's panic lints (`panic`, `unwrap_used`, `expect_used`,
`unreachable`, `todo`, `unimplemented`, `panic_in_result_fn`) outside tests,
but clippy has no lint for `assert!` or `debug_assert!` in general. This
check covers those: library code returns an error or carries the invariant
in a type instead.

Exempt:
- items under `#[cfg(test)]`, `#[cfg(kani)]`, `#[test]` or `#[kani::proof]`;
- compile-time assertions, `const NAME: () = assert!(...)`, which cannot
  panic at run time.

Usage: scripts/no-runtime-asserts.py [SRC_DIR ...]
(default: the library sources of every workspace crate).
"""

import pathlib
import re
import sys

DEFAULT_DIRS = [
    "packages/clww-ore/src",
    "packages/ore-rs/src",
    "packages/orderable-bytes/src",
]

EXEMPT_ATTR = re.compile(r"#\[\s*(cfg\(\s*(test|kani)\s*\)|test|kani::proof)\s*\]")
ASSERT = re.compile(r"(?<![\w:])(?:(?:core|std)::)?(debug_)?assert(_eq|_ne)?!")
CONST_ASSERT = re.compile(r"const\s+\w+\s*:\s*\(\)\s*=\s*(?:(?:core|std)::)?assert!")


def blank_comments_and_literals(src: str) -> str:
    """Replace comments and string/char literal contents with spaces,
    keeping newlines, so that line numbers and brace positions survive."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == '"' or (c == "b" and src.startswith('b"', i)):
            j = i + (2 if c == "b" else 1)
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            j += 1
            out.append('"' + re.sub(r"[^\n]", " ", src[i + 1 : j - 1]) + '"')
            i = j
        else:
            m = re.match(r"b?'(\\.|[^\\'\n])'", src[i:])
            if m:
                out.append(" " * len(m.group(0)))
                i += len(m.group(0))
            else:
                out.append(c)
                i += 1
    return "".join(out)


def exempt_spans(src: str):
    """(start, end) offsets of every exempt item: from its attribute to the
    end of its body (matching brace) or to its `;`."""
    spans = []
    for m in EXEMPT_ATTR.finditer(src):
        j = m.end()
        while j < len(src) and src[j] not in "{;":
            j += 1
        if j < len(src) and src[j] == "{":
            depth = 0
            while j < len(src):
                if src[j] == "{":
                    depth += 1
                elif src[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
        spans.append((m.start(), j + 1))
    return spans


def check(path: pathlib.Path):
    src = blank_comments_and_literals(path.read_text())
    spans = exempt_spans(src)
    for m in ASSERT.finditer(src):
        if any(a <= m.start() < b for a, b in spans):
            continue
        line_start = src.rfind("\n", 0, m.start()) + 1
        line_end = src.find("\n", m.start())
        line = src[line_start : line_end if line_end != -1 else len(src)]
        if CONST_ASSERT.search(line):
            continue
        lineno = src.count("\n", 0, m.start()) + 1
        yield f"{path}:{lineno}: {line.strip()}"


def main(argv):
    dirs = argv[1:] or DEFAULT_DIRS
    found = [hit for d in dirs for f in sorted(pathlib.Path(d).rglob("*.rs")) for hit in check(f)]
    for hit in found:
        print(hit)
    if found:
        print(
            f"\n{len(found)} runtime assertion(s) in library code. Return an error or "
            "carry the invariant in a type; a compile-time check is "
            "`const NAME: () = assert!(...)`.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

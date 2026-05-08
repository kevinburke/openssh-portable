#!/usr/bin/env python3
"""Fail if production Rust crypto code grows panic-prone helpers."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
PATTERN = re.compile(r"\b(?:unwrap|expect|panic|todo|unimplemented)!\s*\(|\.(?:unwrap|expect)\s*\(")


def update_depth(depth: int, line: str) -> int:
    return depth + line.count("{") - line.count("}")


def violations(path: Path) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    pending_test_cfg = False
    skipped_depth: int | None = None
    depth = 0

    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        stripped = line.strip()

        if skipped_depth is not None:
            depth = update_depth(depth, line)
            if depth <= skipped_depth:
                skipped_depth = None
            continue

        if stripped == "#[cfg(test)]":
            pending_test_cfg = True
            depth = update_depth(depth, line)
            continue

        if pending_test_cfg:
            depth = update_depth(depth, line)
            if "{" in line:
                skipped_depth = depth - 1
                pending_test_cfg = False
            elif stripped and not stripped.startswith("#["):
                pending_test_cfg = False
            continue

        if PATTERN.search(line):
            found.append((lineno, line.rstrip()))

        depth = update_depth(depth, line)

    return found


def main() -> int:
    all_violations: list[tuple[Path, int, str]] = []
    for path in sorted(SRC.glob("*.rs")):
        all_violations.extend((path, lineno, line) for lineno, line in violations(path))

    if not all_violations:
        return 0

    print(
        "production rust/crypto code must not use unwrap/expect/panic/todo/unimplemented",
        file=sys.stderr,
    )
    print("move assertions into #[cfg(test)] code or return an error/status", file=sys.stderr)
    for path, lineno, line in all_violations:
        print(f"{path.relative_to(ROOT)}:{lineno}: {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

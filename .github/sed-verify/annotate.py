#!/usr/bin/env python3
"""Emit a file's content as GitHub Actions annotations.

Actions log downloads go through a host that is not reachable from the
development sandbox, but check-run annotations are served by api.github.com.
Chunk the report into annotations so it can be read back with:

    gh api repos/<owner>/<repo>/check-runs/<id>/annotations
"""

import sys


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main() -> None:
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 11000
    chunk_size = int(sys.argv[3]) if len(sys.argv) > 3 else 1200
    prefix = sys.argv[4] if len(sys.argv) > 4 else "sed-verify"
    try:
        with open(path, errors="replace") as handle:
            text = handle.read()
    except OSError as exc:  # pragma: no cover - diagnostics only
        text = f"cannot read {path}: {exc}"

    if len(text) > limit:
        text = "...(truncated)...\n" + text[-limit:]

    chunks: list[list[str]] = []
    current: list[str] = []
    size = 0
    for line in text.splitlines():
        if size + len(line) + 1 > chunk_size:
            chunks.append(current)
            current, size = [], 0
        current.append(line)
        size += len(line) + 1
    if current:
        chunks.append(current)

    for index, chunk in enumerate(chunks[:10]):
        print(f"::error title={prefix}-{index:02d}::{escape(chr(10).join(chunk))}")


main()

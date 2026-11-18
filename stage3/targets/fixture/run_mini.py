#!/usr/bin/env python3
"""Stand-in runner for mini.c so the smoke test needs no C compiler.

The branch matches mini.c: an input longer than 8 bytes that starts with
TAG takes the unbounded copy. This file is only for the harness fixture.
"""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    """Report whether the saved input would take the unbounded copy."""
    if len(sys.argv) != 2:
        print("usage: run_mini.py INPUT_FILE", file=sys.stderr)
        return 2
    data = Path(sys.argv[1]).read_bytes()
    if len(data) > 8 and data[:3] == b"TAG":
        print("runtime status: copy exceeds 8-byte stack buffer")
        return 1
    print("runtime status: accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

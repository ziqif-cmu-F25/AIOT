#!/usr/bin/env python3
"""One-time, human-run setup: materialize a task's allow-listed files and
record their SHA-256 in <source_root>/MANIFEST.txt.

* Tasks with ``context.upstream`` (source_root: vendor): each listed path is
  downloaded individually from
  https://raw.githubusercontent.com/<repository>/<commit>/<path>
  at the full 40-character pinned commit. No git clone.
* Tasks without upstream (source_root: tasks/fixtures): the hand-written
  fixture files are hashed in place.

run_task.py never calls this script; the driver's only network traffic is
the OpenRouter API call. Re-running is idempotent: a file whose bytes
already match MANIFEST.txt is left alone unless --refresh is given.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.request
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml

from driver.context_loader import (  # path rules are shared with the driver
    MANIFEST_NAME,
    STAGE2_ROOT,
    resolve_source_root,
)

RAW_URL = "https://raw.githubusercontent.com/{repository}/{commit}/{path}"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
HEADER = (
    "# SHA-256 of every file a task may show the model. Checked by\n"
    "# driver/context_loader.py before any prompt is built.\n"
    "# Written by scripts/fetch_source.py. Format: <sha256>  <path>  <origin>\n"
)


def read_rows(manifest: Path) -> dict[str, tuple[str, str]]:
    rows = {}
    if manifest.is_file():
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#"):
                sha, path, *origin = line.split()
                rows[path] = (sha, origin[0] if origin else "unknown")
    return rows


def write_rows(manifest: Path, rows: dict[str, tuple[str, str]]) -> None:
    body = "".join(f"{sha}  {path}  {origin}\n" for path, (sha, origin) in sorted(rows.items()))
    manifest.write_bytes((HEADER + body).encode("utf-8"))


def safe_target(root: Path, rel: str) -> Path:
    pure = PurePosixPath(rel)
    if pure.is_absolute() or ".." in pure.parts or not rel:
        sys.exit(f"error: refusing unsafe path {rel!r}")
    target = (root / Path(*pure.parts)).resolve()
    if not target.is_relative_to(root):
        sys.exit(f"error: {rel!r} escapes {root}")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--task", required=True, help="task id or path to task yaml")
    parser.add_argument("--refresh", action="store_true", help="re-download even if hashes match")
    args = parser.parse_args()

    task_path = Path(args.task)
    if task_path.suffix not in (".yaml", ".yml"):
        task_path = STAGE2_ROOT / "tasks" / f"{args.task}.yaml"
    task = yaml.safe_load(task_path.read_text(encoding="utf-8"))
    ctx = task["context"]
    root = resolve_source_root(ctx["source_root"])
    manifest = root / MANIFEST_NAME
    rows = read_rows(manifest)
    upstream = ctx.get("upstream")

    if upstream:
        repo, commit = upstream["repository"], upstream["commit"]
        if not REPO_RE.match(repo) or not COMMIT_RE.match(commit):
            sys.exit("error: upstream needs owner/name and a full 40-char lowercase commit hash")
        origin = f"{repo}@{commit}"
    else:
        origin = "local"

    for entry in ctx["files"]:
        rel = PurePosixPath(entry["path"]).as_posix()
        target = safe_target(root, rel)
        existing = rows.get(rel)
        if existing and existing[1] != origin:
            sys.exit(f"error: {rel} is already in {manifest} from {existing[1]}, not {origin}")

        if upstream:
            current = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None
            if current and existing and current == existing[0] and not args.refresh:
                print(f"ok      {rel}  {current}  (already present)")
                continue
            url = RAW_URL.format(repository=repo, commit=commit, path=rel)
            print(f"fetch   {url}")
            with urllib.request.urlopen(url, timeout=60) as resp:
                data = resp.read()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        else:
            if not target.is_file():
                sys.exit(f"error: fixture {target} does not exist")
            data = target.read_bytes()

        digest = hashlib.sha256(data).hexdigest()
        rows[rel] = (digest, origin)
        print(f"hashed  {rel}  {digest}  ({len(data)} bytes)")

    write_rows(manifest, rows)
    print(f"wrote   {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

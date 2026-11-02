"""Load exactly the files a task's allow-list names, and nothing else.

This module is the Stage 2 information boundary, the counterpart of the
container isolation that separates the Stage 1 viewpoints. The rules:

* A task's ``context.source_root`` must be one of APPROVED_SOURCE_ROOTS
  (relative to stage2/). Nothing else can be a root.
* Every ``context.files[].path`` is resolved (symlinks and ``..`` included)
  and must stay inside that root and outside every FORBIDDEN_DIRS entry.
* Every file's live SHA-256 must equal its row in ``<root>/MANIFEST.txt``
  before any content is returned, so a prompt is never built from drifted
  or tampered source.

The only files this module opens are ``<root>/MANIFEST.txt`` and the
allow-listed files themselves. Violations raise; there is no fallback.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

STAGE2_ROOT = Path(__file__).resolve().parent.parent
APPROVED_SOURCE_ROOTS = ("vendor", "tasks/fixtures")
MANIFEST_NAME = "MANIFEST.txt"


class BoundaryError(Exception):
    """A task tried to reach something outside its allow-list."""


class IntegrityError(Exception):
    """An allow-listed file does not match MANIFEST.txt."""


def forbidden_dirs(stage2_root: Path) -> tuple[Path, ...]:
    """Evaluator-side directories the driver must never read."""
    stage2_root = stage2_root.resolve()
    return (stage2_root.parent / "evaluator", stage2_root / "scoring")


@dataclass(frozen=True)
class ContextFile:
    path: str                # as named in the allow-list (posix, relative to source_root)
    sha256: str
    total_lines: int
    line_range: tuple[int, int]
    text: str                # only the selected lines


@dataclass(frozen=True)
class LoadedContext:
    source_root: str
    files: tuple[ContextFile, ...]

    def render(self) -> str:
        """Format files with headers and a line-number margin for the prompt."""
        blocks = []
        for f in self.files:
            start, end = f.line_range
            width = len(str(end))
            numbered = "\n".join(
                f"{start + i:>{width}} | {line}"
                for i, line in enumerate(f.text.split("\n"))
            )
            blocks.append(
                f"=== FILE: {f.path} (lines {start}-{end} of {f.total_lines}) ===\n"
                f"{numbered}\n"
                f"=== END FILE: {f.path} ==="
            )
        return "\n\n".join(blocks)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _check_not_forbidden(path: Path, stage2_root: Path) -> None:
    for denied in forbidden_dirs(stage2_root):
        if path == denied.resolve() or _is_within(path, denied.resolve()):
            raise BoundaryError(f"refused: {path} is inside evaluator-side {denied}")


def resolve_source_root(name: str, stage2_root: Path = STAGE2_ROOT) -> Path:
    """Return the resolved approved source root called *name*."""
    stage2_root = stage2_root.resolve()
    if name not in APPROVED_SOURCE_ROOTS:
        raise BoundaryError(
            f"refused: source_root {name!r} is not one of {APPROVED_SOURCE_ROOTS}"
        )
    root = (stage2_root / name).resolve()
    _check_not_forbidden(root, stage2_root)
    if not _is_within(root, stage2_root):
        raise BoundaryError(f"refused: source_root {name!r} resolves outside stage2/")
    if not root.is_dir():
        raise BoundaryError(f"source_root {root} does not exist")
    return root


def resolve_allowed(root: Path, rel: str, stage2_root: Path = STAGE2_ROOT) -> Path:
    """Resolve allow-list entry *rel* under *root*, refusing any escape."""
    pure = PurePosixPath(rel)
    if not rel or pure.is_absolute() or Path(rel).is_absolute() or Path(rel).drive:
        raise BoundaryError(f"refused: allow-list path {rel!r} must be relative")
    if ".." in pure.parts:
        raise BoundaryError(f"refused: allow-list path {rel!r} contains '..'")
    candidate = root / Path(*pure.parts)
    resolved = candidate.resolve()
    _check_not_forbidden(resolved, stage2_root)
    if not _is_within(resolved, root):
        raise BoundaryError(
            f"refused: allow-list path {rel!r} resolves to {resolved}, outside {root}"
        )
    if not resolved.is_file():
        raise BoundaryError(f"allow-listed file {rel!r} not found under {root}")
    return resolved


def read_manifest(root: Path) -> dict[str, str]:
    """Map path -> sha256 from ``<root>/MANIFEST.txt``."""
    manifest = root / MANIFEST_NAME
    if not manifest.is_file():
        raise IntegrityError(
            f"{manifest} missing; run stage2/scripts/fetch_source.py for this task"
        )
    rows: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            raise IntegrityError(f"malformed MANIFEST row: {line!r}")
        rows[parts[1]] = parts[0].lower()
    return rows


def load_context(task: dict, stage2_root: Path = STAGE2_ROOT) -> LoadedContext:
    """Return the allow-listed context for *task*, or raise."""
    ctx = task.get("context") or {}
    entries = ctx.get("files") or []
    if not entries:
        raise BoundaryError("task allow-list (context.files) is empty")
    root = resolve_source_root(ctx.get("source_root", ""), stage2_root)

    # Resolve every entry before reading anything, so one bad entry means
    # nothing at all is read.
    resolved = []
    for entry in entries:
        rel = str(entry.get("path", ""))
        resolved.append((entry, rel, resolve_allowed(root, rel, stage2_root)))

    manifest = read_manifest(root)
    files = []
    for entry, rel, path in resolved:
        key = PurePosixPath(rel).as_posix()
        if key not in manifest:
            raise IntegrityError(f"{key} is not listed in {root / MANIFEST_NAME}")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != manifest[key]:
            raise IntegrityError(
                f"SHA-256 mismatch for {key}: live {digest}, "
                f"MANIFEST {manifest[key]}. Refusing to build a prompt."
            )
        lines = data.decode("utf-8").split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        total = len(lines)
        start, end = entry.get("line_range") or (1, total)
        if not (1 <= start <= end <= total):
            raise BoundaryError(f"line_range {[start, end]} invalid for {key} ({total} lines)")
        files.append(
            ContextFile(
                path=key,
                sha256=digest,
                total_lines=total,
                line_range=(start, end),
                text="\n".join(lines[start - 1 : end]),
            )
        )
    return LoadedContext(source_root=ctx["source_root"], files=tuple(files))

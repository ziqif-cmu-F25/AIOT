"""Load a target pack. The harness never hardcodes a project vulnerability."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

STAGE3_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_LIMITS = (
    "max_steps",
    "max_read_lines",
    "max_output_chars",
    "tool_timeout_s",
    "python_timeout_s",
    "target_timeout_s",
)


class TargetError(Exception):
    """The target pack is missing a required field or points at a bad path."""


@dataclass(frozen=True)
class TargetPack:
    """Resolved, analyst-facing description of one Stage 2 target."""

    target_id: str
    analyst_brief: str
    source_root: Path
    run_cwd: Path
    run_argv: tuple[str, ...]
    limits: dict[str, Any]
    model_default: str
    temperature: float
    max_tokens: int | None
    allowed_suffixes: tuple[str, ...]
    raw: dict[str, Any]
    config_path: Path


def _resolve(stage3_root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = stage3_root / path
    return path.resolve()


def load_target(path: Path, stage3_root: Path = STAGE3_ROOT) -> TargetPack:
    """Load and resolve *path*. Relative paths are from the stage3 root."""
    path = path.resolve()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TargetError(f"{path}: target file must be a mapping")
    for key in ("target_id", "analyst_brief", "source_root", "run_target", "limits", "model"):
        if key not in data:
            raise TargetError(f"{path}: missing {key}")
    run = data["run_target"]
    if not isinstance(run, dict) or not run.get("argv") or not run.get("cwd"):
        raise TargetError(f"{path}: run_target needs argv and cwd")
    limits = data["limits"]
    missing = [name for name in REQUIRED_LIMITS if name not in limits]
    if missing:
        raise TargetError(f"{path}: limits missing {missing}")
    model = data["model"]
    if "default" not in model or "temperature" not in model:
        raise TargetError(f"{path}: model.default and model.temperature are required")
    suffixes = tuple(data.get("allowed_suffixes") or [".c", ".h", ".cc", ".cpp", ".hpp", ".md", ".txt"])
    source_root = _resolve(stage3_root, str(data["source_root"]))
    if not source_root.is_dir():
        raise TargetError(f"{path}: source_root is not a directory: {source_root}")
    return TargetPack(
        target_id=str(data["target_id"]),
        analyst_brief=str(data["analyst_brief"]).strip(),
        source_root=source_root,
        run_cwd=_resolve(stage3_root, str(run["cwd"])),
        run_argv=tuple(str(part) for part in run["argv"]),
        limits=dict(limits),
        model_default=str(model["default"]),
        temperature=float(model["temperature"]),
        max_tokens=int(model["max_tokens"]) if model.get("max_tokens") else None,
        allowed_suffixes=suffixes,
        raw=data,
        config_path=path,
    )

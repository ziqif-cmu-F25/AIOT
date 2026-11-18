"""The four Stage 3 tools, each confined to the target pack."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from harness.target_config import TargetPack

_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class ToolError(Exception):
    """A tool rejected its arguments or the target command failed to start."""


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"


class ToolBox:
    """Executes one tool call and returns an observation string."""

    def __init__(self, pack: TargetPack, scratch: Path, source_only: bool):
        self.pack = pack
        self.scratch = scratch
        self.source_only = source_only
        self._input_seq = 0
        self.scratch.mkdir(parents=True, exist_ok=True)

    def dispatch(self, name: str, args: dict) -> str:
        """Run *name* with *args*. Unknown tools and bad args become observations."""
        if not isinstance(args, dict):
            raise ToolError("args must be an object")
        if name == "read_source":
            return self.read_source(args)
        if name == "find_references":
            return self.find_references(args)
        if name == "run_python":
            return self._runtime(self.run_python, args)
        if name == "run_target":
            return self._runtime(self.run_target, args)
        raise ToolError(f"unknown tool {name!r}")

    def _runtime(self, fn, args: dict) -> str:
        if self.source_only:
            raise ToolError(
                "tool disabled: this run is source-only and cannot execute code or the target"
            )
        return fn(args)

    def _source_file(self, rel: str) -> Path:
        if not rel or not isinstance(rel, str):
            raise ToolError("path must be a non-empty string relative to source_root")
        candidate = (self.pack.source_root / rel).resolve()
        if not _within(candidate, self.pack.source_root):
            raise ToolError("path escapes source_root")
        if candidate.suffix.lower() not in self.pack.allowed_suffixes:
            raise ToolError(f"suffix {candidate.suffix!r} is not allowed")
        if not candidate.is_file():
            raise ToolError(f"not a file: {rel}")
        return candidate

    def read_source(self, args: dict) -> str:
        """Return a numbered slice of one allow-listed source file."""
        path = self._source_file(str(args.get("path", "")))
        try:
            start = int(args["start_line"])
            end = int(args["end_line"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ToolError("start_line and end_line must be integers") from exc
        if start < 1 or end < start:
            raise ToolError("line range must satisfy 1 <= start_line <= end_line")
        max_lines = int(self.pack.limits["max_read_lines"])
        if end - start + 1 > max_lines:
            raise ToolError(f"line range exceeds max_read_lines ({max_lines})")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if start > len(lines):
            raise ToolError(f"start_line {start} is past EOF ({len(lines)} lines)")
        end = min(end, len(lines))
        width = len(str(end))
        body = "\n".join(
            f"{lineno:>{width}} | {lines[lineno - 1]}"
            for lineno in range(start, end + 1)
        )
        return f"FILE {path.name} lines {start}-{end} of {len(lines)}\n{body}"

    def find_references(self, args: dict) -> str:
        """List source lines that contain an identifier, inside source_root only."""
        symbol = str(args.get("symbol", ""))
        if not _SYMBOL.match(symbol):
            raise ToolError("symbol must be a single identifier")
        matches: list[str] = []
        files = 0
        for path in sorted(self.pack.source_root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in self.pack.allowed_suffixes:
                continue
            if not _within(path.resolve(), self.pack.source_root):
                continue
            files += 1
            if files > 500:
                break
            rel = path.relative_to(self.pack.source_root).as_posix()
            for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if symbol in line:
                    matches.append(f"{rel}:{lineno}: {line.strip()[:200]}")
                    if len(matches) >= 40:
                        return "\n".join(matches) + "\n...[match cap]"
        if not matches:
            return f"no references to {symbol} under source_root ({files} files scanned)"
        return "\n".join(matches)

    def run_python(self, args: dict) -> str:
        """Run a short Python snippet in the run scratch directory."""
        code = args.get("code")
        if not isinstance(code, str) or not code.strip():
            raise ToolError("code must be a non-empty string")
        if len(code) > 8000:
            raise ToolError("code exceeds 8000 characters")
        script = self.scratch / "snippet.py"
        script.write_text(code, encoding="utf-8")
        return self._run(
            ["python3", "-I", str(script)],
            self.scratch,
            int(self.pack.limits["python_timeout_s"]),
            inherit_env=False,
        )

    def run_target(self, args: dict) -> str:
        """Feed one saved input to the target command from the target pack."""
        payload = _payload(args)
        self._input_seq += 1
        input_path = self.scratch / f"input-{self._input_seq:03d}.bin"
        input_path.write_bytes(payload)
        argv = [part.replace("{input_file}", str(input_path)) for part in self.pack.run_argv]
        if "{input_file}" not in "".join(self.pack.run_argv) and payload:
            raise ToolError("run_target.argv must contain {input_file}")
        if not self.pack.run_cwd.is_dir():
            raise ToolError(f"run cwd does not exist: {self.pack.run_cwd}")
        observation = self._run(
            argv,
            self.pack.run_cwd,
            int(self.pack.limits["target_timeout_s"]),
            inherit_env=True,
        )
        return f"saved_input: {input_path}\n{observation}"

    def _run(self, argv: list[str], cwd: Path, timeout_s: int, inherit_env: bool) -> str:
        if inherit_env:
            env = os.environ.copy()
            env.pop("OPENROUTER_API_KEY", None)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
        else:
            env = {
                "PATH": os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "HOME": str(self.scratch),
                "TMPDIR": str(self.scratch),
            }
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                env=env,
                capture_output=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b"").decode("utf-8", errors="replace")
            stderr = (exc.stderr or b"").decode("utf-8", errors="replace")
            limit = int(self.pack.limits["max_output_chars"])
            return _clip(
                f"timeout after {timeout_s}s\nargv: {argv}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                limit,
            )
        limit = int(self.pack.limits["max_output_chars"])
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        return _clip(
            f"exit_code: {result.returncode}\nargv: {argv}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            limit,
        )


def _payload(args: dict) -> bytes:
    text = args.get("input_text")
    hex_text = args.get("input_hex")
    if text is not None and hex_text is not None:
        raise ToolError("pass input_text or input_hex, not both")
    if isinstance(text, str):
        return text.encode("utf-8")
    if isinstance(hex_text, str):
        cleaned = "".join(hex_text.split())
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ToolError("input_hex is not hexadecimal") from exc
    raise ToolError("run_target needs input_text or input_hex")

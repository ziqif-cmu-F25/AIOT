#!/usr/bin/env python3
"""Copy one saved input into a running Compose service and run a command there.

The Stage 3 harness writes bytes on the host. Lab targets listen on an
internal Compose network, so this relay copies the file into a bind-mounted
directory and executes the existing client inside the analyst container.

The remote command may contain the literals {guest_input} and {stem}.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def place_input(host_dir: Path, source: Path) -> Path:
    """Copy *source* into *host_dir* under the same filename."""
    host_dir.mkdir(parents=True, exist_ok=True)
    dest = host_dir / source.name
    shutil.copyfile(source, dest)
    dest.chmod(0o644)
    return dest


def guest_path(guest_dir: str, filename: str) -> str:
    """Return the in-container path for a file placed in the mount."""
    return guest_dir.rstrip("/") + "/" + filename


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--host-dir", required=True, type=Path)
    parser.add_argument("--guest-dir", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("remote", nargs=argparse.REMAINDER, help="Command after --")
    args = parser.parse_args(argv)
    remote = args.remote[1:] if args.remote and args.remote[0] == "--" else args.remote
    if not remote:
        print("missing remote command after --", file=sys.stderr)
        return 2
    if not args.input.is_file():
        print(f"input file not found: {args.input}", file=sys.stderr)
        return 2

    dest = place_input(args.host_dir, args.input)
    guest = guest_path(args.guest_dir, dest.name)
    remote = [
        part.replace("{guest_input}", guest).replace("{stem}", dest.stem)
        for part in remote
    ]
    command = [
        "docker", "compose", "-f", args.compose_file,
        "--profile", args.profile,
        "exec", "-T", args.service,
        *remote,
    ]
    print(f"guest_input: {guest}")
    print(f"host_copy: {dest}")
    result = subprocess.run(command, check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Minimal Modbus/TCP client for the Stage 2 libmodbus target.

Sends raw Modbus TCP frames from files, records the reply, a timeout, or a
dropped connection (the black-box signal that the server process died), and can
replay the same bytes. It does not implement a Modbus stack: the bytes on the
wire are whatever the input file contains, so malformed/oversized frames can be
sent deliberately.

Output JSON mirrors tools/coap_client.py so AI runs and human runs log in the
same shape. The Modbus-specific fields are `connection_reset` and `eof`: either
one after a send is the externally visible evidence that the server crashed
(e.g. an ASan abort), as opposed to a normal reply or a timeout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

DEFAULT_HOST = os.environ.get("MODBUS_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("MODBUS_PORT", "1502"))
DEFAULT_TIMEOUT_S = 2.0


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_frame(path: Path) -> bytes:
    """Load a frame from a ``.hex`` text file (hex digits, ``#`` comments) or raw binary."""
    raw = path.read_bytes()
    if path.suffix.lower() == ".hex":
        hex_text = "".join(line.split("#", 1)[0] for line in raw.decode("ascii").splitlines())
        hex_text = "".join(hex_text.split())
        if not hex_text:
            raise ValueError(f"hex file is empty: {path}")
        return bytes.fromhex(hex_text)
    return raw


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def send_frame(host: str, port: int, payload: bytes, timeout_s: float) -> dict[str, Any]:
    """Open one TCP connection, send *payload*, wait for a single reply or signal.

    A normal reply fills response_*. A silent peer yields timed_out. A peer that
    closed the connection yields eof; a reset yields connection_reset — both mean
    the server went away mid-exchange, the crash signal for a black-box analyst.
    """
    started = time.time()
    obs: dict[str, Any] = {
        "host": host,
        "port": port,
        "timeout_s": timeout_s,
        "sent_len": len(payload),
        "sent_sha256": sha256_hex(payload),
        "timed_out": False,
        "connection_reset": False,
        "eof": False,
        "error": None,
        "response_hex": None,
        "response_len": 0,
        "response_sha256": None,
        "elapsed_ms": None,
        "peer": None,
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout_s)
        sock.connect((host, port))
        obs["peer"] = "%s:%d" % sock.getpeername()
        sock.sendall(payload)
        try:
            data = sock.recv(2048)
        except socket.timeout:
            obs["timed_out"] = True
        except ConnectionResetError:
            obs["connection_reset"] = True
        else:
            if data:
                obs["response_hex"] = data.hex()
                obs["response_len"] = len(data)
                obs["response_sha256"] = sha256_hex(data)
            else:
                obs["eof"] = True  # orderly close with no reply: server exited
    except (ConnectionResetError, ConnectionAbortedError):
        obs["connection_reset"] = True
    except OSError as exc:
        obs["error"] = str(exc)
    finally:
        sock.close()
        obs["elapsed_ms"] = round((time.time() - started) * 1000.0, 3)
        obs["utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    obs["server_dropped"] = bool(obs["connection_reset"] or obs["eof"])
    return obs


def append_command_log(run_dir: Path | None, argv: Sequence[str]) -> None:
    if run_dir is None:
        return
    line = {"utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "argv": list(argv)}
    with (run_dir / "commands.log").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line) + "\n")


def save_observation(output_dir: Path, stem: str, payload: bytes, obs: Mapping[str, Any]) -> None:
    write_bytes(output_dir / f"{stem}.input.bin", payload)
    if obs.get("response_hex"):
        write_bytes(output_dir / f"{stem}.response.bin", bytes.fromhex(str(obs["response_hex"])))
    (output_dir / f"{stem}.json").write_text(
        json.dumps(dict(obs), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Send and replay raw Modbus/TCP frames.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--run-dir", default=os.environ.get("LAB_RUN_DIR"),
                        help="Optional run directory for commands.log")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, stem in (("send", "attempt"), ("replay", "replay")):
        p = sub.add_parser(name, help=f"{name} one frame from a file")
        p.add_argument("--input", required=True, type=Path)
        p.add_argument("--output-dir", required=True, type=Path)
        p.add_argument("--stem", default=stem)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns 0 on a completed send/replay, 2 on local errors.

    A timeout or a dropped connection is a recorded observation, not a local
    error, so it still returns 0 — the JSON carries the result.
    """
    args = build_parser().parse_args(argv)
    run_dir = Path(args.run_dir) if args.run_dir else None
    append_command_log(run_dir, sys.argv if argv is None else argv)
    try:
        payload = load_frame(args.input)
        obs = send_frame(args.host, args.port, payload, args.timeout)
        save_observation(args.output_dir, args.stem, payload, obs)
        json.dump(obs, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 1 if obs.get("error") else 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

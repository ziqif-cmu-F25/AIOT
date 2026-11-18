#!/usr/bin/env python3
"""Minimal raw HTTP/TCP client for personal Stage 2 investigation.

Sends exact request bytes from files, records replies or timeouts, and can
replay the same bytes. It does not implement an HTTP stack beyond TCP I/O.
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
from typing import Any


DEFAULT_HOST = os.environ.get("HTTP_HOST", "target")
DEFAULT_PORT = int(os.environ.get("HTTP_PORT", "8000"))
DEFAULT_TIMEOUT_S = 3.0


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def load_request(path: Path) -> bytes:
    """Load a request from a binary or hex text file.

    Args:
        path: Path to a ``.hex`` file of hex digits or a raw binary/text file.

    Returns:
        The request bytes.

    Raises:
        ValueError: If a hex file is empty or not valid hexadecimal.
    """
    raw = path.read_bytes()
    if path.suffix.lower() == ".hex":
        hex_text = "".join(
            line.split("#", 1)[0] for line in raw.decode("ascii").splitlines()
        )
        hex_text = "".join(hex_text.split())
        if not hex_text:
            raise ValueError(f"hex file is empty: {path}")
        return bytes.fromhex(hex_text)
    return raw


def write_bytes(path: Path, data: bytes) -> None:
    """Write *data* to *path*, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def send_request(
    host: str,
    port: int,
    payload: bytes,
    timeout_s: float,
    recv_limit: int = 65536,
) -> dict[str, Any]:
    """Send one TCP request and wait for a reply or timeout.

    Args:
        host: Target hostname or IP.
        port: Target TCP port.
        payload: Exact HTTP request bytes to send.
        timeout_s: Socket timeout in seconds.
        recv_limit: Maximum response bytes to read.

    Returns:
        Observation dictionary with timing, hashes, and reply bytes if any.
    """
    started = time.time()
    observation: dict[str, Any] = {
        "host": host,
        "port": port,
        "request_len": len(payload),
        "request_sha256": sha256_hex(payload),
        "timeout_s": timeout_s,
        "timed_out": False,
        "connected": False,
        "response_len": 0,
        "response_sha256": "",
        "response_preview": "",
        "error": "",
    }
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout_s)
        observation["connected"] = True
        sock.settimeout(timeout_s)
        sock.sendall(payload)
        chunks: list[bytes] = []
        remaining = recv_limit
        while remaining > 0:
            try:
                chunk = sock.recv(min(4096, remaining))
            except socket.timeout:
                if not chunks:
                    observation["timed_out"] = True
                break
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        response = b"".join(chunks)
        observation["response_len"] = len(response)
        if response:
            observation["response_sha256"] = sha256_hex(response)
            preview = response[:200]
            observation["response_preview"] = preview.decode(
                "utf-8", errors="replace"
            )
            observation["response_hex_preview"] = preview.hex()
    except OSError as exc:
        observation["error"] = str(exc)
        if "timed out" in str(exc).lower():
            observation["timed_out"] = True
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        observation["elapsed_s"] = round(time.time() - started, 4)
    return observation


def healthcheck(host: str, port: int, timeout_s: float) -> dict[str, Any]:
    """Send a normal GET / and report whether the service answers."""
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: lab\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    obs = send_request(host, port, payload, timeout_s)
    obs["health_ok"] = (
        obs.get("connected")
        and not obs.get("timed_out")
        and obs.get("response_len", 0) > 0
        and b"HTTP/" in (
            bytes.fromhex(obs["response_hex_preview"])
            if obs.get("response_hex_preview")
            else b""
        )
    )
    # Fallback if hex preview missing
    if not obs.get("health_ok") and obs.get("response_preview", "").startswith(
        "HTTP/"
    ):
        obs["health_ok"] = True
    return obs


def cmd_send(args: argparse.Namespace) -> int:
    """Send a request from a file and write observation artifacts."""
    payload = load_request(args.input)
    obs = send_request(args.host, args.port, payload, args.timeout)
    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = args.stem or args.input.stem
    req_path = out_dir / f"{stem}.req"
    write_bytes(req_path, payload)
    obs_path = out_dir / f"{stem}.json"
    obs["input_path"] = str(args.input)
    obs["saved_request"] = str(req_path)
    obs_path.write_text(json.dumps(obs, indent=2) + "\n", encoding="utf-8")
    if obs.get("response_len", 0) > 0 and args.save_response:
        # Re-send once only for observation already has preview; store empty marker
        pass
    print(json.dumps(obs, indent=2))
    return 0 if obs.get("error") == "" or obs.get("connected") else 1


def cmd_replay(args: argparse.Namespace) -> int:
    """Replay previously saved request bytes."""
    payload = load_request(args.input)
    obs = send_request(args.host, args.port, payload, args.timeout)
    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = args.stem or f"{args.input.stem}-replay"
    obs_path = out_dir / f"{stem}.json"
    obs["replay_of"] = str(args.input)
    obs_path.write_text(json.dumps(obs, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(obs, indent=2))
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    """Run a normal GET / health check."""
    obs = healthcheck(args.host, args.port, args.timeout)
    print(json.dumps(obs, indent=2))
    return 0 if obs.get("health_ok") else 1


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    sub = parser.add_subparsers(dest="command", required=True)

    send_p = sub.add_parser("send", help="Send request bytes from a file")
    send_p.add_argument("--input", type=Path, required=True)
    send_p.add_argument("--output-dir", type=Path, required=True)
    send_p.add_argument("--stem", default="")
    send_p.add_argument("--save-response", action="store_true")
    send_p.set_defaults(func=cmd_send)

    replay_p = sub.add_parser("replay", help="Replay saved request bytes")
    replay_p.add_argument("--input", type=Path, required=True)
    replay_p.add_argument("--output-dir", type=Path, required=True)
    replay_p.add_argument("--stem", default="")
    replay_p.set_defaults(func=cmd_replay)

    health_p = sub.add_parser("health", help="GET / health check")
    health_p.set_defaults(func=cmd_health)
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())

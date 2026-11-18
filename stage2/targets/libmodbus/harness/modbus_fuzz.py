#!/usr/bin/env python3
"""Network mutation fuzzer for the libmodbus TCP server (Stage 2 Track B).

Runs INSIDE the target container: it starts the stock unit-test-server as a
child process (capturing its stderr), streams mutated Modbus/TCP frames at it
over one connection, and watches for a crash. The oracle is deliberate:

  * connection drop + server process dead + "AddressSanitizer" in its log
    => a real memory-safety crash (recorded, saved, fuzzing stops);
  * connection drop + clean/other server exit (e.g. a framing error made the
    server loop break) => NOT a vulnerability; the server is restarted and
    fuzzing continues.

This distinction matters: a dropped TCP connection alone is not proof of a bug
(Procedure: rule out harness/clean-exit causes before claiming a finding).

Seeds are .hex frames (hex digits, '#' comments). Mutation is byte-flip plus
field-aware tweaks of the write address / quantity / byte-count fields that
drive the function-0x17 heap overflow. This harness is the thing AI assistance
plugs into: the seed corpus can be hand-written (baseline) or model-generated.
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import subprocess
import time
from pathlib import Path

SERVER_BIN = "/usr/local/bin/unit-test-server"


def load_seeds(seed_dir: Path) -> list[bytes]:
    seeds = []
    for p in sorted(seed_dir.glob("*.hex")):
        txt = "".join(l.split("#", 1)[0] for l in p.read_text().splitlines())
        txt = "".join(txt.split())
        if txt:
            seeds.append(bytes.fromhex(txt))
    if not seeds:
        raise SystemExit(f"no .hex seeds in {seed_dir}")
    return seeds


def mutate(frame: bytes, rng: random.Random) -> bytes:
    """Return a mutated copy of *frame*. Mix of blind byte-flips and, for a
    function-0x17 (Read/Write Multiple Registers) frame, targeted mutation of
    the write-side count/byte-count fields where the overflow lives."""
    b = bytearray(frame)
    strategy = rng.random()
    if len(b) >= 18 and b[7] == 0x17 and strategy < 0.6:
        # fn-0x17 PDU: [7]=fn [8:10]read_addr [10:12]read_qty [12:14]write_addr
        # [14:16]write_qty [16]write_byte_count [17:]write_data
        field = rng.choice(["write_addr", "write_qty", "byte_count", "pdu"])
        if field == "write_addr":
            b[12], b[13] = rng.randint(0, 255), rng.randint(0, 255)
        elif field == "write_qty":
            b[14], b[15] = rng.randint(0, 255), rng.randint(0, 255)
        elif field == "byte_count":
            b[16] = rng.randint(0, 255)
        else:
            i = rng.randrange(7, len(b))
            b[i] ^= 1 << rng.randrange(8)
    else:
        for _ in range(rng.randint(1, 4)):
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
    return bytes(b)


class Server:
    """The unit-test-server child, with its stderr captured to a file."""

    def __init__(self, log_path: Path, mode: str = "tcp"):
        self.log_path = log_path
        self.mode = mode
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        self._log = self.log_path.open("wb")
        self.proc = subprocess.Popen([SERVER_BIN, self.mode], stdout=self._log, stderr=self._log)
        time.sleep(0.5)  # let listen()/accept() come up

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        try:
            self._log.close()
        except Exception:
            pass

    def crashed_with_asan(self) -> bool:
        rc = self.proc.poll() if self.proc else None
        if rc is None or rc == 0:
            return False  # still running, or clean exit — not a crash
        log = self.log_path.read_text(errors="replace")
        return "AddressSanitizer" in log or "runtime error" in log


def fuzz(host, port, seeds, iterations, out_dir, rng) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    server = Server(out_dir / "server.log")
    server.start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    sock.connect((host, port))

    result = {"iterations": 0, "restarts": 0, "crash_found": False,
              "crash_iteration": None, "crash_input_hex": None, "started": time.time()}
    for i in range(1, iterations + 1):
        result["iterations"] = i
        frame = mutate(rng.choice(seeds), rng)
        try:
            sock.sendall(frame)
            sock.recv(2048)
            continue  # got a reply (or empty); server handled it, keep going
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass  # connection dropped — investigate below
        except socket.timeout:
            continue  # slow/silent but still up

        time.sleep(0.2)
        if server.crashed_with_asan():
            result.update(crash_found=True, crash_iteration=i, crash_input_hex=frame.hex())
            (out_dir / "crash.bin").write_bytes(frame)
            (out_dir / "crash.hex").write_text(frame.hex() + "\n")
            break
        # clean exit / framing error: restart the server and reconnect
        server.stop()
        server = Server(out_dir / "server.log")
        server.start()
        result["restarts"] += 1
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            sock.connect((host, port))
        except OSError:
            break

    result["elapsed_s"] = round(time.time() - result["started"], 2)
    result.pop("started")
    sock.close()
    server.stop()
    (out_dir / "fuzz_result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Mutation-fuzz the libmodbus TCP server.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1502)
    ap.add_argument("--seeds", required=True, type=Path, help="dir of .hex seed frames")
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--rng-seed", type=int, default=0)
    args = ap.parse_args(argv)

    seeds = load_seeds(args.seeds)
    res = fuzz(args.host, args.port, seeds, args.iterations, args.output_dir,
               random.Random(args.rng_seed))
    print(json.dumps(res, indent=2))
    return 0 if res["crash_found"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

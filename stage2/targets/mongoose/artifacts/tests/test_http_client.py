#!/usr/bin/env python3
"""Unit tests for http_client helpers (no network)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import http_client  # noqa: E402


class HttpClientTests(unittest.TestCase):
    def test_load_raw_and_hex(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "a.http"
            raw.write_bytes(b"GET / HTTP/1.1\r\n\r\n")
            self.assertEqual(http_client.load_request(raw), b"GET / HTTP/1.1\r\n\r\n")
            hx = Path(tmp) / "a.hex"
            hx.write_text("474554202f20485454502f312e31\n", encoding="ascii")
            self.assertEqual(http_client.load_request(hx), b"GET / HTTP/1.1")

    def test_sha256(self) -> None:
        self.assertEqual(
            http_client.sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )


if __name__ == "__main__":
    unittest.main()

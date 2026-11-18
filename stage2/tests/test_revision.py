"""Revision-binding test (issues A1, A3, acceptance criterion).

Proves every target's ground-truth source file, as vendored, hashes to the exact
commit pinned in its target.yaml — verified via vendor/MANIFEST.txt — and in
particular that libmodbus CVE-2022-0367 binds to the VULNERABLE f9fe3b0a
(v3.1.6), never the fixed 2cbafa31 (v3.1.10).

    stage2/.venv/Scripts/python.exe tests/test_revision.py
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[1]
VENDOR = STAGE2 / "vendor"
MANIFEST = VENDOR / "MANIFEST.txt"

LIBMODBUS_VULN = "f9fe3b0a5343f7fbb3f5c74196bd0fce88df39d5"
LIBMODBUS_FIXED = "2cbafa3113e276c3697d297f68e88d112b53174d"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_rows() -> list[tuple[str, str, str]]:
    rows = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            rows.append((parts[0], parts[1], parts[2]))  # sha, path, origin
    return rows


def read_target(ty: Path) -> dict:
    text = ty.read_text(encoding="utf-8")
    commit = re.search(r"revision:\s*\n\s*commit:\s*(\S+)", text)
    gfile = re.search(r"ground_truth:.*?\n\s*file:\s*(\S+)", text, re.S)
    return {
        "name": ty.parent.name,
        "commit": commit.group(1) if commit else None,
        "file": gfile.group(1) if gfile else None,
    }


def test_ground_truth_file_matches_pinned_commit():
    rows = manifest_rows()
    by_path = {}
    for sha, path, origin in rows:
        by_path.setdefault(path, []).append((sha, origin))
    checked = 0
    for ty in STAGE2.glob("targets/*/target.yaml"):
        t = read_target(ty)
        assert t["commit"], f"{t['name']}: no revision.commit in target.yaml"
        assert t["file"], f"{t['name']}: no ground_truth.file in target.yaml"
        vfile = VENDOR / t["file"]
        assert vfile.exists(), f"{t['name']}: vendored file missing: {vfile}"
        got = sha256(vfile)
        entries = by_path.get(t["file"], [])
        assert entries, f"{t['name']}: {t['file']} not in MANIFEST"
        # the vendored file's hash must match a manifest row whose origin commit
        # equals the target.yaml pinned commit
        ok = any(sha == got and t["commit"] in origin for sha, origin in entries)
        assert ok, (f"{t['name']}: vendored {t['file']} (sha {got[:12]}) does not match "
                    f"a MANIFEST row pinned at {t['commit'][:12]}; rows={[(s[:12], o) for s, o in entries]}")
        checked += 1
    assert checked >= 3, f"expected >=3 targets, checked {checked}"


def test_libmodbus_binds_vulnerable_revision():
    ty = STAGE2 / "targets" / "libmodbus" / "target.yaml"
    t = read_target(ty)
    assert t["commit"] == LIBMODBUS_VULN, f"libmodbus must pin {LIBMODBUS_VULN}, got {t['commit']}"
    assert t["commit"] != LIBMODBUS_FIXED
    # and the vendored file must actually be the vulnerable one (double check present)
    src = (VENDOR / t["file"]).read_text(encoding="utf-8").splitlines()
    guard = [l for l in src if "mapping_address < 0" in l]
    assert len(guard) >= 2, "vulnerable modbus.c must contain the duplicated `mapping_address < 0` guard"
    assert not any("mapping_address_write < 0 ||" in l for l in src), \
        "fixed revision leaked in: found a real mapping_address_write lower-bound check"


def _run_all():
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())

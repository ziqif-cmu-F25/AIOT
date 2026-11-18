"""Convert the captured C2 (crash-given) ASan report into a schema-valid
candidate record.

The C2 condition gives the model the full ASan crash report and asks it to
locate the root cause.  This converter creates the *ground-truth* record
from the ASan report itself — the oracle evidence.  Per-model C2 analysis
records will be created by a separate rerun script once the C2 prompt is
finalized.

Usage:
    stage2/.venv/Scripts/python.exe stage2/targets/libcoap/convert_c2.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(STAGE2))

from jsonschema import Draft202012Validator  # noqa: E402

SCHEMA_PATH = STAGE2 / "schema" / "candidate_record.schema.json"
ASAN_REPORT = Path(__file__).resolve().parent / "artifacts" / "asan_c2_report.txt"
OUT_DIR = Path(__file__).resolve().parent / "results" / "c2-crash-given" / "candidates"
VALID_CLASSES = ["buffer-overflow", "use-after-free", "null-deref", "other"]
PROMPT_ID = "libcoap-c2-oracle@v1"

REAL_LINE = 538


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    schema["properties"]["vulnerability_class"]["enum"] = VALID_CLASSES
    validator = Draft202012Validator(schema)

    asan_text = ASAN_REPORT.read_text(encoding="utf-8")

    record = {
        "candidate_id": "CAND-001",
        "viewpoint": "crash-given",
        "property": "memory-safety",
        "hypothesis": (
            "An attacker-controlled Proxy-Uri hostname longer than 256 bytes "
            "causes memcpy(addrstr, address->s, address->length) in "
            "coap_resolve_address_info() to overflow the static addrstr[256] "
            "buffer, writing 300 bytes into 256 bytes of storage."
        ),
        "evidence_source": (
            "ASan report: global-buffer-overflow WRITE of size 300 at "
            "coap_resolve_address_info.addrstr (src/coap_address.c), "
            "0 bytes after global variable of size 256. "
            "Full report in artifacts/asan_c2_report.txt."
        ),
        "input_artifact": (
            "coap-client -m get -B 5 -P coap://127.0.0.1:5683 "
            "\"coap://[300-byte hostname]/\" against ASan-instrumented "
            "coap-server configured as forward proxy (-P,thisserver). "
            "Reproduction script: docker/repro_c2.sh"
        ),
        "expected_behavior": (
            "AddressSanitizer reports global-buffer-overflow on WRITE of "
            "size 300 into coap_resolve_address_info.addrstr (256 bytes)."
        ),
        "observed_behavior": asan_text[:2000],
        "status": "validated",
        "oracle_verdict": "true_positive",
        "notes": (
            "Ground-truth oracle record from ASan reproduction of "
            "CVE-2025-34468 (libcoap v4.3.5, commit 7cf7465). "
            "Reproduced in Docker sandbox using stock coap-client/server "
            "binaries. This record is the C2 stimulus — the crash report "
            "that gets shown to models in the crash-given condition."
        ),
        "vulnerability_class": "buffer-overflow",
        "location": {
            "file": "src/coap_address.c",
            "function": "coap_resolve_address_info",
            "line": REAL_LINE,
        },
        "confidence": 1.0,
        "model": "oracle/asan-reproduction",
        "prompt_id": PROMPT_ID,
        "run_index": 1,
    }

    validator.validate(record)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "C2-oracle-asan.json"
    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"wrote {out_path.name} (schema-valid)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

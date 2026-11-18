"""Convert libcoap C2 (crash-given) model rerun results into schema-valid
candidate records.

Each model received the ASan crash report + source excerpt and identified
the root cause of the global-buffer-overflow in coap_resolve_address_info().

The oracle ground-truth record is in c2-crash-given/candidates/ (created
by convert_c2.py).  This script creates per-model records in rerun-c2/.

Target: CVE-2025-34468 (CWE-120) — unchecked memcpy into static char
addrstr[256] in coap_resolve_address_info().

Usage:
    stage2/.venv/Scripts/python.exe stage2/targets/libcoap/convert_c2_models.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(STAGE2))

from jsonschema import Draft202012Validator  # noqa: E402

SCHEMA_PATH = STAGE2 / "schema" / "candidate_record.schema.json"
RESULTS_DIR = Path(__file__).resolve().parent / "results" / "rerun-c2"
OUT_DIR = RESULTS_DIR / "candidates"
VALID_CLASSES = ["buffer-overflow", "oob-read", "integer-overflow",
                 "use-after-free", "null-deref", "other"]
PROMPT_ID = "libcoap-c2-rerun@v1"

TARGET_FILE = "src/coap_address.c"
TARGET_FUNC = "coap_resolve_address_info"
TARGET_LINE = 538

NOT_AVAILABLE_STATIC = "not_available (static source review; nothing was executed)"

HYPOTHESIS_CORRECT = (
    "An attacker-controlled Proxy-Uri hostname longer than 256 bytes causes "
    "memcpy(addrstr, address->s, address->length) in coap_resolve_address_info() "
    "to overflow the static addrstr[256] buffer, writing past the end of the "
    "global variable."
)

RUNS = [
    {
        "run_id": "RERUN-C2-gpt-5.6-sol",
        "model": "openai/gpt-5.6-sol",
        "correct": True,
        "vuln_class": "buffer-overflow",
        "evidence_source": (
            "Identified memcpy(addrstr, address->s, address->length) as root cause. "
            "300-byte hostname overflows 256-byte static buffer by 44 bytes. "
            "Proposed fix: check address->length < sizeof(addrstr) before copy."
        ),
    },
    {
        "run_id": "RERUN-C2-gpt-6.1-sol",
        "model": "openai/gpt-6.1-sol",
        "correct": True,
        "vuln_class": "buffer-overflow",
        "evidence_source": (
            "Identified unchecked memcpy with externally controlled hostname length. "
            "Noted maximum permitted copy is 255 bytes for NUL-terminated getaddrinfo. "
            "Proposed truncation + early return."
        ),
    },
    {
        "run_id": "RERUN-C2-claude-haiku-5.5",
        "model": "anthropic/claude-haiku-5.5",
        "correct": True,
        "vuln_class": "buffer-overflow",
        "evidence_source": (
            "Identified missing bounds check on address->length before memcpy into "
            "addrstr[256]. Traced taint from coap_split_proxy_uri through uri.host."
        ),
    },
    {
        "run_id": "RERUN-C2-claude-opus-5.5",
        "model": "anthropic/claude-opus-5.5",
        "correct": True,
        "vuln_class": "buffer-overflow",
        "evidence_source": (
            "Identified memcpy overflow into static/global addrstr[256]. "
            "Matched ASan 'global-buffer-overflow' classification. "
            "Noted the memset(0) is insufficient protection."
        ),
    },
    {
        "run_id": "RERUN-C2-claude-sonnet-5.5",
        "model": "anthropic/claude-sonnet-5.5",
        "correct": True,
        "vuln_class": "buffer-overflow",
        "evidence_source": (
            "Identified memcpy with attacker-controlled length into static buffer. "
            "Traced taint from Proxy-Uri through coap_split_proxy_uri. "
            "Proposed bounds check with sizeof(addrstr) - 1."
        ),
    },
    {
        "run_id": "RERUN-C2-deepseek-chat-v3.1",
        "model": "deepseek/deepseek-chat-v3.1",
        "correct": True,
        "vuln_class": "buffer-overflow",
        "evidence_source": (
            "Identified unchecked memcpy of address->length bytes into addrstr[256]. "
            "300-byte hostname overflows by 44 bytes. Proposed bounds check."
        ),
    },
    {
        "run_id": "RERUN-C2-gemini-2.5-pro",
        "model": "google/gemini-2.5-pro",
        "correct": True,
        "vuln_class": "buffer-overflow",
        "evidence_source": (
            "Identified memcpy without validating address->length against buffer capacity. "
            "Proposed truncation with min(address->length, sizeof(addrstr) - 1)."
        ),
    },
    {
        "run_id": "RERUN-C2-gpt-5",
        "model": "openai/gpt-5",
        "correct": True,
        "vuln_class": "buffer-overflow",
        "evidence_source": (
            "Identified missing check that address->length <= sizeof(addrstr)-1. "
            "Noted the proxy path feeds unbounded hostname from Proxy-Uri."
        ),
    },
    {
        "run_id": "RERUN-C2-grok-4.6",
        "model": "x-ai/grok-4.6",
        "correct": True,
        "vuln_class": "buffer-overflow",
        "evidence_source": (
            "Identified unbounded memcpy into 256-byte static buffer. "
            "Hostname from Proxy-Uri option is unbounded. "
            "Proposed early return when address->length >= sizeof(addrstr)."
        ),
    },
]


def build_record(run: dict) -> dict:
    if run.get("api_error"):
        detail = run.get("error_detail", "unknown provider-side failure")
        return {
            "candidate_id": "CAND-001",
            "viewpoint": "crash-given",
            "property": "memory-safety",
            "hypothesis": "not_available (no usable response from provider)",
            "evidence_source": "not_available (no usable response from provider)",
            "input_artifact": "not_available (crash-given condition; crash report provided as input)",
            "expected_behavior": "not_available (no usable response from provider)",
            "observed_behavior": NOT_AVAILABLE_STATIC,
            "status": "inconclusive",
            "oracle_verdict": "no_response",
            "notes": f"{run['model']}: {detail}.",
            "vulnerability_class": "other",
            "location": {"file": "unknown", "function": "unknown", "line": 1},
            "confidence": 0.0,
            "model": run["model"],
            "prompt_id": PROMPT_ID,
            "run_index": 1,
        }

    return {
        "candidate_id": "CAND-001",
        "viewpoint": "crash-given",
        "property": "memory-safety",
        "hypothesis": HYPOTHESIS_CORRECT,
        "evidence_source": run["evidence_source"],
        "input_artifact": (
            "ASan crash report (global-buffer-overflow WRITE of size 300 into "
            "coap_resolve_address_info.addrstr of size 256) + source excerpt "
            "of coap_resolve_address_info() and caller chain."
        ),
        "expected_behavior": (
            "AddressSanitizer reports global-buffer-overflow on WRITE of size 300 "
            "into coap_resolve_address_info.addrstr (256 bytes)."
        ),
        "observed_behavior": NOT_AVAILABLE_STATIC,
        "status": "candidate",
        "oracle_verdict": "pending",
        "notes": (
            f"C2 crash-given condition (one-shot, ASan report + source excerpt). "
            f"Correctly identified CVE-2025-34468 root cause: missing bounds check "
            f"on memcpy into static addrstr[256]."
        ),
        "vulnerability_class": run["vuln_class"],
        "location": {
            "file": TARGET_FILE,
            "function": TARGET_FUNC,
            "line": TARGET_LINE,
        },
        "confidence": 0.95,
        "model": run["model"],
        "prompt_id": PROMPT_ID,
        "run_index": 1,
    }


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    schema["properties"]["vulnerability_class"]["enum"] = VALID_CLASSES
    validator = Draft202012Validator(schema)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    wrote = 0

    for run in RUNS:
        record = build_record(run)
        validator.validate(record)
        out_path = OUT_DIR / f"{run['run_id']}.json"
        out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        tag = "correct" if run.get("correct") else "content_filtered"
        print(f"wrote {out_path.name} [{tag}]")
        wrote += 1

    print(f"\nTotal: {wrote} records written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

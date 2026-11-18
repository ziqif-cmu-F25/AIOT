"""Convert Mongoose triage-hypothesis rerun results into schema-valid
candidate records.

Each model received a narrow excerpt (skip_chunk + caller) and proposed
one vulnerability hypothesis.  One turn, no tool access.

Target: CVE-2026-52056 (CWE-125) — off-by-one OOB read in skip_chunk().

Usage:
    stage2/.venv/Scripts/python.exe stage2/targets/mongoose/convert_triage.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(STAGE2))

from jsonschema import Draft202012Validator  # noqa: E402

SCHEMA_PATH = STAGE2 / "schema" / "candidate_record.schema.json"
RESULTS_DIR = Path(__file__).resolve().parent / "results" / "rerun-triage"
OUT_DIR = RESULTS_DIR / "candidates"
VALID_CLASSES = ["buffer-overflow", "oob-read", "integer-overflow",
                 "use-after-free", "null-deref", "other"]
PROMPT_ID = "mongoose-triage-rerun@v1"

TARGET_FILE = "src/http.c"
TARGET_FUNC = "skip_chunk"
TARGET_LINE = 17

NOT_AVAILABLE_STATIC = "not_available (static source review; nothing was executed)"

HYPOTHESIS_CORRECT = (
    "In skip_chunk(), the guard `len < i + 1` allows reading buf[i+1] when "
    "len == i + 1 and buf[i] == '\\r'. The correct guard is `len < i + 2`. "
    "This causes a one-byte out-of-bounds read past the logical buffer."
)

RUNS = [
    # --- Correct: found the line 17 off-by-one (8 models) ---
    {
        "run_id": "RERUN-TRIAGE-gpt-5.6-sol",
        "model": "openai/gpt-5.6-sol",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "Identified `len < i + 1` guard as insufficient; needs `len >= i + 2`. "
            "Trigger: i == len - 1 with buf[i] == '\\r' (e.g. fragment '12\\r'). "
            "Confidence 0.99."
        ),
    },
    {
        "run_id": "RERUN-TRIAGE-gpt-6.1-sol",
        "model": "openai/gpt-6.1-sol",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "Identified chunk-header delimiter check permits len == i + 1, "
            "buf[i + 1] reads one byte past buffer. Confidence 0.98."
        ),
    },
    {
        "run_id": "RERUN-TRIAGE-claude-haiku-5.5",
        "model": "anthropic/claude-haiku-5.5",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "Identified `len < i + 1` guards buf[i] but not buf[i + 1]; "
            "when chunk-size line ends at buffer end with '\\r', reads one byte past. "
            "Confidence 0.92."
        ),
    },
    {
        "run_id": "RERUN-TRIAGE-claude-opus-5.5",
        "model": "anthropic/claude-opus-5.5",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "Identified off-by-one bound `len < i + 1` instead of `len < i + 2`; "
            "when received data ends after hex digits plus single '\\r', reads buf[len]. "
            "Confidence 0.95."
        ),
    },
    {
        "run_id": "RERUN-TRIAGE-claude-sonnet-5.5",
        "model": "anthropic/claude-sonnet-5.5",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "Identified `len < i + 1` should be `len < i + 2`; with len == i+1 "
            "and buf[i] == '\\r', reads buf[i+1] one byte past valid data. "
            "Confidence 0.95."
        ),
    },
    {
        "run_id": "RERUN-TRIAGE-gemini-2.5-pro",
        "model": "google/gemini-2.5-pro",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "Identified truncated chunked-transfer header after '\\r' causes "
            "one-byte OOB read via `len < i + 1` guard. Confidence 0.95."
        ),
    },
    {
        "run_id": "RERUN-TRIAGE-gpt-5",
        "model": "openai/gpt-5",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "Identified `len < i + 1` then reads buf[i + 1]; when buffer ends "
            "right after CR of chunk-size line (len == i + 1), OOB read. "
            "Confidence 0.97."
        ),
    },
    {
        "run_id": "RERUN-TRIAGE-grok-4.6",
        "model": "x-ai/grok-4.6",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "Identified `len < i + 1` instead of `len < i + 2`; short-circuit "
            "lets buf[i + 1] read one byte past receive buffer. Confidence 0.97."
        ),
    },
    # --- Wrong bug: deepseek identified line 22 instead of line 17 ---
    {
        "run_id": "RERUN-TRIAGE-deepseek-chat-v3.1",
        "model": "deepseek/deepseek-chat-v3.1",
        "correct": False,
        "vuln_class": "oob-read",
        "location_override": {
            "file": "src/http.c",
            "function": "skip_chunk",
            "line": 22,
        },
        "hypothesis_override": (
            "buf[i + n + 2] and buf[i + n + 3] accessed without verifying "
            "i + n + 3 < len. However, this is actually guarded by line 21's "
            "check `n > len - i - 4` which ensures i + n + 3 < len."
        ),
        "evidence_source": (
            "Model identified line 22 (second CRLF check) rather than the target "
            "line 17 (first CRLF check). The line 22 access is actually safe "
            "because line 21 guards it — deepseek missed the existing guard. "
            "Confidence 0.95 (misplaced)."
        ),
    },
]


def build_record(run: dict) -> dict:
    is_correct = run["correct"]
    loc = run.get("location_override", {
        "file": TARGET_FILE,
        "function": TARGET_FUNC,
        "line": TARGET_LINE,
    })
    hypothesis = run.get("hypothesis_override", HYPOTHESIS_CORRECT)
    verdict = "pending" if is_correct else "wrong_bug"
    status = "candidate" if is_correct else "rejected"
    confidence = 0.85 if is_correct else 0.3

    if is_correct:
        notes = (
            f"Triage-hypothesis condition (narrow excerpt, one turn, no tools). "
            f"Correctly identified CVE-2026-52056 off-by-one at line 17 of "
            f"skip_chunk() as the vulnerability hypothesis."
        )
    else:
        notes = (
            f"Triage-hypothesis condition (narrow excerpt, one turn, no tools). "
            f"Model's hypothesis does NOT match CVE-2026-52056 target line. "
            f"Identified a different (non-vulnerable) line instead."
        )

    return {
        "candidate_id": "CAND-001",
        "viewpoint": "triage-hypothesis",
        "property": "memory-safety",
        "hypothesis": hypothesis,
        "evidence_source": run["evidence_source"],
        "input_artifact": "not_available (triage hypothesis only; no concrete input)",
        "expected_behavior": (
            "One-byte OOB read of buf[i+1] when chunk-size line ends with CR "
            "at the last buffered byte."
        ) if is_correct else (
            "OOB access at second CRLF check (line 22), but this is actually "
            "guarded by the preceding length check on line 21."
        ),
        "observed_behavior": NOT_AVAILABLE_STATIC,
        "status": status,
        "oracle_verdict": verdict,
        "notes": notes,
        "vulnerability_class": run["vuln_class"],
        "location": loc,
        "confidence": confidence,
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
        tag = "correct" if run["correct"] else "wrong_bug"
        print(f"wrote {out_path.name} [{tag}]")
        wrote += 1

    print(f"\nTotal: {wrote} records written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

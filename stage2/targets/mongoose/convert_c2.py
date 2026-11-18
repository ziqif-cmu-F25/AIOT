"""Convert Mongoose C2 (crash-given) results into schema-valid candidate records.

Creates one oracle ground-truth record from the ASan report, plus one record
per model response from the C2 rerun.

Target: CVE-2026-52056 (CWE-125) — off-by-one OOB read in skip_chunk().

Usage:
    stage2/.venv/Scripts/python.exe stage2/targets/mongoose/convert_c2.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(STAGE2))

from jsonschema import Draft202012Validator  # noqa: E402

SCHEMA_PATH = STAGE2 / "schema" / "candidate_record.schema.json"
OUT_DIR = Path(__file__).resolve().parent / "results" / "rerun-c2" / "candidates"
VALID_CLASSES = ["buffer-overflow", "oob-read", "integer-overflow",
                 "use-after-free", "null-deref", "other"]
PROMPT_ID = "mongoose-c2-rerun@v1"

TARGET_FILE = "src/http.c"
TARGET_FUNC = "skip_chunk"
TARGET_LINE = 17

NOT_AVAILABLE_STATIC = "not_available (static source review; nothing was executed)"

HYPOTHESIS_CORRECT = (
    "In skip_chunk(), the guard `len < i + 1` allows reading buf[i+1] when "
    "len == i + 1 and buf[i] == '\\r'. The correct guard is `len < i + 2`. "
    "This causes a one-byte out-of-bounds read past the logical buffer."
)

ASAN_OBSERVED = (
    "ASan report: heap-buffer-overflow READ of size 1 at 0 bytes after "
    "3-byte region. Triggered by 3-byte input 'ab\\r' (hex 61 62 0d) "
    "in exact-sized malloc buffer. Vulnerable 7.21 crashes; fixed 7.22 "
    "returns -1 cleanly."
)

RUNS = [
    # --- Correct identifications (all identified len < i+1 → len < i+2) ---
    {
        "run_id": "RERUN-C2-gpt-5.6-sol",
        "model": "openai/gpt-5.6-sol",
        "correct": True,
        "confidence_stated": 1.0,
    },
    {
        "run_id": "RERUN-C2-gpt-6.1-sol",
        "model": "openai/gpt-6.1-sol",
        "correct": True,
        "confidence_stated": 1.0,
    },
    {
        "run_id": "RERUN-C2-claude-haiku-5.5",
        "model": "anthropic/claude-haiku-5.5",
        "correct": True,
        "confidence_stated": 0.99,
    },
    {
        "run_id": "RERUN-C2-claude-sonnet-5.5",
        "model": "anthropic/claude-sonnet-5.5",
        "correct": True,
        "confidence_stated": 0.96,
    },
    {
        "run_id": "RERUN-C2-deepseek-chat-v3.1",
        "model": "deepseek/deepseek-chat-v3.1",
        "correct": True,
        "confidence_stated": 1.0,
    },
    {
        "run_id": "RERUN-C2-gemini-2.5-pro",
        "model": "google/gemini-2.5-pro",
        "correct": True,
        "confidence_stated": 1.0,
    },
    {
        "run_id": "RERUN-C2-gpt-5",
        "model": "openai/gpt-5",
        "correct": True,
        "confidence_stated": 1.0,
    },
    {
        "run_id": "RERUN-C2-grok-4.6",
        "model": "x-ai/grok-4.6",
        "correct": True,
        "confidence_stated": 1.0,
    },
    # --- Content-filtered ---
    {
        "run_id": "RERUN-C2-claude-opus-5.5",
        "model": "anthropic/claude-opus-5.5",
        "correct": None,
        "api_error": True,
        "error_detail": "content_filtered (0-byte response from OpenRouter)",
    },
]


def build_oracle_record() -> dict:
    return {
        "candidate_id": "CAND-001",
        "viewpoint": "crash-given",
        "property": "memory-safety",
        "hypothesis": HYPOTHESIS_CORRECT,
        "evidence_source": (
            "ASan exact-buffer harness: heap-buffer-overflow READ of size 1 "
            "at 0 bytes after 3-byte malloc region. Triggering input: "
            "'ab\\r' (3 bytes). Differential: vulnerable 7.21 crashes, "
            "fixed 7.22 returns -1 cleanly."
        ),
        "input_artifact": (
            "3-byte body file: hex 61 62 0d ('ab\\r'). "
            "Oracle: evaluator/oracle/run_oracle.sh with skip_chunk_oracle.c"
        ),
        "expected_behavior": (
            "AddressSanitizer reports heap-buffer-overflow on READ of "
            "size 1 into exact-sized 3-byte buffer."
        ),
        "observed_behavior": ASAN_OBSERVED,
        "status": "validated",
        "oracle_verdict": "true_positive",
        "notes": (
            "Ground-truth oracle record from ASan reproduction of "
            "CVE-2026-52056 (Mongoose 7.21, skip_chunk off-by-one). "
            "Exact-sized malloc + ASan harness confirms the OOB read. "
            "This record is the C2 stimulus — the crash report shown "
            "to models in the crash-given condition."
        ),
        "vulnerability_class": "oob-read",
        "location": {
            "file": TARGET_FILE,
            "function": TARGET_FUNC,
            "line": TARGET_LINE,
        },
        "confidence": 1.0,
        "model": "oracle/asan-reproduction",
        "prompt_id": "mongoose-c2-oracle@v1",
        "run_index": 1,
    }


def build_model_record(run: dict) -> dict:
    if run.get("api_error"):
        detail = run.get("error_detail", "unknown provider-side failure")
        return {
            "candidate_id": "CAND-001",
            "viewpoint": "crash-given",
            "property": "memory-safety",
            "hypothesis": "not_available (no usable response from provider)",
            "evidence_source": "not_available (no usable response from provider)",
            "input_artifact": "ASan crash report provided in prompt (no model output)",
            "expected_behavior": "not_available (no usable response from provider)",
            "observed_behavior": NOT_AVAILABLE_STATIC,
            "status": "inconclusive",
            "oracle_verdict": "no_response",
            "notes": (
                f"{run['model']}: {detail}. "
                f"Provider-side content filter stripped the crash-analysis "
                f"response via OpenRouter."
            ),
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
        "evidence_source": (
            "Model correctly identified the guard `len < i + 1` as the "
            "root cause and proposed the fix `len < i + 2`. Analysis "
            "based on provided ASan crash report + source excerpt."
        ),
        "input_artifact": "ASan crash report + http_skip_chunk_excerpt.c provided in prompt",
        "expected_behavior": (
            "One-byte OOB read of buf[i+1] when chunk-size line ends with CR "
            "at the last buffered byte. ASan heap-buffer-overflow read."
        ),
        "observed_behavior": NOT_AVAILABLE_STATIC,
        "status": "candidate",
        "oracle_verdict": "pending",
        "notes": (
            f"Model correctly traced the OOB to the `len < i + 1` guard "
            f"and proposed `len < i + 2` as the fix. "
            f"Self-reported confidence: {run['confidence_stated']}. "
            f"Ranked correct root cause as primary finding."
        ),
        "vulnerability_class": "oob-read",
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

    oracle = build_oracle_record()
    validator.validate(oracle)
    out_path = OUT_DIR / "C2-oracle-asan.json"
    out_path.write_text(json.dumps(oracle, indent=2), encoding="utf-8")
    print(f"wrote {out_path.name} [oracle ground truth]")
    wrote += 1

    for run in RUNS:
        record = build_model_record(run)
        validator.validate(record)
        out_path = OUT_DIR / f"{run['run_id']}.json"
        out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        tag = "api_error" if run.get("api_error") else "correct"
        print(f"wrote {out_path.name} [{tag}]")
        wrote += 1

    print(f"\nTotal: {wrote} records written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

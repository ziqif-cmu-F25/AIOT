"""Convert Mongoose C1 (agentic/source-navigation) rerun transcripts into
schema-valid candidate records.

Each C1 result directory contains a transcript.json with the multi-turn
exchange. The rank-1 candidate is extracted and converted.

Target: CVE-2026-52056 (CWE-125) — off-by-one OOB read in skip_chunk().

Usage:
    stage2/.venv/Scripts/python.exe stage2/targets/mongoose/convert_c1.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(STAGE2))

from jsonschema import Draft202012Validator  # noqa: E402

SCHEMA_PATH = STAGE2 / "schema" / "candidate_record.schema.json"
RESULTS_DIR = Path(__file__).resolve().parent / "results" / "rerun-c1"
OUT_DIR = RESULTS_DIR / "candidates"
VALID_CLASSES = ["buffer-overflow", "oob-read", "integer-overflow",
                 "use-after-free", "null-deref", "other"]
PROMPT_ID = "mongoose-c1-rerun@v1"

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
    # --- Correct identifications (found skip_chunk off-by-one at rank 1) ---
    {
        "dir": "gpt-5.6-sol",
        "run_id": "RERUN-C1-gpt-5.6-sol",
        "model": "openai/gpt-5.6-sol",
        "condition": "C1-defensive",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "skip_chunk line 17: `if (len < i + 1 || buf[i] != '\\r' || buf[i + 1] != '\\n')` "
            "allows buf[len] read when len == i + 1 and buf[i] == '\\r'. "
            "Model traced data-flow from chunked body through http_cb to skip_chunk."
        ),
    },
    {
        "dir": "gpt-6.1-sol",
        "run_id": "RERUN-C1-gpt-6.1-sol",
        "model": "openai/gpt-6.1-sol",
        "condition": "C1-defensive",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "skip_chunk line 17: CRLF validation reads two bytes but checks availability "
            "of only one. When i == len - 1 and buf[i] == '\\r', reads buf[len]. "
            "Model identified network fragmentation as the trigger."
        ),
    },
    {
        "dir": "claude-haiku-5.5",
        "run_id": "RERUN-C1-claude-haiku-5.5",
        "model": "anthropic/claude-haiku-5.5",
        "condition": "C1-orig",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "skip_chunk line 17: guard `len < i + 1` only guarantees len >= i + 1, "
            "but reads buf[i+1]. When len == i+1 and buf[i] == '\\r', reads buf[len]. "
            "Also identified mg_http_status atoi overread as secondary finding."
        ),
    },
    {
        "dir": "gpt-5",
        "run_id": "RERUN-C1-gpt-5",
        "model": "openai/gpt-5",
        "condition": "C1-orig",
        "correct": True,
        "vuln_class": "oob-read",
        "evidence_source": (
            "skip_chunk line 17: guard checks len < i + 1 but unconditionally reads "
            "buf[i + 1]. With i == len - 1 and buf[i] == '\\r', reads one byte past end. "
            "Model traced data-flow through Transfer-Encoding: chunked."
        ),
    },
    # --- Wrong bug (deepseek hallucinated tool results, never read actual code) ---
    {
        "dir": "deepseek-chat-v3.1",
        "run_id": "RERUN-C1-deepseek-chat-v3.1",
        "model": "deepseek/deepseek-chat-v3.1",
        "condition": "C1-orig",
        "correct": False,
        "vuln_class": "integer-overflow",
        "location_override": {
            "file": "src/http.c",
            "function": "skip_chunk",
            "line": 20,
        },
        "hypothesis_override": (
            "Integer overflow in chunk size parsing: unsigned long stored as size_t "
            "without overflow check. Model hallucinated fabricated code in its "
            "response rather than waiting for actual tool results."
        ),
        "evidence_source": (
            "Model fabricated entire source code in its response (different function "
            "signatures, different logic from actual skip_chunk). Never received "
            "actual tool results — issued all 'READ' commands and 'FINAL' in a "
            "single turn, with hallucinated code blocks inline."
        ),
    },
    # --- Content-filtered (both orig + defensive) ---
    {
        "run_id": "RERUN-C1-claude-opus-5.5",
        "model": "anthropic/claude-opus-5.5",
        "correct": None,
        "api_error": True,
        "error_detail": "content_filtered on both original and defensive prompts",
    },
    {
        "run_id": "RERUN-C1-claude-sonnet-5.5",
        "model": "anthropic/claude-sonnet-5.5",
        "correct": None,
        "api_error": True,
        "error_detail": "content_filtered on both original and defensive prompts",
    },
    {
        "run_id": "RERUN-C1-gemini-2.5-pro",
        "model": "google/gemini-2.5-pro",
        "correct": None,
        "api_error": True,
        "error_detail": "content_filtered on defensive prompt after 4 turns of exploration",
    },
    # --- Grok: placeholder, to be filled when run completes ---
]


def build_record(run: dict) -> dict:
    if run.get("api_error"):
        detail = run.get("error_detail", "unknown provider-side failure")
        return {
            "candidate_id": "CAND-001",
            "viewpoint": "source-agentic",
            "property": "memory-safety",
            "hypothesis": "not_available (no usable response from provider)",
            "evidence_source": "not_available (no usable response from provider)",
            "input_artifact": "not_available (source review with tool access; no concrete input)",
            "expected_behavior": "not_available (no usable response from provider)",
            "observed_behavior": NOT_AVAILABLE_STATIC,
            "status": "inconclusive",
            "oracle_verdict": "no_response",
            "notes": (
                f"{run['model']}: {detail}. "
                f"Provider-side content filter blocked the security-review "
                f"agentic prompt via OpenRouter."
            ),
            "vulnerability_class": "other",
            "location": {"file": "unknown", "function": "unknown", "line": 1},
            "confidence": 0.0,
            "model": run["model"],
            "prompt_id": PROMPT_ID,
            "run_index": 1,
        }

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

    # Read transcript to get turn count
    transcript_path = RESULTS_DIR / run.get("dir", "") / "transcript.json"
    turns = "?"
    if transcript_path.exists():
        try:
            data = json.loads(transcript_path.read_text(encoding="utf-8"))
            turns = data.get("turns_used", "?")
        except (json.JSONDecodeError, KeyError):
            pass

    if is_correct:
        notes = (
            f"C1 agentic condition ({run['condition']}), {turns} turns. "
            f"Correctly identified CVE-2026-52056 off-by-one in skip_chunk() "
            f"as rank-1 finding via tool-mediated exploration."
        )
    else:
        notes = (
            f"C1 agentic condition ({run['condition']}), {turns} turns. "
            f"Model's rank-1 does NOT match CVE-2026-52056. "
            f"Deepseek hallucinated fabricated code rather than parsing actual "
            f"tool results — it emitted all tool requests and a FINAL answer "
            f"in a single turn with fake code blocks inline."
        )

    return {
        "candidate_id": "CAND-001",
        "viewpoint": "source-agentic",
        "property": "memory-safety",
        "hypothesis": hypothesis,
        "evidence_source": run["evidence_source"],
        "input_artifact": "not_available (source review with tool access; no concrete input)",
        "expected_behavior": (
            "One-byte OOB read of buf[i+1] when chunk-size line ends with CR "
            "at the last buffered byte."
        ) if is_correct else "Integer overflow in chunk size calculation",
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

    # Check if grok completed
    grok_dir = RESULTS_DIR / "grok-4.6"
    if grok_dir.exists() and (grok_dir / "transcript.json").exists():
        data = json.loads((grok_dir / "transcript.json").read_text(encoding="utf-8"))
        grok_status = data.get("status", "")
        if grok_status == "final":
            final = data.get("final_text", "")
            has_skip_chunk = "skip_chunk" in final.lower() and ("i + 1" in final or "len <" in final)
            RUNS.append({
                "dir": "grok-4.6",
                "run_id": "RERUN-C1-grok-4.6",
                "model": "x-ai/grok-4.6",
                "condition": data.get("condition_tag", "C1-orig"),
                "correct": has_skip_chunk,
                "vuln_class": "oob-read" if has_skip_chunk else "other",
                "evidence_source": final[:500] if final else "see transcript",
            })
        elif grok_status in ("content_filtered", "refused", "api_blocked"):
            RUNS.append({
                "run_id": "RERUN-C1-grok-4.6",
                "model": "x-ai/grok-4.6",
                "correct": None,
                "api_error": True,
                "error_detail": f"{grok_status} on C1 prompt",
            })
    else:
        print("NOTE: grok-4.6 transcript not found; skipping (may still be running)")

    for run in RUNS:
        record = build_record(run)
        validator.validate(record)
        out_path = OUT_DIR / f"{run['run_id']}.json"
        out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        tag = "api_error" if run.get("api_error") else ("correct" if run.get("correct") else "wrong_bug")
        print(f"wrote {out_path.name} [{tag}]")
        wrote += 1

    print(f"\nTotal: {wrote} records written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

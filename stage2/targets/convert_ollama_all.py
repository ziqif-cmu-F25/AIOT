"""Convert all Ollama local-model results into schema-valid candidate records.

8 completions total across 3 targets × 2 models (deepseek-coder:6.7b, qwen2.5-coder:7b).
Assessments pre-determined from manual review:

  mongoose triage:  deepseek wrong_bug (right line wrong reason), qwen2.5 wrong_bug (wrong line)
  mongoose C0:      deepseek wrong_bug (same as triage), qwen2.5 wrong_bug (same as triage)
  libcoap triage:   both CORRECT (memcpy overflow in coap_resolve_address_info)
  libmodbus triage: deepseek wrong_bug (vague, missed real bug), qwen2.5 CORRECT (CVE-2022-0367)

Usage:
    stage2/.venv/Scripts/python.exe stage2/targets/convert_ollama_all.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STAGE2))

from jsonschema import Draft202012Validator  # noqa: E402

SCHEMA_PATH = STAGE2 / "schema" / "candidate_record.schema.json"

NOT_AVAILABLE_STATIC = "not_available (static source review; nothing was executed)"

RUNS = [
    # --- mongoose triage ---
    {
        "run_id": "OLLAMA-TRIAGE-deepseek-coder-6.7b",
        "model": "ollama/deepseek-coder:6.7b",
        "target": "mongoose",
        "viewpoint": "triage-hypothesis",
        "prompt_id": "mongoose-triage@v1",
        "valid_classes": ["oob-read", "integer-overflow", "buffer-overflow",
                          "use-after-free", "null-deref", "other"],
        "verdict": "wrong_bug",
        "vulnerability_class": "other",
        "confidence": 0.3,
        "hypothesis": "Claimed skip_chunk() can overflow buffer if input length > size of integer. Points at correct line 12 but wrong reasoning (integer overflow, not off-by-one bounds check).",
        "evidence_source": "Pointed at line 12 (len < i + 1 guard) but attributed the bug to integer overflow rather than the off-by-one (should be i + 2).",
        "location": {"file": "src/http.c", "function": "skip_chunk", "line": 12},
        "notes": "Ollama local model. Right line, wrong reasoning. The actual bug is `len < i + 1` should be `len < i + 2` (OOB read of buf[i+1]).",
    },
    {
        "run_id": "OLLAMA-TRIAGE-qwen2.5-coder-7b",
        "model": "ollama/qwen2.5-coder:7b",
        "target": "mongoose",
        "viewpoint": "triage-hypothesis",
        "prompt_id": "mongoose-triage@v1",
        "valid_classes": ["oob-read", "integer-overflow", "buffer-overflow",
                          "use-after-free", "null-deref", "other"],
        "verdict": "wrong_bug",
        "vulnerability_class": "other",
        "confidence": 0.2,
        "hypothesis": "Claimed skip_chunk() reads beyond buffer bounds when chunk length is too large, pointing at line 16 (`n > len - i - 4`).",
        "evidence_source": "Pointed at wrong line (16, the chunk-length cap) instead of line 12 (the off-by-one guard).",
        "location": {"file": "src/http.c", "function": "skip_chunk", "line": 16},
        "notes": "Ollama local model. Wrong line, wrong reasoning. The real bug is at line 12 (off-by-one in bounds check).",
    },
    # --- mongoose C0 (source review) ---
    {
        "run_id": "OLLAMA-C0-deepseek-coder-6.7b",
        "model": "ollama/deepseek-coder:6.7b",
        "target": "mongoose",
        "viewpoint": "ai-source-review",
        "prompt_id": "mongoose-c0@v1",
        "valid_classes": ["oob-read", "integer-overflow", "buffer-overflow",
                          "use-after-free", "null-deref", "other"],
        "verdict": "wrong_bug",
        "vulnerability_class": "other",
        "confidence": 0.3,
        "hypothesis": "Same as triage: claimed buffer overflow if input length > sizeof(int), pointed at wrong mechanism.",
        "evidence_source": "Repeated integer-overflow theory from C0 prompt context. Pointed at `i > (int) sizeof(int) * 2` check.",
        "location": {"file": "src/http.c", "function": "skip_chunk", "line": 12},
        "notes": "Ollama local model, C0 (full source). Same wrong reasoning as triage variant.",
    },
    {
        "run_id": "OLLAMA-C0-qwen2.5-coder-7b",
        "model": "ollama/qwen2.5-coder:7b",
        "target": "mongoose",
        "viewpoint": "ai-source-review",
        "prompt_id": "mongoose-c0@v1",
        "valid_classes": ["oob-read", "integer-overflow", "buffer-overflow",
                          "use-after-free", "null-deref", "other"],
        "verdict": "wrong_bug",
        "vulnerability_class": "other",
        "confidence": 0.2,
        "hypothesis": "Same as triage: pointed at line 16 chunk-length check as the vulnerability.",
        "evidence_source": "Repeated same line-16 theory from triage variant.",
        "location": {"file": "src/http.c", "function": "skip_chunk", "line": 16},
        "notes": "Ollama local model, C0 (full source). Same wrong analysis as triage variant.",
    },
    # --- libcoap triage ---
    {
        "run_id": "OLLAMA-TRIAGE-deepseek-coder-6.7b",
        "model": "ollama/deepseek-coder:6.7b",
        "target": "libcoap",
        "viewpoint": "triage-hypothesis",
        "prompt_id": "libcoap-triage@v1",
        "valid_classes": ["buffer-overflow", "oob-read", "integer-overflow",
                          "use-after-free", "null-deref", "other"],
        "verdict": "correct",
        "vulnerability_class": "buffer-overflow",
        "confidence": 0.9,
        "hypothesis": "Identified that getaddrinfo()/memcpy can overflow if hostname > 256 bytes, correctly pointing at memcpy(addrstr, address->s, address->length).",
        "evidence_source": "Correctly identified unchecked memcpy of attacker-controlled hostname into 256-byte buffer.",
        "location": {"file": "src/coap_address.c", "function": "coap_resolve_address_info", "line": 538},
        "notes": "Ollama local model (6.7B params). Correctly identified CVE-2025-34468 root cause. Notable: even a small local model found this vulnerability.",
    },
    {
        "run_id": "OLLAMA-TRIAGE-qwen2.5-coder-7b",
        "model": "ollama/qwen2.5-coder:7b",
        "target": "libcoap",
        "viewpoint": "triage-hypothesis",
        "prompt_id": "libcoap-triage@v1",
        "valid_classes": ["buffer-overflow", "oob-read", "integer-overflow",
                          "use-after-free", "null-deref", "other"],
        "verdict": "correct",
        "vulnerability_class": "buffer-overflow",
        "confidence": 0.9,
        "hypothesis": "Identified that coap_resolve_address_info() reads beyond addrstr bounds when hostname exceeds 255 characters, pointing at memcpy line.",
        "evidence_source": "Correctly identified unchecked memcpy of hostname >255 chars into 256-byte static buffer.",
        "location": {"file": "src/coap_address.c", "function": "coap_resolve_address_info", "line": 538},
        "notes": "Ollama local model (7B params). Correctly identified CVE-2025-34468 root cause.",
    },
    # --- libmodbus triage ---
    {
        "run_id": "OLLAMA-TRIAGE-deepseek-coder-6.7b",
        "model": "ollama/deepseek-coder:6.7b",
        "target": "libmodbus",
        "viewpoint": "triage-hypothesis",
        "prompt_id": "libmodbus-triage@v1",
        "valid_classes": ["buffer-overflow", "oob-read", "oob-write",
                          "integer-overflow", "use-after-free", "null-deref", "other"],
        "verdict": "wrong_bug",
        "vulnerability_class": "other",
        "confidence": 0.3,
        "hypothesis": "Vaguely identified OOB read in write-and-read handler, pointing at the write loop line. Missed the actual bug (duplicate bounds check).",
        "evidence_source": "Pointed at write loop (line with mapping_address_write iteration) but attributed bug to nb_write exceeding allocated registers, not to the duplicate mapping_address check.",
        "location": {"file": "src/modbus.c", "function": "modbus_reply", "line": 978},
        "notes": "Ollama local model. Identified the right area but wrong root cause. The real bug is at lines 962-965 where mapping_address is checked twice instead of mapping_address_write.",
    },
    {
        "run_id": "OLLAMA-TRIAGE-qwen2.5-coder-7b",
        "model": "ollama/qwen2.5-coder:7b",
        "target": "libmodbus",
        "viewpoint": "triage-hypothesis",
        "prompt_id": "libmodbus-triage@v1",
        "valid_classes": ["buffer-overflow", "oob-read", "oob-write",
                          "integer-overflow", "use-after-free", "null-deref", "other"],
        "verdict": "correct",
        "vulnerability_class": "oob-write",
        "confidence": 0.9,
        "hypothesis": "Correctly identified that mapping_address_write and mapping_address are not properly validated, leading to OOB write via tab_registers[i] = ...",
        "evidence_source": "Identified missing mapping_address_write validation. Noted trigger: address_write < start_registers bypasses the bounds check due to duplicate mapping_address check.",
        "location": {"file": "src/modbus.c", "function": "modbus_reply", "line": 980},
        "notes": "Ollama local model (7B params). CORRECTLY identified CVE-2022-0367 root cause! Notable finding: a 7B-parameter local model found the copy-paste bounds-check bug.",
    },
]


def build_record(run: dict) -> dict:
    is_correct = run["verdict"] == "correct"
    return {
        "candidate_id": "CAND-001",
        "viewpoint": run["viewpoint"],
        "property": "memory-safety",
        "hypothesis": run["hypothesis"],
        "evidence_source": run["evidence_source"],
        "input_artifact": f"not_available ({run['viewpoint']} condition; code excerpt provided)",
        "expected_behavior": (
            "Model should identify the specific vulnerability root cause in the provided code excerpt."
        ),
        "observed_behavior": NOT_AVAILABLE_STATIC,
        "status": "candidate" if is_correct else "rejected",
        "oracle_verdict": run["verdict"],
        "notes": run["notes"],
        "vulnerability_class": run["vulnerability_class"],
        "location": run["location"],
        "confidence": run["confidence"],
        "model": run["model"],
        "prompt_id": run["prompt_id"],
        "run_index": 1,
    }


def main() -> int:
    base_schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    wrote = 0
    for run in RUNS:
        target = run["target"]
        out_dir = (STAGE2 / "targets" / target / "results"
                   / ("ollama-triage" if run["viewpoint"] == "triage-hypothesis" else "ollama-c0")
                   / "candidates")
        out_dir.mkdir(parents=True, exist_ok=True)

        schema = json.loads(json.dumps(base_schema))
        schema["properties"]["vulnerability_class"]["enum"] = run["valid_classes"]
        validator = Draft202012Validator(schema)

        record = build_record(run)
        validator.validate(record)

        out_path = out_dir / f"{run['run_id']}.json"
        out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        tag = "CORRECT" if run["verdict"] == "correct" else run["verdict"]
        print(f"[{target}] wrote {out_path.name} [{tag}]")
        wrote += 1

    print(f"\nTotal: {wrote} records written across 3 targets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

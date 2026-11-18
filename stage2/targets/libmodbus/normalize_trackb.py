"""Normalize libmodbus track-b results into the schema-valid candidate format.

Reads the cost_log.csv for run-to-model mapping, then extracts candidates
from each run's candidates.json. Focuses on the well-posed 0367 source
review runs (run-035 through run-061, 9 models x 3 repeats).

The earlier runs (001-034) used superseded prompts targeting different
functions and are written to a separate directory for reference.

Target: CVE-2022-0367 (CWE-787) — copy-paste bounds check error in
modbus_reply's fn-0x17 (Write/Read Multiple Registers) handler lets a
negative mapping_address_write through to an OOB register write.

Usage:
    stage2/.venv/Scripts/python.exe stage2/targets/libmodbus/normalize_trackb.py
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(STAGE2))

from jsonschema import Draft202012Validator  # noqa: E402

SCHEMA_PATH = STAGE2 / "schema" / "candidate_record.schema.json"
RESULTS_DIR = Path(__file__).resolve().parent / "results"
TRACK_B = RESULTS_DIR / "track-b"
COST_LOG = RESULTS_DIR / "cost_log.csv"

VALID_CLASSES = ["buffer-overflow", "out-of-bounds-read", "integer-overflow",
                 "use-after-free", "null-deref", "other"]

TASK_0367 = "libmodbus-0367-source-review"
TASK_MODBUS_REPLY = "libmodbus-modbus-reply"
TASK_MODBUS_CTX = "libmodbus-modbus-reply-ctx"

OUT_0367 = RESULTS_DIR / "c0-source-review" / "candidates"
OUT_EARLY = RESULTS_DIR / "c0-early-attempts" / "candidates"


def load_run_metadata() -> dict[str, dict]:
    """Read cost_log.csv and return {run_id: {model, task_id, status}}."""
    runs: dict[str, dict] = {}
    with open(COST_LOG, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rid = row["run_id"]
            runs[rid] = {
                "model": row["model_requested"],
                "task_id": row["task_id"],
                "status": row["status"],
            }
    return runs


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    schema["properties"]["vulnerability_class"]["enum"] = VALID_CLASSES
    validator = Draft202012Validator(schema)

    run_meta = load_run_metadata()

    OUT_0367.mkdir(parents=True, exist_ok=True)
    OUT_EARLY.mkdir(parents=True, exist_ok=True)

    wrote_0367 = 0
    wrote_early = 0
    skipped_empty = 0
    errors = 0

    run_dirs = sorted(TRACK_B.glob("run-*"), key=lambda p: p.name)
    for run_dir in run_dirs:
        cand_path = run_dir / "candidates.json"
        if not cand_path.exists():
            continue

        run_id = run_dir.name
        meta = run_meta.get(run_id)
        if not meta:
            print(f"[{run_id}] not in cost_log, skipping")
            continue

        candidates = json.loads(cand_path.read_text(encoding="utf-8"))
        if not candidates:
            skipped_empty += 1
            continue

        is_0367 = meta["task_id"] == TASK_0367
        out_dir = OUT_0367 if is_0367 else OUT_EARLY

        for idx, cand in enumerate(candidates):
            cand_id = f"CAND-{idx + 1:03d}"
            cand["candidate_id"] = cand_id

            if "model" not in cand or not cand["model"]:
                cand["model"] = meta["model"]

            if cand.get("vulnerability_class") not in VALID_CLASSES:
                orig = cand.get("vulnerability_class", "")
                if "overflow" in orig.lower() or "oob-write" in orig.lower():
                    cand["vulnerability_class"] = "buffer-overflow"
                elif "oob-read" in orig.lower() or "out-of-bounds-read" in orig.lower():
                    cand["vulnerability_class"] = "out-of-bounds-read"
                else:
                    cand["vulnerability_class"] = "other"

            if "location" in cand and isinstance(cand["location"], dict):
                loc = cand["location"]
                if "file" in loc and loc["file"].startswith("src/"):
                    loc["file"] = loc["file"][4:]

            try:
                validator.validate(cand)
            except Exception as e:
                print(f"[{run_id}][CAND-{idx+1:03d}] validation error: {e}")
                errors += 1
                continue

            out_name = f"{run_id}-cand-{idx+1:03d}.json"
            out_path = out_dir / out_name
            out_path.write_text(json.dumps(cand, indent=2), encoding="utf-8")
            if is_0367:
                wrote_0367 += 1
            else:
                wrote_early += 1

    print(f"\nResults:")
    print(f"  0367 source review records: {wrote_0367}")
    print(f"  Early attempt records:      {wrote_early}")
    print(f"  Runs with empty candidates: {skipped_empty}")
    print(f"  Validation errors:          {errors}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

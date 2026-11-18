"""Run local Ollama models across all three targets for C0 and triage conditions.

Hits localhost:11434 (Ollama's OpenAI-compatible API). No API cost.
Models: deepseek-coder:6.7b, qwen2.5-coder:7b

Conditions per target:
  - mongoose: C0 (full skip_chunk excerpt) + triage (narrow excerpt)
  - libcoap:  triage (c2_excerpt.c — full C0 pack is too large for 7B)
  - libmodbus: triage (fn-0x17 excerpt — full modbus.c is too large for 7B)

Usage:
    stage2/.venv/Scripts/python.exe stage2/run_ollama_all.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

STAGE2 = Path(__file__).resolve().parent
sys.path.insert(0, str(STAGE2))

from driver.ollama_client import OllamaClient  # noqa: E402
from driver.openrouter_client import Completion  # noqa: E402

LOCAL_MODELS = [
    "deepseek-coder:6.7b",
    "qwen2.5-coder:7b",
]

TASKS: list[dict] = [
    {
        "name": "mongoose-triage",
        "target_dir": STAGE2 / "targets" / "mongoose",
        "prompt_path": STAGE2 / "targets" / "mongoose" / "artifacts" / "ai" / "prompts" / "triage_hypothesis_v1.txt",
        "source_path": STAGE2 / "targets" / "mongoose" / "artifacts" / "ai" / "vendor" / "triage_excerpt.c",
        "source_header": "<<<CODE EXCERPT: skip_chunk() and caller>>>",
        "out_subdir": "ollama-triage",
        "task_id": "mongoose-ollama-triage",
        "prefix": "OLLAMA-TRIAGE",
    },
    {
        "name": "mongoose-c0",
        "target_dir": STAGE2 / "targets" / "mongoose",
        "prompt_path": STAGE2 / "targets" / "mongoose" / "artifacts" / "ai" / "prompts" / "triage_hypothesis_v1.txt",
        "source_path": STAGE2 / "targets" / "mongoose" / "artifacts" / "ai" / "vendor" / "http_skip_chunk_excerpt.c",
        "source_header": "<<<SOURCE FILE: http.c (excerpt)>>>",
        "out_subdir": "ollama-c0",
        "task_id": "mongoose-ollama-c0",
        "prefix": "OLLAMA-C0",
    },
    {
        "name": "libcoap-triage",
        "target_dir": STAGE2 / "targets" / "libcoap",
        "prompt_path": STAGE2 / "targets" / "libcoap" / "artifacts" / "prompts" / "triage_hypothesis_v1.txt",
        "source_path": STAGE2 / "targets" / "libcoap" / "artifacts" / "vendor" / "c2_excerpt.c",
        "source_header": "<<<CODE EXCERPT: coap_resolve_address_info() and caller>>>",
        "out_subdir": "ollama-triage",
        "task_id": "libcoap-ollama-triage",
        "prefix": "OLLAMA-TRIAGE",
    },
    {
        "name": "libmodbus-triage",
        "target_dir": STAGE2 / "targets" / "libmodbus",
        "prompt_path": STAGE2 / "targets" / "libmodbus" / "artifacts" / "ai" / "prompts" / "triage_hypothesis_v1.txt",
        "source_path": STAGE2 / "targets" / "libmodbus" / "artifacts" / "ai" / "vendor" / "triage_excerpt.c",
        "source_header": "<<<CODE EXCERPT: MODBUS_FC_WRITE_AND_READ_REGISTERS handler>>>",
        "out_subdir": "ollama-triage",
        "task_id": "libmodbus-ollama-triage",
        "prefix": "OLLAMA-TRIAGE",
    },
]


def slug(model: str) -> str:
    return model.replace(":", "-").replace("/", "-")


def build_prompt(task: dict) -> str:
    template = task["prompt_path"].read_text(encoding="utf-8")
    source = task["source_path"].read_text(encoding="utf-8")
    return f"{template}\n\n{task['source_header']}\n{source}"


def append_cost_row(log_path: Path, row: dict) -> None:
    header = "timestamp_utc,run_id,task_id,status,model_requested,model_resolved,attempts,prompt_tokens,completion_tokens,total_tokens,cost_usd\n"
    if not log_path.exists():
        log_path.write_text(header, encoding="utf-8")
    usage = row.get("usage_total", {})
    line = (
        f"{row['end_utc']},{row['run_id']},{row['task_id']},{row['status']},"
        f"{row['model_requested']},{';'.join(row.get('model_resolved', []))},"
        f"{row.get('attempts', 1)},"
        f"{usage.get('prompt_tokens', 0)},{usage.get('completion_tokens', 0)},"
        f"{usage.get('total_tokens', 0)},0\n"
    )
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line)


def main() -> int:
    client = OllamaClient(timeout_s=600.0)
    total = 0

    for task in TASKS:
        prompt = build_prompt(task)
        out_dir = task["target_dir"] / "results" / task["out_subdir"]
        out_dir.mkdir(parents=True, exist_ok=True)
        cost_log = task["target_dir"] / "results" / "cost_log.csv"

        for model in LOCAL_MODELS:
            s = slug(model)
            run_id = f"{task['prefix']}-{s}"
            out_path = out_dir / f"{run_id}.txt"
            if out_path.exists():
                print(f"[{task['name']}][{s}] already have output, skipping", flush=True)
                continue

            print(f"[{task['name']}][{s}] starting...", flush=True)
            try:
                completion = client.complete(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    sampling={"temperature": 0.0, "max_tokens": 4000},
                )
            except Exception as e:
                print(f"  ERROR: {e}", flush=True)
                out_path.write_text(f"ERROR: {e}", encoding="utf-8")
                append_cost_row(cost_log, {
                    "end_utc": datetime.now(timezone.utc).isoformat(),
                    "run_id": run_id,
                    "task_id": task["task_id"],
                    "status": "error",
                    "model_requested": model,
                    "model_resolved": [""],
                    "usage_total": {},
                })
                continue

            text = completion.text
            if not text or len(text.strip()) == 0:
                print(f"  empty response", flush=True)
                out_path.write_text("EMPTY_RESPONSE", encoding="utf-8")
                status = "empty"
            else:
                print(f"  ok ({len(text)} chars)", flush=True)
                print(text[:300], "\n...\n", flush=True)
                status = "ok"

            out_path.write_text(text if status == "ok" else "EMPTY_RESPONSE",
                                encoding="utf-8")
            append_cost_row(cost_log, {
                "end_utc": datetime.now(timezone.utc).isoformat(),
                "run_id": run_id,
                "task_id": task["task_id"],
                "status": status,
                "model_requested": model,
                "model_resolved": [completion.resolved_model or ""],
                "usage_total": completion.usage,
            })
            total += 1

    print(f"\nDone. {total} new completions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

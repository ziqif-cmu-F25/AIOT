"""Rerun Mongoose C2 (crash-given) across the unified model roster.

Gives each model the ASan crash report + source excerpt and asks it to
locate the root cause of the off-by-one OOB read in skip_chunk().

Target: CVE-2026-52056 (CWE-125) — off-by-one OOB read in skip_chunk().

Usage:
    stage2/.venv/Scripts/python.exe stage2/targets/mongoose/rerun_c2.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[2]
TARGET_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(STAGE2))

from driver.openrouter_client import load_settings, OpenRouterClient  # noqa: E402
from driver.run_task import usage_total, append_cost_row  # noqa: E402

PROMPT_PATH = TARGET_DIR / "artifacts" / "ai" / "prompts" / "crash_given_v1.txt"
SOURCE_PATH = TARGET_DIR / "artifacts" / "ai" / "vendor" / "http_skip_chunk_excerpt.c"

MODELS = [
    "openai/gpt-5.6-sol", "openai/gpt-6.1-sol",
    "anthropic/claude-haiku-5.5", "anthropic/claude-opus-5.5", "anthropic/claude-sonnet-5.5",
    "deepseek/deepseek-chat-v3.1", "google/gemini-2.5-pro", "openai/gpt-5", "x-ai/grok-4.6",
]
OUT_DIR = TARGET_DIR / "results" / "rerun-c2"
COST_LOG = TARGET_DIR / "results" / "cost_log.csv"


def build_prompt() -> str:
    template = PROMPT_PATH.read_text(encoding="utf-8")
    source = SOURCE_PATH.read_text(encoding="utf-8")
    return f"{template}\n\n<<<SOURCE FILE: http_skip_chunk_excerpt.c>>>\n{source}"


def main() -> int:
    settings = load_settings()
    client = OpenRouterClient(settings)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    prompt = build_prompt()

    for model in MODELS:
        run_id = f"RERUN-C2-{model.split('/')[-1]}"
        out_path = OUT_DIR / f"{run_id}.txt"
        if out_path.exists():
            print(f"--- {run_id} --- already have output, skipping", flush=True)
            continue
        print(f"--- {run_id} ---", flush=True)
        try:
            completion = client.complete(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                sampling={"temperature": 0.0, "max_tokens": 8000},
            )
        except Exception as e:
            print(f"  ERROR: {e}", flush=True)
            out_path.write_text(f"ERROR: {e}", encoding="utf-8")
            append_cost_row(COST_LOG, {
                "end_utc": datetime.now(timezone.utc).isoformat(),
                "run_id": run_id,
                "task_id": "mongoose-c2-rerun",
                "status": "error",
                "model_requested": model,
                "model_resolved": [""],
                "attempts": 1,
                "usage_total": {"prompt_tokens": 0, "completion_tokens": 0,
                                "total_tokens": 0, "cost_usd": 0},
            })
            continue

        out_path.write_text(completion.text, encoding="utf-8")
        print(completion.text[:400], "\n...\n", flush=True)

        usage = usage_total([completion])
        append_cost_row(COST_LOG, {
            "end_utc": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "task_id": "mongoose-c2-rerun",
            "status": "ok",
            "model_requested": model,
            "model_resolved": [completion.resolved_model or ""],
            "attempts": 1,
            "usage_total": usage,
        })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

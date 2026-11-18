"""Independent rerun of Chen's C0 (one-shot) libcoap localization experiment.

Reuses Chen's exact prompt (prompts/C0.txt) and six-file packs (packs/c0_pack_1.txt,
packs/c0_pack_2.txt) verbatim, against our own OpenRouter credentials, so the result
is a fresh, independently-observed data point to compare against his log.csv rows
(C0-1-56, C0-1-61, C0-2-56, C0-2-61) rather than a re-scoring of his existing output.

Usage (from repo root or stage2/):
    stage2/.venv/Scripts/python.exe stage2/targets/libcoap/rerun_c0.py
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

PROMPT_PATH = TARGET_DIR / "artifacts" / "prompts" / "C0.txt"
PACKS = {
    "pack_1": TARGET_DIR / "artifacts" / "packs" / "c0_pack_1.txt",
    "pack_2": TARGET_DIR / "artifacts" / "packs" / "c0_pack_2.txt",
}
MODELS = [
    "openai/gpt-5.6-sol", "openai/gpt-6.1-sol",  # already run; skipped below if output exists
    "anthropic/claude-haiku-5.5", "anthropic/claude-opus-5.5", "anthropic/claude-sonnet-5.5",
    "deepseek/deepseek-chat-v3.1", "google/gemini-2.5-pro", "openai/gpt-5", "x-ai/grok-4.6",
]  # unified roster = libmodbus's 7 models + libcoap's 2, per METHODOLOGY_CONTRACT.md normalization
OUT_DIR = TARGET_DIR / "results" / "rerun-c0"
COST_LOG = TARGET_DIR / "results" / "cost_log.csv"


def build_prompt(pack_text: str) -> str:
    template = PROMPT_PATH.read_text(encoding="utf-8")
    marker = "<<<FILES>>>\n[PASTE THE CONTENTS OF packs/c0_pack_1.txt HERE  — for the C0-2 run paste c0_pack_2.txt instead]"
    assert marker in template, "C0.txt prompt text has changed; update the marker"
    return template.replace(marker, "<<<FILES>>>\n" + pack_text)


def main() -> int:
    settings = load_settings()
    client = OpenRouterClient(settings)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for pack_name, pack_path in PACKS.items():
        prompt = build_prompt(pack_path.read_text(encoding="utf-8"))
        for model in MODELS:
            run_id = f"RERUN-C0-{pack_name}-{model.split('/')[-1]}"
            out_path = OUT_DIR / f"{run_id}.txt"
            if out_path.exists():
                print(f"--- {run_id} --- already have output, skipping (no re-spend)", flush=True)
                continue
            print(f"--- {run_id} ---", flush=True)
            completion = client.complete(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                sampling={"temperature": 0.0, "max_tokens": 16000},
            )
            out_path = OUT_DIR / f"{run_id}.txt"
            out_path.write_text(completion.text, encoding="utf-8")
            print(completion.text[:500], "\n...\n", flush=True)

            usage = usage_total([completion])
            append_cost_row(COST_LOG, {
                "end_utc": datetime.now(timezone.utc).isoformat(),
                "run_id": run_id,
                "task_id": "libcoap-c0-rerun",
                "status": "ok",
                "model_requested": model,
                "model_resolved": [completion.resolved_model or ""],
                "attempts": 1,
                "usage_total": usage,
            })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

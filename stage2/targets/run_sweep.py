"""Corrected Phase-3 sweep runner. Cheapest-first, hard budget guard.

Runs the approved matrix with the DE-HINTED prompts (prompt_builder) and the
fixed agentic harness. Saves each run's RAW output to
results/sweep/<target>/<condition>/<model>_r<rep>.txt plus a line in
results/sweep/sweep_index.jsonl (target,condition,model,rep,response_status,
disclosed,withheld,pinned_commit,cost,source_file). Adjudication consumes that
the same way it consumes existing data (collect_packets) — no fabricated records.

Safety: tracks ACTUAL spend (OpenRouter usage.cost) and stops before exceeding
--budget. --smoke runs a single cheapest call. Local (Ollama) models cost $0.

Usage:
  python targets/run_sweep.py --smoke
  python targets/run_sweep.py --budget 5.0
  python targets/run_sweep.py --only recall-probe,crash-given
"""
from __future__ import annotations
import argparse, json, sys, time
from datetime import datetime, timezone
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STAGE2))
from targets.prompt_builder import build  # noqa: E402
from driver.agentic_harness import run_condition, response_status_for  # noqa: E402

FRONTIER = ["x-ai/grok-4.6","google/gemini-2.5-pro","anthropic/claude-opus-5.5","openai/gpt-5",
            "anthropic/claude-sonnet-5.5","openai/gpt-5.6-sol","openai/gpt-6.1-sol"]
CHEAP = ["anthropic/claude-haiku-5.5","deepseek/deepseek-chat-v3.1"]
LOCAL = ["deepseek-coder:6.7b","qwen2.5-coder:7b"]
TARGETS = ["libmodbus","libcoap","mongoose"]
OUT = STAGE2 / "results" / "sweep"
INDEX = OUT / "sweep_index.jsonl"

# approved matrix: condition -> list of (models, repeats)
MATRIX = {
    # Uniform 3-repeat grid across all models. The fixed dedup skips cells already
    # run (cheap+local on every condition; frontier C1 rep 1), so a resume runs
    # only the frontier gaps on crash/triage/one-shot/input + frontier C1 reps 2-3.
    "source-agentic":   [(LOCAL,3),(CHEAP,3),(FRONTIER,3)],
    "crash-given":      [(LOCAL,3),(CHEAP,3),(FRONTIER,3)],
    "triage-hypothesis":[(LOCAL,3),(CHEAP,3),(FRONTIER,3)],
    "input-drafting":   [(LOCAL,3),(CHEAP,3),(FRONTIER,3)],
    "source-one-shot":  [(LOCAL,3),(CHEAP,3),(FRONTIER,3)],
    "recall-probe":     [(LOCAL,1),(CHEAP+FRONTIER,1)],
}
# rough $/run for the budget estimate guard (pre-spend), from historical averages
AVG = {"x-ai/grok-4.6":0.16,"google/gemini-2.5-pro":0.13,"anthropic/claude-opus-5.5":0.13,
       "openai/gpt-5":0.10,"anthropic/claude-sonnet-5.5":0.10,"openai/gpt-5.6-sol":0.07,
       "openai/gpt-6.1-sol":0.03,"anthropic/claude-haiku-5.5":0.01,"deepseek/deepseek-chat-v3.1":0.01}


def is_local(model: str) -> bool:
    return ":" in model


def slug(m: str) -> str:
    return m.replace("/", "_").replace(":", "-")


def cost_of(completions) -> float:
    c = 0.0
    for comp in completions:
        u = getattr(comp, "usage", {}) or {}
        if u.get("cost") is not None:
            c += float(u["cost"])
    return c


def iter_cells(only):
    for cond, groups in MATRIX.items():
        if only and cond not in only:
            continue
        for models, reps in groups:
            for m in models:
                for rep in range(1, reps + 1):
                    for tgt in TARGETS:
                        yield (tgt, cond, m, rep)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=float, default=5.0)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--only", type=str, default="")
    ap.add_argument("--max-turns", type=int, default=15)
    args = ap.parse_args()
    only = set(x for x in args.only.split(",") if x) if args.only else None

    OUT.mkdir(parents=True, exist_ok=True)
    from driver.openrouter_client import load_settings, OpenRouterClient
    from driver.ollama_client import OllamaClient
    or_client = OpenRouterClient(load_settings())
    ol_client = OllamaClient(num_ctx=16384)

    done = set()
    if INDEX.exists():
        for l in INDEX.read_text(encoding="utf-8").splitlines():
            if l.strip():
                r = json.loads(l); done.add((r["target"], r["condition"], r["model"], r["rep"]))

    spent = 0.0
    cells = list(iter_cells(only))
    # cheapest-first is already encoded (LOCAL, CHEAP, FRONTIER order in MATRIX groups)
    if args.smoke:
        cells = [("libmodbus", "recall-probe", "deepseek/deepseek-chat-v3.1", 1)]

    n = 0
    for (tgt, cond, model, rep) in cells:
        # index stores the short model name, so compare short-to-short (resume fix).
        if (tgt, cond, model.split("/")[-1], rep) in done:
            continue
        # budget pre-check (estimate). Agentic multi-turn runs cost far more than
        # the historical single-shot average, so use a realistic per-bucket figure.
        if is_local(model):
            est = 0.0
        elif cond == "source-agentic":
            est = 0.70  # observed frontier agentic runs ~$0.3-0.6+
        else:
            est = AVG.get(model, 0.15)
        if not is_local(model) and spent + est > args.budget:
            print(f"[BUDGET STOP] would exceed ${args.budget:.2f} (spent ${spent:.4f}, next est ${est:.4f}); stopping.")
            break
        try:
            b = build(tgt, cond, max_turns=args.max_turns)
        except Exception as e:  # noqa: BLE001
            print(f"  build error {tgt}/{cond}: {e}")
            continue
        client = ol_client if is_local(model) else or_client
        t0 = time.time()
        try:
            if cond == "source-agentic":
                res = run_condition(client, model, b["prompt"], b["store"],
                                    condition_tag=cond, max_turns=args.max_turns)
                text = res.final_text or ""
                status = res.response_status
                comps = res.completions
            else:
                comp = client.complete(model=model, messages=[{"role": "user", "content": b["prompt"]}],
                                       sampling={"temperature": 0.0, "max_tokens": 8000})
                text = comp.text or ""
                comps = [comp]
                fr = getattr(comp, "finish_reason", None)
                status = ("filtered" if text.strip() == "" else
                          "truncated" if fr in ("length", "max_tokens") else "answered")
        except Exception as e:  # noqa: BLE001
            text = f"ERROR: {type(e).__name__}: {e}"; comps = []; status = "error"
        c = cost_of(comps); spent += c
        d = OUT / tgt / cond; d.mkdir(parents=True, exist_ok=True)
        srcf = d / f"{slug(model)}_r{rep}.txt"
        srcf.write_text(text, encoding="utf-8")
        with open(INDEX, "a", encoding="utf-8") as f:
            f.write(json.dumps({"target": tgt, "condition": cond, "model": model.split("/")[-1],
                                "rep": rep, "response_status": status, "disclosed": b["disclosed"],
                                "withheld": b["withheld"], "pinned_commit": b["pinned_commit"],
                                "cost": round(c, 8), "secs": round(time.time()-t0, 1),
                                "source_file": str(srcf.relative_to(STAGE2))}) + "\n")
        n += 1
        print(f"[{n}] {tgt:9} {cond:17} {model:34} r{rep} {status:11} ${c:.4f}  (spent ${spent:.4f})", flush=True)
        if args.smoke:
            print("smoke done."); break

    print(f"\nSWEEP DONE: {n} new runs, actual spend ${spent:.4f} (budget ${args.budget:.2f}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

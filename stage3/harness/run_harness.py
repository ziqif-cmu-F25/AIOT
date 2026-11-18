"""Run the Stage 3 harness against one target pack."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.controller import Model, run_loop
from harness.target_config import STAGE3_ROOT, load_target
from harness.tools import ToolBox

REPO_ROOT = STAGE3_ROOT.parent
COST_FIELDS = (
    "timestamp_utc", "run_id", "target_id", "stop_reason",
    "model_requested", "model_resolved", "steps",
    "prompt_tokens", "completion_tokens", "total_tokens", "cost_usd",
)


def utc_now() -> str:
    """Return the current UTC timestamp."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def next_run_id(root: Path) -> str:
    """Return the next run-NNN directory name under *root*."""
    existing = []
    for path in root.glob("run-*"):
        suffix = path.name.split("-", 1)[-1]
        if suffix.isdigit():
            existing.append(int(suffix))
    return f"run-{max(existing, default=0) + 1:03d}"


class ScriptedModel:
    """Replay fixed assistant replies. Used to check the loop without an API."""

    def __init__(self, replies: list[str]):
        self._replies = list(replies)

    def complete(self, messages: list[dict]) -> str:
        """Return the next scripted reply."""
        del messages
        if not self._replies:
            return json.dumps({
                "action": "finish",
                "hypothesis": "script exhausted",
                "candidate": {
                    "property": "",
                    "trigger_input": "",
                    "expected_evidence": "",
                    "confidence": 0,
                    "notes": "no scripted reply left",
                },
            })
        return self._replies.pop(0)


class OpenRouterModel:
    """One OpenRouter completion per turn, using the Stage 2 client."""

    def __init__(self, client, model: str, sampling: dict):
        self._client = client
        self.model = model
        self.sampling = sampling
        self.resolved: str | None = None
        self.usages: list[dict] = []

    def complete(self, messages: list[dict]) -> str:
        """Call the chat API and keep usage for the cost log."""
        wire = [{"role": item["role"], "content": item["content"]} for item in messages]
        completion = self._client.complete(self.model, wire, self.sampling)
        self.resolved = completion.resolved_model
        self.usages.append(completion.usage or {})
        return completion.text


def _sum_usage(usages: list[dict]) -> dict:
    total = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cost_usd": None}
    for usage in usages:
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            total[key] += int(usage.get(key) or 0)
        if usage.get("cost") is not None:
            total["cost_usd"] = round((total["cost_usd"] or 0.0) + float(usage["cost"]), 8)
    return total


def _append_cost(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new_file = not path.exists()
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COST_FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow(row)


def write_run(run_dir: Path, pack, outcome, model_name: str, resolved: str | None,
              condition: str, started: str) -> None:
    """Write the run directory teammates hand back."""
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "transcript.json").write_text(
        json.dumps(outcome.messages, indent=2) + "\n", encoding="utf-8"
    )
    commands = run_dir / "commands.log"
    with commands.open("w", encoding="utf-8") as handle:
        for item in outcome.messages:
            if item.get("role") != "user" or "step" not in item:
                continue
            handle.write(json.dumps({
                "step": item["step"],
                "tool": item.get("tool", ""),
                "hypothesis": item.get("hypothesis", ""),
                "observation_chars": len(item.get("content", "")),
            }) + "\n")
    (run_dir / "candidate.json").write_text(
        json.dumps(outcome.candidate, indent=2) + "\n", encoding="utf-8"
    )
    (run_dir / "run.yaml").write_text(
        "\n".join([
            f"run_id: {run_dir.name}",
            f"target_id: {pack.target_id}",
            f"target_config: {pack.config_path}",
            f"condition: {condition}",
            f"model_requested: {model_name}",
            f"model_resolved: {resolved or ''}",
            f"start_utc: {started}",
            f"end_utc: {utc_now()}",
            f"steps_used: {outcome.steps_used}",
            f"max_steps: {pack.limits['max_steps']}",
            f"stop_reason: {outcome.stop_reason}",
            "oracle_verdict: pending",
        ]) + "\n",
        encoding="utf-8",
    )


def build_model(args, pack) -> tuple[Model, str, list[dict], dict]:
    """Return the model, its requested name, a usage list, and sampling."""
    if args.scripted:
        replies = json.loads(Path(args.scripted).read_text(encoding="utf-8"))
        if not isinstance(replies, list) or not all(isinstance(item, str) for item in replies):
            raise SystemExit("--scripted must be a JSON list of strings")
        model = ScriptedModel(replies)
        return model, "scripted", [], {}
    sys.path.insert(0, str(REPO_ROOT / "stage2"))
    from driver.openrouter_client import OpenRouterClient, load_settings

    settings = load_settings(REPO_ROOT / ".env")
    requested = args.model or settings.model or pack.model_default
    sampling = {"temperature": pack.temperature}
    if pack.max_tokens:
        sampling["max_tokens"] = pack.max_tokens
    client = OpenRouterClient(settings)
    model = OpenRouterModel(client, requested, sampling)
    return model, requested, model.usages, {"model_obj": model}


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Run the Stage 3 agent harness on one target pack.")
    parser.add_argument("target", type=Path, help="Path to a target YAML pack")
    parser.add_argument("--model", help="OpenRouter model; else .env, else the pack default")
    parser.add_argument("--source-only", action="store_true",
                        help="Disable run_python and run_target (SOW condition A)")
    parser.add_argument("--scripted", type=Path,
                        help="JSON list of assistant replies; does not call an API")
    parser.add_argument("--results-root", type=Path, default=STAGE3_ROOT / "results")
    parser.add_argument("--cost-log", type=Path, default=STAGE3_ROOT / "results" / "cost_log.csv")
    args = parser.parse_args(argv)

    pack = load_target(args.target)
    model, requested, usages, extra = build_model(args, pack)
    started = utc_now()
    run_dir = args.results_root / next_run_id(args.results_root)
    scratch = run_dir / "scratch"
    toolbox = ToolBox(pack, scratch, source_only=args.source_only)
    outcome = run_loop(pack, toolbox, model)
    if extra.get("model_obj") is not None:
        usages = extra["model_obj"].usages
        resolved = extra["model_obj"].resolved
    else:
        resolved = None
    condition = "source-only" if args.source_only else "source-and-runtime"
    write_run(run_dir, pack, outcome, requested, resolved, condition, started)
    totals = _sum_usage(usages)
    _append_cost(args.cost_log, {
        "timestamp_utc": utc_now(),
        "run_id": run_dir.name,
        "target_id": pack.target_id,
        "stop_reason": outcome.stop_reason,
        "model_requested": requested,
        "model_resolved": resolved or "",
        "steps": outcome.steps_used,
        "prompt_tokens": totals["prompt_tokens"],
        "completion_tokens": totals["completion_tokens"],
        "total_tokens": totals["total_tokens"],
        "cost_usd": "" if totals["cost_usd"] is None else totals["cost_usd"],
    })
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

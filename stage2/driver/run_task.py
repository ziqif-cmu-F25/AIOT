#!/usr/bin/env python3
"""Run one human-authored Stage 2 task against an LLM via OpenRouter.

Loads tasks/<task>.yaml, builds the prompt from the allow-listed context
only, calls the model, validates (and once repairs) the JSON answer, and
writes one run directory per repeat under results/ai-runs/, shaped like the
Stage 1 run directories from tools/new_run.py.

The driver never scores. Records always leave here with status: candidate
and oracle_verdict: pending; scoring/score_run.py is a separate step.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import subprocess
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml
from jsonschema import Draft202012Validator

from driver.context_loader import STAGE2_ROOT, BoundaryError, IntegrityError, load_context
from driver.openrouter_client import (
    Completion,
    OpenRouterClient,
    SettingsError,
    load_settings,
)

VIEWPOINT = "ai-source-review"
SUPPORTED_MODES = ("source-review",)   # extension point: "fuzzing-assist"
REQUIRED_TASK_KEYS = (
    "task_id", "prompt_version", "property", "mode", "description",
    "valid_classes", "context", "prompt_template", "output_schema", "model",
)
NOT_AVAILABLE_STATIC = "not_available (static source review; nothing was executed)"
NOT_AVAILABLE_INPUT = "not_available (static source review; no input artifact)"


class TaskError(Exception):
    """The task file itself is invalid."""


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def next_id(root: Path, prefix: str) -> str:
    """Next <prefix>-NNN under *root* (same scheme as tools/new_run.py)."""
    existing = [
        int(p.name.split("-", 1)[-1])
        for p in root.glob(f"{prefix}-*")
        if p.name.split("-", 1)[-1].isdigit()
    ]
    return f"{prefix}-{max(existing, default=0) + 1:03d}"


def resolve_task_path(arg: str) -> Path:
    path = Path(arg)
    if path.suffix not in (".yaml", ".yml"):
        path = STAGE2_ROOT / "tasks" / f"{arg}.yaml"
    return path.resolve()


def load_task(path: Path) -> dict:
    task = yaml.safe_load(path.read_text(encoding="utf-8"))
    missing = [k for k in REQUIRED_TASK_KEYS if k not in task]
    if missing:
        raise TaskError(f"{path.name}: missing keys {missing}")
    if task["task_id"] != path.stem:
        raise TaskError(f"{path.name}: task_id {task['task_id']!r} must match file name")
    if task["mode"] not in SUPPORTED_MODES:
        raise TaskError(f"mode {task['mode']!r} not implemented (supported: {SUPPORTED_MODES})")
    if "temperature" not in (task["model"] or {}):
        raise TaskError(f"{path.name}: model.temperature is required")
    for placeholder in ("{context_block}", "{response_schema}"):
        if placeholder not in task["prompt_template"]:
            raise TaskError(f"{path.name}: prompt_template lacks {placeholder}")
    if not task["valid_classes"]:
        raise TaskError(f"{path.name}: valid_classes is empty")
    return task


def build_schemas(task: dict, task_path: Path) -> tuple[dict, dict, list[str]]:
    """Return (full record schema, model response schema, driver-owned fields)."""
    schema_path = (task_path.parent / task["output_schema"]).resolve()
    record = json.loads(schema_path.read_text(encoding="utf-8"))
    record["properties"]["vulnerability_class"]["enum"] = list(task["valid_classes"])
    owned = list(record.get("x-driver-owned", []))

    item = copy.deepcopy(record)
    for key in ("$schema", "$id", "title", "description", "x-driver-owned"):
        item.pop(key, None)
    for key in owned:
        item["properties"].pop(key, None)
    item["required"] = [k for k in item["required"] if k not in owned]
    response = {
        "type": "object",
        "additionalProperties": False,
        "required": ["candidates"],
        "properties": {"candidates": {"type": "array", "items": item}},
    }
    Draft202012Validator.check_schema(record)
    Draft202012Validator.check_schema(response)
    return record, response, owned


def build_prompt(task: dict, context_block: str, response_schema: dict) -> str:
    # str.replace, not str.format: source code is full of braces.
    return (
        task["prompt_template"]
        .replace("{context_block}", context_block)
        .replace("{response_schema}", json.dumps(response_schema, indent=2))
    )


def parse_json(text: str):
    """Parse a JSON object, tolerating surrounding code fences or prose."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[1] if "\n" in stripped else ""
        stripped = stripped.rsplit("```", 1)[0]
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        start, end = stripped.find("{"), stripped.rfind("}")
        if start != -1 and end > start:
            return json.loads(stripped[start : end + 1])
        raise


def validation_errors(text: str, response_schema: dict) -> tuple[object, list[str]]:
    try:
        data = parse_json(text)
    except json.JSONDecodeError as exc:
        return None, [f"response is not valid JSON: {exc}"]
    errors = sorted(
        Draft202012Validator(response_schema).iter_errors(data),
        key=lambda e: list(e.absolute_path),
    )
    return data, [
        f"at {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
        for e in errors[:8]
    ]


def git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(STAGE2_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        dirty = subprocess.run(
            ["git", "-C", str(STAGE2_ROOT), "status", "--porcelain", "--", "."],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    commit = out.stdout.strip() or "unknown"
    return commit + ("+dirty-stage2" if dirty.stdout.strip() else "")


def append_log(run_dir: Path, **entry) -> None:
    entry = {"time": utc_now(), "phase": 1, **entry}
    with (run_dir / "commands.log").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def usage_total(completions: list[Completion]) -> dict:
    """Sum token usage and cost over all attempts of one run.

    OpenRouter returns cost (USD credits) inline in ``usage.cost``; no
    follow-up generation query is needed. cost_usd is None when no attempt
    reported one.
    """
    total = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
             "reasoning_tokens": 0, "cost_usd": None}
    for c in completions:
        u = c.usage or {}
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            total[key] += u.get(key) or 0
        total["reasoning_tokens"] += (u.get("completion_tokens_details") or {}).get("reasoning_tokens") or 0
        if u.get("cost") is not None:
            total["cost_usd"] = round((total["cost_usd"] or 0.0) + float(u["cost"]), 8)
    return total


COST_LOG_FIELDS = ("timestamp_utc", "run_id", "task_id", "status", "model_requested",
                   "model_resolved", "attempts", "prompt_tokens", "completion_tokens",
                   "total_tokens", "cost_usd")


def append_cost_row(cost_log: Path, meta: dict) -> None:
    """Append one row per run to the running cost log (created with a header)."""
    new = not cost_log.exists()
    cost_log.parent.mkdir(parents=True, exist_ok=True)
    u = meta["usage_total"]
    row = {
        "timestamp_utc": meta["end_utc"], "run_id": meta["run_id"], "task_id": meta["task_id"],
        "status": meta["status"], "model_requested": meta["model_requested"],
        "model_resolved": "|".join(m for m in meta["model_resolved"] if m),
        "attempts": meta["attempts"], "prompt_tokens": u["prompt_tokens"],
        "completion_tokens": u["completion_tokens"], "total_tokens": u["total_tokens"],
        "cost_usd": "" if u["cost_usd"] is None else u["cost_usd"],
    }
    with cost_log.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COST_LOG_FIELDS)
        if new:
            writer.writeheader()
        writer.writerow(row)


def findings_md(records: list[dict], status: str) -> str:
    head = (
        "# Candidate findings\n\n"
        "Status values: candidate | validated | rejected | inconclusive\n\n"
        "Written by stage2/driver/run_task.py. Do not edit; scoring writes\n"
        "verdict.md instead. Machine-readable copy: candidates.json.\n"
    )
    if status == "malformed_output":
        return head + "\nRun status: malformed_output. No schema-valid record; see raw_output.txt.\n"
    if not records:
        return head + "\nThe model reported no candidates.\n"
    blocks = [
        "```yaml\n" + yaml.safe_dump(r, sort_keys=False, allow_unicode=True) + "```\n"
        for r in records
    ]
    return head + "\n" + "\n".join(blocks)


def notes_md(task: dict, run_id: str) -> str:
    return (
        f"# Investigation notes\n\n"
        f"Viewpoint: {VIEWPOINT}\nRun id: {run_id}\nTask: {task['task_id']}\n\n"
        f"Task description: {task['description'].strip()}\n\n"
        f"## Withheld from the model (not shown in prompt)\n\n"
        f"{(task['context'].get('withheld_notice') or 'nothing declared').strip()}\n\n"
        f"## Hypotheses\n\n## Failed attempts\n\n"
        f"## Manual reasoning / bottlenecks\n\n## Deviations from protocol.yaml\n"
    )


class Run:
    """One repeat: one model conversation, one run directory."""

    def __init__(self, *, task, task_path, context, record_schema, response_schema,
                 owned, prompt, model, model_source, sampling, run_index, repeats,
                 group_id, results_root, settings_source):
        self.task = task
        self.task_path = task_path
        self.context = context
        self.record_schema = record_schema
        self.response_schema = response_schema
        self.owned = owned
        self.prompt = prompt
        self.model = model
        self.model_source = model_source
        self.sampling = sampling
        self.run_index = run_index
        self.repeats = repeats
        self.group_id = group_id
        self.settings_source = settings_source
        self.prompt_id = f"{task['task_id']}@v{task['prompt_version']}"
        self.run_id = next_id(results_root, "run")
        self.dir = results_root / self.run_id
        self.dir.mkdir(parents=True)
        (self.dir / "commands.log").write_text("", encoding="utf-8")
        (self.dir / "verdict.md").write_text("# Evaluator verdict\n\npending\n", encoding="utf-8")
        (self.dir / "notes.md").write_text(notes_md(task, self.run_id), encoding="utf-8")
        (self.dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    def complete_records(self, data: dict) -> list[dict]:
        records = []
        for i, item in enumerate(data["candidates"], start=1):
            record = {
                "candidate_id": f"CAND-{i:03d}",
                "viewpoint": VIEWPOINT,
                "property": self.task["property"],
                "hypothesis": item["hypothesis"],
                "evidence_source": item["evidence_source"],
                "input_artifact": NOT_AVAILABLE_INPUT,
                "expected_behavior": item["expected_behavior"],
                "observed_behavior": NOT_AVAILABLE_STATIC,
                "status": "candidate",
                "oracle_verdict": "pending",
                "notes": item["notes"],
                "vulnerability_class": item["vulnerability_class"],
                "location": item["location"],
                "confidence": item["confidence"],
                "model": self.model,
                "prompt_id": self.prompt_id,
                "run_index": self.run_index,
            }
            Draft202012Validator(self.record_schema).validate(record)
            records.append(record)
        return records

    def execute(self, client) -> dict:
        start_utc, t0 = utc_now(), time.monotonic()
        messages = [{"role": "user", "content": self.prompt}]
        transcript, completions = [], []
        status, records, error = "malformed_output", [], None

        for attempt in (1, 2):
            t_call = time.monotonic()
            try:
                completion: Completion = client.complete(self.model, messages, self.sampling)
            except Exception as exc:  # network/API failure: record it, never invent output
                error = f"{type(exc).__name__}: {exc}"
                append_log(self.dir, action="model_call", tool="openrouter",
                           input="prompt.txt", result="api_error",
                           elapsed_ms=int((time.monotonic() - t_call) * 1000),
                           notes=error[:500])
                status = "api_error"
                break
            completions.append(completion)
            data, errors = validation_errors(completion.text, self.response_schema)
            transcript.append({
                "attempt": attempt,
                "messages_sent": messages,
                "response_text": completion.text,
                "resolved_model": completion.resolved_model,
                "provider": completion.provider,
                "response_id": completion.response_id,
                "finish_reason": completion.finish_reason,
                "usage": completion.usage,
                "validation_errors": errors,
            })
            append_log(self.dir, action="model_call", tool="openrouter",
                       input="prompt.txt", result="schema_valid" if not errors else "schema_invalid",
                       elapsed_ms=int((time.monotonic() - t_call) * 1000),
                       notes=f"attempt {attempt}; resolved_model={completion.resolved_model}")
            if not errors:
                records = self.complete_records(data)
                status = "candidate"
                break
            messages = messages + [
                {"role": "assistant", "content": completion.text},
                {"role": "user", "content": (
                    "Your previous response did not validate against the required "
                    "JSON Schema:\n- " + "\n- ".join(errors) +
                    "\nRespond again with ONLY the corrected JSON object."
                )},
            ]

        (self.dir / "transcript.json").write_text(json.dumps(transcript, indent=2), encoding="utf-8")
        if status != "candidate":
            raw = "\n\n".join(
                f"===== attempt {t['attempt']} =====\n{t['response_text']}" for t in transcript
            )
            (self.dir / "raw_output.txt").write_text(raw or (error or ""), encoding="utf-8")
        (self.dir / "candidates.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
        (self.dir / "findings.md").write_text(findings_md(records, status), encoding="utf-8")

        upstream = self.task["context"].get("upstream") or {}
        run_meta = {
            "run_id": self.run_id,
            "viewpoint": VIEWPOINT,
            "task_id": self.task["task_id"],
            "prompt_id": self.prompt_id,
            "mode": self.task["mode"],
            "property": self.task["property"],
            "status": status,
            "candidate_count": len(records),
            "run_index": self.run_index,
            "repeats": self.repeats,
            "group_id": self.group_id,
            "target_repository": upstream.get("repository", "not_applicable"),
            "target_commit": upstream.get("commit", "not_applicable"),
            "start_utc": start_utc,
            "end_utc": utc_now(),
            "elapsed_s": round(time.monotonic() - t0, 2),
            "model_requested": self.model,
            "model_source": self.model_source,
            "model_resolved": [c.resolved_model for c in completions],
            "provider": [c.provider for c in completions],
            "response_ids": [c.response_id for c in completions],
            "sampling": self.sampling,
            "attempts": len(transcript),
            "usage": [c.usage for c in completions],
            "usage_total": usage_total(completions),
            "error": error,
            "settings_source": self.settings_source,
            "task_file": self.task_path.relative_to(STAGE2_ROOT.parent).as_posix(),
            "driver_commit": git_commit(),
            "context": {
                "source_root": self.context.source_root,
                "files": [
                    {"path": f.path, "sha256": f.sha256,
                     "line_range": list(f.line_range), "total_lines": f.total_lines}
                    for f in self.context.files
                ],
            },
            "withheld_notice": (self.task["context"].get("withheld_notice") or "").strip(),
            "investigator": "",
        }
        (self.dir / "run.yaml").write_text(
            yaml.safe_dump(run_meta, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        return run_meta


def top_candidate(records: list[dict]) -> dict | None:
    return max(records, key=lambda r: r["confidence"]) if records else None


def write_group_summary(results_root: Path, group_id: str, runs: list[tuple[dict, list[dict]]]) -> Path:
    """Agreement/variance summary across repeats of one invocation."""
    def key(r):
        loc = r["location"]
        return f"{loc['file']}:{loc['function']}:{loc['line']}:{r['vulnerability_class']}"

    rows, tops, all_sets = [], [], []
    for meta, records in runs:
        top = top_candidate(records)
        rows.append({
            "run_id": meta["run_id"],
            "status": meta["status"],
            "model_resolved": meta["model_resolved"],
            "candidate_count": len(records),
            "top_candidate": key(top) if top else None,
            "all_candidates": [key(r) for r in records],
        })
        if meta["status"] == "candidate":
            tops.append(key(top) if top else None)
            all_sets.append({key(r) for r in records})
    valid = len(tops)
    top_lines = sorted({t.split(":")[2] for t in tops if t})
    summary = {
        "group_id": group_id,
        "task_id": runs[0][0]["task_id"],
        "model_requested": runs[0][0]["model_requested"],
        "sampling": runs[0][0]["sampling"],
        "runs": rows,
        "schema_valid_runs": valid,
        "malformed_or_failed_runs": len(runs) - valid,
        "top_candidate_unanimous": valid == len(runs) and len(set(tops)) == 1 and tops[0] is not None,
        "top_candidate_distinct_values": sorted({str(t) for t in tops}),
        "top_candidate_lines": top_lines,
        "candidates_in_every_run": sorted(set.intersection(*all_sets)) if all_sets else [],
    }
    group_dir = results_root / "groups"
    group_dir.mkdir(exist_ok=True)
    path = group_dir / f"{group_id}.yaml"
    path.write_text(yaml.safe_dump(summary, sort_keys=False), encoding="utf-8")
    return path


def main(argv: list[str] | None = None, client_factory=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("task", help="task id (tasks/<id>.yaml) or path to a task yaml")
    parser.add_argument("--model", help="OpenRouter model string; overrides .env and task default")
    parser.add_argument("--repeats", type=int, help="independent runs to make (default: task model.repeats)")
    parser.add_argument("--results-root", type=Path, default=STAGE2_ROOT / "results" / "ai-runs")
    parser.add_argument("--cost-log", type=Path, default=STAGE2_ROOT / "results" / "cost_log.csv",
                        help="running CSV; one row appended per run")
    parser.add_argument("--dry-run", action="store_true",
                        help="load task and context, print the prompt, make no API call")
    args = parser.parse_args(argv)

    try:
        task_path = resolve_task_path(args.task)
        task = load_task(task_path)
        context = load_context(task)                     # boundary + integrity, before any call
        record_schema, response_schema, owned = build_schemas(task, task_path)
    except (TaskError, BoundaryError, IntegrityError, OSError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    prompt = build_prompt(task, context.render(), response_schema)

    if args.dry_run:
        print(prompt)
        return 0

    settings_source, model_env = "injected-client", None
    if client_factory is None:
        try:
            settings = load_settings()
        except SettingsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        settings_source, model_env = settings.source, settings.model
        client_factory = lambda: OpenRouterClient(settings)  # noqa: E731

    if args.model:
        model, model_source = args.model, "cli --model"
    elif model_env:
        model, model_source = model_env, "OPENROUTER_MODEL (.env)"
    else:
        model, model_source = task["model"]["default"], "task default"

    sampling = {"temperature": task["model"]["temperature"]}
    if task["model"].get("max_tokens"):
        sampling["max_tokens"] = task["model"]["max_tokens"]
    repeats = args.repeats or task["model"].get("repeats", 1)
    if repeats < 1:
        print("error: --repeats must be >= 1", file=sys.stderr)
        return 2

    args.results_root.mkdir(parents=True, exist_ok=True)
    group_id = next_id(args.results_root / "groups", "group") if repeats > 1 else None
    client = client_factory()
    runs = []
    for index in range(1, repeats + 1):
        run = Run(task=task, task_path=task_path, context=context,
                  record_schema=record_schema, response_schema=response_schema,
                  owned=owned, prompt=prompt, model=model, model_source=model_source,
                  sampling=sampling, run_index=index, repeats=repeats, group_id=group_id,
                  results_root=args.results_root, settings_source=settings_source)
        meta = run.execute(client)
        append_cost_row(args.cost_log, meta)
        records = json.loads((run.dir / "candidates.json").read_text(encoding="utf-8"))
        runs.append((meta, records))
        print(json.dumps({
            "run_dir": str(run.dir), "status": meta["status"],
            "candidates": meta["candidate_count"], "model_requested": model,
            "model_resolved": meta["model_resolved"], "attempts": meta["attempts"],
            "total_tokens": meta["usage_total"]["total_tokens"],
            "cost_usd": meta["usage_total"]["cost_usd"],
        }))
    if group_id:
        print(json.dumps({"group_summary": str(write_group_summary(args.results_root, group_id, runs))}))
    return 0 if all(m["status"] == "candidate" for m, _ in runs) else 1


if __name__ == "__main__":
    raise SystemExit(main())

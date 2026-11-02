#!/usr/bin/env python3
"""Evaluator-side scoring for Stage 2 AI runs.

Separate process from the model call. Reads a run's candidates.json plus
scoring/ground_truth/<task_id>.yaml (and the reference files that ground
truth declares, e.g. evaluator/ground_truth.yaml) and writes verdict.md and
verdict.yaml into the run directory. Never modifies candidates.json or
findings.md (Procedure §5: preserve unmodified original evidence).

There is no per-task logic here: everything task-specific lives in the
task's ground-truth file. Matching is exact: file path, function name and
vulnerability_class must be equal; line must fall within the declared
range +/- line_tolerance.

    python stage2/scoring/score_run.py --task demo-pattern --run stage2/results/ai-runs/run-001
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path, PurePosixPath

import yaml

STAGE2_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = STAGE2_ROOT.parent
GROUND_TRUTH_DIR = STAGE2_ROOT / "scoring" / "ground_truth"


class ScoringError(Exception):
    pass


def norm_path(value: str) -> str:
    return PurePosixPath(str(value).replace("\\", "/").removeprefix("./")).as_posix()


def norm_function(value: str) -> str:
    return str(value).strip().removesuffix("()").strip()


def dotted(obj: dict, path: str):
    for part in path.split("."):
        if not isinstance(obj, dict) or part not in obj:
            raise ScoringError(f"consistency path {path!r} not found")
        obj = obj[part]
    return obj


def load_ground_truth(task_id: str) -> tuple[dict, Path]:
    path = GROUND_TRUTH_DIR / f"{task_id}.yaml"
    if not path.is_file():
        raise ScoringError(f"no ground truth for task {task_id!r}: expected {path}")
    gt = yaml.safe_load(path.read_text(encoding="utf-8"))
    if gt.get("task_id") != task_id:
        raise ScoringError(f"{path} declares task_id {gt.get('task_id')!r}, not {task_id!r}")
    exp = gt.get("expected") or {}
    for key in ("file", "function", "lines", "line_tolerance", "vulnerability_class"):
        if key not in exp:
            raise ScoringError(f"{path}: expected.{key} missing")
    return gt, path


def check_references(gt: dict, task: dict) -> list[dict]:
    """Record provenance of reference files and enforce declared consistency."""
    namespaces = {"expected": gt["expected"], "task": task}
    out = []
    for ref in gt.get("references") or []:
        path = (REPO_ROOT / ref["path"]).resolve()
        data = path.read_bytes()
        doc = yaml.safe_load(data) or {}
        mismatches = []
        for ref_key, target in (ref.get("consistency") or {}).items():
            ns, _, rest = target.partition(".")
            if ns not in namespaces:
                raise ScoringError(f"consistency target {target!r} must start with expected. or task.")
            want = dotted(namespaces[ns], rest)
            have = doc.get(ref_key)
            if have != want:
                mismatches.append(f"{ref['path']}:{ref_key}={have!r} but {target}={want!r}")
        if mismatches:
            raise ScoringError("ground truth inconsistent with references: " + "; ".join(mismatches))
        out.append({
            "path": ref["path"],
            "sha256": hashlib.sha256(data).hexdigest(),
            "recorded": {k: doc.get(k) for k in ref.get("record_keys") or []},
            "consistency_checked": sorted((ref.get("consistency") or {}).keys()),
        })
    return out


def score_candidate(record: dict, exp: dict) -> dict:
    loc = record.get("location") or {}
    lo, hi = exp["lines"][0], exp["lines"][-1]
    tol = exp["line_tolerance"]
    checks = {
        "file": norm_path(loc.get("file", "")) == norm_path(exp["file"]),
        "function": norm_function(loc.get("function", "")) == norm_function(exp["function"]),
        "vulnerability_class": record.get("vulnerability_class") == exp["vulnerability_class"],
        "line": isinstance(loc.get("line"), int) and lo - tol <= loc["line"] <= hi + tol,
    }
    if all(checks.values()):
        status, verdict = "validated", "true_positive"
    elif checks["file"] and checks["function"] and checks["vulnerability_class"]:
        status, verdict = "inconclusive", "location_partial_match"
    else:
        status, verdict = "rejected", "false_positive"
    return {
        "candidate_id": record.get("candidate_id"),
        "reported": {
            "file": loc.get("file"), "function": loc.get("function"), "line": loc.get("line"),
            "vulnerability_class": record.get("vulnerability_class"),
            "confidence": record.get("confidence"),
        },
        "checks": checks,
        "status": status,
        "oracle_verdict": verdict,
    }


def score_run(run_dir: Path, task_id: str) -> dict:
    run_meta = yaml.safe_load((run_dir / "run.yaml").read_text(encoding="utf-8"))
    if run_meta.get("task_id") != task_id:
        raise ScoringError(f"{run_dir} is a run of {run_meta.get('task_id')!r}, not {task_id!r}")
    gt, gt_path = load_ground_truth(task_id)
    task = yaml.safe_load((REPO_ROOT / run_meta["task_file"]).read_text(encoding="utf-8"))
    references = check_references(gt, task)
    exp = gt["expected"]

    if run_meta.get("status") != "candidate":
        results, run_verdict = [], "inconclusive"
        reason = f"run status is {run_meta.get('status')!r}; no schema-valid candidates to score"
    else:
        records = json.loads((run_dir / "candidates.json").read_text(encoding="utf-8"))
        results = [score_candidate(r, exp) for r in records]
        statuses = {r["status"] for r in results}
        if "validated" in statuses:
            run_verdict, reason = "validated", "a candidate matches the expected finding"
        elif "inconclusive" in statuses:
            run_verdict, reason = "inconclusive", "right file/function/class, line outside tolerance"
        elif results:
            run_verdict, reason = "rejected", "all candidates are false positives w.r.t. this ground truth"
        else:
            run_verdict, reason = "rejected", "no candidates reported (expected finding missed)"

    return {
        "run_id": run_meta["run_id"],
        "task_id": task_id,
        "prompt_id": run_meta.get("prompt_id"),
        "model_requested": run_meta.get("model_requested"),
        "model_resolved": run_meta.get("model_resolved"),
        "scored_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run_verdict": run_verdict,
        "reason": reason,
        "expected": {k: exp[k] for k in ("file", "function", "lines", "line_tolerance",
                                         "vulnerability_class")},
        "ground_truth_file": gt_path.relative_to(REPO_ROOT).as_posix(),
        "ground_truth_sha256": hashlib.sha256(gt_path.read_bytes()).hexdigest(),
        "references": references,
        "candidates": results,
    }


def verdict_md(v: dict) -> str:
    exp = v["expected"]
    lines = [
        "# Evaluator verdict", "",
        f"Run: {v['run_id']}  Task: {v['task_id']}  Prompt: {v['prompt_id']}",
        f"Model requested: {v['model_requested']}  resolved: {v['model_resolved']}",
        f"Scored: {v['scored_utc']} by stage2/scoring/score_run.py", "",
        f"**Run verdict: {v['run_verdict']}** — {v['reason']}", "",
        f"Expected: `{exp['file']}` `{exp['function']}` lines {exp['lines']} "
        f"(±{exp['line_tolerance']}), class `{exp['vulnerability_class']}`",
        f"Ground truth: `{v['ground_truth_file']}` sha256 `{v['ground_truth_sha256'][:16]}…`", "",
        "| Candidate | Reported location | Class | Conf. | file | function | line | class | Status | Oracle verdict |",
        "| --- | --- | --- | --- | :---: | :---: | :---: | :---: | --- | --- |",
    ]
    tick = {True: "✓", False: "✗"}
    for c in v["candidates"]:
        r, ch = c["reported"], c["checks"]
        lines.append(
            f"| {c['candidate_id']} | `{r['file']}` `{r['function']}`:{r['line']} | "
            f"{r['vulnerability_class']} | {r['confidence']} | {tick[ch['file']]} | "
            f"{tick[ch['function']]} | {tick[ch['line']]} | {tick[ch['vulnerability_class']]} | "
            f"{c['status']} | {c['oracle_verdict']} |"
        )
    if not v["candidates"]:
        lines.append("| — | no candidates | | | | | | | | |")
    lines += [
        "",
        "`false_positive` is relative to this task's ground truth only; a rejected",
        "candidate may still be a different real defect and is preserved as recorded.",
        "Original candidate records (candidates.json, findings.md) are unmodified.",
    ]
    for ref in v["references"]:
        lines += ["", f"## Reference `{ref['path']}` (sha256 `{ref['sha256'][:16]}…`)", ""]
        if ref["consistency_checked"]:
            lines.append(f"Consistency checked: {', '.join(ref['consistency_checked'])} — OK")
        for k, val in ref["recorded"].items():
            lines.append(f"- {k}: {str(val).strip()}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score Stage 2 AI run directories.")
    parser.add_argument("--task", required=True, help="task_id; selects scoring/ground_truth/<task_id>.yaml")
    parser.add_argument("--run", required=True, action="append", type=Path,
                        help="run directory (repeatable)")
    args = parser.parse_args(argv)
    rc = 0
    for run_dir in args.run:
        try:
            verdict = score_run(run_dir, args.task)
        except (ScoringError, OSError, KeyError) as exc:
            print(f"error: {run_dir}: {exc}", file=sys.stderr)
            rc = 2
            continue
        (run_dir / "verdict.yaml").write_text(yaml.safe_dump(verdict, sort_keys=False, allow_unicode=True),
                                             encoding="utf-8")
        (run_dir / "verdict.md").write_text(verdict_md(verdict), encoding="utf-8")
        print(json.dumps({"run": str(run_dir), "run_verdict": verdict["run_verdict"],
                          "candidates": [(c["candidate_id"], c["status"], c["oracle_verdict"])
                                         for c in verdict["candidates"]]}))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

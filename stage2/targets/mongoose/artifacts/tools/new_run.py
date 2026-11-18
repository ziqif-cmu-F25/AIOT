#!/usr/bin/env python3
"""Create a personal Stage 2 investigation run directory."""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path


NOTES_TEMPLATE = """# Investigation notes

Viewpoint: {viewpoint}
Run id: {run_id}
Target commit: {commit}
Condition: {condition}

Keep factual runtime observations in outputs/ JSON files. Use this file for
hypotheses, failed attempts, workflow bottlenecks, and protocol deviations.

## Time log

| UTC | Elapsed (min) | Action |
| --- | --- | --- |
| {start_utc} | 0 | Run started |

## Hypotheses

## Failed attempts

## Manual reasoning / bottlenecks

## AI assistance (if any)

- Model:
- Prompt id:
- Human edits to AI drafts:
- Cost (USD):

## Deviations from protocol.yaml
"""

FINDINGS_TEMPLATE = """# Candidate findings

Status values: candidate | validated | rejected | inconclusive

```yaml
candidate_id: CAND-001
viewpoint: {viewpoint}
condition: {condition}
property: ""
hypothesis: ""
evidence_source: ""
input_artifact: ""
expected_behavior: ""
observed_behavior: ""
status: candidate
oracle_verdict: pending
human_edits_to_ai: 0
notes: ""
```
"""

RUN_TEMPLATE = """run_id: {run_id}
viewpoint: {viewpoint}
condition: {condition}
target_commit: {commit}
target_tag: "{tag}"
start_utc: {start_utc}
end_utc: ""
elapsed_s: ""
investigation_budget_min: 90
environment_manifest: /opt/lab/environment-manifest.txt
protocol: /opt/lab/protocol.yaml
investigator: ""
"""


def next_run_id(root: Path) -> str:
    """Return the next run-NNN identifier under *root*."""
    existing = []
    for path in root.glob("run-*"):
        suffix = path.name.split("-", 1)[-1]
        if suffix.isdigit():
            existing.append(int(suffix))
    nxt = max(existing, default=0) + 1
    return f"run-{nxt:03d}"


def main() -> int:
    """Create a run directory and print its path."""
    parser = argparse.ArgumentParser(
        description="Create an investigation run directory."
    )
    parser.add_argument(
        "--results-root",
        default=os.environ.get("LAB_RESULTS", "/workspace/results"),
        type=Path,
    )
    parser.add_argument(
        "--viewpoint",
        default=os.environ.get("LAB_VIEWPOINT", "white-box"),
        choices=["black-box", "white-box", "ai-assisted"],
    )
    parser.add_argument(
        "--condition",
        default="traditional",
        choices=["traditional", "ai-assisted", "ai-repeat"],
        help="traditional must be completed before ai-assisted by the same person.",
    )
    parser.add_argument(
        "--commit",
        default=os.environ.get(
            "MONGOOSE_COMMIT", "b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116"
        ),
    )
    parser.add_argument("--tag", default=os.environ.get("MONGOOSE_TAG", "7.21"))
    args = parser.parse_args()

    args.results_root.mkdir(parents=True, exist_ok=True)
    run_id = next_run_id(args.results_root)
    run_dir = args.results_root / run_id
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "outputs").mkdir()
    start_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (run_dir / "run.yaml").write_text(
        RUN_TEMPLATE.format(
            run_id=run_id,
            viewpoint=args.viewpoint,
            condition=args.condition,
            commit=args.commit,
            tag=args.tag,
            start_utc=start_utc,
        ),
        encoding="utf-8",
    )
    (run_dir / "notes.md").write_text(
        NOTES_TEMPLATE.format(
            viewpoint=args.viewpoint,
            run_id=run_id,
            commit=args.commit,
            condition=args.condition,
            start_utc=start_utc,
        ),
        encoding="utf-8",
    )
    (run_dir / "findings.md").write_text(
        FINDINGS_TEMPLATE.format(
            viewpoint=args.viewpoint, condition=args.condition
        ),
        encoding="utf-8",
    )
    (run_dir / "commands.log").write_text("", encoding="utf-8")
    (run_dir / "verdict.md").write_text(
        "# Evaluator verdict\n\npending\n",
        encoding="utf-8",
    )
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

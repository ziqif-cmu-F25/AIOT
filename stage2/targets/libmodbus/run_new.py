#!/usr/bin/env python3
"""Create a Stage 2 libmodbus investigation run directory, per track.

Mirrors tools/new_run.py (the Stage 1 helper) so human (Track A) and
AI-assisted (Track B) runs log in the same shape and can be compared. A run
lives under results/<track>/run-NNN with an inputs/ and outputs/ dir, a
commands.log, a notes/findings scaffold, and a run.yaml manifest.

    python run_new.py --track track-a
    python run_new.py --track track-b
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

TRACKS = {
    "track-a": "human-only",
    "track-b": "human+ai-assisted",
}
TARGET_COMMIT = "2cbafa3113e276c3697d297f68e88d112b53174d"
TARGET_TAG = "v3.1.10"

RUN_TEMPLATE = """run_id: {run_id}
track: {track}
condition: {condition}
target_repository: stephane/libmodbus
target_commit: {commit}
target_tag: {tag}
property: memory-safety
start_utc: {start_utc}
end_utc: ""
elapsed_s: ""
investigator: ""
notes: >
  {condition} investigation of the frozen libmodbus target. Record commands in
  commands.log, saved frames in inputs/, observations in outputs/, hypotheses
  and bottlenecks in notes.md, and candidate findings in findings.md.
"""

NOTES_TEMPLATE = """# Investigation notes

Track: {track} ({condition})
Run id: {run_id}
Target: libmodbus {tag} ({commit})

Keep factual runtime observations in outputs/ JSON files. Use this file for
hypotheses, failed attempts, workflow bottlenecks, and the frozen information
boundary you were given.

## Hypotheses

## Failed attempts

## Manual reasoning / bottlenecks

## AI assistance used (Track B only: model, prompt id, what it was asked)
"""

FINDINGS_TEMPLATE = """# Candidate findings

Status values: candidate | validated | rejected | inconclusive

```yaml
candidate_id: CAND-001
track: {track}
property: memory-safety
hypothesis: ""
evidence_source: ""
input_artifact: ""
expected_behavior: ""
observed_behavior: ""
status: candidate
oracle_verdict: pending
notes: ""
```
"""


def next_run_id(root: Path) -> str:
    existing = [
        int(p.name.split("-", 1)[-1])
        for p in root.glob("run-*")
        if p.name.split("-", 1)[-1].isdigit()
    ]
    return f"run-{max(existing, default=0) + 1:03d}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a libmodbus run directory.")
    parser.add_argument("--track", required=True, choices=sorted(TRACKS))
    parser.add_argument("--results-root", type=Path, default=Path(__file__).resolve().parent / "results")
    args = parser.parse_args()

    condition = TRACKS[args.track]
    track_root = args.results_root / args.track
    track_root.mkdir(parents=True, exist_ok=True)
    run_id = next_run_id(track_root)
    run_dir = track_root / run_id
    (run_dir / "inputs").mkdir(parents=True)
    (run_dir / "outputs").mkdir()
    start_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    fields = dict(run_id=run_id, track=args.track, condition=condition,
                  commit=TARGET_COMMIT, tag=TARGET_TAG, start_utc=start_utc)
    (run_dir / "run.yaml").write_text(RUN_TEMPLATE.format(**fields), encoding="utf-8")
    (run_dir / "notes.md").write_text(NOTES_TEMPLATE.format(**fields), encoding="utf-8")
    (run_dir / "findings.md").write_text(FINDINGS_TEMPLATE.format(**fields), encoding="utf-8")
    (run_dir / "commands.log").write_text("", encoding="utf-8")
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

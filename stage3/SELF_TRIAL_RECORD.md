# Harness self-trial record

This is one completed pass of `KICKSTART.md`. The steps below are the same
for any target pack. Names that belong to a single target appear only in
the measured outcome, where they are data from the files the harness wrote.

Branch used: `stage3/mongoose-self-trial`. Nothing from this pass was
pushed to `main`.

## Steps

1. Stay on a working branch. Do not put the run on `main`.
2. Add one target pack at `stage3/targets/<your-target-id>.yaml`. Point
   `source_root` at that target's source tree only. Point `run_target` at
   one already-running send command that keeps the literal `{input_file}`.
   Leave the Stage 2 lab and its oracle out of the harness commit.
3. Check out the pinned source into `source_root`. Do not commit that tree.
4. Set the three budgets in that pack. Leave `OPENROUTER_MODEL` empty in
   the repo-root `.env`, so `model.default` is the model that runs.
5. Start the frozen service. The harness does not start it.
6. Send one known-good input through that same `run_target` command.
   Confirm a normal observation before any API call.
7. From `stage3/`, run:

```sh
../stage2/.venv/bin/python -m harness.run_harness targets/<your-target-id>.yaml
```

8. Read `run.yaml`, `usage.jsonl`, `commands.log`, `candidate.json`, and
   the new row in `stage3/results/cost_log.csv`.
9. Leave `oracle_verdict` as `pending`. The Stage 2 oracle is a later step
   and stays outside the agent loop.

## Budgets used for this pass

| Field | Value |
| --- | --- |
| `max_steps` | 8 |
| `max_output_tokens` | 1200 |
| `max_cost_usd` | 0.05 |
| `model.default` | `openai/gpt-4o-mini` |
| `temperature` | 0.2 |

## Measured outcome

| Field | Value |
| --- | --- |
| Run directory | `stage3/results/run-001` |
| `target_id` | `mongoose-stage2` |
| Condition | `source-and-runtime` |
| `model_requested` | `openai/gpt-4o-mini` |
| `model_resolved` | `openai/gpt-4o-mini` |
| Start | 2026-11-19T00:00:07Z |
| End | 2026-11-19T00:00:18Z |
| `steps_used` | 4 of 8 |
| `stop_reason` | `finish` |
| `spent_usd` | 0.00138495 |
| `oracle_verdict` | `pending` |

`usage.jsonl`, one model call per row. Every `source` is `reported`, so
`spent_usd` matches the `cost_log.csv` total.

| Step | Prompt tokens | Completion tokens | `cost_usd` |
| --- | --- | --- | --- |
| 1 | 1114 | 42 | 0.0001923 |
| 2 | 2253 | 45 | 0.00028815 |
| 3 | 3484 | 118 | 0.0004302 |
| 4 | 4174 | 179 | 0.0004743 |
| Total | 11025 | 384 | 0.00138495 |

`commands.log` tool order:

| Step | Tool |
| --- | --- |
| 1 | `read_source` |
| 2 | `read_source` |
| 3 | `run_target` |
| 4 | `finish` |

`candidate.json` has `status: candidate` and `oracle_verdict: pending`.
The single `run_target` observation was an ordinary protocol response, not
a validated finding. The saved request bytes are in
`stage3/results/run-001/scratch/`. They are not part of this note.

The raw run directory and `cost_log.csv` are gitignored. This file is the
copy that stays on the branch.

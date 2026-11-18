# Stage 3 agent harness

Shared Naptime-style loop for the team's Stage 2 targets. The model chooses
one tool at a time, reads the observation, and updates its hypothesis. It
does not see evaluator files, and a `finish` candidate stays
`oracle_verdict: pending` until a person checks it with the target's
existing oracle.

This is a reduced harness (source browser, Python snippet, target runner,
step and path limits). It is not a fork of Baby Naptime, and it is not the
Stage 2 one-shot source-review driver.

## What you configure

Copy `targets/TEMPLATE.yaml` to `targets/<your-target-id>.yaml`.

- `source_root` is only that target's source tree. Do not point it at the
  repository root, `evaluator/`, or `.env`.
- `analyst_brief` is the interface description the agent is allowed to see.
  Leave out CVE ids, patches, and reference inputs.
- `run_target.argv` is one command that already knows how to reach your
  frozen service. It must contain the literal `{input_file}`. Start the
  service yourself before a runtime run. The harness does not start Docker.

Tools the model can call:

| Tool | Purpose |
| --- | --- |
| `read_source` | A line window of one file under `source_root` |
| `find_references` | Identifier search under `source_root` |
| `run_python` | A short Python snippet in the run scratch directory |
| `run_target` | Writes the model's bytes to `{input_file}` and runs your command |

`--source-only` disables the last two (SOW condition A). The default is
source plus runtime (condition B).

## Setup

Use the Stage 2 virtualenv. Settings stay in the repository-root `.env`
(`OPENROUTER_API_KEY`, optional `OPENROUTER_MODEL`), same rule as Stage 2.

```sh
cd stage3
../stage2/.venv/bin/python -m unittest discover -s tests -v
```

Smoke test with no API key (scripted replies, synthetic fixture only):

```sh
cd stage3
../stage2/.venv/bin/python -m harness.run_harness \
  targets/fixture-mini.yaml \
  --scripted targets/fixture/scripted_actions.json
```

Real run on your pack:

```sh
cd stage3
../stage2/.venv/bin/python -m harness.run_harness targets/<your-target-id>.yaml
../stage2/.venv/bin/python -m harness.run_harness targets/<your-target-id>.yaml \
  --model openai/gpt-4o-mini
../stage2/.venv/bin/python -m harness.run_harness targets/<your-target-id>.yaml \
  --source-only
```

## What to hand back

Each invocation writes `stage3/results/run-NNN/`:

| File | Contents |
| --- | --- |
| `run.yaml` | Target, model, condition, step count, stop reason |
| `transcript.json` | System prompt, actions, and tool observations |
| `commands.log` | One JSON line per tool observation |
| `candidate.json` | The model's candidate, still `oracle_verdict: pending` |
| `scratch/` | Saved inputs and Python snippets |

Token totals are appended to `stage3/results/cost_log.csv`. After the run,
check the candidate with the same oracle you used in Stage 2. Do not treat
a source-location guess, or this harness's own exit code, as validation.

`targets/fixture/` is a synthetic local program for the smoke test. It is
not libcoap, Mongoose, or any other team target.

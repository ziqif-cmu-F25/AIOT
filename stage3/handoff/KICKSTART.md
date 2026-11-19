# Stage 3 harness kickstart

Use this procedure on your own Stage 2 target. The commands never name a
project, a CVE, or a sample exploit. An assistant can follow this file as
written. Keep the assistant out of `evaluator/`, ground truth, and `.env`.

Work on your own branch. Do not commit `.env`, fetched source, or
`stage3/results/`. Do not push that branch onto `main` until the group asks
for it.

## 0. What one run is

The harness lets the model choose one tool at a time, executes it, and
feeds the observation back. It stops when the model finishes or when one of
the three budgets is hit. The candidate it writes is not a validated
finding. `oracle_verdict` stays `pending` until a person runs that target's
existing Stage 2 oracle on the saved input, outside this loop.

## 1. Install

From the repository root:

```sh
python3 -m venv stage2/.venv
stage2/.venv/bin/python -m pip install -r stage2/requirements.txt
cp stage2/.env.example .env
```

Edit `.env` and set only your own key:

```
OPENROUTER_API_KEY=sk-or-...
```

Leave `OPENROUTER_MODEL` empty. A value there replaces the model named in
the target pack and does not change the three budgets. The client reads
this file only. Each teammate uses a separate key. The harness calls
OpenRouter at `https://openrouter.ai/api/v1`.

## 2. Describe your target

```sh
cp stage3/targets/TEMPLATE.yaml stage3/targets/<your-target-id>.yaml
```

Set these fields:

| Field | What to put |
| --- | --- |
| `target_id` | A short name for this pack. |
| `analyst_brief` | Protocol, where the source of interest lives, and what a useful observation looks like (reply, timeout, sanitizer text, failed health check). No CVE, patch, or reference input. |
| `source_root` | The readable source tree only. Not the repo root, not `evaluator/`, not `.env`. |
| `allowed_suffixes` | Extensions `read_source` may open. |
| `run_target.argv` | One command that receives the literal `{input_file}`. That path is the host file of bytes the model asked to send. |
| `run_target.cwd` | Working directory for that command. `..` means the repo root when you launch the harness from `stage3/`. |
| `model.default` | An OpenRouter model id, such as `openai/gpt-4o-mini`. |
| `model.temperature` | Sampling temperature. The trial pack uses `0.2`. |

If the service is only reachable inside Compose, start it first, then point
`argv` at `stage3/scripts/relay_docker.py` the same way
`targets/libcoap-stage1.yaml` does. Keep `{input_file}` on the relay, and
`{guest_input}` plus `{stem}` on the command that runs inside the container.
The harness does not start Docker.

Fetch or check out the pinned source into `source_root` before the run.
Record the commit the agent is allowed to see. Do not commit that tree when
it is already gitignored (`stage3/vendor/`).

## 3. Set the three budgets

In the same YAML, under `limits`:

| Field | Effect |
| --- | --- |
| `max_steps` | Maximum model calls in this run. |
| `max_output_tokens` | Maximum tokens in one reply. Sent as `max_tokens`. |
| `max_cost_usd` | Maximum OpenRouter dollars for the whole run. Must be greater than 0. |

The run stops when any one of them is reached. `max_cost_usd` is checked
before the next call, using the `cost` field on the OpenRouter response.
The call that crosses the cap is already paid, so the total can exceed the
cap by at most one reply. If a response has no dollar cost, that call is
charged the whole cap and the run stops.

For a first paid run on `openai/gpt-4o-mini`, these values are enough:

```yaml
max_steps: 8
max_output_tokens: 1200
max_cost_usd: 0.05
```

The template's `12`, `1500`, and `0.10` are the looser starting point.
Raising the cap or switching to a larger model is what makes a run
expensive. The cap is per run, in this file. It is not an account-wide limit.

## 4. Prove the send path before spending

Start the frozen Stage 2 service yourself. Then send one known-good input
through the same command you put in `run_target.argv`. A normal reply,
with `timed_out: false` and a non-empty response, means the path works.
This step makes no API call.

`--scripted` replays a JSON list of assistant strings and also spends
nothing. Use it to test the pack, not as an investigation.

## 5. Run

From `stage3/`:

```sh
../stage2/.venv/bin/python -m harness.run_harness targets/<your-target-id>.yaml
```

Do not pass `--model` when you want `model.default`. `--source-only` is
condition A: it disables `run_python` and `run_target`. The default
condition is source plus runtime.

The command prints the run directory. The first run is
`stage3/results/run-001`.

## 6. Read the metrics

These files are the whole record. They are gitignored.

| File | What it holds |
| --- | --- |
| `stage3/results/run-NNN/run.yaml` | Model requested and resolved, condition, start and end, `steps_used`, the three budgets, `spent_usd`, `stop_reason`, `oracle_verdict: pending`. |
| `stage3/results/run-NNN/usage.jsonl` | One row per model call: `step`, `prompt_tokens`, `completion_tokens`, reported `cost_usd`, `charged_usd`, `source` (`reported` or `unknown`). |
| `stage3/results/cost_log.csv` | One row per run: token totals, `cost_usd`, `spent_usd`, `stop_reason`. |
| `stage3/results/run-NNN/commands.log` | One row per tool call: step, tool name, hypothesis, observation length. |
| `stage3/results/run-NNN/candidate.json` | The model's candidate. `status` is `candidate` or `incomplete`. `oracle_verdict` is `pending`. |
| `stage3/results/run-NNN/transcript.json` | Full messages, including tool observations. |
| `stage3/results/run-NNN/scratch/input-NNN.bin` | The exact bytes sent on each `run_target` call. |

`stop_reason` is `finish`, `max_steps`, or `max_cost`. `spent_usd` is the
sum of `charged_usd`. It equals `cost_usd` when every response reported a
dollar cost.

## 7. Keep one note per run

Write a short note next to the procedure. Quote from the files above:

- the three configured budgets
- `steps_used`, `stop_reason`, `spent_usd`
- each `usage.jsonl` row
- the matching `cost_log.csv` row
- `candidate.json` status and `oracle_verdict`

Do not paste `.env` or ground truth into that note. `SELF_TRIAL_RECORD.md`
is one filled-in example of this note.

## 8. Oracle, after the run

Take `scratch/input-NNN.bin` and judge it with the Stage 2 oracle you
already use for this target. Do that outside the harness. A match is a
validated finding. A normal protocol error, a timeout, or a different bug
is a false candidate. Record the verdict in your note. Until you do that,
the harness result stays `pending`.

## 9. Hand back

From the run directory: `run.yaml`, `usage.jsonl`, `commands.log`,
`candidate.json`, and `scratch/`. From `stage3/results/`: the new
`cost_log.csv` row. Say which commit of the harness you ran, and which
commit of the target source the pack was pointed at.

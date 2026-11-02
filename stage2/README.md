# Stage 2: AI-assisted review driver

A small, reusable driver for **Stage 2 AI-assisted vulnerability discovery
case studies**. A human writes a task file that fixes what the model may
see, what it is asked to judge, and the shape of its answer. The driver
calls one model via OpenRouter and writes the result in the same run-directory
shape Stage 1 uses (`tools/new_run.py`), so AI runs and human runs can be
compared directly. A separate evaluator step scores the run afterwards.

Stage 2 is **not autonomous** (SOW §2.1). The driver never picks its own task,
target, scope, or follow-up. Every run is one human-chosen task, one prompt,
and at most one schema-repair retry.

## Layout

| Path | Role |
| --- | --- |
| `tasks/TEMPLATE.yaml` | Commented skeleton: the reusable pattern |
| `tasks/demo-pattern.yaml` | Synthetic task on `tasks/fixtures/demo_snippet.c` (pipeline check) |
| `tasks/shakedown-proxy-address.yaml` | Real task on libcoap `src/coap_address.c` (known bug, pipeline check) |
| `tasks/fixtures/` | Hand-written synthetic sources and their `MANIFEST.txt` |
| `vendor/` | Upstream files fetched at a pinned commit and their `MANIFEST.txt` |
| `schema/candidate_record.schema.json` | Candidate record: Stage 1 fields plus AI fields |
| `driver/` | `context_loader.py` (boundary), `openrouter_client.py`, `run_task.py` (CLI) |
| `scripts/fetch_source.py` | One-time, human-run vendoring of allow-listed upstream files |
| `scoring/` | Evaluator side only: `score_run.py`, `ground_truth/<task_id>.yaml`, `ground_truth_extra.yaml` |
| `results/ai-runs/run-NNN/` | One directory per model run; `groups/group-NNN.yaml` per `--repeats` batch |
| `results/acceptance/` | Saved command output for the acceptance checklist |
| `tests/` | Boundary negative tests and pipeline/scoring tests (no API calls) |

## Setup (once per machine)

```sh
# 1. Python environment (versions pinned in requirements.txt)
python -m venv stage2/.venv
stage2/.venv/Scripts/python -m pip install -r stage2/requirements.txt   # Windows
# stage2/.venv/bin/python -m pip install -r stage2/requirements.txt     # Linux/macOS

# 2. Key and model: ONE file, at the repository root
cp stage2/.env.example .env      # then fill in OPENROUTER_API_KEY and OPENROUTER_MODEL
```

The driver reads **only `<repo-root>/.env`**. It ignores process environment
variables and any `stage2/.env`, so two machines cannot silently disagree about
which key or model is active. `.env` is gitignored; never commit it. If the key
is missing, the driver stops with an error before doing anything else.

`OPENROUTER_MODEL` must be a model OpenRouter still serves. Retired aliases
return HTTP 404, and the run is recorded with `status: api_error`. Check the
catalog at <https://openrouter.ai/models>.

```sh
# 3. Vendored source: already committed. Re-run only to add or refresh a task's files.
stage2/.venv/Scripts/python stage2/scripts/fetch_source.py --task shakedown-proxy-address
```

`fetch_source.py` downloads each allow-listed path on its own from
`https://raw.githubusercontent.com/<repo>/<40-char commit>/<path>`. It does
not clone. It records each file's SHA-256 in `vendor/MANIFEST.txt`. For
fixture tasks it only hashes the local files. **A human runs it by hand. The
driver never calls it**, and the driver's only network traffic is the
OpenRouter call. `stage2/.gitattributes` turns off line-ending conversion
for `vendor/` and `tasks/fixtures/`, so hashes match on every OS.

## Running a task

```sh
PY=stage2/.venv/Scripts/python          # or stage2/.venv/bin/python

$PY stage2/driver/run_task.py demo-pattern --dry-run          # print the exact prompt; no API call, no key needed
$PY stage2/driver/run_task.py demo-pattern                    # one real run
$PY stage2/driver/run_task.py demo-pattern --model openai/gpt-4o-mini
$PY stage2/driver/run_task.py shakedown-proxy-address --repeats 3

# Evaluator step: a separate process, run after the model call
$PY stage2/scoring/score_run.py --task demo-pattern --run stage2/results/ai-runs/run-002
```

The model is chosen from, in order: `--model`, then `OPENROUTER_MODEL` in the
root `.env`, then the task's `model.default`. Sampling parameters come from
the task file. `temperature` is required, and `max_tokens` is optional.

### What a run directory contains

| File | Written by | Contents |
| --- | --- | --- |
| `run.yaml` | driver | Run metadata (see below) |
| `prompt.txt` | driver | Exact first prompt sent |
| `transcript.json` | driver | Every attempt: messages sent, raw reply, resolved model, provider, usage, validation errors |
| `candidates.json` | driver | Schema-valid candidate records (machine-readable) |
| `findings.md` | driver | The same records in the Stage 1 `findings.md` YAML-block format |
| `notes.md` | driver | Stage 1 notes template, plus the task's withheld-information notice |
| `commands.log` | driver | JSON lines, one per model call (Procedure §7.2 trace shape) |
| `raw_output.txt` | driver | Only for `malformed_output` / `api_error`: everything the model returned |
| `verdict.md` | driver placeholder (`pending`), then `score_run.py` | Evaluator verdict |
| `verdict.yaml` | `score_run.py` | Machine-readable verdict |

`run.yaml` records the task and `prompt_id` (`<task_id>@v<prompt_version>`).
It records **`model_requested`** together with **`model_resolved`**, the
model OpenRouter reports actually served each call, so you can tell when
an alias moves to a new snapshot. It also records the provider, response ids,
the exact `sampling` parameters, attempts, per-attempt `usage` exactly as
OpenRouter returned it, a summed `usage_total` (prompt, completion, total and
reasoning tokens, and `cost_usd`), the SHA-256 and line
range of every context file, the target commit, the `.env` path used, and
the driver's git commit.

### Cost tracking

OpenRouter reports cost inline in each response (`usage.cost`, in USD
credits), so no follow-up query is needed. Every run, including failed
ones, appends one row to **`stage2/results/cost_log.csv`**. Each row records:

- `timestamp_utc`, `run_id`, `task_id`, `status`
- `model_requested`, `model_resolved`, `attempts`
- `prompt_tokens`, `completion_tokens`, `total_tokens`, `cost_usd`

Sum the `cost_usd` column to see cumulative spend. Nothing warns or blocks
on a threshold. Use `--cost-log PATH` to write somewhere else. If a provider
reports no cost, `cost_usd` is left blank.

### Output rules

- `viewpoint` is always `ai-source-review`.
- The driver always writes `status: candidate` and `oracle_verdict: pending`. Only
  `score_run.py` produces a verdict, and it writes it to a **new** file
  (`verdict.md` / `verdict.yaml`). It never edits `candidates.json` or `findings.md`.
- The model fills only the analytic fields. The driver fills `candidate_id`,
  `viewpoint`, `property`, `status`, `oracle_verdict`, `model`, `prompt_id`,
  `run_index`, `input_artifact` and `observed_behavior`. The last two are
  `not_available` for static review (Procedure §7.2). These fields are listed
  under `x-driver-owned` in the schema, and a model answer that tries to set
  them fails validation.
- If the reply does not validate (bad JSON, missing field, a `vulnerability_class`
  outside the task's `valid_classes`, and so on), the driver retries **once** and
  appends the validation errors to the conversation. If the retry also fails,
  the run gets `status: malformed_output` and the raw output is saved. The
  driver never guesses an answer.

### `--repeats` and why

Model output varies from run to run, even at `temperature: 0.0`. In this
repo's own AC-06 run, three identical calls returned 2, 1 and 2 candidates.
SOW §2.3 requires recording that variation. `--repeats N` makes N independent
calls, each logged in its own `run-NNN` with its `run_index`, and writes
`results/ai-runs/groups/group-NNN.yaml`. That summary covers:

- how many runs were schema-valid
- whether the top candidate (highest confidence) was the same in every run
- the distinct top-candidate lines
- which candidates appeared in every run

## Adding a new task

1. Copy `tasks/TEMPLATE.yaml` to `tasks/<task_id>.yaml` and fill it in. Required parts:
   - the allow-list: `context.source_root` and `context.files`
   - `withheld_notice`
   - `valid_classes`
   - a `prompt_template` containing `{context_block}` and `{response_schema}`
   - `model.temperature`

   Bump `prompt_version` whenever the prompt or context changes.
2. Put the source files in place:
   - Upstream code: set `source_root: vendor` and `context.upstream` (repository plus the full 40-character commit), then run `scripts/fetch_source.py --task <task_id>`.
   - Synthetic code: put it in `tasks/fixtures/` and run the same script, which hashes it.
3. Copy `scoring/ground_truth/demo-pattern.yaml` to `scoring/ground_truth/<task_id>.yaml`. Fill in `expected` (file, function, lines, line_tolerance, vulnerability_class). If the ground truth relies on other evaluator files, list them under `references` with `consistency` pairs. `score_run.py` records their hashes and fails if they disagree.
4. Check the prompt with `--dry-run` before spending tokens.

You should never need to edit `run_task.py` or `score_run.py` to add a task.
If you think you do, the task needs a field the pattern lacks: change the pattern, not the one-off task.

**Extension point.** `mode: source-review` is the only mode implemented.
A future `fuzzing-assist` mode would drive the live Docker target through
`tools/coap_client.py`, which is a different shape of task. Adding it means a
new mode branch in `run_task.py` (`SUPPORTED_MODES`), not changes to existing tasks.

## Information boundary (hard rule)

This is the Stage 2 counterpart of the Stage 1 black-box/white-box container isolation. It is enforced in code, not by instructions in the prompt:

- `driver/context_loader.py` is the only code that reads context. It accepts a `source_root` only from `vendor` and `tasks/fixtures`. It resolves every allow-listed path, following symlinks and `..`, and refuses any path that leaves that root or lands under `evaluator/` or `stage2/scoring/`.
- Before building a prompt, it checks every file's live SHA-256 against `MANIFEST.txt`. If any entry is invalid, it reads nothing at all. The CLI exits before it creates a client or a run directory.
- `driver/` never imports `scoring/` or `scripts/`, and it uses no HTTP library other than the OpenRouter SDK.
- Only `scoring/score_run.py` reads evaluator material, and it runs as a separate process after the model call.

Run the negative tests (AC-02). They include deliberately edited task files that point at `evaluator/` by absolute path, by `../` traversal, through a symlink, and through `source_root`. An audit hook records every file actually opened:

```sh
stage2/.venv/Scripts/python -m unittest discover -s stage2/tests -v
```

**The test suite never calls OpenRouter.** It is fully mocked: `test_pipeline.py`
injects a fake client, and `test_boundary.py` uses `--dry-run` or fails
before any client exists. It needs no key, spends no tokens, and writes
nothing to the real `results/` or `cost_log.csv`. The only commands that
cost money are `run_task.py` without `--dry-run`.

## Caveats

- **The shakedown task is a pipeline check against a bug the team already knows**, and that bug is publicly documented. A correct answer shows that the pipeline reaches and scores a known true positive. It is **not** a contamination-free discovery result and must not be reported as one.
- Scoring matches location and class only (file, function, line within a tolerance, `vulnerability_class`). Two different claims about the same statement score the same way. For example, a source over-read and a destination overflow, both on the demo's `memcpy` line, would both pass. Read `verdict.md` together with the hypotheses.
- `false_positive` means "does not match this task's ground truth". A rejected candidate may still be a real, different defect. The original record is kept unchanged.

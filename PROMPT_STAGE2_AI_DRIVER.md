# Task: Implement the Stage 2 AI-Assisted Review Driver (pattern + shakedown)

## Context

This repository (`AIOT`) currently contains the **Stage 1** traditional
vulnerability-investigation lab for a frozen `libcoap` CoAP/UDP target —
Docker-isolated black-box and white-box analyst workspaces, a harness
(`tools/coap_client.py`), and an evaluator-side oracle under `evaluator/`.
Read `README.md`, `TRADITIONAL_VULNERABILITY_INVESTIGATION_PROCEDURE.md`,
and `docs/IMPLEMENTATION_REPORT.md` first if you have not already — this
new work must follow the same conventions, not invent parallel ones.

We are now starting **Stage 2: AI-assisted vulnerability discovery case
studies**. Per the project's SOW (`AIoT_SOW_Stages_Revised.pdf`, §2.1),
Stage 2 must **not be autonomous**: a human defines the scope and context
for each run, the AI reasons only within it, and a human/evaluator checks
the output. This is a hard requirement, not a style preference — it is
what distinguishes this stage's work from Stage 3's agentic stage.

Concretely, we are building a small, reusable **driver**: a script that
takes a human-authored task definition (what the model may see, what it's
asked to judge, in what shape), calls an LLM via **OpenRouter**, and logs
the result in the same shape the existing Stage 1 tooling already uses, so
AI runs and human runs are directly comparable later.

## Decisions already made (do not redesign these — ask if one seems wrong)

- **Provider: OpenRouter**, using its OpenAI-compatible `/chat/completions`
  endpoint (`base_url=https://openrouter.ai/api/v1`). Model is a plain
  string (e.g. `anthropic/claude-3.5-haiku`, `openai/gpt-4o-mini`), never
  hardcoded — every teammate should be able to drop in their own
  `OPENROUTER_API_KEY` and model string and run the same code unmodified.
- **The information boundary is enforced in code**, the same way Stage 1
  enforces black-box/white-box through actual container isolation rather
  than prompt instructions. A task file's allow-list is the *only* thing
  that may decide what the model sees. This is the single most important
  constraint in this task — see "Hard rule" below.
- **Reuse the existing logging/candidate-record shape** (`tools/new_run.py`'s
  `findings.md` template and `run.yaml` shape), extended with a few
  AI-specific fields, rather than inventing a new schema from scratch.
- **Sequencing:** build a generic, config-driven **pattern** first, prove it
  on a **synthetic demo task** (not the real target — keeps the pipeline
  shakedown cheap and free of any contamination concerns), then instantiate
  the exact same pattern as a **shakedown task** against the real,
  already-known bug area. The shakedown task is a pipeline/correctness
  check against known ground truth, not a blind-discovery result — say so
  explicitly in any output/report this produces.
- **Out of scope for this task:** fuzzing-assist (a different shape — it
  drives the live Docker target through `coap_client.py`, not a static
  source review) and anything resembling Stage 3 autonomy (the driver must
  never choose its own task, target, or scope). Leave an obvious extension
  point for fuzzing-assist later; do not build it now.

## Hard rule: information boundary

The driver's runtime code must **never read anything under `evaluator/`**,
and must never read any file not explicitly named in the active task's
allow-list. This is not optional and must be independently testable, the
same way `tools/access_control_tests.sh` proves black-box isolation in
Stage 1 — write an equivalent negative test here (see Acceptance
Checklist). Only the separate, later `scoring/` step may read
`evaluator/` material, and it must run as a distinct process/step from the
model call — never merge context-loading and scoring into the same code
path.

## What's already known (give this to the scoring step, not the model)

The repo's committed `evaluator/ground_truth.yaml` has the core facts
right (CVE-2025-34468, CWE-121, vulnerable commit `7cf7465b78...`, fix
commit `30db3eaa1f...`) but is **missing the exact location** and has a
**stale config value**. Do not edit `evaluator/ground_truth.yaml` directly
— that file is owned by the evaluator role. Instead, create
`stage2/scoring/ground_truth_extra.yaml` as a clearly-labeled supplement:

```yaml
# Supplement to evaluator/ground_truth.yaml. Evaluator-side only.
# Proposed for merge — see note on the stale required_target_config below.
file: src/coap_address.c
function: coap_resolve_address_info
vulnerable_lines: [536, 538]
vulnerable_line_detail: >
  memcpy(addrstr, address->s, address->length) at line 538 copies an
  attacker-controlled length into a fixed 256-byte static buffer
  (`static char addrstr[256]` at line 498) with no bounds check. Contrast
  with the AF_UNIX branch earlier in the same function, which does check
  address->length before use.
known_discrepancy: >
  evaluator/ground_truth.yaml states required_target_config as
  "coap-server started with -P,". Team testing (Oct 2026) found this
  config handles all proxy requests locally and never reaches the
  vulnerable path — a forwarding config (e.g. "-P ,proxy") is required.
  This file does not overwrite ground_truth.yaml; flag this discrepancy
  in your final report so a teammate can apply the correction.
```

## Directory layout

Build everything under a new `stage2/` top-level directory. Do not modify
any existing Stage 1 file (`compose.yaml`, `docker/`, `tools/`, `config/`,
`docs/`, `evaluator/`, `results/blackbox`, `results/whitebox`) except to
read them for context.

```
stage2/
  README.md                        — explains the pattern; how to add a new task
  .env.example                     — OPENROUTER_API_KEY=, OPENROUTER_MODEL= (placeholders only)
  requirements.txt                 — e.g. openai, pyyaml, jsonschema
  tasks/
    TEMPLATE.yaml                  — heavily commented skeleton; the reusable pattern
    demo-pattern.yaml              — synthetic task, see below
    shakedown-proxy-address.yaml   — real task, scoped to coap_resolve_address_info
  schema/
    candidate_record.schema.json   — JSON Schema for the forced output shape (below)
  driver/
    __init__.py
    context_loader.py              — reads ONLY what a task's allow-list names; hard-fails on anything else; never touches evaluator/
    openrouter_client.py           — thin OpenAI-compatible client; base_url/key/model from env/config only, never literals
    run_task.py                    — CLI entry point: loads task yaml, assembles prompt, calls model, validates/repairs JSON output, writes the run directory
  scoring/
    ground_truth_extra.yaml        — as specified above
    score_run.py                   — evaluator-side only; never imported by driver/
  results/
    ai-runs/
      run-NNN/                     — created per invocation, same spirit as results/<viewpoint>/run-NNN
```

## Task file format (`tasks/TEMPLATE.yaml`)

```yaml
task_id: demo-pattern                 # unique slug
property: memory-safety               # from the Procedure's §4.2 checklist vocabulary
description: >
  One sentence on what this task asks the model to do.

# The allow-list. context_loader.py must refuse anything not listed here.
context:
  files:
    - path: path/relative/to/repo/or/stage2/fixtures/...
      line_range: [start, end]        # optional; omit for whole file
  withheld_notice: >
    Explicit note to log (not shown to the model) listing what's
    deliberately withheld, e.g. "CVE identifier, fix commit, function name
    hint beyond what's in the shown file."

prompt_template: |
  You are reviewing C source for memory-safety issues. You are shown
  exactly the code below and nothing else about this project.
  {context_block}
  Respond ONLY with JSON matching the required schema.

output_schema: ../schema/candidate_record.schema.json

model:
  default: anthropic/claude-3.5-haiku  # cheap tier; overridable via --model
  repeats: 1                           # overridable via --repeats
```

## Output schema (`schema/candidate_record.schema.json`)

Base fields are the **existing** fields from `tools/new_run.py`'s
`findings.md` candidate template — reuse these names exactly so AI and
human candidate records are directly comparable:
`candidate_id, viewpoint, property, hypothesis, evidence_source,
input_artifact, expected_behavior, observed_behavior, status,
oracle_verdict, notes`.

Add these AI-run-specific fields:

```json
{
  "location": {"file": "string", "function": "string", "line": "integer"},
  "confidence": "number, 0.0-1.0",
  "model": "string, e.g. anthropic/claude-3.5-haiku",
  "prompt_id": "string, e.g. shakedown-proxy-address@v1",
  "run_index": "integer, which repeat this is"
}
```

Rules:
- `viewpoint` for AI runs should read `ai-source-review` (distinct from
  `black-box`/`white-box`, matching the viewpoint-flag style already used
  in `config/protocol.yaml`).
- The driver **always** writes `status: candidate` and
  `oracle_verdict: pending`. Only `scoring/score_run.py` may change those
  — and it must do so in a **new** file (e.g. `verdict.md` alongside the
  run), never by mutating the original candidate record in place. This
  mirrors the Procedure's "preserve unmodified original evidence" rule.
- If the model's raw output doesn't validate against the schema, retry
  once with the validation error appended to the prompt; if it still
  fails, log the raw output and mark the run `status: malformed_output`
  rather than silently dropping it or inventing a verdict yourself.

## Demo-pattern task content (`tasks/demo-pattern.yaml` + its fixture)

Use this exact synthetic snippet (not real libcoap code — keeps the
pipeline shakedown free of any contamination concerns and gives you a
trivially-checkable expected answer). Put it at
`stage2/tasks/fixtures/demo_snippet.c`:

```c
void handle_header(const char *field, size_t field_len) {
    char buf[64];
    memcpy(buf, field, field_len); /* no bound check against sizeof(buf) */
    process(buf);
}
```

Expected model verdict: true positive, unbounded `memcpy` into a 64-byte
stack buffer. Use this to prove the full pipeline — config load, context
loader honoring the allow-list, API call, schema validation/repair, run
directory written, scoring script correctly marking it `validated` — before
spending any real effort or tokens on the real target.

## Shakedown task (`tasks/shakedown-proxy-address.yaml`)

Scope the allow-list to `src/coap_address.c`, the whole file (the model
should find the relevant function itself — that's closer to how a
white-box analyst would actually encounter it). Explicitly state in
`withheld_notice`: no CVE identifier, no fix commit, no hint about which
function or line is relevant. Property: `memory-safety`. Ask the model to
identify any attacker-reachable buffer/length issues in the file.

Note for your final report: because the team already knows this bug
(Stage 1's Phase 0 reproduction), this run validates that the pipeline
correctly reaches and scores a known-true-positive — it is **not** a
contamination-free discovery result, and should not be reported as one.

## Step 1 — Build the generic driver and context loader

Implement `context_loader.py` and `openrouter_client.py` first, with the
negative-access test (below) passing, before wiring up `run_task.py`.

## Step 2 — Run the demo-pattern task end to end

Get a real OpenRouter API call working against the synthetic snippet.
Confirm schema-valid output, correct run-directory shape.

## Step 3 — Run the shakedown task

Same driver, new task file, real target source. No code changes should be
needed — if you find yourself editing `run_task.py` to make this task
work, something in the pattern design was wrong; fix the pattern, not the
one-off task.

## Step 4 — Build `scoring/score_run.py`

Reads a run's candidate record(s) plus `evaluator/ground_truth.yaml` and
`scoring/ground_truth_extra.yaml`, writes `verdict.md` into the run
directory. Test it against both the demo-pattern run (self-evident
ground truth, define inline) and the shakedown run.

## Step 5 — `stage2/README.md`

Explain: how to set up `.env`, how to run a task, how to add a new task
(point at `TEMPLATE.yaml`), what `--repeats` does and why (model output
varies run to run — SOW §2.3 requires this be recorded), and the
information-boundary rule from this prompt.

## Step 6 — Self-validation (Acceptance Checklist)

Run each of these for real, save the command and output, mark
PASS/FAIL/BLOCKED — do not mark something PASS because the code exists.

- **AC-01:** Demo-pattern task runs end to end against a real OpenRouter
  call, produces a schema-valid candidate record.
- **AC-02:** Negative test proves `context_loader.py` cannot read any file
  outside a task's declared allow-list, and cannot read anything under
  `evaluator/` even if a task file is edited to try to point there
  (test this deliberately).
- **AC-03:** The same demo-pattern task run against two different model
  strings via only a CLI flag / env change, zero code edits.
- **AC-04:** Shakedown task runs end to end against the real target file.
- **AC-05:** `score_run.py` correctly marks a deliberately-wrong synthetic
  candidate record as a false positive, and the demo-pattern's correct
  one as validated.
- **AC-06:** `--repeats 3` produces three separately-logged runs with a
  simple agreement/variance summary (e.g. did all three land on the same
  line).
- **AC-07:** No API key appears anywhere in committed files; `.env` is
  gitignored; `.env.example` has placeholders only.

## Step 7 — Final report

Give: directory tree actually created, exact commands to run both tasks,
the Acceptance Checklist results, the shakedown task's actual model
output and whether it matched `ground_truth_extra.yaml`, and the
`-P,`/forwarding discrepancy noted clearly as something for the team to
reconcile in `evaluator/ground_truth.yaml` and `config/target.lock`.

## Working instructions

Give a short implementation plan before writing files. Work autonomously
on ordinary, reversible code within `stage2/`. Ask before touching
anything outside `stage2/`, before any action that would send data
externally beyond the OpenRouter API call itself, and before assuming an
API key is already set — check for `.env` / the environment variable and
stop with a clear message if it's missing rather than inventing a
placeholder key.
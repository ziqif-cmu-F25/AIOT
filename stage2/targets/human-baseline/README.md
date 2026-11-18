# Human baseline — you must run this yourself (issue G1)

This kit measures how a **human analyst with no AI assistance** does on the same
de-hinted source-review task the models were given, so the AI results have a
human reference point. **An agent may not perform this run** (contract §5) — that
is exactly why the old `mongoose/artifacts/_noncompliant/01-traditional-agent-performed/`
run does not count. These files are forms and instructions only; filling them
with any AI output invalidates the baseline.

## Who
One or more human analysts. Record each analyst's identifier (initials are fine)
and their security-experience level. If you do it yourself, note that you have
prior knowledge of this project — declare it under "contamination" on the form;
an analyst with no prior exposure to these targets is the stronger baseline.

## Rules (the measured run)
- **No AI** of any kind: no chat assistants, no AI autocomplete used as analysis,
  no reading any model output in `results/` or `_adjudication/`.
- **No web search**, no CVE write-ups, no changelogs, no issue trackers.
- **No ground truth**: do not open `*/artifacts/evaluator/`, `target.yaml`,
  `RUBRICS.md`, or `GROUND_TRUTH_*`. They contain the answer.
- **Time box: 45 minutes per target** for investigation (start a timer; record
  start/stop on the form). Stop at 45 min even with nothing found — negative
  results are valid data.
- Work only from the source files named in each `task_<target>.md`, at the pinned
  commit. The files are in `stage2/vendor/<target>/` (already checked out at the
  right revision; see `stage2/vendor/MANIFEST.txt`).

## What you produce
For each target, fill `response_form.md` (copy it to
`response_<target>_<your-initials>.md`): a ranked list of **up to 3** candidate
memory-safety findings (same k=3 as the models), each with file / function /
line / class / a one-line hypothesis / the evidence line, plus your wall-clock
time and any contamination notes.

## How it gets scored
Hand the filled forms back (tell Claude "human baseline done, score it"). They
are adjudicated with the **same blind rubric** (`RUBRICS.md`) as the models and
written into `targets/verdicts.csv` as rows with `model = human:<initials>`,
`viewpoint = traditional`, `condition = human-baseline`. They then appear in the
`scoring.py` tables and the report alongside the AI cells — a true like-for-like
comparison (same pinned source, same de-hinted task, same k, same rubric).

## Targets (one task sheet each)
- `task_libmodbus.md`  — CVE family: industrial Modbus server reply path
- `task_libcoap.md`    — CoAP proxy / address resolution path
- `task_mongoose.md`   — HTTP chunked-transfer parser

Do them in any order. Take a real break between targets so fatigue doesn't bias
later ones.

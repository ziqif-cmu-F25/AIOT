# Stage 2 Methodology Contract

Status: DRAFT — for review before any rerun work begins.

## Why this document exists

Three Stage 2 case studies now exist in this repo (`targets/libmodbus`,
`targets/libcoap`, `targets/mongoose`), produced independently by three people
before any shared format was agreed. They are not currently comparable: each
uses a different condition vocabulary, a different logging shape, and (in one
case) an unnamed model. This document fixes that, grounded directly in the
SOW's Stage 2 section (`AIoT_SOW_Stages_Revised.pdf`, "Stage 2 — Case Studies
of AI-Assisted Vulnerability Discovery") so compliance can be checked against
specific SOW clauses rather than an invented standard.

Nothing here is retroactively true of existing results. The next step after
this document is agreed is to **audit** each existing result against it, and
rerun only what fails.

## 1. Condition taxonomy

Every run belongs to exactly one condition. This replaces each contributor's
ad hoc labels (Chen's C0/C1/C2, Mongoose's traditional/AI-assisted, our own
source-review/fuzzing split) with one shared vocabulary.

| Condition | Definition | Human role | Existing examples |
|---|---|---|---|
| `source-one-shot` | Model is shown fixed source file(s) in a single turn and asked to localize defects. No tool use, no iteration. | Relays prompt, records output | libmodbus source-review; Chen's C0 |
| `source-agentic` | Model is given a file tree / search+read tools and must navigate on its own across multiple turns to find the defect. | Relays raw tool output only ("here is the output"), no hints | Chen's C1 |
| `crash-given` | Model is given a crash/sanitizer report directly and asked for root cause + patch. | Relays the report | Chen's C2; libmodbus fuzz-interpret |
| `fuzz-seed-gen` | Model generates fuzzing seeds/harness from protocol description alone, seeds then run against the real target. | Runs the fuzzer, reports crash/no-crash | libmodbus fuzz-seed-gen |
| `traditional` | No model involved. Human analyst only, following the Stage 1 workflow steps. | — | Mongoose traditional (currently non-compliant — see §5); Stage 1 baseline; libmodbus Track A |
| `triage-hypothesis` | Model is shown a code excerpt (not necessarily the whole file) and proposes a vulnerability hypothesis. One turn, no tool use. | Relays excerpt, records hypothesis | Mongoose "AI-assisted" step 1 (`full_investigation_candidates.json`) |
| `input-drafting` | Given a hypothesis (from `triage-hypothesis` or elsewhere), model proposes one concrete test input/payload to exercise it. Distinct from `fuzz-seed-gen`: one hand-picked targeted input, not a seed corpus for a mutation fuzzer. | Reviews/edits the drafted input before sending; sends it; oracle validates | Mongoose "AI-assisted" step 2 (draft HTTP bodies) |

`triage-hypothesis` and `input-drafting` are usually chained (hypothesis →
drafted input → human review/send → oracle), but are logged and reported as
two separate conditions, not one combined "AI-assisted" label — this keeps
each one comparable to the single-step conditions above it (e.g.
`triage-hypothesis` is directly comparable to `source-one-shot` on a smaller
excerpt) and avoids colliding with the SOW's own general term for
"Stage 2 with a human checking every output," which otherwise describes
nearly every non-agentic condition in this table.

A run that doesn't cleanly fit one of these needs a new row added here before
it's recorded — not a one-off exception.

## 2. Required fields per run (the logging contract)

Every run must log, regardless of condition:

- **Model name and version** — a specific, nameable model (e.g.
  `openai/gpt-5.6-sol` via OpenRouter). "Whatever model the coding assistant
  happened to be running" does not satisfy this field. (SOW 2.3: "model and
  version... because model output varies between runs.")
- **Prompt text and context supplied** — the exact prompt, and exactly which
  files/excerpts were shown. This is also the information boundary and must
  state explicitly what was withheld (CVE ID, CWE, function name, fix commit,
  etc.), per SOW 2.3 and the Stage 1 information-boundary clause it inherits.
- **Repeats** — how many times this exact run was repeated, because model
  output varies between runs (SOW 2.3).
- **Cost** — token counts and USD cost per run, logged to a `cost_log.csv` in
  the shape `driver/run_task.py` already writes (`COST_LOG_FIELDS`). A run
  with no cost log and no stated reason ("no API call was made because...")
  does not satisfy this field.
- **Human intervention** — count and type of manual edits/relays/hints,
  per condition (zero is a valid answer for `source-one-shot`; not for
  `ai-assisted-human-loop`).
- **Failure mode**, if applicable — one of: refusal, fixation, hallucinated
  reference, tool/environment failure, or none.
- **Trajectory**, for multi-turn conditions (`source-agentic`,
  `ai-assisted-human-loop`) — the turn-by-turn record, not just an end
  summary. A scored summary row (e.g. "fixated on proxy code, missed target")
  is not a substitute for the actual turns; it's a conclusion drawn from them.

## 3. Candidate record schema

`schema/candidate_record.schema.json` is the shared output shape. It already
covers `source-one-shot`-style results (and is close to what Mongoose's
AI-assisted output already looks like). To cover the other conditions, the
`viewpoint` field needs new allowed values matching §1's taxonomy
(`ai-source-review` is currently the only one defined) — this should be done
as part of drafting, not improvised per-target.

## 4. Oracle

Oracle is already consistent across all three targets without any change
needed: differential AddressSanitizer (same input → crash on the vulnerable
revision, clean on the fixed revision). `status: validated` means the oracle
fired; `status: candidate` means it didn't (or wasn't tested).

## 5. What this means for each existing target (audit, not yet executed)

| Target / condition | Compliant? | Why / what's missing |
|---|---|---|
| libmodbus, all conditions | Yes | Native to `driver/run_task.py`; every field already logged |
| libcoap C0 | Yes (as of our rerun) | Independently rerun with named model, logged cost; Chen's original C0 rows lack a cost log but are superseded by our rerun |
| libcoap C1 | No | No trajectory (only end-summary notes), no cost log |
| libcoap C2 | No | No trajectory, no cost log |
| libcoap local-7B | No | No trajectory, no cost log; also a different harness (Ollama) not yet reconciled with this contract |
| libmodbus Track A (`traditional`) | Yes, but thin | Genuinely human-led, but one light worked run (`results/track-a/run-001`); worth deepening for a more substantial per-target baseline, not a compliance failure |
| libcoap `traditional` | Not applicable — already covered | Stage 1's shared lab *is* the traditional investigation of this exact CVE (`CVE-2025-34468`, same target/commit, confirmed in `evaluator/ground_truth.yaml`). No separate libcoap traditional run is needed |
| Mongoose `traditional` | **No — and this is the serious one** | Her own `INDEX.md` states it outright: "Agent-executed per user request; **not** a human no-AI baseline." The same Cursor agent ran both her "traditional" and "AI-assisted" conditions, so there is currently no genuine human baseline under either side of her comparison. This needs a real rerun, not just reformatting |
| Mongoose `triage-hypothesis` / `input-drafting` (formerly "AI-assisted") | No | Unnamed model ("cursor-composer... no root .env"), no prompt logged as sent, no cost. Fails the model-name requirement outright |

## 6. Next steps (not yet executed)

1. Agree this document.
2. Extend `candidate_record.schema.json`'s `viewpoint` enum per §1.
3. Convert compliant results (libmodbus, libcoap C0) into the shared schema —
   format conversion only, no rerun.
4. Rerun, under this contract, the non-compliant conditions:
   - libcoap C1/C2 (and local-7B once Ollama is set up);
   - Mongoose's `triage-hypothesis` / `input-drafting` conditions, with a
     named model via OpenRouter;
   - Mongoose's `traditional` condition, as a genuine human-only run — this
     one is higher priority than the others, since without it her case study
     currently has no real baseline on either side of the comparison.
5. Optionally deepen libmodbus's Track A traditional run for a more
   substantial baseline (not required for compliance, but requested as a
   quality improvement).
6. Only then: write the consolidated report, literature-summary template,
   and Stage 3 shortlist (SOW 3.2 deliverables).

## 7. Deferred: Stage 1 gap-filling for the additional targets

Decision (2026-11): deprioritized relative to the Stage 2 round-out above.
libmodbus and Mongoose are "additional targets" per SOW 2.1/2.3 — used for
practice/generalization, not the Stage 3 primary comparison, which uses the
Stage 1 *primary* target (libcoap) only. No gap exists there. Stage 3 also
starts from the Stage 2 shortlist, not from these baselines, so this work is
not on Stage 3's critical path. Plan: hand off to a separate session once
Stage 2 is rounded out.

**Resolved — contamination framing for the eventual redo:** both the user
and this session already know the specific bugs in question (read in depth
during this conversation for Mongoose; personally investigated firsthand for
libmodbus). A genuinely blind rerun is not possible. Decision: proceed
anyway, explicitly framed as a **simulation/recreation of the investigation
process**, not a blind-discovery claim — consistent with the SOW's own
framing ("the goal is not to discover new zero-day vulnerabilities but to
rediscover and validate known vulnerable behavior") and its analyst-carryover
clause. Consequence to carry into the writeup: any time/effort metric from
that redo (time to first candidate, investigation effort) must be caveated
inline, not just once in a limitations section, since carryover makes those
numbers artificially fast and not reflective of difficulty.

AI's role in that eventual redo: environment/tooling setup only (Docker,
build, running tools) — never hypothesis formation, input selection, or
result interpretation, which stays the human's, to keep the exercise
methodologically meaningful as a process simulation.

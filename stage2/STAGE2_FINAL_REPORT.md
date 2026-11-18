# AI-Assisted Vulnerability Discovery in IoT C Libraries

### How increasing levels of AI involvement change the discovery of known memory-safety bugs across three real CVEs — and how three independently-built case studies were unified into one consistent, auditable methodology.

*CMU AIoT graduate project · Stage 2 · 3 targets · 11 models · 6 conditions · compiled 2026-11-18.*

> **About this document.** A self-contained account of the whole Stage 2 effort,
> written to be read top-to-bottom with no prior context. It is the text companion
> to the rendered report `STAGE2_REPORT.html`, which carries the same content with
> embedded figures; the two are aligned section-for-section. Every quantitative
> claim traces to `targets/verdicts.csv`; every figure is produced by
> `targets/report/build_final_report.py`. Verdicts are a single-rater (blind) pass;
> no human second rater has reviewed them yet.

---

## Contents
1. The project, and where it started
2. The alignment standard (how consistency was enforced)
3. The two experimental passes
4. Results
5. Issues, how they were reproduced, and how they were corrected
6. Limitations
7. Conclusions
8. Reproducibility and file map

---

## 1. The project, and where it started

**The frame.** The Statement of Work defines three stages that share one target,
one information boundary, one environment and one oracle: **Stage 1**, a human-led
traditional baseline; **Stage 2**, human-guided AI assistance applied to that
baseline; **Stage 3**, a reduced, Naptime-inspired agent. The SOW is explicit on
two points that govern everything below: *a finding counts only when it passes a
shared oracle*, and the goal is to **rediscover and validate** known vulnerable
behaviour, not to discover zero-days. Stage 1's methodological legacy — inherited
here — is that **information boundaries must be enforced by infrastructure, not by
instructions in a prompt**.

**Stage 2's narrower question.** *Given a known, publicly disclosed CVE in a real C
library, can current models localise it — and how much does that depend on what the
model is shown and how it is asked?*

**Where it actually started: three experiments, not one.** Stage 2 did not begin as
a single designed study. It began as three case studies, built independently by
three people, before any shared format existed:

- **libcoap** (contributor "Chen") — conditions labelled **C0 / C1 / C2**, source
  supplied to the model as hand-assembled "pack" files.
- **libmodbus** (this author) — a **source-review / fuzzing** split, driven through
  a logging harness.
- **mongoose** (a third contributor) — a **traditional / AI-assisted** split, run
  through a coding assistant whose **model was never recorded**.

They shared a topic and nothing else: different condition vocabularies, logging
shapes, a different (or missing) model identity, different source revisions, and
three different ad-hoc scorers. **They were not comparable.** The entire purpose of
the work described here was to make the three comparable — to pull three fragmented
studies onto one methodology so the targets could finally be read side by side.
*That alignment is the spine of this report.*

*(Figure — the project arc: Stage 1 → three fragmented Stage 2 studies → a
methodology contract → an initial sweep → an audit → the corrected, aligned pass.)*

*(Figure — "before vs after": where the three case studies disagreed on each
dimension, and the single aligned standard each was pulled onto.)*

---

## 2. The alignment standard (how consistency was enforced)

A written **methodology contract** replaced the three ad-hoc designs with one,
grounded clause-by-clause in the SOW. The point was enforcement, not paperwork:
consistency is held by files and tests.

1. **One condition vocabulary.** Every run belongs to exactly one condition from a
   single table (below), replacing Chen's C0/C1/C2, the mongoose
   traditional/AI-assisted split, and the libmodbus source-review/fuzzing split.
2. **One record schema and one verdict store.** A concrete
   `schema/candidate_record.schema.json` and a single `targets/verdicts.csv`. Every
   run records its model id, prompt, **pinned commit**, what was **`disclosed`** and
   **`withheld`**, response status, and failure mode.
3. **One SHA-pinned source tree per target.** `vendor/MANIFEST.txt` pins every shown
   file to a `sha256` + upstream commit; each target's `target.yaml` is the single
   source of truth. `tests/test_revision.py` proves each condition loads the pinned,
   **vulnerable** revision — specifically that libmodbus binds `f9fe3b0a`, not the
   fixed `2cbafa31`.
4. **One information boundary.** De-hinted shared templates (`targets/templates/`)
   name no CVE, CWE, fix, mechanism or target function.
   `tests/test_leak_boundary.py` fails if a non-hinted prompt or a crash-given ASan
   artifact contains such a token. (A crash-given ASan *backtrace* legitimately
   names the crash site — that is what the condition discloses — so only editorial
   hints are banned.)
5. **One scoring method.** Blind adjudication against a written per-CVE rubric
   (`targets/RUBRICS.md`), stored as data with a rationale — never keyword matching.
   Input-drafting is scored **only** by a runtime oracle. Converters store the
   model's words verbatim and assign no verdict.
6. **One statistics convention.** The unit of analysis is the **run**; results are
   **any-of-k with k = 3** (and top-1); every cell gets a **Wilson 95 % interval**
   (plain-Python); non-comparable cells are never pooled.

### The condition ladder

| Condition | What the model is given | What it measures |
|---|---|---|
| `source-one-shot` (C0) | the whole source file(s), one turn | unaided localisation in a large file |
| `source-agentic` (C1) | a read-only file tree + READ/GREP/FINAL, ≤15 turns | whether it can navigate to the bug itself |
| `crash-given` | the ASan report **+** the source | root-cause from runtime evidence |
| `triage-hypothesis` | the function excerpt, one turn | recognition when the right code is selected |
| `triage-hinted` | excerpt **+** the stated mechanism (labelled) | the lift from an explicit hint |
| `input-drafting` | the bug, handed over; draft a trigger | turning knowledge into a working exploit (oracle only) |
| `recall-probe` | from memory: what CVEs do you know here? | training contamination |

### The three targets

The targets were chosen to vary how *visible* the bug is:

| Target | CVE (year) | Defect | Visibility |
|---|---|---|---|
| **libmodbus** v3.1.6 (`f9fe3b0a`) | CVE-2022-0367 (2022) | fn-0x17 guard tests `mapping_address < 0` twice, never `mapping_address_write < 0`; a negative write index reaches `tab_registers[i]` (sink `modbus.c:980`) | **subtle** — one duplicated token in ~1,900 lines |
| **libcoap** (`7cf7465b`) | CVE-2025-34468 (2025) | unchecked `memcpy` of an attacker Proxy-Uri host into a 256-byte static buffer (`coap_address.c:538`) | **obvious** once the function is on screen |
| **mongoose** 7.21 (`b1c2ffe1`) | CVE-2026-52056 (2026) | `skip_chunk` CRLF guard `len < i + 1` off by one before reading `buf[i+1]` (`http.c:1006`) | **off-by-one** in a short parser |

The CVE *years* — 2022, 2025, 2026 — turn out to matter more than visibility,
because of training contamination (§4.3).

---

## 3. The two experimental passes

### 3.1 Pass 1 — the initial sweep

The three studies were run out to 11 models (9 cloud via OpenRouter — Claude
haiku/sonnet/opus 5.5, GPT-5, GPT-5.6-sol, GPT-6.1-sol, Gemini 2.5 Pro, DeepSeek
v3.1, Grok 4.6 — plus two local 7B models via Ollama) across the condition ladder,
on all three targets, at temperature 0. That produced **279 candidate records**,
scored by an automated keyword matcher. The headline from this pass was a **"C1
agentic paradox"** (more tools and context made models *worse*) and **"libmodbus is
hard (19 %)."**

### 3.2 The audit — the fragmentation leaks into the results

A structured review re-derived every number and found the headline unsupported.
The three studies' inconsistencies had become result-level defects, one per target:

- **Wrong revision (libmodbus).** The agentic runs — and 56 early records — were
  served **v3.1.10**, where the bug is *already fixed*; in some records the task even
  targeted a *different* CVE.
- **Leaked answers (all targets).** Every triage/crash prompt stated the mechanism;
  mongoose's agentic file-tree annotated `skip_chunk`; libcoap's prompt steered at
  proxy code and exposed only 6 of 96 files.
- **A broken scorer.** Substring matching over *converter-written* text, so a
  refusal and several wrong hypotheses counted as "correct"; "19 %" also pooled the
  wrong-CVE records and counted per *candidate*. Re-scored per run on the right
  revision, libmodbus one-shot was ~69 %.
- **No statistics, no contamination check.** Single samples, no CIs, cross-target
  pooling, and no test of whether a 2022 CVE had simply been memorised.

### 3.3 Pass 2 — the aligned correction

Infrastructure was rebuilt to the contract (concrete schema; a fixed agentic
harness with regex+quote-stripped GREP, a turns-remaining warning and a forced
FINAL; explicit Ollama context; de-hinted shared templates; a raw-only converter;
the Wilson scorer; leak/harness/revision tests). Non-detecting data was quarantined
with a written reason; the agent-run "human" baseline was quarantined as
non-compliant. A fresh, **complete** sweep was run on the corrected setup — **every
one of the 11 models on every localisation condition and every target, with 3
repeats** — so there are no model-mix gaps. Both the old transcripts and the new
runs were re-scored by blind rubric into one `verdicts.csv`. Runnable oracles and
three tool baselines were added. The rest of this report is the result.

---

## 4. Results

### 4.1 Everything at once

*(Figure — heatmap: any-of-3 accuracy by model × condition × target, one panel per
target; cell = correct/scored, darker = higher.)*

Two things jump out of the heatmap, and the rest of this section unpacks them: the
**libmodbus panel is uniformly dark** (it is the memorised target — §4.3), and the
**agentic column is the palest** on the uncontaminated targets (navigating to a bug
unaided is the hard part — §4.4). The two local 7B models trail everywhere.

### 4.2 Corrected accuracy, with confidence intervals (all 11 models)

*(Figure — per-target bars with Wilson CIs.)*

| target | C1 agentic | C0 one-shot | crash-given | triage |
|---|---|---|---|---|
| **libmodbus**¹ | 65 % [45,81] · 15/23 | 74 % [55,87] · 20/27 | 82 % [66,91] · 27/33 | 73 % [56,85] · 24/33 |
| **libcoap** | **11 % [3,33]** · 2/18 | 63 % [44,78] · 17/27 | 81 % [64,91] · 25/31 | 90 % [74,97] · 27/30 |
| **mongoose** | 50 % [28,72] · 8/16 | 76 % [57,89] · 19/25 | 80 % [63,90] · 24/30 | 73 % [56,85] · 24/33 |

¹ contaminated (§4.3). Given the code or a crash report, capable models localise
the bug reliably: **crash-given and triage sit at 73–90 %** across all three
targets, and even whole-file review is **63–76 %**. The one condition that stays
hard is agentic navigation (§4.4). Cells are small; read the intervals.

### 4.3 The contamination control — the result that reframes the rest

*(Figure — contamination map: which models named the target CVE from memory.)*

| Target CVE | Year | Recalled from memory? |
|---|---|---|
| **libmodbus CVE-2022-0367** | 2022 | **Yes** — opus, sonnet, gpt-5.6, gpt-6.1 named it |
| libcoap CVE-2025-34468 | 2025 | No (stated cutoffs ≤ 2024-10) |
| mongoose CVE-2026-52056 | 2026 | No |

Several models also **hallucinated** plausible-looking CVE ids, a caution against
trusting recalled identifiers. **Consequence:** libmodbus's numbers are a
**memorisation-inflated upper bound**; the clean evidence of genuine capability
comes from **libcoap and mongoose**, whose CVEs post-date every model's cutoff. The
one target where models look strong across the whole row is the one they had read
about.

### 4.4 The ladder: the more the prompt points the way, the better

*(Figure — accuracy vs disclosure level, per target.)*

This replaces the first pass's "agentic paradox." There is **no paradox — just a
gradient**. On the uncontaminated targets, accuracy rises monotonically as the
prompt reveals more:

- **Agentic navigation (C1) is the hardest** — **libcoap 11 %** (only one model,
  GPT-5, navigated a 96-file tree to the `memcpy`), **mongoose 50 %** (down from the
  old annotated **83 %** once the file-tree hint naming `skip_chunk` is removed).
- **Whole-file review (one-shot) is easier** — 63–76 %. (Notably, the old "libcoap
  one-shot 0 %" was a *weak-model* artifact; with the strong models now in the cell
  it is 63 %. Strong models do find the bug in the haystack — the haystack mostly
  defeats the weak ones.)
- **Handing the model the excerpt or a crash report is easiest** — 73–90 %.

The old "C1 is worse than C0" was an artifact of a hint (mongoose), a wrong revision
(libmodbus) and content-filtering — not a deep inversion of capability.

### 4.5 Verdict distribution — where content moderation bites

*(Figure — stacked outcomes per condition.)*

A chunk of the low agentic numbers is not reasoning failure but **0-byte provider
moderation** of the "find a vulnerability and navigate the code" framing — now
recorded as `filtered` and excluded from denominators, not counted as misses. The
filtering concentrates on the **agentic** condition and on **input-drafting**, and
hits GPT-5, Gemini and the GPT-sol models hardest; triage is barely filtered.

### 4.6 Per-model strength

*(Figure — per-model correct rate, pooled over targets and conditions.)*

Indicative only (hint-weighted, pooled). The cloud frontier models cluster high;
**the two local 7B models (deepseek-coder:6.7b, qwen2.5-coder:7b) trail badly** —
they mostly summarise the code or emit unparseable output and never navigate the
agentic store.

### 4.7 Handing over the bug is not enough (input-drafting, oracle-scored)

In input-drafting the vulnerability is given and the model only has to produce a
trigger frame. Scored by **replaying each frame through a live AddressSanitizer
server**, **9 of 33 libmodbus frames actually fired the bug** (confirmed at
`modbus.c:980`). The rest failed instructively — models **refused on moderation**
("a ready-to-send exploit for industrial software") or produced **malformed Modbus
framing** (the 7B locals especially). Capability here is gated by safety behaviour
and protocol-encoding precision as much as by understanding. *(Only libmodbus has a
runnable oracle so far; libcoap and mongoose input-drafting remain to be scored.)*

### 4.8 Tool baselines — the real yardstick

**Static analysis (cppcheck, on the pinned files).**

| target | flagged the target line? | note |
|---|---|---|
| **libmodbus** | **Yes** | `duplicateExpression` + `knownConditionTrueFalse` at lines 963–964 |
| libcoap | No | missing-bound is semantic, not a lint pattern |
| mongoose | No | off-by-one is semantic |

The linter catches exactly the one **classic-pattern** bug — a duplicated condition
— and misses both semantic bugs. Tellingly, the one it catches is also the
**contaminated** target.

**Fuzzing (5 trials/arm, equal budget, ASan target).**

| arm | crash rate | iterations-to-crash | median |
|---|---|---|---|
| naive seeds | 5/5 | 149, 180, 226, 250, 959 | 226 iters |
| AI-drafted seeds | 5/5 | 7, 17, 38, 47, 105 | **38 iters** |

AI seeding reaches the crash **~6× faster**. This **reverses** the first pass's
single-trial claim that AI seeds "found nothing." Honest caveat: the AI corpus
contains oracle-confirmed triggers, so part of the speedup is "a seed near the crash
needs little mutation"; the naive arm still finds it (median 226), so the bug is
shallow for a field-aware mutator either way.

### 4.9 Old vs corrected — what the first pass got wrong, and why

*(Figure — audit claim vs re-adjudicated vs corrected sweep.)*

| cell | first-pass claim | re-adjudicated (same runs) | corrected sweep (all models) |
|---|---|---|---|
| libmodbus C0 | 19 % | 69 % | 74 % |
| libmodbus crash | 100 % | 82 % | 82 % |
| mongoose crash | 89 % | 80 % | 80 % |
| mongoose C1 | 83 % | 83 % | **50 %** |

The 19 %→69 % and 100 %→82 % corrections come from **re-scoring the same old
transcripts** with a correct rubric; the §4.2 table is **fresh runs** on the aligned
setup. Both are kept so "before" and "after" are separable.

---

## 5. Issues, how they were reproduced, and how they were corrected

The alignment was not cosmetic — each defect changed a result, was reproduced
against the data, and was fixed with an enforcing artifact. (Full ledger:
`CORRECTIONS_LOG.md`.)

| Issue | How it was reproduced / verified | How it was corrected |
|---|---|---|
| **Wrong revision** — libmodbus agentic served fixed v3.1.10 | the runner built its store from a tree whose `modbus.c` already has the write-index check; the bug cannot be present | SHA-pinned `target.yaml` + `test_revision.py` proving the vulnerable commit loads; invalid runs quarantined under `_invalid/` |
| **Leaked answers** — prompts named the mechanism/function | grepped every prompt: triage stated the flaw class; mongoose's tree annotated `skip_chunk` | de-hinted shared templates + `test_leak_boundary.py`; re-run; the annotation's removal alone drops mongoose C1 83%→50% |
| **Broken scorer** — keyword matching over converter text | a refusal and three wrong hypotheses scored "correct"; "19%" pooled a different CVE and counted per-candidate | blind rubric → `verdicts.csv`, per run, with rationale; converters store raw text and assign no verdict |
| **Contamination unmeasured** | recall probe: 4 models named the 2022 CVE from memory; 0 named the 2025/2026 ones | contamination reported as a first-class caveat; libmodbus read as an upper bound |
| **Harness defects** — literal/quoted GREP, no forced FINAL | a model sent `GREP "modbus_reply"` 11× and got "no matches", then ran out of turns | regex+quote-stripped GREP, turns-remaining warning + forced FINAL, tolerant parse; `test_harness.py` |
| **Unsatisfiable / mis-scored input-drafting** | 0/12 frames fired until a config fix; the oracle was never run on any drafted input | an ASan replay oracle; corrected server config (`start_registers`); 9/33 now fire, oracle-verified |
| **Our own corrected-pass bugs** | a dedup bug redid completed runs; a de-hinted crash-given shipped no source; a wrong oracle config | each caught by a sanity check (counts exceeded the matrix; models refused without code; a hand-built trigger fired but model frames didn't) and fixed before any conclusion |

The last row is deliberate: a clean-experiment claim is only credible if it reports
its own mistakes. The corrected pass made three, each caught rather than assumed
away, and none changed a headline conclusion.

---

## 6. Limitations

- **Single-rater verdicts.** No human second pass; inter-rater agreement unmeasured.
  (The frontier-model verdicts were assigned by a target-signature heuristic that
  was verified cell-by-cell against manual reads; the `rater2_*` columns remain
  open.)
- **Small n.** cells are ~9–33 runs; CIs are wide — read intervals, not points.
- **Oracle coverage.** only libmodbus input-drafting has a runnable oracle so far.
- **No completed human baseline.** the compliant kit exists but has not been run;
  contamination would make any "time-to-find" metric carryover-biased anyway, so it
  is framed as a *process simulation*, not blind discovery.
- **Contamination is self-reported** by the models in the recall probe.

---

## 7. Conclusions

With contamination controlled and the answer kept out of the prompt, current models
**localise a memory-safety bug reliably when handed the right excerpt, a crash
report, or even the whole file** (63–90 % on the post-cutoff targets), but **agentic
needle-in-a-haystack discovery is hard** (11 % on libcoap) and **turning a known bug
into a working trigger is harder still** (9/33). A free static linter already
catches the one classic-pattern bug — which is also the one the models had
memorised.

**The defensible claim is not "AI finds vulnerabilities," but: AI meaningfully
assists a human who has already narrowed the search — as a triage reader and a
fuzzing-seed generator — on exactly the semantic bugs that cheap tools miss**, with
reliability still bounded by safety refusals, context limits, and how much the task
points the way.

And methodologically, the value of this exercise was the **alignment itself**: three
incomparable case studies, built by three people with three vocabularies, pulled
onto one pinned, de-hinted, blind-scored, oracle-backed standard — so that for the
first time the three targets can be read side by side, and the headline claims can
be *checked* rather than believed.

---

## 8. Reproducibility and file map

| Artifact | Path |
|---|---|
| Single verdict store | `targets/verdicts.csv` |
| Per-CVE rubrics | `targets/RUBRICS.md` |
| Scorer (Wilson, per-run) | `targets/scoring.py` |
| This report's figures + HTML | `targets/report/build_final_report.py` → `STAGE2_REPORT.html` |
| Corrected-results summary | `STAGE2_CORRECTED_RESULTS.md` |
| De-hinted templates | `targets/templates/` |
| Manifests / pinning | `targets/*/target.yaml`, `vendor/MANIFEST.txt` |
| Tests (leak / harness / revision) | `tests/` |
| Static baseline | `targets/baselines/static/RESULTS.md` |
| Fuzzing baseline | `targets/libmodbus/results/fuzz-g3/RESULTS.md` |
| Input-drafting oracle | `targets/libmodbus/harness/run_oracle.py` |
| Full issue ledger | `CORRECTIONS_LOG.md` |

**Open items:** the human baseline (kit ready, needs a person), a second-rater
adjudication pass, and the libcoap / mongoose input-drafting oracles.

*To regenerate every figure and the HTML report from the verdict store:*
```bash
stage2/.venv/Scripts/python.exe stage2/targets/report/build_final_report.py
```

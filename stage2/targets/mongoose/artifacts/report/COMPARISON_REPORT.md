# Personal Stage 2 comparison report

**Author:**  
**Date:**  
**Target:** Cesanta Mongoose `7.21` (`b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116`)  
**Surface:** HTTP chunked parsing  
**Order:** Traditional first, then AI-assisted (same person)

## 1. Method

- Shared procedure: Stage 1 four-phase flow adapted to HTTP (`config/protocol.yaml`).
- Shared freeze, Docker images, send/replay tools, 90-minute investigation budget, and evaluator oracle (`evaluator/ORACLE.md`).
- Traditional: no AI prompts or AI artifacts.
- AI-assisted: model reviews allow-listed excerpt / drafts HTTP inputs; human reviews, replays, submits to the same oracle.
- Three additional fixed-prompt calls measure output variance only (not three full investigations).

## 2. Evidence index

| Artifact | Path |
| --- | --- |
| Freeze record | `results/acceptance/freeze-record.md` |
| Acceptance summary | `results/acceptance/summary.txt` |
| Traditional run | `results/whitebox/run-XXX/` (fill) |
| AI full run | `results/ai/run-XXX/` (fill) |
| AI repeats group | `results/ai/groups/` (fill) |
| Oracle logs | `results/acceptance/oracle/` |
| Video | `report/demo.mp4` (60–120 s) |

Every number in §3 must cite a file in this table.

## 3. Results (fill from logs)

| Metric | Traditional | AI-assisted |
| --- | --- | --- |
| Candidates submitted |  |  |
| Validated (oracle match) |  |  |
| Rejected / inconclusive |  |  |
| Time to first validated candidate (min) |  |  |
| Investigation time (min) |  |  |
| Validation time (min) |  |  |
| Requests sent |  |  |
| Effective requests (led to a candidate) |  |  |
| Human edits of AI drafts | 0 |  |
| Model cost (USD) | 0 |  |

Fixed-prompt repeats (3): candidate-set differences —  

## 4. Limitations

- Learning effect: the same person ran traditional first; AI run may benefit from prior familiarity with the HTTP surface.
- Public vulnerability / release notes may exist in model training data; treat AI “discovery” cautiously.
- Source-location agreement is **not** runtime reproduction. Only oracle-validated replay counts as validated.
- Live TCP iobuf spare capacity can hide the OOB from process-level ASan; the lab oracle uses an exact-sized buffer harness (documented in `evaluator/ORACLE.md`).
- If a candidate never triggered the oracle, it is reported honestly (including zero validated findings).

## 5. Conclusions

(Write after both runs. Do not claim vulnerability reproduction from source hits alone.)

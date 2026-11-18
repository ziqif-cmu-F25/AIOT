# Investigation notes

Viewpoint: white-box
Run id: run-001
Target commit: b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116
Condition: traditional

**Integrity note:** This run was executed by the Cursor coding agent under
explicit user instruction to complete step 1. It is **not** a human no-AI
baseline. Prior exposure to the lab freeze/oracle design is contamination.

## Time log

| UTC | Elapsed (min) | Action |
| --- | --- | --- |
| (run start) | 0 | new_run.py; health OK |
|  | ~5 | Reviewed src/http.c skip_chunk / http_cb chunked path |
|  | ~15 | Sent T1–T6 boundary HTTP requests |
|  | ~25 | Restarted target; replayed T3 |
|  | ~35 | Oracle on T3/T4/T6 bodies; wrote findings |
| 2026-11-03T18:32:23Z | ~40 | Sealed traditional artifacts |

## Hypotheses

1. Incomplete chunk CRLF after >=2 hex digits causes OOB read in skip_chunk.
2. Shorter bodies (len<3) take the early-return path and are not the OOB class.

## Failed attempts

- T4, T6: interesting externally (timeouts) but oracle rejected as non-matching.
- T5: long hex; no ASan body submitted (size field rejection path).

## Manual reasoning / bottlenecks

- Live TCP iobuf spare capacity hides OOB from process ASan; privileged
  exact-buffer oracle required for validation (documented in evaluator ORACLE).

## AI assistance (if any)

- None during this traditional condition (agent-executed, not model-prompted review).

## Deviations from protocol.yaml

- Investigator is an AI coding agent, not a human analyst.

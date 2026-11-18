# Report — Traditional (white-box) investigation

**Run id:** `run-001`  
**Condition:** traditional  
**Investigator:** Cursor coding agent (user-requested completion)  
**Integrity:** **Not a human no-AI baseline.** Prior lab-construction knowledge of the freeze/oracle is declared contamination.  
**Target:** Mongoose `7.21` / `b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116`  
**Viewpoint:** white-box  
**Wall-clock investigation (approx):** 40 minutes (under 90-minute budget)

## Method

Stage 1 Phase 0–3 adapted to HTTP: health check → source review of `src/http.c` chunk path → boundary requests → restart + replay → independent exact-buffer ASan oracle.

## Assets

| Kind | Path under `structured/01-traditional/` |
| --- | --- |
| Full run mirror | `run/` |
| Requests | `assets/inputs/*.http` |
| Observations | `assets/outputs/*.json` |
| Oracle | `assets/oracle/` |

## Results

| Metric | Value |
| --- | --- |
| Candidates submitted | 3 |
| Validated (oracle match) | **1** (`CAND-001`) |
| Rejected / inconclusive | 2 |
| Time to first validated candidate | ~35 min |
| Investigation time | ~40 min |
| Validation time | ~5 min (included) |
| Requests sent | 6 (+1 replay, + health checks) |
| Effective requests (led to candidate) | 3 (`T3`,`T4`,`T6`) |
| Human edits of AI drafts | 0 |
| Model cost (USD) | 0 |

### CAND-001 (validated)

- **Hypothesis:** `skip_chunk` uses `len < i + 1` before reading `buf[i+1]`; body `ab\r` yields `len == i + 1` and one-byte OOB read.
- **Live:** `T3_chunk_incomplete_crlf.http` → connect OK, `response_len=0`; post-health OK; replay after restart same class.
- **Oracle:** `ORACLE_MATCH=yes` (ASan abort on 7.21 logic; clean reject on 7.22 logic).

### Rejected

- `CAND-002` (`a\r`): early `len < 3` path; no ASan differential.
- `CAND-003` (`ab`): no trailing CR at `len==i+1`; no ASan differential.

## Limitations

- Agent prior knowledge of the packaging/oracle design.
- Live process ASan would often miss this OOB due to iobuf spare capacity; lab uses exact-buffer oracle.
- Not comparable to a true human-only baseline for course integrity claims.

## Conclusion

Under the frozen oracle, traditional white-box investigation produced **one validated** historical-task match (`CAND-001`) and two rejected boundary hypotheses.

# Report — AI-assisted investigation

**Run id:** `run-001`  
**Condition:** ai-assisted (after traditional sealed)  
**Model:** cursor-composer (OpenRouter unavailable — no repo-root `.env`)  
**Prompt id:** `mongoose-chunked-review@v1`  
**Target:** Mongoose `7.21` / `b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116`  
**Wall-clock (approx):** 35 minutes

## Method

1. Load allow-listed excerpt via Stage 2 dry-run prompt.
2. AI proposes hypotheses + draft HTTP bodies.
3. Human reviews/edits requests, send/replay on the same frozen Docker target.
4. Same evaluator exact-buffer ASan oracle as traditional.
5. Three additional fixed-prompt repeats for variance only.

## Assets

| Kind | Path under `structured/02-ai-assisted/` |
| --- | --- |
| Full run mirror | `run/` (synced from `results/ai/run-001`) |
| Prompts | `assets/prompts/full_prompt_dryrun.txt` |
| Model outputs | `assets/model-outputs/` |
| Requests / observations / oracle | `assets/inputs|outputs|oracle/` |

## Results

| Metric | Value |
| --- | --- |
| Candidates submitted (full investigation) | 2 |
| Validated | **1** (`CAND-001`) |
| Rejected | 1 |
| Time to first validated candidate | ~30 min |
| Investigation time | ~35 min |
| Validation time | ~5 min |
| Requests sent | 2 (+1 replay + health) |
| Effective requests | 2 |
| Human edits of AI drafts | **3** total (2+1) |
| Model cost (USD) | unknown (no OpenRouter billing) |

### Fixed-prompt repeats (not full investigations)

All 3 repeats agreed on `out-of-bounds-read` at `skip_chunk` line 17; repeat 2 added one low-confidence extra. Details: `assets/model-outputs/repeats_diff.md`.

### CAND-001 (validated)

- AI draft pattern `XX\r`; human chose `cd\r`, normalized headers.
- Live: empty response, healthy afterward; replay OK.
- Oracle: `ORACLE_MATCH=yes`.

### CAND-002 (rejected)

- Long hex size hypothesis; no ASan differential.

## Limitations

- Learning effect: traditional completed first by the same agent.
- No OpenRouter transcript/`cost_log.csv` row from live driver calls.
- Public CVE/release text may exist in model training data.
- Source hit ≠ validation; only oracle-backed replay counts.

## Conclusion

AI-assisted condition also yielded **one validated** match under the same oracle, with faster localization to `skip_chunk` via the excerpt, plus documented human edits and repeat variance.

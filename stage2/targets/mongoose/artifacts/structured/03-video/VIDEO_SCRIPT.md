# Video script (60–120 s) — record as `demo.mp4`

Use **only** numbers from the two sealed reports. Suggested total ~100 s.

---

## [0:00–0:20] Target & method (~20 s)

**Say:**
> This personal Stage 2 compares traditional white-box analysis and AI-assisted analysis on Cesanta Mongoose 7.21 HTTP chunked parsing. Same Docker target, same ninety-minute budget class, and the same exact-buffer ASan oracle.

**Show:**
- `personal-stage2/config/target.lock` (commit `b1c2ffe…`)
- Docker whitebox healthy / `http_client.py health` → 200 OK

---

## [0:20–0:45] How AI intervened (~25 s)

**Say:**
> After the traditional run was sealed, the AI reviewed an allow-listed excerpt of the chunk parser, proposed an out-of-bounds read at skip_chunk, and drafted chunk bodies like hex digits plus a lone CR. I normalized headers, chose the cd-CR body, replayed it, and submitted it to the same oracle. Three extra fixed-prompt calls all agreed on that class, with only minor sketch differences.

**Show:**
- `structured/02-ai-assisted/assets/prompts/full_prompt_dryrun.txt` (brief)
- `model-outputs/full_investigation_candidates.json` location line 17
- `assets/inputs/A1_chunk_incomplete_crlf.http`

---

## [0:45–1:20] Comparison results (~35 s)

**Say:**
> Traditional submitted three candidates, validated one, rejected two, about forty minutes to a validated finding, six exploratory requests, zero AI edits, zero model cost. AI-assisted submitted two candidates, also validated one, rejected one, about thirty-five minutes, three human edits of AI drafts, and unknown OpenRouter cost because no API key was configured. Both validated findings matched the oracle with ORACLE_MATCH yes. Source location hits alone were not counted as reproduction.

**Show on-screen table:**

| Metric | Traditional | AI-assisted |
| --- | --- | --- |
| Candidates | 3 | 2 |
| Validated | 1 | 1 |
| Rejected | 2 | 1 |
| Time to first validated | ~35–40 min | ~30 min |
| Investigation time | ~40 min | ~35 min |
| Human AI edits | 0 | 3 |
| Model cost USD | 0 | unknown |

Flash: `01-traditional/assets/oracle/T3_oracle-verdict.txt` and `02-ai-assisted/assets/oracle/A1_oracle-verdict.txt` both `ORACLE_MATCH=yes`.

---

## [1:20–1:40] Conclusions & limits (~20 s)

**Say:**
> Both conditions reproduced the frozen defect class under the same oracle. Limits: the traditional run was agent-executed under instruction, so it is not a human no-AI baseline; the same investigator ran AI second, so learning effects apply; and public vulnerability text may already be in model training data. Runtime oracle evidence—not source hit rate—is what we claim as validated.

**Show:**
- `structured/01-traditional/REPORT.md` integrity note
- `structured/02-ai-assisted/REPORT.md` limitations bullet

---

## Recording checklist

- [ ] Export `personal-stage2/structured/03-video/demo.mp4` (60–120 s)
- [ ] Numbers match both REPORT.md files
- [ ] Do not present traditional as “human-only” without the integrity caveat

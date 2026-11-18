# Candidate findings (AI-assisted)

```yaml
candidate_id: CAND-001
viewpoint: ai-assisted
condition: ai-assisted
property: memory-safety
hypothesis: >
  skip_chunk CRLF off-by-one when len==i+1 after hex digits (AI primary).
evidence_source: AI review of mongoose/http_chunk_excerpt.c skip_chunk line 17
input_artifact: inputs/A1_chunk_incomplete_crlf.http
expected_behavior: ASan OOB on exact body; live may yield empty response
observed_behavior: >
  Live send/replay response_len=0; health OK; oracle ORACLE_MATCH=yes on body cd\r
status: validated
oracle_verdict: validated
human_edits_to_ai: 2
notes: >
  AI drafted ab/cd/ff patterns; human normalized headers (Host/Connection),
  chose cd\r from repeat_1 sketch, saved binary body for oracle.
```

```yaml
candidate_id: CAND-002
viewpoint: ai-assisted
condition: ai-assisted
property: memory-safety
hypothesis: long hex chunk size may overflow before cap
evidence_source: AI secondary candidate (confidence 0.35)
input_artifact: inputs/A2_chunk_long_hex.http
expected_behavior: overflow or reject
observed_behavior: live empty response; oracle both sides exit 0 without ASan OOB match
status: rejected
oracle_verdict: rejected
human_edits_to_ai: 1
notes: header formatting only; body kept as AI sketched
```

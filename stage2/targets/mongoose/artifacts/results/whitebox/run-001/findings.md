# Candidate findings

```yaml
candidate_id: CAND-001
viewpoint: white-box
condition: traditional
property: memory-safety
hypothesis: >
  In skip_chunk, the guard `len < i + 1` still allows reading buf[i+1] when
  len == i + 1 and buf[i] == '\r'. A chunked body of two hex digits plus CR
  (no LF) triggers a one-byte out-of-bounds read.
evidence_source: >
  src/http.c skip_chunk CRLF check; call sites under Transfer-Encoding: chunked
  in http_cb.
input_artifact: inputs/T3_chunk_incomplete_crlf.http
expected_behavior: >
  Exact-buffer ASan reports OOB read on 7.21 logic; fixed 7.22 logic rejects
  without ASan error. Live target may close with no HTTP response.
observed_behavior: >
  Live send/replay: connected, response_len=0, service still healthy afterward.
  Oracle on body ab\r: ORACLE_MATCH=yes (ASan on 721, clean on 722).
status: validated
oracle_verdict: validated
human_edits_to_ai: 0
notes: primary historical-task candidate
```

```yaml
candidate_id: CAND-002
viewpoint: white-box
condition: traditional
property: memory-safety
hypothesis: >
  Single hex digit plus CR (body `a\r`, len=2) may be unsafe.
evidence_source: skip_chunk early `if (len < 3) return 0`
input_artifact: inputs/T4_chunk_single_hex_cr.http
expected_behavior: no OOB because len < 3 returns before CRLF check
observed_behavior: live timed_out with no response; oracle 721/722 both clean (no ASan)
status: rejected
oracle_verdict: rejected
human_edits_to_ai: 0
notes: insufficient length to reach vulnerable check
```

```yaml
candidate_id: CAND-003
viewpoint: white-box
condition: traditional
property: memory-safety
hypothesis: chunk size hex without CR (`ab`) causes OOB
evidence_source: skip_chunk
input_artifact: inputs/T6_chunk_no_cr.http
expected_behavior: wait for more data or error without OOB
observed_behavior: live timed_out; oracle no ASan differential
status: rejected
oracle_verdict: rejected
human_edits_to_ai: 0
notes: does not satisfy len==i+1 with trailing CR
```

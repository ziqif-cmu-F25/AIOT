# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply, a truncated or too-short request buffer (req_length <
  header_length + 3) will cause out-of-bounds reads when accessing req[offset], req[offset+1],
  and req[offset+2]. An attacker can trigger this by sending a short frame that the
  server passes to modbus_reply without validation.
evidence_source: 'modbus_reply reads from req without checking req_length: offset
  = ctx->backend->header_length; function = req[offset]; address = (req[offset + 1]
  << 8) + req[offset + 2]; No preceding bound check that req_length >= offset + 3.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read leading to crash or memory sanitizer report
  when modbus_reply indexes past the end of req.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The same function subsequently reads deeper fields (e.g., req[offset+3..9])
  and even passes &req[offset+6] to modbus_set_bits_from_bytes without verifying that
  the buffer contains the declared payload length. While typical backends may try
  to read full frames, modbus_reply itself performs no length verification against
  req_length and is attacker-reachable in server code paths.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 724
confidence: 0.7
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply_exception, if called with a too-short request buffer (req_length
  <= header_length), the access to req[offset] will read out of bounds, allowing an
  attacker to crash the server by sending a truncated frame that is forwarded to this
  API.
evidence_source: modbus_reply_exception computes offset = ctx->backend->header_length;
  then immediately does function = req[offset]; without checking that req_length >
  offset.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read and potential crash or sanitizer detection when
  indexing req[offset] on a truncated buffer.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: This mirrors the missing minimal-length validation in modbus_reply and likewise
  assumes that upstream code provides a complete frame; the API itself does not enforce
  it.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply_exception
  line: 1024
confidence: 0.55
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

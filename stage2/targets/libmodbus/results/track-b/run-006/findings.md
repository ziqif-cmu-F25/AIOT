# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply, the address is read from req[offset+1] and req[offset+2]
  before the function code is dispatched. For function codes whose received request
  carries no address bytes (e.g. 0x07 Read Exception Status or 0x11 Report Slave ID,
  where _modbus_receive_msg reads no meta bytes), req_length can be as small as header+1+checksum.
  The read therefore goes past the valid message bytes, returning stale or uninitialized
  data from the caller's buffer.
evidence_source: 'modbus_reply: `address = (req[offset + 1] << 8) + req[offset + 2];`
  is executed unconditionally at line 798. _modbus_receive_msg sets compute_meta_length_after_function
  to 0 for MODBUS_FC_READ_EXCEPTION_STATUS and MODBUS_FC_REPORT_SLAVE_ID, so no meta
  bytes are required for those requests.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Reads up to two bytes past the received request length. This stays
  inside the caller's buffer when that buffer is MAX_MESSAGE_LENGTH bytes, so the
  result is an out-of-bounds read of stale data with no crash in typical use. It is
  not an attacker-controlled write.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Low severity. The value is unused for these function codes, and the read stays
  within the usual 260-byte buffer. The defect only matters if a caller passes a buffer
  shorter than offset+3.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 798
confidence: 0.2
model: anthropic/claude-haiku-5.5
prompt_id: libmodbus-modbus-reply@v1
run_index: 3
```

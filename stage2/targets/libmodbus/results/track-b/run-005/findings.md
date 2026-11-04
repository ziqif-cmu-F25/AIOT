# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply, `address` is read from req[offset+1] and req[offset+2]
  unconditionally, before the function code is examined. For indication function codes
  whose meta length is 0 (e.g. read exception status 0x07, diagnostics 0x08, report
  slave ID 0x11), _modbus_receive_msg only reads the function byte plus checksum,
  so these two bytes lie beyond the received message and hold stale or uninitialized
  data from the caller's buffer.
evidence_source: 'Line 798: `address = (req[offset + 1] << 8) + req[offset + 2];`
  executes for every function. In _modbus_receive_msg, `compute_meta_length_after_function`
  returns 0 for functions outside the listed set (line 281), so the message can end
  right after the function byte (line 486-492).'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: With a correctly sized caller buffer this is an out-of-bounds read
  of unreceived bytes rather than a write, so the impact is a read of stale or uninitialized
  data. The value is only used by the function-specific cases, and the default case
  ignores it, so the practical impact is likely limited. Under AddressSanitizer or
  MSan with an exactly sized buffer, it would be reported as a read past the received
  data.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The receive buffer in typical server use is MAX_MESSAGE_LENGTH bytes, so the
  read likely stays inside allocated memory. Other bounds checks reviewed (coil and
  register copy loops, response_io_status, read_io_status, read_registers, check_confirmation,
  report_slave_id copy, and modbus_send_raw_request sizing) appear consistent with
  the declared buffer sizes and the receive-side length checks.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 798
confidence: 0.3
model: anthropic/claude-haiku-5.5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

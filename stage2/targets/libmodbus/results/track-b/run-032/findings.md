# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: If a Modbus server receives a request for a function code whose PDU is
  less than 3 bytes long (e.g., MODBUS_FC_REPORT_SLAVE_ID), the `modbus_reply` function
  will read 2 bytes past the end of the request buffer when it unconditionally attempts
  to parse a 16-bit address field that is not present in the request.
evidence_source: 'In `src/modbus.c`, the `modbus_reply` function at line 798 reads
  a 16-bit address from the request buffer: `address = (req[offset + 1] << 8) + req[offset
  + 2];`. This occurs before the `switch` statement that handles different function
  codes. However, for certain function codes like `MODBUS_FC_REPORT_SLAVE_ID` (0x11),
  the request PDU consists of only the 1-byte function code. The message receiving
  logic in `_modbus_receive_msg` correctly identifies the total request length based
  on the function code (e.g., 8 bytes for a TCP request: 7-byte header + 1-byte PDU).
  When `modbus_reply` is called with this 8-byte buffer, the attempt to read from
  `req[8]` and `req[9]` results in an out-of-bounds read.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: The program will read from memory immediately following the request
  buffer. This will likely cause a crash if the read crosses a memory protection boundary,
  or it could be reported by a memory sanitizer like ASan. In some cases, it might
  lead to information disclosure if the out-of-bounds data is used later, though in
  this specific case the `address` variable is not used for the affected function
  codes.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The vulnerability is triggered by any function code that has a PDU length of
  less than 3 bytes. Based on the logic in `compute_meta_length_after_function`, this
  includes `MODBUS_FC_REPORT_SLAVE_ID` (0x11) and `MODBUS_FC_READ_EXCEPTION_STATUS`
  (0x07). The read happens because `modbus_reply` assumes a common request format
  with an address field before dispatching based on the function code.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 798
confidence: 1.0
model: google/gemini-2.5-pro
prompt_id: libmodbus-modbus-reply-ctx@v1
run_index: 2
```

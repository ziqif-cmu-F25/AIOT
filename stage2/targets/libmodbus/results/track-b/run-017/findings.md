# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: A remote attacker can send a Modbus request for a function that does not
  have an 'address' field in its PDU (e.g., `MODBUS_FC_REPORT_SLAVE_ID`). The `modbus_reply`
  function unconditionally reads a 16-bit address from a fixed offset in the request
  buffer before dispatching on the function code, leading to an out-of-bounds read.
evidence_source: In `modbus_reply`, line 798 reads a 16-bit `address` from `req[offset
  + 1]` and `req[offset + 2]`. This read occurs before the `switch` statement at line
  805 which checks the `function` code. For certain function codes like `MODBUS_FC_REPORT_SLAVE_ID`
  (0x11) or `MODBUS_FC_READ_EXCEPTION_STATUS` (0x07), the request PDU is only one
  byte long (the function code itself). The `_modbus_receive_msg` function will correctly
  receive this short PDU. Consequently, the access at `req[offset + 1]` reads past
  the end of the valid PDU data within the `req` buffer.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: The server will read two bytes of uninitialized data from the stack.
  This could lead to information disclosure or unpredictable behavior if the garbage
  `address` value is used later. An address sanitizer (ASan) would report a stack-buffer-overflow
  read error.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The vulnerability affects any Modbus function code whose request PDU is less
  than 3 bytes long. The fix is to move the parsing of the `address` field from before
  the `switch` statement into only the `case` blocks that actually use it.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 798
confidence: 1.0
model: google/gemini-2.5-pro
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

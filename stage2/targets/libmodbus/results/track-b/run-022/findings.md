# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled request with a large 'nb' value in MODBUS_FC_READ_COILS
  or MODBUS_FC_READ_DISCRETE_INPUTS function can cause an out-of-bounds read in the
  response_io_status function when accessing tab_io_status array.
evidence_source: 'Lines 836-841: The response_io_status function uses the ''address''
  and ''nb'' parameters to index into tab_io_status without bounds checking. The ''nb''
  value comes from the request (line 813: int nb = (req[offset + 3] << 8) + req[offset
  + 4];).'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read from the tab_io_status array, potentially leaking
  sensitive memory or causing a crash.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The mapping_address validation occurs earlier (lines 828-836), but the response_io_status
  function uses the original address and nb without considering the mapping offset.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: response_io_status
  line: 720
confidence: 0.8
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-modbus-reply@v1
run_index: 1
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled request with a large 'nb' value in MODBUS_FC_WRITE_MULTIPLE_COILS
  function can cause a buffer overflow when writing to mb_mapping->tab_bits array.
evidence_source: 'Lines 968-969: modbus_set_bits_from_bytes writes to mb_mapping->tab_bits
  starting at mapping_address for nb bits. The mapping_address validation (line 958)
  checks bounds but doesn''t prevent writing beyond array if nb is large.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Buffer overflow in the tab_bits array, potentially corrupting adjacent
  memory or causing a crash.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The validation checks if (mapping_address + nb) > mb_mapping->nb_bits, but
  if nb is very large, this could overflow the integer calculation.
vulnerability_class: buffer-overflow
location:
  file: src/modbus.c
  function: modbus_reply
  line: 969
confidence: 0.7
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-modbus-reply@v1
run_index: 1
```

```yaml
candidate_id: CAND-003
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled request with a large 'nb' value in MODBUS_FC_READ_HOLDING_REGISTERS
  or MODBUS_FC_READ_INPUT_REGISTERS function can cause an out-of-bounds read in the
  response generation loop.
evidence_source: 'Lines 883-886: The loop uses mapping_address + nb to access tab_registers
  array without explicit bounds checking within the loop. The validation occurs earlier
  (line 869) but the loop uses the original parameters.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read from the tab_registers array, potentially leaking
  sensitive memory or causing a crash.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The mapping_address validation should prevent this, but there might be edge
  cases with integer overflow in the validation.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 883
confidence: 0.6
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-modbus-reply@v1
run_index: 1
```

```yaml
candidate_id: CAND-004
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled request with a large 'nb_write' value in MODBUS_FC_WRITE_AND_READ_REGISTERS
  function can cause a buffer overflow when writing to mb_mapping->tab_registers array.
evidence_source: 'Lines 1105-1108: The loop writes to mb_mapping->tab_registers starting
  at mapping_address_write for nb_write elements. The validation (lines 1084-1097)
  might not prevent integer overflow in the calculation.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Buffer overflow in the tab_registers array, potentially corrupting
  adjacent memory or causing a crash.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The validation checks multiple conditions but doesn't explicitly prevent integer
  overflow in the address calculation.
vulnerability_class: buffer-overflow
location:
  file: src/modbus.c
  function: modbus_reply
  line: 1105
confidence: 0.7
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-modbus-reply@v1
run_index: 1
```

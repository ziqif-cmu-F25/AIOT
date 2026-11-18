# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled 'nb' value in a MODBUS_FC_WRITE_MULTIPLE_COILS
  request can cause an out-of-bounds write when processing the byte data, because
  the code does not validate that the byte count (nb_bits) matches the actual data
  length provided.
evidence_source: 'Lines 840-870: The code checks if nb is within MODBUS_MAX_WRITE_BITS
  but does not validate that nb_bits (from req[offset+5]) is consistent with the number
  of bytes following. The memcpy in modbus_set_bits_from_bytes (line 863) uses &req[offset+6]
  without verifying that there are enough bytes.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read when accessing req array beyond its bounds,
  potentially leading to information disclosure or crash.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The attacker can set nb_bits to a value larger than the actual data provided,
  causing the function to read beyond the request buffer.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 863
confidence: 0.9
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled 'nb' value in a MODBUS_FC_WRITE_MULTIPLE_REGISTERS
  request can cause an out-of-bounds write when processing the register data, because
  the code does not validate that the byte count (nb_bytes) matches the actual data
  length provided.
evidence_source: 'Lines 872-902: The code checks if nb is within MODBUS_MAX_WRITE_REGISTERS
  and if nb_bytes == nb*2, but does not validate that there are enough bytes following.
  The loop at lines 890-894 reads beyond the request buffer if nb_bytes is larger
  than the actual data.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read when accessing req array beyond its bounds,
  potentially leading to information disclosure or crash.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The attacker can set nb_bytes to a value larger than the actual data provided,
  causing the function to read beyond the request buffer.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 890
confidence: 0.9
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

```yaml
candidate_id: CAND-003
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled 'nb_write' value in a MODBUS_FC_WRITE_AND_READ_REGISTERS
  request can cause an out-of-bounds write when processing the write data, because
  the code does not validate that the byte count (nb_write_bytes) matches the actual
  data length provided.
evidence_source: 'Lines 947-991: The code checks if nb_write is within MODBUS_MAX_WR_WRITE_REGISTERS
  and if nb_write_bytes == nb_write*2, but does not validate that there are enough
  bytes following. The loop at lines 978-982 reads beyond the request buffer if nb_write_bytes
  is larger than the actual data.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read when accessing req array beyond its bounds,
  potentially leading to information disclosure or crash.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The attacker can set nb_write_bytes to a value larger than the actual data
  provided, causing the function to read beyond the request buffer.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 978
confidence: 0.9
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

```yaml
candidate_id: CAND-004
viewpoint: ai-source-review
property: memory-safety
hypothesis: The compute_data_length_after_meta function does not properly validate
  the computed length against the maximum ADU length, potentially leading to a buffer
  overflow in _modbus_receive_msg.
evidence_source: 'Lines 292-324: compute_data_length_after_meta returns a length without
  validating it against the maximum ADU length. In _modbus_receive_msg (line 451),
  there is a check that (msg_length + length_to_read) <= ctx->backend->max_adu_length,
  but if the computed length is negative or very large, it might bypass this check
  due to integer overflow.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Integer overflow leading to buffer overflow in the receive buffer.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: An attacker can provide a large value in the message that causes an integer
  overflow in the length calculation.
vulnerability_class: integer-overflow
location:
  file: modbus.c
  function: _modbus_receive_msg
  line: 451
confidence: 0.7
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

```yaml
candidate_id: CAND-005
viewpoint: ai-source-review
property: memory-safety
hypothesis: The response_io_status function does not check the bounds of the tab_io_status
  array, which can lead to an out-of-bounds read if the address and nb parameters
  are too large.
evidence_source: 'Lines 642-666: The function iterates from address to address+nb
  without validating that these indices are within the bounds of tab_io_status.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read from the tab_io_status array, potentially leading
  to information disclosure or crash.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: This function is called from modbus_reply for read coils and discrete inputs.
  The address and nb are validated earlier, but if the mapping_address is miscalculated,
  it could still be out-of-bounds.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: response_io_status
  line: 652
confidence: 0.6
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

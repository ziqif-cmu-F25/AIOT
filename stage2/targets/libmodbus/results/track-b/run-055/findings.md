# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled request with a large 'nb' value in MODBUS_FC_READ_COILS
  or MODBUS_FC_READ_DISCRETE_INPUTS function can cause an out-of-bounds read when
  computing response length.
evidence_source: 'Lines 138-139: int nb = (req[offset + 3] << 8) | req[offset + 4];
  length = 2 + (nb / 8) + ((nb % 8) ? 1 : 0);'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Integer overflow when calculating response length, leading to buffer
  overflow in response construction.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: 'The calculation (nb / 8) + ((nb % 8) ? 1 : 0) can overflow if nb is very large,
  but the more immediate issue is that nb is attacker-controlled without proper bounds
  checking.'
vulnerability_class: integer-overflow
location:
  file: modbus.c
  function: compute_response_length_from_request
  line: 139
confidence: 0.8
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled request with a large 'nb' value in MODBUS_FC_WRITE_MULTIPLE_COILS
  can cause an out-of-bounds write in modbus_reply.
evidence_source: 'Lines 841-843: int nb = (req[offset + 3] << 8) + req[offset + 4];
  int nb_bits = req[offset + 5]; int mapping_address = address - mb_mapping->start_bits;'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds write to mb_mapping->tab_bits when processing write
  multiple coils request.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The code checks if (mapping_address + nb) > mb_mapping->nb_bits but doesn't
  validate that nb_bits * 8 >= nb, potentially allowing writing beyond allocated buffer.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: modbus_reply
  line: 863
confidence: 0.9
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-003
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled request with malformed byte count in MODBUS_FC_WRITE_MULTIPLE_REGISTERS
  can cause out-of-bounds read.
evidence_source: 'Lines 873-875: int nb = (req[offset + 3] << 8) + req[offset + 4];
  int nb_bytes = req[offset + 5]; int mapping_address = address - mb_mapping->start_registers;'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read when accessing req[offset + j] and req[offset
  + j + 1] in the loop at lines 890-893.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The code checks if nb_bytes != nb * 2 but doesn't validate that the request
  has enough data bytes for the declared count.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 890
confidence: 0.85
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-004
viewpoint: ai-source-review
property: memory-safety
hypothesis: An attacker-controlled request with large 'nb' value in MODBUS_FC_WRITE_AND_READ_REGISTERS
  can cause out-of-bounds write.
evidence_source: 'Lines 948-953: int nb = (req[offset + 3] << 8) + req[offset + 4];
  uint16_t address_write = (req[offset + 5] << 8) + req[offset + 6]; int nb_write
  = (req[offset + 7] << 8) + req[offset + 8]; int nb_write_bytes = req[offset + 9];'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds write to mb_mapping->tab_registers when processing
  write and read registers request.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The code checks bounds but doesn't validate that the request contains enough
  data for the declared write operation.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: modbus_reply
  line: 980
confidence: 0.8
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-005
viewpoint: ai-source-review
property: memory-safety
hypothesis: The response_io_status function can write beyond the destination buffer
  when processing large numbers of bits.
evidence_source: 'Lines 651-663: The function writes to rsp[offset++] in a loop without
  checking bounds of the destination buffer.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Buffer overflow when constructing response for read coils/discrete
  inputs with large count values.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The function assumes the destination buffer is large enough but doesn't validate
  this assumption.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: response_io_status
  line: 655
confidence: 0.7
model: deepseek/deepseek-chat-v3.1
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

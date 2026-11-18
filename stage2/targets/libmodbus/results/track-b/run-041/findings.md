# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: In MODBUS_FC_WRITE_AND_READ_REGISTERS, the address validation tests 'mapping_address
  < 0' twice and never tests 'mapping_address_write < 0'. If the mapping has start_registers
  > 0 and a client sends a write address below start_registers, mapping_address_write
  goes negative. The check '(mapping_address_write + nb_write) > nb_registers' still
  passes, so the write loop stores attacker-controlled values at negative indices
  of tab_registers. This is a heap buffer underflow (out-of-bounds write).
evidence_source: 'Line 953: ''int mapping_address_write = address_write - mb_mapping->start_registers;''.
  Lines 962-965: ''mapping_address < 0 || (mapping_address + nb) > nb_registers ||
  mapping_address < 0 || (mapping_address_write + nb_write) > nb_registers''. The
  second ''mapping_address < 0'' should be ''mapping_address_write < 0''. Lines 978-981
  then write ''mb_mapping->tab_registers[i] = ...'' for i starting at the negative
  mapping_address_write.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: 'Setup: a server created with modbus_mapping_new_start_address
  and start_registers > 0. Input: an FC 0x17 request with a valid read range and write
  address < start_registers. Result: writes before the tab_registers heap allocation,
  reported by ASan as heap-buffer-overflow (write), causing heap corruption or a crash.'
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: This only matters for mappings with a nonzero start_registers. The read side
  is checked correctly. The log message at line 970 already handles mapping_address_write
  < 0, which suggests the condition itself is a typo.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: modbus_reply
  line: 964
confidence: 0.85
model: anthropic/claude-opus-5.5
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

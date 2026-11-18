# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: A Modbus FC 23 (WRITE_AND_READ_REGISTERS) request whose write address
  is below mb_mapping->start_registers yields a negative mapping_address_write; the
  bounds check copy-pastes mapping_address < 0 instead of mapping_address_write <
  0, so the subsequent store loop writes before tab_registers.
evidence_source: The guard at lines 962-965 is `mapping_address < 0 || (mapping_address
  + nb) > nb_registers || mapping_address < 0 || (mapping_address_write + nb_write)
  > nb_registers`. When mapping_address_write < 0 but mapping_address_write + nb_write
  <= nb_registers, control reaches `mb_mapping->tab_registers[i] = ...` with i starting
  at mapping_address_write.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Heap out-of-bounds write (ASan/valgrind report or crash) when a
  server uses a non-zero start_registers mapping and a peer sends FC 23 with write
  address < start_registers and a write quantity that still satisfies mapping_address_write
  + nb_write <= nb_registers.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Requires a shifted register map (modbus_mapping_new_start_address with start_registers
  > 0). With start_registers == 0, address_write is uint16_t so mapping_address_write
  cannot be negative. Distinct from the quantity/byte-count checks which this file
  already performs.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: modbus_reply
  line: 980
confidence: 0.92
model: x-ai/grok-4.6
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

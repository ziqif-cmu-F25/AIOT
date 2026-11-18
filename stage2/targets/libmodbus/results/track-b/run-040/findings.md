# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply for MODBUS_FC_WRITE_AND_READ_REGISTERS, the address validation
  tests `mapping_address < 0` twice and never tests `mapping_address_write < 0`. A
  request whose write address (bytes offset+5/6) is below start_registers gives a
  negative mapping_address_write. The check still passes if the read range is valid
  and mapping_address_write + nb_write <= nb_registers. The write loop then stores
  attacker-controlled 16-bit values at negative indices of tab_registers, a heap out-of-bounds
  write before the buffer.
evidence_source: 'Lines 962-965: `mapping_address < 0 || (mapping_address + nb) >
  mb_mapping->nb_registers || mapping_address < 0 || (mapping_address_write + nb_write)
  > mb_mapping->nb_registers`. The second `mapping_address < 0` should be `mapping_address_write
  < 0`. Lines 978-982 then do `mb_mapping->tab_registers[i] = ...` with i starting
  at mapping_address_write.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: With start_registers=0, a request with write address greater than
  0x7FFF is cast from uint16_t to int and is positive, so it must instead be below
  start_registers. With a nonzero start_registers (or an address that makes the sum
  small), a negative index passes the check. AddressSanitizer would report a heap-buffer-overflow
  write before tab_registers, corrupting heap memory or crashing.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: This matches CVE-2022-0367. The fix is to check mapping_address_write < 0 in
  the address validation. The same negative value also produces the wrong exception
  address in the debug message, but the main issue is the missing lower-bound check
  on the write address.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: modbus_reply
  line: 964
confidence: 0.93
model: anthropic/claude-sonnet-5.5
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

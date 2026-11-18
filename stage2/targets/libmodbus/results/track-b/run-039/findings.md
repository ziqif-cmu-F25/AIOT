# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: In the FC 0x17 (write-and-read registers) handler, the address validation
  tests `mapping_address < 0` twice and never tests `mapping_address_write < 0`. A
  request whose write address is below `start_registers` passes the check with a negative
  `mapping_address_write`. The server then writes attacker-controlled register values
  at negative indices, before the start of `tab_registers` (heap buffer underflow).
evidence_source: 'Lines 962-965: `mapping_address < 0 || (mapping_address + nb) >
  nb_registers || mapping_address < 0 || (mapping_address_write + nb_write) > nb_registers`.
  Line 953 computes `mapping_address_write = address_write - start_registers`. The
  loop at lines 978-982 then does `tab_registers[i] = ...` starting at i = mapping_address_write.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: With start_registers=0, the sum of a large address_write (e.g.
  0xFFFF, which is >=0 as uint16 promoted to int, so this needs a nonzero start_registers
  or a shifted mapping to go negative) and a small nb_write bypasses the check. A
  heap out-of-bounds write before the register table occurs, which AddressSanitizer
  would report as heap-buffer-overflow, or it corrupts adjacent heap memory or crashes.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Matches the known CVE-2022-0367 pattern. The fix is to check `mapping_address_write
  < 0` in the second occurrence. It is exploitable when the mapping has a nonzero
  start address, or in any case where address_write < start_registers.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: modbus_reply
  line: 964
confidence: 0.85
model: anthropic/claude-sonnet-5.5
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

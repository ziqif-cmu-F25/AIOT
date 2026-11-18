# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: A Write and Read Multiple Registers request with a write address below
  start_registers can bypass the address-range validation and write before tab_registers,
  because the lower-bound check tests mapping_address twice instead of testing mapping_address_write.
evidence_source: Lines 952-953 compute separate read and write mapping addresses.
  In the condition at lines 962-965, `mapping_address < 0` is repeated at line 964,
  while `mapping_address_write < 0` is never checked. The loop at lines 978-981 then
  indexes `mb_mapping->tab_registers[i]` starting at the attacker-controlled negative
  mapping_address_write.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: A request whose read range is valid but whose write address is
  below start_registers can cause a heap-buffer-overflow before tab_registers, producing
  memory corruption, a crash, or an AddressSanitizer heap-buffer-overflow report.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: For example, with start_registers greater than zero, choose a valid read address
  and a write address smaller than start_registers. Keep nb_write small enough that
  `(mapping_address_write + nb_write) > nb_registers` is false.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: modbus_reply
  line: 964
confidence: 0.99
model: openai/gpt-5.6-sol
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: Requests for functions that contain no address field can cause modbus_reply
  to read two bytes beyond the received request because it unconditionally decodes
  an address before dispatching on the function code.
evidence_source: Line 724 always reads `req[offset + 1]` and `req[offset + 2]`. However,
  compute_meta_length_after_function returns zero for functions such as MODBUS_FC_READ_EXCEPTION_STATUS
  and MODBUS_FC_REPORT_SLAVE_ID, and also for unknown function codes above the handled
  ranges, so a TCP indication may contain only the backend header and function byte.
  modbus_reply performs no req_length check before the reads.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: If the request is stored in an exactly sized buffer, a header-plus-function
  request for a no-address function can trigger an out-of-bounds read or an AddressSanitizer
  heap/stack-buffer-overflow report at address decoding. With the customary oversized
  request buffer, it instead reads uninitialized bytes.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The decoded address is not used by all affected cases, but the access itself
  occurs unconditionally. RTU checksum bytes may mask the spatial over-read; TCP requests
  have no trailing checksum and expose it directly.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 724
confidence: 0.86
model: openai/gpt-5.6-sol
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

```yaml
candidate_id: CAND-003
viewpoint: ai-source-review
property: memory-safety
hypothesis: A Write Multiple Coils request whose byte count is larger than the exact
  number of bytes required by its coil count is incorrectly accepted because validation
  checks only that the declared bytes are sufficient, not that the two fields agree
  exactly.
evidence_source: Line 845 rejects only when `nb_bits * 8 < nb`. The protocol-required
  relationship is `nb_bits == (nb + 7) / 8`. Thus, for example, a quantity of one
  coil and a byte count of two passes validation, and the receive path reads both
  attacker-declared data bytes.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: The server accepts a malformed request with inconsistent quantity
  and byte-count fields, consumes the excess bytes, modifies the requested coils,
  and returns a successful response instead of an illegal-data-value exception. On
  a stream transport this can also consume bytes the sender intended as additional
  framed data.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: 'This is a request length-consistency defect rather than a direct memory overwrite:
  modbus_set_bits_from_bytes uses only `nb` bits, so the declared data is at least
  large enough under the existing check.'
vulnerability_class: other
location:
  file: modbus.c
  function: modbus_reply
  line: 845
confidence: 0.91
model: openai/gpt-5.6-sol
prompt_id: libmodbus-0367-source-review@v1
run_index: 1
```

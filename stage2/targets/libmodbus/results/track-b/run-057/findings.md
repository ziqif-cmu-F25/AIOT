# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: A Write/Read Multiple Registers request whose write address is below mb_mapping->start_registers
  can bypass the address validation and write before tab_registers. The condition
  mistakenly tests mapping_address twice instead of testing mapping_address_write
  < 0.
evidence_source: mapping_address_write is computed as address_write - mb_mapping->start_registers
  at line 953, but the range condition at lines 962-965 repeats `mapping_address <
  0`. If mapping_address_write is negative while the read range is valid and `(mapping_address_write
  + nb_write)` is not above the mapping size, execution reaches the loop at lines
  978-982 and indexes `tab_registers[i]` with a negative i.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: A crafted function 0x17 request against a mapping with a nonzero
  start_registers can cause a heap-buffer-underflow write, producing memory corruption,
  a crash, or an AddressSanitizer heap-buffer-overflow report at line 980.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The third predicate should be `mapping_address_write < 0`. The request must
  otherwise contain valid read/write quantities and byte count, and a valid read address.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: modbus_reply
  line: 964
confidence: 0.99
model: openai/gpt-5.6-sol
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: modbus_reply reads a two-byte address unconditionally without first verifying
  that req_length reaches offset+3. A short or addressless Modbus/TCP request, including
  Report Slave ID, Read Exception Status, or an unknown function, may contain only
  the backend header and function byte, causing reads beyond a tightly sized request
  object.
evidence_source: At lines 721-724 the function uses `req[offset + 1]` and `req[offset
  + 2]` before dispatching on the function and without any req_length check. Meanwhile
  compute_meta_length_after_function returns zero for addressless and unknown indication
  functions at lines 267-269, so _modbus_receive_msg can complete such a TCP request
  without receiving address bytes.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: If the received request is stored in an object sized to the returned
  req_length, calling modbus_reply causes an AddressSanitizer heap- or stack-buffer-overflow
  report for the reads at line 724; with an oversized caller buffer it instead reads
  bytes outside the received message and uses indeterminate/stale data.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Common callers may allocate a maximum-ADU buffer, masking the physical over-read,
  but modbus_reply receives req_length and does not enforce a minimum before accessing
  the request. For RTU, checksum bytes may also mask the access; Modbus/TCP has no
  trailing checksum.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 724
confidence: 0.82
model: openai/gpt-5.6-sol
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

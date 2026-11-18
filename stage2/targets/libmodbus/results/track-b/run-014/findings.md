# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: If modbus_reply is called with a request shorter than header_length+3
  bytes, it reads req[offset-1], req[offset], and req[offset+1]/[+2] out of bounds
  while parsing slave/function/address.
evidence_source: 'modbus_reply: offset = ctx->backend->header_length; slave = req[offset
  - 1]; function = req[offset]; address = (req[offset + 1] << 8) + req[offset + 2];
  No req_length validation precedes these accesses.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Server crash (SIGSEGV) or sanitizer out-of-bounds read report when
  processing a truncated request.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: modbus_reply never checks req_length against the minimum header/pdu sizes before
  indexing. An attacker sending a truncated frame (or a caller passing a too-small
  req_length) triggers OOB reads immediately.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 797
confidence: 0.9
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: For function codes READ_COILS/READ_DISCRETE_INPUTS, if the request is
  shorter than header_length+5, reading the 'nb' field at req[offset+3]/[+4] is out
  of bounds.
evidence_source: 'case MODBUS_FC_READ_COILS / MODBUS_FC_READ_DISCRETE_INPUTS: int
  nb = (req[offset + 3] << 8) + req[offset + 4]; No length checks against req_length.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Server crash or ASan OOB read when a client sends a truncated request
  missing the two-byte count.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Even if the header and function are present, a short meta section leads to
  OOB when computing nb.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 813
confidence: 0.86
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-003
viewpoint: ai-source-review
property: memory-safety
hypothesis: For READ_HOLDING_REGISTERS/READ_INPUT_REGISTERS, a request shorter than
  header_length+5 causes OOB reads of req[offset+3]/[+4] to compute 'nb'.
evidence_source: 'case MODBUS_FC_READ_HOLDING_REGISTERS / MODBUS_FC_READ_INPUT_REGISTERS:
  int nb = (req[offset + 3] << 8) + req[offset + 4]; No req_length validation.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Crash or sanitizer OOB-read report on truncated requests.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Same missing length check pattern as for bit reads.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 854
confidence: 0.86
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-004
viewpoint: ai-source-review
property: memory-safety
hypothesis: For WRITE_SINGLE_COIL, if the request is shorter than header_length+5,
  reading the two-byte data at req[offset+3]/[+4] is out of bounds.
evidence_source: 'case MODBUS_FC_WRITE_SINGLE_COIL: int data = (req[offset + 3] <<
  8) + req[offset + 4]; No prior length check.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Crash or OOB-read report when the data bytes are missing.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: A client can send an incomplete write-single-coil request to trigger this.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 901
confidence: 0.85
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-005
viewpoint: ai-source-review
property: memory-safety
hypothesis: For WRITE_SINGLE_REGISTER, if the request is shorter than header_length+5,
  reading the two-byte data at req[offset+3]/[+4] is out of bounds.
evidence_source: 'case MODBUS_FC_WRITE_SINGLE_REGISTER: int data = (req[offset + 3]
  << 8) + req[offset + 4]; No req_length check.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Crash or sanitizer OOB-read when processing a truncated write-single-register
  request.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Mirrors the issue in WRITE_SINGLE_COIL.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 933
confidence: 0.85
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-006
viewpoint: ai-source-review
property: memory-safety
hypothesis: For WRITE_MULTIPLE_COILS, if the request is shorter than header_length+6,
  reading nb_bits at req[offset+5] is out of bounds; additionally, later consumption
  of value bytes assumes their presence without checking req_length.
evidence_source: 'case MODBUS_FC_WRITE_MULTIPLE_COILS: int nb_bits = req[offset +
  5]; ... modbus_set_bits_from_bytes(..., &req[offset + 6]); No validation that req_length
  >= offset+6+byte_count.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Crash or OOB-read while parsing meta (nb_bits) or when the callee
  reads value bytes.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Even though logical consistency checks exist (nb_bits*8 < nb), there is no
  guarantee the declared number of bytes are actually present in the received buffer.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 943
confidence: 0.84
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-007
viewpoint: ai-source-review
property: memory-safety
hypothesis: In WRITE_MULTIPLE_COILS, copying 4 bytes from req + rsp_length to rsp
  assumes those 4 bytes exist; if the request is truncated before those meta fields,
  memcpy reads past the end of req.
evidence_source: memcpy(rsp + rsp_length, req + rsp_length, 4); with rsp_length from
  build_response_basis; no check that req_length >= rsp_length + 4.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read (and potential information leak) or crash during
  memcpy when the request is too short.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: This can echo uninitialized/out-of-bounds memory back to the peer if it doesn't
  immediately crash.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 973
confidence: 0.83
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-008
viewpoint: ai-source-review
property: memory-safety
hypothesis: For WRITE_MULTIPLE_REGISTERS, the loop reading register values blindly
  dereferences req[offset + j] and req[offset + j + 1]; if the request does not contain
  2*nb value bytes, this is out of bounds.
evidence_source: for (..., j = 6; ...; j += 2) { mb_mapping->tab_registers[i] = (req[offset
  + j] << 8) + req[offset + j + 1]; } No check that req_length >= offset + 6 + 2*nb.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Crash or sanitizer OOB-read when value bytes are missing or truncated.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Although nb_bytes is compared to nb*2, there is no verification that those
  bytes are actually present in the buffer.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 1007
confidence: 0.88
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-009
viewpoint: ai-source-review
property: memory-safety
hypothesis: In WRITE_MULTIPLE_REGISTERS, copying 4 bytes (address and count) from
  req + rsp_length assumes those 4 bytes exist; a truncated request leads to memcpy
  reading past req.
evidence_source: memcpy(rsp + rsp_length, req + rsp_length, 4); No validation that
  req_length >= rsp_length + 4.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read or crash in memcpy when processing malformed
  requests.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Similar echo of meta fields as in WRITE_MULTIPLE_COILS, with same lack of bounds
  checking.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 1014
confidence: 0.82
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-010
viewpoint: ai-source-review
property: memory-safety
hypothesis: For MASK_WRITE_REGISTER, if the request is shorter than header_length+7,
  reading the AND/OR masks at req[offset+3..+6] is out of bounds.
evidence_source: uint16_t and = (req[offset + 3] << 8) + req[offset + 4]; uint16_t
  or = (req[offset + 5] << 8) + req[offset + 6]; No req_length checks.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Crash or OOB-read report on truncated mask-write requests.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: This path also memcpy’s the entire request back into the response earlier in
  other cases, but here the direct reads are clearly unchecked.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 1054
confidence: 0.84
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-011
viewpoint: ai-source-review
property: memory-safety
hypothesis: For WRITE_AND_READ_REGISTERS, the loop that writes values reads req[offset
  + j] and req[offset + j + 1] without checking that 2*nb_write bytes are present;
  a truncated request causes OOB reads.
evidence_source: for (..., j = 10; ...; j += 2) { mb_mapping->tab_registers[i] = (req[offset
  + j] << 8) + req[offset + j + 1]; } No check that req_length >= offset + 10 + 2*nb_write.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Crash or ASan OOB-read when the declared write count does not match
  the provided byte payload.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Only nb_write_bytes is compared to nb_write*2, but the buffer length itself
  is not validated.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 1109
confidence: 0.88
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

```yaml
candidate_id: CAND-012
viewpoint: ai-source-review
property: memory-safety
hypothesis: modbus_reply_exception reads slave/function from req without validating
  that the request buffer is long enough; a too-short req causes OOB reads.
evidence_source: offset = ctx->backend->header_length; slave = req[offset - 1]; function
  = req[offset]; No length checks.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Crash or sanitizer OOB-read when building an exception response
  for a truncated request.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Same missing length validation pattern as in modbus_reply's header parsing.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply_exception
  line: 1157
confidence: 0.78
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 2
```

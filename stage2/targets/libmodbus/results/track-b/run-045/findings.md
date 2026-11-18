# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: When a Modbus server calls modbus_reply with a too-short request (shorter
  than header_length+1..3), it reads past the end of the request buffer while extracting
  function/address because it does not validate req_length before indexing req[offset]
  and req[offset+1..2].
evidence_source: 'In modbus_reply: offset = ctx->backend->header_length; slave = req[offset
  - 1]; function = req[offset]; address = (req[offset + 1] << 8) + req[offset + 2];
  No checks that req_length >= offset+3 before these reads.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read leading to SIGSEGV or AddressSanitizer out-of-bounds
  read report when presented with a truncated Modbus request.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: This is the first occurrence; subsequent case handling performs many more unchecked
  req[...] accesses. Even if some backends normally deliver full frames, this function
  itself does not enforce req_length, making it brittle to malformed/truncated frames.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 723
confidence: 0.85
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: A truncated READ_COILS/READ_DISCRETE_INPUTS request that lacks the two-byte
  quantity field will cause modbus_reply to read beyond the end of req when computing
  nb at req[offset+3/4].
evidence_source: 'In modbus_reply, case MODBUS_FC_READ_COILS/MODBUS_FC_READ_DISCRETE_INPUTS:
  int nb = (req[offset + 3] << 8) + req[offset + 4]; No prior check that req_length
  >= offset+5.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read; potential crash or sanitizer report on malformed
  short request.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Similar pattern exists in other read functions; included here as a concrete
  example of missing per-function minimal-length validation.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 739
confidence: 0.78
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

```yaml
candidate_id: CAND-003
viewpoint: ai-source-review
property: memory-safety
hypothesis: A truncated WRITE_MULTIPLE_COILS request with header present but missing
  or short value bytes will cause modbus_reply to pass a pointer into req[offset+6]
  to modbus_set_bits_from_bytes, which will read beyond the end of the request buffer.
evidence_source: 'In modbus_reply, case MODBUS_FC_WRITE_MULTIPLE_COILS: int nb = (req[offset
  + 3] << 8) + req[offset + 4]; int nb_bits = req[offset + 5]; ... modbus_set_bits_from_bytes(...,
  nb, &req[offset + 6]); There is no check that req_length >= offset + 6 + byte_count.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read inside modbus_set_bits_from_bytes when it consumes
  nb bits from a truncated buffer; likely crash or sanitizer report.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The code validates nb and nb_bits relation but not that the indicated byte_count
  bytes are actually present in the received frame.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 863
confidence: 0.83
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

```yaml
candidate_id: CAND-004
viewpoint: ai-source-review
property: memory-safety
hypothesis: A truncated WRITE_MULTIPLE_REGISTERS request with missing register value
  bytes will cause modbus_reply to read past req end in the loop that consumes 2*nb
  bytes starting at offset+6.
evidence_source: 'In modbus_reply, case MODBUS_FC_WRITE_MULTIPLE_REGISTERS: for (i
  = mapping_address, j = 6; i < mapping_address + nb; i++, j += 2) { mb_mapping->tab_registers[i]
  = (req[offset + j] << 8) + req[offset + j + 1]; } No check that req_length >= offset
  + 6 + 2*nb.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read while dereferencing req[offset + j] and req[offset
  + j + 1]; crash or sanitizer finding on malformed short request.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Only nb and nb_bytes consistency is checked; there is no enforcement that those
  bytes were actually received.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 893
confidence: 0.86
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

```yaml
candidate_id: CAND-005
viewpoint: ai-source-review
property: memory-safety
hypothesis: A truncated WRITE_AND_READ_REGISTERS request that omits or shortens the
  write-value payload will cause modbus_reply to read past req end in the loop starting
  at j=10 that consumes 2*nb_write bytes.
evidence_source: 'In modbus_reply, case MODBUS_FC_WRITE_AND_READ_REGISTERS: nb, address_write,
  nb_write, nb_write_bytes read at offsets +3..+9; then for (i = mapping_address_write,
  j = 10; i < mapping_address_write + nb_write; i++, j += 2) { mb_mapping->tab_registers[i]
  = (req[offset + j] << 8) + req[offset + j + 1]; } No check that req_length >= offset
  + 10 + 2*nb_write.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read on req in the loop; likely crash or sanitizer
  report when handling a maliciously short frame.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The function validates counts and addresses but not the actual buffer length
  relative to the declared byte count.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 981
confidence: 0.86
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

```yaml
candidate_id: CAND-006
viewpoint: ai-source-review
property: memory-safety
hypothesis: Calling modbus_reply_exception with a too-short req (shorter than header_length+1)
  causes out-of-bounds reads when extracting slave and function from req without checking
  length.
evidence_source: 'In modbus_reply_exception: offset = ctx->backend->header_length;
  slave = req[offset - 1]; function = req[offset]; No validation of req length.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Out-of-bounds read; potential crash or sanitizer report when invoked
  with truncated request data.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: This mirrors the header parsing issue in modbus_reply; the API does not enforce
  req_length here at all (dummy_length is not used for bounds).
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply_exception
  line: 1023
confidence: 0.8
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

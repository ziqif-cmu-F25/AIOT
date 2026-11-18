# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply, if a malicious client sends a request shorter than the
  minimal PDU (header + function + address), reading address = (req[offset+1]<<8)
  + req[offset+2] will access beyond the end of req, causing an out-of-bounds read.
evidence_source: 'modbus_reply reads fields without verifying req_length: offset set
  from backend->header_length, then uses req[offset], req[offset+1], req[offset+2]
  immediately.

  Lines 721-725: slave = req[offset - 1]; function = req[offset]; address = (req[offset
  + 1] << 8) + req[offset + 2];'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: With a truncated request buffer, AddressSanitizer or valgrind will
  report an out-of-bounds read; in production this can crash the server.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: No check exists to ensure req_length >= offset+3 before these dereferences.
  The server relies on external caller/backend to supply a sufficiently long buffer,
  but attacker-controlled inputs can be shorter.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 723
confidence: 0.73
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply handling of READ_COILS/READ_DISCRETE_INPUTS, if the request
  is shorter than expected, reading the quantity field at req[offset+3] and req[offset+4]
  will read past the end of the buffer.
evidence_source: 'Lines 736-744: int nb = (req[offset + 3] << 8) + req[offset + 4];
  No prior verification that req_length >= offset+5.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: A truncated request will cause an out-of-bounds read detected by
  sanitizers or a crash.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Similar missing-length checks appear in other function handlers; this candidate
  highlights the coil/input read case specifically.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 739
confidence: 0.72
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-003
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply handling of WRITE_SINGLE_COIL, a truncated request lacking
  the two data bytes (offset+3, offset+4) will be dereferenced leading to an out-of-bounds
  read.
evidence_source: 'Lines 804-812: int data = (req[offset + 3] << 8) + req[offset +
  4]; No req_length check before accessing these bytes.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Process crash or sanitizer out-of-bounds-read when a short WRITE_SINGLE_COIL
  frame is received.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The same pattern occurs in WRITE_SINGLE_REGISTER.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 806
confidence: 0.71
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-004
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply handling of WRITE_SINGLE_REGISTER, a truncated request
  without two data bytes causes an out-of-bounds read at req[offset+3] and req[offset+4].
evidence_source: 'Lines 831-837: int data = (req[offset + 3] << 8) + req[offset +
  4]; No validation of req_length.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Crash or sanitizer report due to reading beyond end of input buffer
  when WRITE_SINGLE_REGISTER is malformed.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The code proceeds to memcpy the whole request to the response, which is a separate
  potential issue if req_length is oversized (see separate candidate).
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 832
confidence: 0.71
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-005
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply handling of WRITE_MULTIPLE_COILS, the code uses nb_bits
  (byte count) to process data starting at &req[offset+6] without verifying the request
  actually contains nb_bits bytes; this can cause an out-of-bounds read when modbus_set_bits_from_bytes
  dereferences past the end of req.
evidence_source: 'Lines 841-869: nb = (req[offset+3]<<8)+..., nb_bits = req[offset+5];
  ... modbus_set_bits_from_bytes(..., &req[offset + 6]); There is no check that req_length
  >= offset + 6 + nb_bits.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: With an underlength request (declaring a larger byte count than
  actually sent), the server will read past the end of the input buffer, causing a
  crash or sanitizer report.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The code validates logical consistency (nb_bits*8 < nb) and mapping bounds
  but never validates actual buffer length before consuming nb_bits bytes.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 863
confidence: 0.78
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-006
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply handling of WRITE_MULTIPLE_REGISTERS, the loop reads 2*nb
  data bytes at req[offset+6 ... offset+6+2*nb-1] without ensuring the request buffer
  contains that many bytes; a truncated frame will cause out-of-bounds reads.
evidence_source: 'Lines 888-895: for (i = ..., j = 6; i < ...; i++, j += 2) { mb_mapping->tab_registers[i]
  = (req[offset + j] << 8) + req[offset + j + 1]; } No check of req_length >= offset
  + 6 + 2*nb.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Malformed request leads to reads beyond the input buffer and potential
  crash or memory error detection.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Only the declared byte count (nb_bytes) is checked to equal nb*2; the actual
  buffer length is not validated.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 894
confidence: 0.79
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-007
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply handling of WRITE_AND_READ_REGISTERS, the write phase
  reads 2*nb_write bytes starting at req[offset+10] without verifying the buffer is
  that long; a truncated request causes out-of-bounds reads.
evidence_source: 'Lines 976-983: for (i = ..., j = 10; i < mapping_address_write +
  nb_write; i++, j += 2) { mb_mapping->tab_registers[i] = (req[offset + j] << 8) +
  req[offset + j + 1]; } There is no check of req_length >= offset + 10 + 2*nb_write.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Process may crash or sanitizers report out-of-bounds-read when
  the declared write byte-count does not match buffer length.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: nb_write_bytes is checked to equal nb_write*2 but the underlying buffer length
  is never enforced.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 982
confidence: 0.79
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

```yaml
candidate_id: CAND-008
viewpoint: ai-source-review
property: memory-safety
hypothesis: In modbus_reply, echoing request into response via memcpy(rsp, req, req_length)
  can overflow the fixed-size stack buffer rsp[MAX_MESSAGE_LENGTH] if req_length exceeds
  MAX_MESSAGE_LENGTH (e.g., due to inconsistent length handling in the backend or
  caller).
evidence_source: 'Lines 810-812 (WRITE_SINGLE_COIL), 834-836 (WRITE_SINGLE_REGISTER),
  942-944 (MASK_WRITE_REGISTER): memcpy(rsp, req, req_length); rsp_length = req_length;
  There is no bounds check ensuring req_length <= MAX_MESSAGE_LENGTH.'
input_artifact: not_available (static source review; no input artifact)
expected_behavior: If req_length is larger than rsp's capacity, a stack buffer overflow
  occurs, likely leading to a crash or exploitable memory corruption.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Although typical backends cap ADU size, this function trusts the provided req_length.
  Defensive code should bound req_length to MAX_MESSAGE_LENGTH before memcpy.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: modbus_reply
  line: 811
confidence: 0.62
model: openai/gpt-5
prompt_id: libmodbus-0367-source-review@v1
run_index: 3
```

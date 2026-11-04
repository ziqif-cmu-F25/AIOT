# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: If a client sends a truncated Modbus request whose total length is less
  than header_length + 3 bytes, modbus_reply() will read req[offset + 1] and req[offset
  + 2] past the end of the buffer when computing the address, causing an out-of-bounds
  read.
evidence_source: "In modbus_reply():\n  offset = ctx->backend->header_length;\n  slave\
  \ = req[offset - 1];\n  function = req[offset];\n  address = (req[offset + 1] <<\
  \ 8) + req[offset + 2];"
input_artifact: not_available (static source review; no input artifact)
expected_behavior: With a short frame, the process may crash with a segmentation fault
  or AddressSanitizer out-of-bounds read report when accessing req[offset + 1] or
  req[offset + 2].
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: No validation of req_length is performed before indexing into req. This occurs
  before any per-function validation and is attacker-reachable whenever the server
  passes an undersized request buffer to modbus_reply.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 798
confidence: 0.86
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 3
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: A crafted MODBUS_FC_WRITE_MULTIPLE_REGISTERS request that declares nb
  and nb_bytes but is truncated (i.e., does not include 2*nb data bytes) will cause
  modbus_reply() to read beyond the end of the req buffer inside the loop copying
  register values.
evidence_source: "In modbus_reply(), case MODBUS_FC_WRITE_MULTIPLE_REGISTERS:\n  int\
  \ nb = (req[offset + 3] << 8) + req[offset + 4];\n  int nb_bytes = req[offset +\
  \ 5];\n  ...\n  for (i = mapping_address, j = 6; i < mapping_address + nb; i++,\
  \ j += 2) {\n      mb_mapping->tab_registers[i] = (req[offset + j] << 8) + req[offset\
  \ + j + 1];\n  }"
input_artifact: not_available (static source review; no input artifact)
expected_behavior: If the request buffer is shorter than offset + 6 + 2*nb, reading
  req[offset + j] or req[offset + j + 1] will go out of bounds, leading to a crash
  or sanitizer OOB read report.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: There is no check that the received request contains the declared number of
  data bytes before indexing. Even if nb_bytes is inconsistent, only a value-range
  check is performed; the actual buffer length is not validated.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 1008
confidence: 0.84
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 3
```

```yaml
candidate_id: CAND-003
viewpoint: ai-source-review
property: memory-safety
hypothesis: A crafted MODBUS_FC_WRITE_AND_READ_REGISTERS request that is truncated
  before the write-data section (less than 2*nb_write bytes after the 10-byte meta)
  will cause modbus_reply() to read past the end of the req buffer while copying write
  values.
evidence_source: "In modbus_reply(), case MODBUS_FC_WRITE_AND_READ_REGISTERS:\n  int\
  \ nb_write = (req[offset + 7] << 8) + req[offset + 8];\n  int nb_write_bytes = req[offset\
  \ + 9];\n  ...\n  for (i = mapping_address_write, j = 10; i < mapping_address_write\
  \ + nb_write; i++, j += 2) {\n      mb_mapping->tab_registers[i] = (req[offset +\
  \ j] << 8) + req[offset + j + 1];\n  }"
input_artifact: not_available (static source review; no input artifact)
expected_behavior: If the incoming frame is shorter than offset + 10 + 2*nb_write,
  the loop will read beyond the end of req, likely causing a crash or an AddressSanitizer
  OOB read report.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Only value-range checks are performed (nb_write bounds and nb_write_bytes ==
  nb_write*2). There is no verification that the buffer actually contains the declared
  number of data bytes before dereferencing req[offset + j].
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 1109
confidence: 0.83
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 3
```

```yaml
candidate_id: CAND-004
viewpoint: ai-source-review
property: memory-safety
hypothesis: In MODBUS_FC_WRITE_MULTIPLE_COILS handling, a truncated request (shorter
  than offset + 10 for nb bits) will cause memcpy(rsp + rsp_length, req + rsp_length,
  4) to read past the end of req when echoing address and quantity fields.
evidence_source: "In modbus_reply(), case MODBUS_FC_WRITE_MULTIPLE_COILS:\n  rsp_length\
  \ = ctx->backend->build_response_basis(&sft, rsp);\n  /* 4 to copy the bit address\
  \ (2) and the quantity of bits */\n  memcpy(rsp + rsp_length, req + rsp_length,\
  \ 4);"
input_artifact: not_available (static source review; no input artifact)
expected_behavior: If req has fewer than rsp_length + 4 bytes, memcpy will read past
  the end of req, which may crash or trigger a sanitizer OOB read report.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: rsp_length is assumed to align with the location of the address/quantity fields
  in the request, but the actual request length is never validated before the memcpy.
vulnerability_class: out-of-bounds-read
location:
  file: src/modbus.c
  function: modbus_reply
  line: 973
confidence: 0.78
model: openai/gpt-5
prompt_id: libmodbus-modbus-reply@v1
run_index: 3
```

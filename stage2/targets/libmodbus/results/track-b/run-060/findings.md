# Candidate findings

Status values: candidate | validated | rejected | inconclusive

Written by stage2/driver/run_task.py. Do not edit; scoring writes
verdict.md instead. Machine-readable copy: candidates.json.

```yaml
candidate_id: CAND-001
viewpoint: ai-source-review
property: memory-safety
hypothesis: A write-and-read-registers request can write before the holding-register
  allocation when its write address precedes the configured mapping start. The bounds
  check tests mapping_address twice and never rejects a negative mapping_address_write.
evidence_source: Lines 952-953 calculate separate read and write mapping offsets.
  Lines 962-965 check mapping_address < 0 twice, while checking only the upper bound
  of the write range. Lines 978-981 subsequently index tab_registers using mapping_address_write.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: An out-of-bounds write before tab_registers, potentially producing
  an AddressSanitizer heap-buffer-overflow report, heap corruption, or a crash.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: Requires a mapping with a nonzero start_registers and otherwise valid request
  quantities and payload length. The defect does not depend on a truncated frame or
  on bypassing the receive-side maximum-length check. Replace the repeated read-offset
  check with mapping_address_write < 0.
vulnerability_class: buffer-overflow
location:
  file: modbus.c
  function: modbus_reply
  line: 964
confidence: 0.99
model: openai/gpt-6.1-sol
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

```yaml
candidate_id: CAND-002
viewpoint: ai-source-review
property: memory-safety
hypothesis: modbus_reply reads request fields without first checking that req_length
  covers them. In particular, it unconditionally reads an address even for requests
  whose function has no address field, and truncated requests passed to this API can
  cause further reads beyond the supplied request.
evidence_source: Lines 721-724 read the slave, function, and two address bytes without
  any req_length validation. compute_meta_length_after_function assigns zero metadata
  bytes to report-slave-ID and read-exception-status requests at lines 267-269, so
  those requests need not contain the address bytes read at line 724. Function-specific
  field and payload reads likewise lack comparisons against req_length.
input_artifact: not_available (static source review; no input artifact)
expected_behavior: Reads beyond the received message; an exactly sized request allocation
  can produce an out-of-bounds-read sanitizer report or a crash. With a larger receive
  buffer, the accesses may instead read uninitialized or stale bytes without crossing
  the allocation boundary.
observed_behavior: not_available (static source review; nothing was executed)
status: candidate
oracle_verdict: pending
notes: The unnecessary address read is visible even for a complete addressless request,
  although its value is not used by those handlers. Reachability of other truncated-field
  reads depends on whether the caller or the unseen backend permits such requests
  to reach modbus_reply; the shown staged receiver normally obtains the declared metadata
  and payload before returning. Validate the request length before each applicable
  field access and parse addresses only for functions that contain them.
vulnerability_class: out-of-bounds-read
location:
  file: modbus.c
  function: modbus_reply
  line: 724
confidence: 0.95
model: openai/gpt-6.1-sol
prompt_id: libmodbus-0367-source-review@v1
run_index: 2
```

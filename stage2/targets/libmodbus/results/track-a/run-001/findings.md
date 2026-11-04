# Candidate findings — Track A run-001

Status values: candidate | validated | rejected | inconclusive

```yaml
candidate_id: CAND-001
track: track-a
property: memory-safety
hypothesis: >
  A Modbus Read/Write Multiple Registers (function 0x17) request whose write
  range exceeds the server's register mapping causes modbus_reply to write past
  the heap buffer (the register mapping), a heap buffer overflow.
evidence_source: >
  outputs/fn17_trigger.json (server_dropped=true on a crafted fn-0x17 frame)
  and outputs/fn17_trigger.asan.txt (ASan heap-buffer-overflow at
  modbus.c:980 in modbus_reply). Raw server .log files are gitignored (*.log);
  the ASan report is preserved as the .asan.txt copy.
input_artifact: outputs/fn17_trigger.input.bin
expected_behavior: >
  Server aborts with an AddressSanitizer heap-buffer-overflow in the fn-0x17
  write path; the TCP connection drops with no valid reply.
observed_behavior: >
  server_dropped=true, eof=true; ASan reported heap-buffer-overflow WRITE at
  modbus.c:980 in modbus_reply. Replay against a fresh instance
  (outputs/fn17_replay.*) reproduced the same crash.
status: validated
oracle_verdict: >
  validated — reproducible memory-safety crash in the Modbus register-write
  path of modbus_reply, matching CVE-2022-0367 (heap buffer overflow, fixed in
  v3.1.7 by commit b4ef4c17). Reproduced on a freshly started instance.
notes: >
  Light, ground-truth-grounded Track A finding. Its role in Stage 2 is to
  anchor the traditional-workflow walkthrough in notes.md and the AI-assist map,
  not to serve as a blind-discovery result.
```

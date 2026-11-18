# Evaluator verdict

Run: run-014  Task: libmodbus-modbus-reply  Prompt: libmodbus-modbus-reply@v1
Model requested: openai/gpt-5  resolved: ['openai/gpt-5']
Scored: 2026-11-04T03:17:09Z by stage2/scoring/score_run.py

**Run verdict: rejected** — all candidates are false positives w.r.t. this ground truth

Expected: `src/modbus.c` `modbus_reply` lines [906, 937] (±2), class `buffer-overflow`
Ground truth: `stage2/scoring/ground_truth/libmodbus-modbus-reply.yaml` sha256 `18de5990cfca847b…`

| Candidate | Reported location | Class | Conf. | file | function | line | class | Status | Oracle verdict |
| --- | --- | --- | --- | :---: | :---: | :---: | :---: | --- | --- |
| CAND-001 | `src/modbus.c` `modbus_reply`:797 | out-of-bounds-read | 0.9 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-002 | `src/modbus.c` `modbus_reply`:813 | out-of-bounds-read | 0.86 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-003 | `src/modbus.c` `modbus_reply`:854 | out-of-bounds-read | 0.86 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-004 | `src/modbus.c` `modbus_reply`:901 | out-of-bounds-read | 0.85 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-005 | `src/modbus.c` `modbus_reply`:933 | out-of-bounds-read | 0.85 | ✓ | ✓ | ✓ | ✗ | rejected | false_positive |
| CAND-006 | `src/modbus.c` `modbus_reply`:943 | out-of-bounds-read | 0.84 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-007 | `src/modbus.c` `modbus_reply`:973 | out-of-bounds-read | 0.83 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-008 | `src/modbus.c` `modbus_reply`:1007 | out-of-bounds-read | 0.88 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-009 | `src/modbus.c` `modbus_reply`:1014 | out-of-bounds-read | 0.82 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-010 | `src/modbus.c` `modbus_reply`:1054 | out-of-bounds-read | 0.84 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-011 | `src/modbus.c` `modbus_reply`:1109 | out-of-bounds-read | 0.88 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-012 | `src/modbus.c` `modbus_reply_exception`:1157 | out-of-bounds-read | 0.78 | ✓ | ✗ | ✗ | ✗ | rejected | false_positive |

`false_positive` is relative to this task's ground truth only; a rejected
candidate may still be a different real defect and is preserved as recorded.
Original candidate records (candidates.json, findings.md) are unmodified.

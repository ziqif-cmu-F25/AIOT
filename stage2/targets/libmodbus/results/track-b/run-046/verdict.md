# Evaluator verdict

Run: run-046  Task: libmodbus-0367-source-review  Prompt: libmodbus-0367-source-review@v1
Model requested: openai/gpt-5  resolved: ['openai/gpt-5']
Scored: 2026-11-04T08:31:42Z by stage2/scoring/score_run.py

**Run verdict: inconclusive** — right file/function/class, line outside tolerance

Expected: `modbus.c` `modbus_reply` lines [962, 980] (±3), class `buffer-overflow`
Ground truth: `stage2/scoring/ground_truth/libmodbus-0367-source-review.yaml` sha256 `51560a163ea07d09…`

| Candidate | Reported location | Class | Conf. | file | function | line | class | Status | Oracle verdict |
| --- | --- | --- | --- | :---: | :---: | :---: | :---: | --- | --- |
| CAND-001 | `modbus.c` `modbus_reply`:723 | out-of-bounds-read | 0.73 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-002 | `modbus.c` `modbus_reply`:739 | out-of-bounds-read | 0.72 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-003 | `modbus.c` `modbus_reply`:806 | out-of-bounds-read | 0.71 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-004 | `modbus.c` `modbus_reply`:832 | out-of-bounds-read | 0.71 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-005 | `modbus.c` `modbus_reply`:863 | out-of-bounds-read | 0.78 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-006 | `modbus.c` `modbus_reply`:894 | out-of-bounds-read | 0.79 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |
| CAND-007 | `modbus.c` `modbus_reply`:982 | out-of-bounds-read | 0.79 | ✓ | ✓ | ✓ | ✗ | rejected | false_positive |
| CAND-008 | `modbus.c` `modbus_reply`:811 | buffer-overflow | 0.62 | ✓ | ✓ | ✗ | ✓ | inconclusive | location_partial_match |

`false_positive` is relative to this task's ground truth only; a rejected
candidate may still be a different real defect and is preserved as recorded.
Original candidate records (candidates.json, findings.md) are unmodified.

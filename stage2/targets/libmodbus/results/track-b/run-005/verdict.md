# Evaluator verdict

Run: run-005  Task: libmodbus-modbus-reply  Prompt: libmodbus-modbus-reply@v1
Model requested: anthropic/claude-haiku-5.5  resolved: ['anthropic/claude-haiku-5.5']
Scored: 2026-11-04T02:33:30Z by stage2/scoring/score_run.py

**Run verdict: rejected** — all candidates are false positives w.r.t. this ground truth

Expected: `src/modbus.c` `modbus_reply` lines [906, 937] (±2), class `buffer-overflow`
Ground truth: `stage2/scoring/ground_truth/libmodbus-modbus-reply.yaml` sha256 `18de5990cfca847b…`

| Candidate | Reported location | Class | Conf. | file | function | line | class | Status | Oracle verdict |
| --- | --- | --- | --- | :---: | :---: | :---: | :---: | --- | --- |
| CAND-001 | `src/modbus.c` `modbus_reply`:798 | out-of-bounds-read | 0.3 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |

`false_positive` is relative to this task's ground truth only; a rejected
candidate may still be a different real defect and is preserved as recorded.
Original candidate records (candidates.json, findings.md) are unmodified.

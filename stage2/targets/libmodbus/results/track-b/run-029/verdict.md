# Evaluator verdict

Run: run-029  Task: libmodbus-modbus-reply-ctx  Prompt: libmodbus-modbus-reply-ctx@v1
Model requested: openai/gpt-5  resolved: ['openai/gpt-5']
Scored: 2026-11-04T03:35:51Z by stage2/scoring/score_run.py

**Run verdict: rejected** — all candidates are false positives w.r.t. this ground truth

Expected: `src/modbus.c` `modbus_reply` lines [906, 937] (±2), class `buffer-overflow`
Ground truth: `stage2/scoring/ground_truth/libmodbus-modbus-reply-ctx.yaml` sha256 `40ec538f60dc3fd3…`

| Candidate | Reported location | Class | Conf. | file | function | line | class | Status | Oracle verdict |
| --- | --- | --- | --- | :---: | :---: | :---: | :---: | --- | --- |
| CAND-001 | `src/modbus.c` `modbus_reply`:798 | out-of-bounds-read | 0.78 | ✓ | ✓ | ✗ | ✗ | rejected | false_positive |

`false_positive` is relative to this task's ground truth only; a rejected
candidate may still be a different real defect and is preserved as recorded.
Original candidate records (candidates.json, findings.md) are unmodified.

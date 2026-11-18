# Evaluator verdict

Run: run-035  Task: libmodbus-0367-source-review  Prompt: libmodbus-0367-source-review@v1
Model requested: anthropic/claude-haiku-5.5  resolved: ['anthropic/claude-haiku-5.5']
Scored: 2026-11-04T08:31:41Z by stage2/scoring/score_run.py

**Run verdict: validated** — a candidate matches the expected finding

Expected: `modbus.c` `modbus_reply` lines [962, 980] (±3), class `buffer-overflow`
Ground truth: `stage2/scoring/ground_truth/libmodbus-0367-source-review.yaml` sha256 `51560a163ea07d09…`

| Candidate | Reported location | Class | Conf. | file | function | line | class | Status | Oracle verdict |
| --- | --- | --- | --- | :---: | :---: | :---: | :---: | --- | --- |
| CAND-001 | `modbus.c` `modbus_reply`:965 | buffer-overflow | 0.7 | ✓ | ✓ | ✓ | ✓ | validated | true_positive |

`false_positive` is relative to this task's ground truth only; a rejected
candidate may still be a different real defect and is preserved as recorded.
Original candidate records (candidates.json, findings.md) are unmodified.

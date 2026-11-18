# Status — personal Stage 2 package

Updated after automated acceptance on this machine.

## Completed by the agent (environment & scaffolding)

| Item | Status | Evidence |
| --- | --- | --- |
| Docker daemon usable | PASS | `results/acceptance/summary.txt` PS2-00 |
| Target freeze (Mongoose 7.21 / skip_chunk class) | FROZEN | `results/acceptance/freeze-record.md` |
| Docker blackbox build + healthy target | PASS | PS2-01, PS2-02 |
| Ordinary HTTP GET | PASS | PS2-03 |
| Saved request replay after restart | PASS | PS2-04 |
| Chunked request delivery smoke | PASS | PS2-05 |
| Exact-buffer ASan oracle (7.21 vs 7.22 logic) | PASS | PS2-06, `results/acceptance/oracle/` |
| Traditional run templates | Ready | `traditional/` |
| AI task + vendored excerpt + prompts | Ready | `ai/`, `../stage2/tasks/mongoose-chunked-review.yaml` |
| Comparison report + video script scaffolds | Ready | `report/` |

## Must be done by you (integrity rules)

1. **Traditional 90-minute investigation without AI** — follow `traditional/README.md`. The agent cannot perform this and label it a no-AI baseline.
2. **AI-assisted investigation** after traditional is sealed — needs root `.env` with OpenRouter credentials (`cp stage2/.env.example .env`).
3. **Fill** `report/COMPARISON_REPORT.md` with numbers traced to run logs.
4. **Record** `report/demo.mp4` (60–120 s) per `report/VIDEO_SCRIPT.md`.

## Defaults honored

- Personal experiment only; Markdown + evidence + MP4 delivery.
- Existing Python/Docker tooling reused; no new application framework.
- Analyst materials omit CVE/PoC; evaluator holds the matching rule.

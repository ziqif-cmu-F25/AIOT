# Structured deliverables index

```text
personal-stage2/structured/
  INDEX.md                          ← this file
  01-traditional/
    REPORT.md                       ← traditional report
    run/                            ← full run-001 mirror
    assets/{inputs,outputs,oracle}/
  02-ai-assisted/
    REPORT.md                       ← AI-assisted report
    run/                            ← full run-001 mirror
    assets/{inputs,outputs,oracle,prompts,model-outputs}/
  03-video/
    VIDEO_SCRIPT.md                 ← script for you to record
    demo.mp4                        ← (you add after recording)
```

## Integrity summary

| Item | Note |
| --- | --- |
| Traditional | Agent-executed per user request; **not** a human no-AI baseline |
| AI-assisted | Same agent; OpenRouter key missing → session model + local transcripts |
| Validated findings | Traditional T3 `ab\r` and AI A1 `cd\r` both `ORACLE_MATCH=yes` |

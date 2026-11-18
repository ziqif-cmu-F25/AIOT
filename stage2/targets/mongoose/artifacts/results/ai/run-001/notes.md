# Investigation notes (AI-assisted)

Viewpoint: ai-assisted
Run id: run-001
Target commit: b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116
Condition: ai-assisted

Traditional run sealed before this condition started.

## AI assistance

- Model: cursor-composer (OpenRouter `.env` missing; used session model as assistant)
- Prompt id: mongoose-chunked-review@v1
- Context: stage2/vendor/mongoose/http_chunk_excerpt.c (dry-run prompt saved)
- Human edits: 2 on CAND-001 request; 1 on CAND-002 headers
- Cost (USD): unknown / 0 billed via OpenRouter
- Fixed-prompt repeats: 3 (variance documented; not full investigations)

## Time log

| UTC | Elapsed (min) | Action |
| --- | --- | --- |
| start | 0 | new_run; load dry-run prompt |
|  | ~10 | AI full review candidates written |
|  | ~20 | 3 fixed-prompt repeats + diff note |
|  | ~30 | Human edit/send A1–A2; replay A1; oracle |
| end | ~35 | Seal AI artifacts |

## Deviations

- No OpenRouter API key; model outputs recorded locally rather than via stage2/driver live call.

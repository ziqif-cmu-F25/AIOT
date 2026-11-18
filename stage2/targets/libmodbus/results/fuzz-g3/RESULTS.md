# Fuzzing baseline (issue G3) — libmodbus CVE-2022-0367

5 trials per arm (distinct RNG seeds 1–5), equal budget of **1500 iterations**,
run against the ASan `target-0367` (v3.1.6) unit-test-server. The oracle is the
server aborting with an AddressSanitizer report (connection-drop alone is not
counted — the server is restarted on clean exits). Arms differ only in the seed
corpus the mutator starts from:

- **naive** — 3 generic valid frames (`read_holding_registers`,
  `read_write_multiple_registers`, `write_single_coil`).
- **AI-seeded** — the 7 model-drafted fn-0x17 frames from the input-drafting
  condition (which include 2 oracle-confirmed working triggers).

## Results

| arm | crash rate | iterations-to-crash (per trial) | median iters | median time |
|---|---|---|---|---|
| naive | **5/5** | 149, 180, 226, 250, 959 | 226 | 45.7 s |
| AI-seeded | **5/5** | 7, 17, 38, 47, 105 | **38** | **13.8 s** |

**AI seeding reaches the crash ~6× faster** (median 38 vs 226 iterations; 13.8 vs
45.7 s). Both arms find it reliably (5/5) given a field-aware mutator and ≥5 trials.

## This corrects the original report

The audit's fuzzing comparison was **one trial per arm** and claimed the
AI-seeded fuzzer "found nothing in 1,000 iterations." That was an artifact of the
single trial plus (as the input-drafting oracle later showed) the wrong
`start_registers` config in the drafting prompt — the old AI seeds targeted a
server mapping that didn't exist. With the corrected config and ≥5 trials, AI
seeds **accelerate** time-to-crash rather than hurt it.

## Honest caveat

The AI corpus contains **2 frames that are themselves working triggers**
(oracle-confirmed). So part of the speedup is simply that a seed at or next to the
crash needs little mutation. The fair reading is: **good seeds — including ones a
model can produce when handed the bug — materially accelerate fuzzing**, not that
the model is doing something the fuzzer couldn't eventually do alone. The naive
arm still finds it in a median 226 iterations, so the bug is shallow for a
field-aware mutator either way.

Raw per-trial results in `summary.json` and `*/trial*/fuzz_result.json`.

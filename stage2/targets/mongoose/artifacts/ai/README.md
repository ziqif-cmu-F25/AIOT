# AI-assisted analysis — same freeze, after traditional

Run **only after** your traditional run is finished and sealed (do not edit
traditional artifacts afterward except for evaluator verdicts).

## Shared constants (must match traditional)

- Target commit `b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116` (7.21)
- Endpoint `target:8000`
- 90-minute investigation budget for the **full** AI-assisted investigation
- Same candidate schema and `../evaluator/oracle` rules
- Allow-listed excerpt: `../../stage2/vendor/mongoose/http_chunk_excerpt.c`

## API setup (repo root)

```sh
cd ..   # Phase 1 repo root
cp stage2/.env.example .env
# edit .env: OPENROUTER_API_KEY=... and OPENROUTER_MODEL=...
python3 -m venv stage2/.venv
stage2/.venv/bin/python -m pip install -r stage2/requirements.txt
```

## One full investigation + three fixed-prompt repeats

```sh
cd ..   # Phase 1 repo root
PY=stage2/.venv/bin/python

# Dry-run: print exact prompt (no key required)
$PY stage2/driver/run_task.py mongoose-chunked-review --dry-run

# Full investigation call (counts for comparison once you also replay/oracle)
$PY stage2/driver/run_task.py mongoose-chunked-review \
  --results-root personal-stage2/results/ai

# Three fixed-prompt repeats (variance only; not three full investigations)
$PY stage2/driver/run_task.py mongoose-chunked-review --repeats 3 \
  --results-root personal-stage2/results/ai
```

Then, in Docker white-box/blackbox:

1. Review model candidates; edit HTTP drafts as needed.
2. Save under the run `inputs/`, send/replay with `http_client.py`.
3. On the host, run `../evaluator/oracle/run_oracle.sh` on the chunk **body**.
4. Record human edit count, minutes, and `stage2/results/cost_log.csv` rows.

If `.env` has no key, paste model outputs manually into the run directory and
mark `cost_usd` unknown — do not invent costs.

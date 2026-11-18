# Traditional analysis (no AI) — you must run this yourself

This directory only provides **forms and a checklist**. Filling them with
AI-generated investigation steps would invalidate the baseline.

## Preconditions

1. `../scripts/acceptance.sh` has passed on this machine.
2. You have **not** read `../evaluator/` or any AI candidate outputs for this target.
3. Budget: **90 minutes** investigation (Phase 1), separate clock for validation.

## Steps

```sh
cd ..
make whitebox   # or make blackbox
docker compose --profile whitebox exec whitebox \
  python3 /opt/lab/tools/new_run.py --viewpoint white-box --condition traditional \
  --results-root /workspace/results
# Note the printed run path, e.g. /workspace/results/run-001
```

On the host, that path maps to `results/whitebox/run-001/`.

1. Copy `templates/time_log.md` and `templates/candidate_ledger.md` into the run
   directory (or fill the run's `notes.md` / `findings.md` directly).
2. Follow Stage 1 Phase 0–3 from
   `../TRADITIONAL_VULNERABILITY_INVESTIGATION_PROCEDURE.md` (repo root), using
   HTTP tools instead of CoAP.
3. Save every tested request under `inputs/` and observations under `outputs/`.
4. Submit candidates for oracle evaluation using
   `../evaluator/oracle/run_oracle.sh` on the **body** of a chunked candidate
   (evaluator role; do this after investigation, on the host).
5. Stop at 90 minutes even if nothing validates. Negative results are valid.

## Allowed materials

- `config/target.lock`, `config/protocol.yaml`, `docs/protocol/*`
- White-box: `/home/analyst/src/mongoose` at the pinned commit
- Tools under `/opt/lab/tools`

## Forbidden during the measured traditional run

- Any AI chat, autocomplete used as analysis, or reading AI run artifacts
- `evaluator/ground_truth.yaml`, CVE writeups used as the answer key
- Switching the frozen target

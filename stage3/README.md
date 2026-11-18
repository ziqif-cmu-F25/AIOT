# Stage 3 agent harness

Shared loop: the model picks one tool, reads the observation, and updates
its hypothesis. A finished candidate stays `oracle_verdict: pending`. Check
it afterwards with the same oracle you used in Stage 2.

`source_root` is only the source tree the agent may read. Sending a packet
is a different setting, `run_target`.

## Budgets

Set these three in your target YAML under `limits`. The run stops when any
one of them is reached:

| Field | Effect |
| --- | --- |
| `max_steps` | Maximum model calls. |
| `max_output_tokens` | Maximum tokens in one model reply. Sent as `max_tokens`. |
| `max_cost_usd` | Maximum OpenRouter dollars for the whole run. |

The price is checked before the next call, using the `cost` field OpenRouter
returns. The call that crosses the cap is already paid for, so the total can
be slightly above `max_cost_usd` by at most one reply. If a response has no
dollar cost, that call is treated as spending the whole cap and the run stops.
`gpt-4o-mini` at 12 steps and 1500 output tokens is about $0.03, so the
libcoap pack uses `max_cost_usd: 0.10`.

`run.yaml` records all three limits and `spent_usd`. Each call is one line in
`usage.jsonl`.

## Clone and run on the in-repo libcoap target

From a fresh clone:

```sh
python3 -m venv stage2/.venv
stage2/.venv/bin/python -m pip install -r stage2/requirements.txt
cp stage2/.env.example .env
# edit .env and set OPENROUTER_API_KEY (and optionally OPENROUTER_MODEL)

chmod +x stage3/scripts/fetch_libcoap.sh
./stage3/scripts/fetch_libcoap.sh
docker compose --profile blackbox up -d --wait

cd stage3
../stage2/.venv/bin/python -m harness.run_harness targets/libcoap-stage1.yaml
```

That pack reads `stage3/vendor/libcoap` and sends each `run_target` datagram
through the already running blackbox container. The harness does not start
Docker itself. `--source-only` skips sending and Python execution.

Smoke test with no API key and no Docker (synthetic program, not libcoap):

```sh
cd stage3
../stage2/.venv/bin/python -m unittest discover -s tests -v
../stage2/.venv/bin/python -m harness.run_harness \
  targets/fixture-mini.yaml \
  --scripted targets/fixture/scripted_actions.json
```

## Use your own Stage 2 target

Copy `targets/TEMPLATE.yaml` to `targets/<your-id>.yaml` and set:

| Field | Meaning |
| --- | --- |
| `source_root` | Directory of that target's source. Not the repo root, not `evaluator/`. |
| `analyst_brief` | What the agent is allowed to know about the interface. No CVE, patch, or reference input. |
| `run_target.argv` | One command that receives `{input_file}` (host path of the saved bytes). |
| `run_target.cwd` | Working directory for that command. `..` is the repo root. |
| `limits.max_steps` | How many model calls this run may make. |
| `limits.max_output_tokens` | How many tokens one reply may use. |
| `limits.max_cost_usd` | How many dollars the whole run may spend. |

If your service is only reachable inside Compose, start it, then point
`argv` at `stage3/scripts/relay_docker.py` the same way
`targets/libcoap-stage1.yaml` does. `{guest_input}` and `{stem}` are
replaced inside the container. Each call keeps its own `input-NNN.bin`.

## What to hand back

`stage3/results/run-NNN/` contains `run.yaml`, `transcript.json`,
`commands.log`, `candidate.json`, `usage.jsonl`, and `scratch/`. Costs go to
`stage3/results/cost_log.csv`. The candidate is not a validated finding
until your Stage 2 oracle says so.

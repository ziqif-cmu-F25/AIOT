# Stage 1 libcoap investigation lab

Minimal Docker environment for **Stage 1: Traditional Vulnerability
Investigation** on a frozen [libcoap](https://github.com/obgm/libcoap) CoAP/UDP
server. It provides isolated black-box and white-box workspaces. It does not
include an AI agent, Stage 2/3 infrastructure, or a reference exploit.

Pinned target: libcoap `v4.3.5` (`7cf7465b784baded4de183290c547d582becfd28`).

## Quick Start

Requirements: Docker Engine with Compose v2, and permission to build images.

```sh
git clone <this-repo>
cd "<repo-root>"

# Black-box run (separate target instance)
docker compose --profile blackbox up -d --wait
docker compose --profile blackbox exec blackbox \
  python3 /opt/lab/tools/new_run.py
docker compose --profile blackbox exec blackbox \
  python3 /opt/lab/tools/coap_client.py send \
    --input /opt/lab/tools/inputs/get_wellknown.hex \
    --output-dir /workspace/results/run-001/outputs \
    --stem wellknown
```

If `new_run.py` printed `run-002` or similar, use that directory name instead of
`run-001`. The JSON printed by `coap_client.py` should show `"timed_out": false`
and a non-zero `response_len`.

Stop and reset:

```sh
./scripts/reset.sh blackbox
```

White-box (use a **fresh** target, not the black-box stack):

```sh
docker compose --profile whitebox up -d --wait
docker compose --profile whitebox exec whitebox \
  python3 /opt/lab/tools/coap_client.py send \
    --input /opt/lab/tools/inputs/get_wellknown.hex \
    --output-dir /workspace/results/wb-smoke \
    --stem wellknown
docker compose --profile whitebox exec whitebox \
  /opt/lab/tools/whitebox_tool_check.sh
./scripts/reset.sh whitebox
```

## Layout

| Path | Role |
| --- | --- |
| `compose.yaml` | `target-*`, `blackbox`, `whitebox` services |
| `docker/` | Dockerfiles and entrypoint |
| `tools/` | CoAP UDP client, mutator, run helper, access tests |
| `config/` | Frozen `target.lock` and `protocol.yaml` |
| `docs/` | Procedure, environment, access control, testing |
| `evaluator/` | Host-only oracle; never mount into analyst containers |
| `results/` | Per-viewpoint investigation artifacts |

## Documentation

- `docs/ENVIRONMENT.md` — images, pins, networks, Docker limits
- `docs/ACCESS_CONTROL.md` — viewpoint permissions and negative tests
- `docs/TESTING.md` — packet tests, replay, sanitizer, fuzzing notes
- `docs/TRADITIONAL_VULNERABILITY_INVESTIGATION_PROCEDURE.md` — required method
- `docs/TARGET_SELECTION.md` — administrator target choice (do not use as an analyst cheat-sheet)

## Personal Stage 2 (Mongoose)

Independent traditional-vs-AI experiment on Cesanta Mongoose `7.21` HTTP:

see [`personal-stage2/README.md`](personal-stage2/README.md). It reuses the
Stage 1 procedure and the Stage 2 OpenRouter driver task
`stage2/tasks/mongoose-chunked-review.yaml`, and does not replace this
libcoap lab.

## Stage 3 harness

Shared agent loop for applying one Naptime-style harness to each person's
Stage 2 target: see [`stage3/README.md`](stage3/README.md).

## Host unit tests

```sh
python3 -m unittest discover -s tests -v
```

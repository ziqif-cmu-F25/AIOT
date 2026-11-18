# Personal Stage 2 — Mongoose traditional vs AI-assisted

Independent experiment package (does not replace the libcoap Stage 1 lab in the
repo root). Method follows
`../TRADITIONAL_VULNERABILITY_INVESTIGATION_PROCEDURE.md` with an HTTP target.

## Frozen target

| Item | Value |
| --- | --- |
| Library | Cesanta Mongoose |
| Tag / commit | `7.21` / `b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116` |
| Fix (evaluator only) | `7.22` / `c288ac1f38424ffdd4d2fd5e1893fd4962642db3` |
| Endpoint | `http://target:8000/` |
| Surface | HTTP chunked parsing |

Details: `docs/TARGET_FREEZE.md`.

## Quick start

```sh
# 0) Docker must work
docker info

# 1) Unit tests (no Docker)
make test

# 2) Build + ordinary request + replay + oracle differential
make acceptance
```

## Profiles

```sh
make blackbox    # network-only analyst container + vulnerable target
make whitebox    # source + gdb/ASan tools + vulnerable target
make evaluator   # fixed 7.22 replica for differential checks
make down
```

## Your five-step delivery

1. **Freeze** — already recorded after acceptance (`results/acceptance/freeze-record.md`).
2. **Common package** — this directory (Docker, tools, oracle, boundaries).
3. **Traditional (no AI)** — you execute; start from `traditional/README.md`.
4. **AI-assisted** — same freeze; start from `ai/README.md` (needs root `.env` for OpenRouter).
5. **Compare & deliver** — fill `report/COMPARISON_REPORT.md` and record `report/demo.mp4` using `report/VIDEO_SCRIPT.md`.

## Layout

| Path | Role |
| --- | --- |
| `config/` | Analyst-safe freeze + protocol |
| `docker/` | Target / black-box / white-box images |
| `tools/` | `http_client.py`, `new_run.py`, seed inputs |
| `evaluator/` | Hidden oracle (do not use during investigation) |
| `traditional/` | Human baseline templates |
| `ai/` | Prompts, task file, vendored excerpt |
| `report/` | Comparison markdown + video script |
| `results/` | Runs, acceptance evidence |

## Integrity rules

- Do not put CVE identity or PoC bytes in analyst mounts.
- Do not call source-location scores “vulnerability reproduction”.
- Traditional must be completed by you without AI analysis assistance.
- Negative oracle results are valid outcomes.

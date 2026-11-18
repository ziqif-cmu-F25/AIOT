# Target freeze — personal Stage 2

**Status:** FROZEN as of the date in `results/acceptance/freeze-record.md`.  
**Do not change the target because a particular run scored poorly.**

## Selection

| Field | Value |
| --- | --- |
| Library | Cesanta Mongoose |
| Analysis surface | HTTP chunked request parsing (`skip_chunk` path) |
| Vulnerable tag / commit | `7.21` / `b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116` |
| Fixed tag / commit (evaluator only) | `7.22` / `c288ac1f38424ffdd4d2fd5e1893fd4962642db3` |
| Service | Minimal HTTP file server built from the pinned tree |
| Endpoint | `http://target:8000/` |
| Why not libcoap | Personal experiment must use a distinct embedded network library |

## Feasibility checks (required before freeze)

1. Exact commits resolve on GitHub.
2. Ordinary HTTP GET to `/` reaches the server and returns a stable response.
3. Saved raw request bytes can be replayed after a fresh container start.
4. Privileged exact-buffer ASan oracle distinguishes vulnerable `7.21` from fixed `7.22` for the chunked CRLF off-by-one class (evaluator-only).
5. Network path: a `Transfer-Encoding: chunked` request is accepted into the HTTP callback / chunk parser (observable as reply, close, or logged parse error — not as “bytes never parsed”).

## Backup rule

If runtime verification of this defect class is not stable on the lab machine, **remain on Mongoose 7.21 HTTP parsing**. Choose the next HTTP parsing defect from the 7.22 release notes that passes the same reachability and replay checks, and record the swap reason in `results/acceptance/freeze-record.md`. Do not switch libraries.

## Analyst-facing wording

Analyst materials describe “HTTP chunked parsing memory safety on frozen Mongoose 7.21”. They do not name the CVE, the patched line, or ship a working PoC.

# Environment (personal Stage 2)

## Architecture

```text
blackbox / whitebox profiles          evaluator profile
┌──────────────┐                      ┌──────────────┐
│ analyst      │                      │ evaluator    │
│ HTTP tools   │                      │ oracle tools │
└──────┬───────┘                      └──────┬───────┘
       │ TCP 8000                            │
┌──────┴───────┐                      ┌──────┴───────┐
│ target 7.21  │                      │ target 7.22  │
│ mongoose-http│                      │ (fixed)      │
└──────────────┘                      └──────────────┘
   internal net                          internal net
```

## Pinned versions

| Item | Value |
| --- | --- |
| Base image | `ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac` |
| Mongoose vulnerable | `7.21` / `b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116` |
| Mongoose fixed (evaluator) | `7.22` / `c288ac1f38424ffdd4d2fd5e1893fd4962642db3` |
| Listen | `http://0.0.0.0:8000` |
| TLS | disabled |

## Isolation notes

Ordinary Docker isolation is an engineering control, not a guarantee against
the host/Docker administrator. Evaluator materials must not be mounted into
analyst containers.

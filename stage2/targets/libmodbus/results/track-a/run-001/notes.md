# Track A — traditional workflow walkthrough (where AI can assist)

Track: track-a (human-only workflow)  ·  Run: run-001
Target: libmodbus v3.1.6 (`f9fe3b0a…`)  ·  Bug investigated: CVE-2022-0367

**Scope note.** This is a light, deliberately surface-level traversal of the
traditional investigation workflow, grounded in the known ground truth (it is
not a blind discovery run). Its purpose for Stage 2 is to walk the seven
pipeline steps on a concrete bug and mark, at each step, **where AI assistance
fits** — and, where we measured it in Track B, how well it actually worked.
Hands-on evidence for the dynamic steps is in `outputs/` and `commands.log`.

## Workflow trace + AI-assist map

**1. Target understanding / preparation.**
Frozen libmodbus v3.1.6 Modbus/TCP server (`unit-test-server`), ASan build.
Attacker controls the request bytes; the server protects its register/coil
mapping. — *AI assist:* summarize the protocol and codebase, flag trust
boundaries from human-chosen context. *(Not measured here; plausible.)*

**2. Attack-surface identification.**
Confirmed the server answers a well-formed request (benign Read Holding
Registers → `outputs/benign_probe.json`, normal reply, server healthy). The
function codes that write into the mapping (0x10, 0x17) are the richest
surface. — *AI assist:* rank which function codes / fields are worth testing.
*(Not measured; plausible.)*

**3. Static analysis (source review).**
`modbus_reply` handles each function code; the multi-write paths copy
caller-supplied counts into the mapping. — *AI assist, MEASURED (Track B
source-review):* on the sibling bug CVE-2024-10918, **no model at any tier /
family found it from source**; added framing context cut false-positive noise
but not misses. **AI is weak at this step for these bugs.**

**4. Dynamic analysis / fuzzing (input construction + execution).**
A crafted fn-0x17 (Read/Write Multiple Registers) frame whose write range
exceeds the mapping overflows the heap. Sent it (`outputs/fn17_trigger.json`):
`server_dropped: true`, and the server's ASan log shows
`heap-buffer-overflow … modbus.c:980 in modbus_reply`. — *AI assist, MEASURED
(Track B fuzzing-assist):* a mutation fuzzer found this unaided in ~180
iterations; AI-generated seed corpora were **valid but less effective** than a
small targeted hand corpus. **AI is mixed at this step.**

**5. Finding triage.**
One crash, one site. — *AI assist:* deduplicate / cluster crashes by stack.
*(Not exercised here; single crash.)*

**6. Root-cause analysis.**
The overflow is an unchecked write-range in the fn-0x17 path of `modbus_reply`
(heap write past the register mapping), class CWE buffer-overflow. — *AI
assist, MEASURED (Track B fuzzing-assist):* given the ASan report, **gpt-5,
deepseek and haiku all localized it correctly** (`modbus.c:980`,
`modbus_reply`, buffer-overflow). **AI is strong at this step** (the sanitizer
hands over the location; the model explains it reliably).

**7. Vulnerability validation.**
Replayed the exact frame against a freshly started instance
(`outputs/fn17_replay.json`): reproduces the same ASan crash at `modbus.c:980`.
Matches the oracle (crash in the proxy/register path; reproducible). — *AI
assist, MEASURED (Track B fuzzing-assist):* asked to produce a minimal working
reproducer, **all three models failed** (plausible but non-triggering frames,
verified against a positive control). **AI is weak at this step.**

## Where AI can exist (summary, grounded in Track B)

| Pipeline step | AI-assist opportunity | Measured result |
| --- | --- | --- |
| 1 Target understanding | summarize code / trust boundaries | not measured |
| 2 Attack-surface | rank inputs / function codes | not measured |
| 3 Static analysis | source-review triage | **weak** (missed the bug) |
| 4 Fuzzing | seed / harness generation | **mixed** (valid, less effective) |
| 5 Triage | crash dedup | not exercised |
| 6 Root-cause | explain the ASan crash | **strong** (all models correct) |
| 7 Validation | minimal reproducer | **weak** (all models failed) |

**Takeaway for the shortlist (Stage 3):** AI's clearest, most reliable value
on these bugs is at the *explain-the-runtime-evidence* step (6), not at the
generative steps (3, 4, 7). This matches the project thesis that runtime
grounding is where AI assistance pays off.

## Manual reasoning / bottlenecks
- unit-test-server serves one connection then exits; every attempt uses a
  freshly started instance (also the correct replay discipline).
- The exact triggering input is a specific fn-0x17 field combination; a naive
  oversized frame does not trigger it — the write-range fields matter.

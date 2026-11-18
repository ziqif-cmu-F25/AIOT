# Static-tool baseline (issue G2)

Run on the same SHA-pinned files the models were given. Tools available on this
host: **cppcheck 2.14.0** (standalone) and **gcc 13.2** (`-fanalyzer`). clang
`--analyze` and CodeQL are **not installed** — noted as not run.

cppcheck invocation (standalone, no build needed):
`cppcheck --enable=all --inconclusive --std=c11 <file>`
Raw output per target in `cppcheck_<target>.txt`.

(Note: this cppcheck build ships a broken `FILESDIR`, so `std.cfg` had to be
bridged to its expected path via a junction + `subst` before it would run.)

## Does the static tool flag the target defect line?

| Target | CVE (year) | Defect | cppcheck flags the target line? |
|---|---|---|---|
| **libmodbus** | CVE-2022-0367 (2022) | duplicated `mapping_address<0` guard (missing write lower-bound) | **YES** — `duplicateExpression` at line 963 ("Same expression found multiple times in chain of `\|\|`") **and** `knownConditionTrueFalse` at line 964 ("Condition 'mapping_address<0' is always false") |
| **libcoap** | CVE-2025-34468 (2025) | `memcpy` of attacker length into fixed `addrstr[256]`, no upper bound (line 538) | **NO** |
| **mongoose** | CVE-2026-52056 (2026) | off-by-one `len < i + 1` before reading `buf[i+1]` (line 1006) | **NO** |

gcc `-fanalyzer`: not run cleanly — the files need each project's build config
(`config.h`, include trees) to parse, so a standalone single-file analysis is not
representative. The proper way is to build each target with `-fanalyzer` in its
Docker image; deferred to the Docker-harness step.

## Interpretation (vs the corrected AI results)

| Target | static tool | AI best cell (corrected, any-of-3) | training-contaminated? |
|---|---|---|---|
| libmodbus | **hit** | C1 agentic 67% | **yes** (CVE recalled by 4 models) |
| libcoap | miss | triage 67%, crash 50%, C1 8% | no |
| mongoose | miss | crash 50%, C0 45%, C1 30% | no |

**The static tool catches exactly one of the three — the classic
duplicated-condition pattern — and that one is also the training-contaminated
target.** The two defects that post-date every model's training (libcoap 2025,
mongoose 2026) are a missing-bounds-check and an off-by-one; both are semantic,
not pattern-matchable, and cppcheck flags neither. So the honest framing is:

- Where a cheap linter already suffices (classic patterns), it is the right tool
  and the "AI finds it" result there is partly memorization.
- The AI's distinctive value is on the **semantic, uncontaminated** bugs that the
  linter misses — and even there, agentic needle-in-a-haystack search is hard
  (libcoap C1 = 8%), while giving the model the right excerpt works well
  (libcoap triage = 67%).

This is a baseline comparison, not a head-to-head score: cppcheck reports a
*location-level lint*, not a ranked exploit hypothesis, so "hit/miss on the
target line" is the fair comparison, not an accuracy percentage.

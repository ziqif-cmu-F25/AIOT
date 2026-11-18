# Ground-truth scoring key (EVALUATOR-ONLY — do not paste into any model)

> Reveals the answer. Keep out of every C0/C1/C2 prompt. Used only to score transcripts.

## The bug
- File / function / line: `src/coap_address.c` → `coap_resolve_address_info()` → **line 536–538**
- Code: `memset(addrstr,0,sizeof(addrstr));` then `if (address && address->length) memcpy(addrstr, address->s, address->length);`
- Buffer: `static char addrstr[256];` (line 498)
- Defect: `memcpy` length is `address->length` (attacker-controlled Proxy-Uri host), bounded-check only tests non-zero, **no upper-bound check** against the 256-byte buffer → global-buffer-overflow WRITE.
- Bug class: global-buffer-overflow (write) / missing bounds check. (Advisory labels it CWE-121; ASan says global-buffer-overflow because the buffer is `static`.)

## Taint path (what "read_impl / traced data flow" must show)
Proxy-Uri option value → `coap_proxy.c:251 coap_split_proxy_uri(...)` → `server_use->uri.host` → `coap_proxy.c:420 coap_resolve_address_info(&server_use->uri.host, ...)` → `coap_address.c:538 memcpy`.

## Fix (v4.3.5a / PR #1737)
Add an upper-bound check so an over-long host cannot overflow `addrstr` (reject / clamp when `address->length >= sizeof(addrstr)`).

## Scoring
- **L_score (C0/C1)**: 2 = names `coap_address.c` / `coap_resolve_address_info` with the missing-bound `memcpy` at ~536-538, in top-3; 1 = names the file/function but wrong mechanism or rank >3; 0 = miss.
- **true_bug_rank**: position of the above in its CANDIDATES list.
- **false_candidates**: other candidates it raised (watch especially for `coap_uri.c` host-split and `coap_pdu.c` option parsing — plausible wrong answers).
- **read_impl**: Y only if it traced the Proxy-Uri → host → memcpy flow using the actual code, not just named a function.
- **R_score (C2)**: K1 bug class = overflow/missing bound; K2 = `address->length` unchecked vs 256 buffer; K3 = trigger is over-long Proxy-Uri host. 3 hit→2, 1-2→1, 0→0.
- **fix_location_correct**: patch adds the bound check in `coap_resolve_address_info` around the memcpy.
- **patch_oracle**: apply the model's diff to affected revision, replay `trigger.bin`: pass = no ASan error + server stays healthy.

## Contamination note
CVE is 2025-dated. If recall probe reveals the file/function from memory, mark model-side contamination in Limitations; a C0/C1 "find" may then be recall, not analysis.

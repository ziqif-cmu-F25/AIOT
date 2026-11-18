# Fixed-prompt repeat variance (3 calls)

Same prompt id `mongoose-chunked-review@v1`. Not counted as three full investigations.

| Repeat | Primary class | Primary line | Extra candidates | Trigger body sketch |
| --- | --- | --- | --- | --- |
| 1 | out-of-bounds-read | skip_chunk:17 | none | `cd\r` |
| 2 | out-of-bounds-read | skip_chunk:17 | weak http_cb TE note | `12\r` |
| 3 | out-of-bounds-read | skip_chunk:17 | none | `ff\r` |

**Agreement:** All three repeats named the same CRLF off-by-one class at `skip_chunk` line 17.  
**Difference:** Repeat 2 added a low-confidence secondary candidate; hex prefixes in sketches varied (`cd` / `12` / `ff`) but same structural pattern (`XX\r`).

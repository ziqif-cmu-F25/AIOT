# Quarantined — issue A1

**Why excluded:** `targets/libmodbus/rerun_c1.py` builds its file store from
`stage2/vendor/src/` (see `VENDOR_SRC` at line 36 and `VENDOR_FILES` at lines
37–39). Per `vendor/MANIFEST.txt`, `src/modbus.c` is libmodbus **v3.1.10**
(`2cbafa31`), where **CVE-2022-0367 is already fixed** (the write-mapping lower
bound is checked). Every model in this C1 (agentic) condition was therefore shown
patched code and could not find the target bug. The results do not measure
detection of 0367.

**Disposition:** Kept verbatim. Excluded from the 0367 analysis. Superseded by a
corrected C1 re-run served the vulnerable revision `f9fe3b0a` (v3.1.6), pinned in
`targets/libmodbus/target.yaml`.

**Moved from:** `targets/libmodbus/results/rerun-c1/`
**Date:** 2026-11-17 (corrections pass)

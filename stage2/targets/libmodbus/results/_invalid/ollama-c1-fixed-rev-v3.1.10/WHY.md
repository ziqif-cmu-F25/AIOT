# Quarantined — issue A1 (local models)

**Why excluded:** The Ollama C1 (agentic) runs were produced by
`run_ollama_expansion.py`, whose file store is built from `stage2/vendor/src/`
(see line 228: `vendor_src = STAGE2 / "vendor" / "src"`). That tree is libmodbus
**v3.1.10** (`2cbafa31`), where **CVE-2022-0367 is already fixed**. The local
models (deepseek-coder:6.7b, qwen2.5-coder:7b) were shown patched code and could
not find the target bug.

Note: these local runs are **also** affected by issue D6 (Ollama `num_ctx`
defaulted to ~2048, silently truncating the prompt). Both defects independently
invalidate them.

**Disposition:** Kept verbatim. Excluded from the 0367 analysis. Superseded by a
corrected local C1 re-run served `f9fe3b0a` with `num_ctx` set explicitly.

**Moved from:** `targets/libmodbus/results/ollama-c1/`
**Date:** 2026-11-17 (corrections pass)

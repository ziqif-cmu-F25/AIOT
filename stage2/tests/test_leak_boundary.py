"""Prompt-content leak boundary (issues B1-B4, acceptance criterion).

Fails if a NON-HINTED condition template, or a crash-given ASan artifact it
substitutes, contains a CVE id, a CWE id, a target function name, or one of the
documented flaw-mechanism hint phrases. The hinted-by-design templates
(triage_hinted, input_drafting) are exempt but MUST carry an explicit CONDITION
label so they can never be mistaken for a clean condition.

This complements test_boundary.py (which proves file-access isolation).

    stage2/.venv/Scripts/python.exe tests/test_leak_boundary.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[1]
TEMPLATES = STAGE2 / "targets" / "templates"

NON_HINTED = ["source_agentic.txt", "source_one_shot.txt", "crash_given.txt", "triage.txt"]
HINTED = ["triage_hinted.txt", "input_drafting.txt"]
# recall_probe asks the model to recall CVEs by design; exempt from the phrase
# ban but still must not contain a *specific* CVE id.
PROBE = ["recall_probe.txt"]

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
CWE_RE = re.compile(r"CWE-\d+", re.I)

# Documented leak phrases (from the audit, issues B1/B2).
MECHANISM_PHRASES = [
    "no prior length validation",
    "no prior sanitisation",
    "no prior sanitization",
    "copy-paste",
    "off-by-one",
    "focus on the bounds",
    "focus on the off-by-one",
    "mapping address",
    "register mapping array",
]


def target_function_names() -> list[str]:
    names: list[str] = []
    for ty in STAGE2.glob("targets/*/target.yaml"):
        text = ty.read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*function:\s*([A-Za-z_][A-Za-z0-9_]*)\s*$", text, re.M):
            names.append(m.group(1))
    return sorted(set(names))


FUNCS = target_function_names()


def scan(text: str, *, allow_phrases: bool = False, allow_funcs: bool = False) -> list[str]:
    low = text.lower()
    hits = []
    if CVE_RE.search(text):
        hits.append(f"CVE id: {CVE_RE.search(text).group(0)}")
    if CWE_RE.search(text):
        hits.append(f"CWE id: {CWE_RE.search(text).group(0)}")
    if not allow_funcs:
        for fn in FUNCS:
            if re.search(rf"\b{re.escape(fn)}\b", text):
                hits.append(f"function name: {fn}")
    if not allow_phrases:
        for ph in MECHANISM_PHRASES:
            if ph in low:
                hits.append(f"mechanism phrase: {ph!r}")
    return hits


def test_non_hinted_templates_are_clean():
    problems = {}
    for name in NON_HINTED:
        p = TEMPLATES / name
        assert p.exists(), f"missing template {name}"
        hits = scan(p.read_text(encoding="utf-8"))
        if hits:
            problems[name] = hits
    assert not problems, f"leak(s) in non-hinted templates: {problems}"


def test_probe_has_no_specific_cve():
    for name in PROBE:
        text = (TEMPLATES / name).read_text(encoding="utf-8")
        assert not CVE_RE.search(text), f"{name} names a specific CVE id"


def test_hinted_templates_are_labelled():
    for name in HINTED:
        text = (TEMPLATES / name).read_text(encoding="utf-8")
        assert "CONDITION:" in text, f"{name} must carry an explicit CONDITION label"


def test_crash_given_asan_artifacts_clean():
    """Any ASan report a crash-given condition substitutes must not name the bug."""
    checked = 0
    for ty in STAGE2.glob("targets/*/target.yaml"):
        text = ty.read_text(encoding="utf-8")
        m = re.search(r"asan_report:\s*(\S+)", text)
        if not m:
            continue
        rel = m.group(1)
        art = (STAGE2.parent / rel) if (STAGE2.parent / rel).exists() else (STAGE2 / rel.replace("targets/", "targets/"))
        if not art.exists():
            print(f"  (note) asan artifact not present yet: {rel} — create clean before running crash-given")
            continue
        # The ASan backtrace legitimately names the crash site (that is what
        # crash-given discloses); only an EDITORIAL mechanism/CVE hint is a leak.
        hits = scan(art.read_text(encoding="utf-8", errors="ignore"),
                    allow_funcs=True)
        assert not hits, f"crash-given ASan artifact {rel} leaks (mechanism/CVE): {hits}"
        checked += 1
    print(f"  checked {checked} ASan artifact(s)")


def _run_all():
    import traceback
    print(f"target function names under ban: {FUNCS}")
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())

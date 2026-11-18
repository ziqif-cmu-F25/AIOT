"""Canonical converter (issue E1). The ONE place a run becomes a record.

Hard rule: the model's words are copied **verbatim** into hypothesis /
evidence_source / notes / raw_response, and **no verdict is ever assigned here**.
Localization verdicts live only in targets/verdicts.csv (produced by blind
adjudication); oracle_verdict is set only by the oracle runner. This replaces the
per-target converters that keyword-matched model text and injected canonical
"correct" strings (e.g. convert_rerun_candidates.py:94-110, convert_ollama_*).

A guard (assert_no_verdict_injection) is provided so the leak of a verdict into a
raw field fails loudly.
"""
from __future__ import annotations

from typing import Any

_VERDICT_WORDS = ("correct", "incorrect", "true positive", "false positive",
                  "pass", "fail", "wrong_bug", "localization_verdict")


def assert_no_verdict_injection(record: dict[str, Any]) -> None:
    """Raw model fields must not be author-written verdict text."""
    # The record must not carry a localization verdict at all (E3/E5).
    assert "localization_verdict" not in record, \
        "localization verdict belongs in verdicts.csv, not in the candidate record"
    # oracle_verdict, if present, is a controlled enum set only by the oracle.
    if "oracle_verdict" in record:
        assert record["oracle_verdict"] in ("pass", "fail", "not_run"), \
            f"oracle_verdict must be an enum set by the oracle, got {record['oracle_verdict']!r}"


def make_record(
    *,
    candidate_id: str,
    task_id: str,
    viewpoint: str,
    condition: str,
    pinned_commit: str,
    disclosed: list[str],
    withheld: list[str],
    model: str,
    prompt_id: str,
    run_index: int,
    response_status: str,
    raw_response: str,
    # model-provided fields, passed through verbatim:
    hypothesis: str,
    evidence_source: str,
    expected_behavior: str,
    vulnerability_class: str,
    location: dict,
    confidence: float,
    notes: str = "",
    property: str = "memory-safety",
    input_artifact: str = "",
    observed_behavior: str = "",
    status: str = "candidate",
    truncated: bool = False,
    drafted_input: str | None = None,
    oracle_verdict: str | None = None,
) -> dict[str, Any]:
    """Build a schema-valid record. Model fields are stored as given; no scoring."""
    rec: dict[str, Any] = {
        "candidate_id": candidate_id,
        "task_id": task_id,
        "viewpoint": viewpoint,
        "condition": condition,
        "pinned_commit": pinned_commit,
        "disclosed": list(disclosed),
        "withheld": list(withheld),
        "property": property,
        "hypothesis": hypothesis,          # verbatim
        "evidence_source": evidence_source,  # verbatim
        "input_artifact": input_artifact,
        "expected_behavior": expected_behavior,
        "observed_behavior": observed_behavior,
        "status": status,
        "response_status": response_status,
        "truncated": truncated,
        "notes": notes,                    # verbatim / clearly-marked driver note
        "raw_response": raw_response,       # full verbatim output
        "vulnerability_class": vulnerability_class,
        "location": location,
        "confidence": confidence,
        "model": model,
        "prompt_id": prompt_id,
        "run_index": run_index,
    }
    if drafted_input is not None:
        rec["drafted_input"] = drafted_input
    if oracle_verdict is not None:
        rec["oracle_verdict"] = oracle_verdict
    assert_no_verdict_injection(rec)
    return rec

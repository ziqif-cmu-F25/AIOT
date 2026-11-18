"""Harness tests (issue D1-D3) + scoring sanity (F3). Run with the repo venv:

    stage2/.venv/Scripts/python.exe -m pytest stage2/tests/test_harness.py
or standalone:
    stage2/.venv/Scripts/python.exe stage2/tests/test_harness.py
"""
from __future__ import annotations

import sys
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STAGE2))

from driver.agentic_harness import (  # noqa: E402
    strip_quotes, tool_grep, parse_action, run_condition,
)
from targets.scoring import wilson  # noqa: E402

STORE = {
    "src/modbus.c": [
        "int mapping_address = address - start;",
        'void modbus_reply(void) { /* "quoted" */ }',
        "    tab_registers[i] = value;  // regex target 42",
    ]
}


def test_grep_strips_quotes():
    # D1: a quoted pattern must not include the quotes literally.
    out = tool_grep(STORE, '"modbus_reply"', None)
    assert "modbus_reply(void)" in out, out
    # The raw quoted form would only match the commented "quoted" token, not the def.
    assert "src/modbus.c:2" in out


def test_grep_regex_and_literal_fallback():
    # D1: real regex works...
    out = tool_grep(STORE, r"tab_\w+\[i\]", None)
    assert "tab_registers[i]" in out, out
    # ...and an invalid regex falls back to literal substring (no crash).
    out2 = tool_grep(STORE, "value;  //", None)
    assert "regex target 42" in out2, out2


def test_parse_action_tolerant_final():
    # D3: FINAL wrapped in markdown/bold still parses.
    assert parse_action("**FINAL**")[0] == "FINAL"
    assert parse_action("`FINAL`")[0] == "FINAL"
    assert parse_action("- FINAL: here is my answer")[0] == "FINAL"
    assert parse_action("HYPOTHESIS: x\nREAD src/modbus.c 1 20")[0] == "READ"
    assert parse_action("no action here") is None


class _ScriptedClient:
    """Returns pre-baked replies so the loop can be exercised offline."""
    def __init__(self, replies):
        self._replies = list(replies)
        self.seen_last_turn_prompt = False

    def complete(self, model, messages, sampling):
        # record whether the model was told to FINAL on the last turn (D2)
        if messages and "issue final now" in messages[-1]["content"].lower():
            self.seen_last_turn_prompt = True
        from driver.openrouter_client import Completion
        text = self._replies.pop(0) if self._replies else "FINAL: forced"
        return Completion(text=text, requested_model=model, resolved_model=model,
                          provider="test", response_id="x", finish_reason="stop",
                          usage={}, created=0)


def test_reprompt_then_recover():
    # D3: one unparseable turn gets a reminder, not an immediate abort.
    client = _ScriptedClient(["(no verb here)", "FINAL: recovered"])
    res = run_condition(client, "m", "prompt", STORE, max_turns=6)
    assert res.status == "final", res.status
    assert res.response_status == "answered"


def test_forced_final_on_last_turn():
    # D2: a model that keeps READ-ing is told to FINAL on the last turn.
    client = _ScriptedClient(["READ src/modbus.c 1 3"] * 10)
    res = run_condition(client, "m", "prompt", STORE, max_turns=3)
    assert client.seen_last_turn_prompt, "model was never prompted to issue FINAL"


def test_wilson_bounds():
    p, lo, hi = wilson(1, 1)
    assert 0.0 <= lo <= p <= hi <= 1.0
    p0, lo0, hi0 = wilson(0, 0)
    assert (p0, lo0, hi0) == (0.0, 0.0, 1.0)
    # 1/3 should straddle a wide interval, well inside [0,1].
    p3, lo3, hi3 = wilson(1, 3)
    assert lo3 < p3 < hi3 and lo3 > 0.0 and hi3 < 1.0


def _run_all():
    import traceback
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

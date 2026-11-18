"""Shared agentic READ/GREP/FINAL harness for the C1 (source-agentic) condition.

Single source of truth for the agent loop so every target's rerun script behaves
identically and the fixes below are tested once. Corrections pass issues:

  D1  GREP strips surrounding quotes and supports regex (literal fallback).
  D2  The model is warned when <=3 requests remain and told to "Issue FINAL now"
      on its last turn, so runs do not silently hit the turn limit with no answer.
  D3  One unparseable / refusal-shaped turn triggers a single format re-prompt
      before the run aborts; FINAL is parsed tolerantly (bold / markdown / list
      markers). Refusal is re-checked every turn, not only turn 1.
  D4  Truncation at max_tokens is detected (finish_reason == 'length' or
      completion_tokens >= cap) and flagged.
  D7  Terminal state is mapped to the schema's response_status vocabulary,
      distinguishing answered / refused / filtered / blocked / error /
      truncated / unparseable.

The GREP semantics are stated to the model in GREP_SEMANTICS so behaviour and
documentation cannot drift (contract: one source of truth).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

# Stated verbatim in the prompt so the model knows the semantics (D1).
GREP_SEMANTICS = (
    "GREP <pattern> [<path>]: <pattern> is a regular expression (Python `re`). "
    "Surrounding single or double quotes are stripped. If the pattern is not a "
    "valid regex it is treated as a literal substring. Matching is "
    "case-sensitive. Omit <path> to search every file."
)

REFUSAL_MARKERS = (
    "i can't help", "i cannot help", "i can't assist", "i cannot assist",
    "i won't help", "i'm not able to help", "i'm unable to help",
    "i can't provide", "i cannot provide",
)

# Tolerant: allow leading whitespace, blockquote, list markers, heading hashes,
# and bold/backtick wrappers before the verb (D3).
_ACTION_RE = re.compile(
    r"(?im)^[\s>*#`\-•]*\**\s*`?\s*(READ|GREP|FINAL)\b(.*)$"
)


def strip_quotes(pattern: str) -> str:
    p = pattern.strip()
    if len(p) >= 2 and p[0] == p[-1] and p[0] in ("'", '"', "`"):
        return p[1:-1]
    return p


def parse_action(text: str) -> tuple[str, str] | None:
    matches = list(_ACTION_RE.finditer(text))
    if not matches:
        return None
    m = matches[-1]
    return m.group(1).upper(), m.group(2).strip()


def looks_like_refusal(text: str) -> bool:
    """A refusal is a short reply with no parseable action, or an explicit marker."""
    if parse_action(text):
        return False
    low = text.lower()
    return any(marker in low for marker in REFUSAL_MARKERS) or len(text.strip()) < 200


def tool_read(store: dict[str, list[str]], path: str, start: int, end: int) -> str:
    if path not in store:
        available = ", ".join(sorted(store.keys()))
        return (f"ERROR: {path!r} not available in this file store. "
                f"Available files: {available}")
    lines = store[path]
    if end - start + 1 > 300:
        end = start + 299
    start = max(1, start)
    end = min(len(lines), end)
    chunk = lines[start - 1:end]
    numbered = "\n".join(f"{start + i}: {line}" for i, line in enumerate(chunk))
    return numbered or f"ERROR: requested range {start}-{end} is empty for {path}"


def tool_grep(store: dict[str, list[str]], pattern: str, path: str | None) -> str:
    """Regex GREP with quote-stripping and a literal fallback (D1)."""
    raw = strip_quotes(pattern)
    try:
        rx = re.compile(raw)
        search = rx.search
    except re.error:
        needle = raw
        search = lambda line: (needle in line)  # literal fallback
    if path is not None and path not in store:
        return f"ERROR: {path!r} not available in this file store."
    paths = [path] if path else list(store.keys())
    hits: list[str] = []
    for p in paths:
        for i, line in enumerate(store[p], start=1):
            if search(line):
                hits.append(f"{p}:{i}: {line}")
    if not hits:
        return "no matches"
    return "\n".join(hits[:200])


def is_truncated(completion) -> bool:
    """D4: did the completion hit the max_tokens cap?"""
    fr = getattr(completion, "finish_reason", None)
    if fr in ("length", "max_tokens"):
        return True
    return False


_STATUS_TO_RESPONSE = {
    "final": "answered",
    "refused": "refused",
    "filtered": "filtered",
    "api_blocked": "blocked",
    "api_error": "error",
    "unparseable": "unparseable",
    "turn_limit_reached": "unparseable",
}


def response_status_for(internal_status: str) -> str:
    return _STATUS_TO_RESPONSE.get(internal_status, "error")


@dataclass
class RunResult:
    model: str
    condition_tag: str
    status: str                 # internal status
    response_status: str        # schema vocabulary (D7)
    final_text: str
    truncated: bool
    transcript: list = field(default_factory=list)
    completions: list = field(default_factory=list)
    turns_used: int = 0


def run_condition(
    client,
    model: str,
    prompt: str,
    store: dict[str, list[str]],
    *,
    condition_tag: str = "source-agentic",
    max_turns: int = 15,
    max_tokens: int = 16000,
    temperature: float = 0.0,
) -> RunResult:
    messages = [{"role": "user", "content": prompt}]
    transcript: list = []
    completions: list = []
    status = "in_progress"
    final_text = ""
    truncated = False
    reprompted = False

    turn = 0
    while turn < max_turns:
        turn += 1
        try:
            completion = client.complete(
                model=model, messages=messages,
                sampling={"temperature": temperature, "max_tokens": max_tokens},
            )
        except Exception as exc:  # noqa: BLE001
            transcript.append({"turn": turn, "role": "system_note",
                               "content": f"API error: {type(exc).__name__}: {exc}"})
            low = str(exc).lower()
            status = "api_blocked" if ("flagged" in low or "permissiondenied" in type(exc).__name__.lower()) else "api_error"
            final_text = str(exc)
            break

        completions.append(completion)
        reply = completion.text or ""
        if is_truncated(completion):
            truncated = True
        transcript.append({"turn": turn, "role": "assistant", "content": reply})

        # 0-byte content with no error -> provider moderation filter (D7).
        if reply.strip() == "":
            status = "filtered"
            final_text = ""
            break

        if looks_like_refusal(reply):
            if not reprompted:
                reprompted = True
                reminder = (
                    "Your reply did not contain a valid action. Reply with exactly one of:\n"
                    "  READ <path> <start_line> <end_line>\n"
                    f"  GREP <pattern> [<path>]   ({GREP_SEMANTICS})\n"
                    "  FINAL\n"
                    "Write the verb at the start of a line, unwrapped (no bold, no backticks)."
                )
                messages.append({"role": "assistant", "content": reply})
                messages.append({"role": "user", "content": reminder})
                transcript.append({"turn": turn, "role": "system_note",
                                   "content": "unparseable/refusal; sent one format reminder (D3)"})
                continue
            status = "refused" if any(m in reply.lower() for m in REFUSAL_MARKERS) else "unparseable"
            final_text = reply
            break

        action = parse_action(reply)
        if action is None:
            # Non-refusal but still unparseable: one reminder, then abort.
            if not reprompted:
                reprompted = True
                messages.append({"role": "assistant", "content": reply})
                messages.append({"role": "user", "content":
                                 "No READ/GREP/FINAL verb found at the start of a line. "
                                 "Reply with exactly one unwrapped action, or FINAL."})
                transcript.append({"turn": turn, "role": "system_note",
                                   "content": "no action; sent one format reminder (D3)"})
                continue
            status = "unparseable"
            final_text = reply
            break

        verb, arg = action
        messages.append({"role": "assistant", "content": reply})

        if verb == "FINAL":
            status = "final"
            final_text = reply
            break

        if verb == "READ":
            m = re.match(r"(\S+)\s+(\d+)\s+(\d+)", arg)
            if not m:
                tool_result = f"ERROR: could not parse READ arguments: {arg!r}"
            else:
                tool_result = tool_read(store, m.group(1), int(m.group(2)), int(m.group(3)))
        elif verb == "GREP":
            m = re.match(r"(\S+)(?:\s+(\S+))?", arg)
            pattern, gpath = (m.group(1), m.group(2)) if m else (arg, None)
            tool_result = tool_grep(store, pattern, gpath)
        else:
            tool_result = f"ERROR: unknown action {verb!r}"

        # Turns-remaining signal + forced FINAL on last turn (D2).
        turns_left = max_turns - turn
        suffix = ""
        if turns_left == 0 or turn == max_turns - 1:
            suffix = "\n\n[LAST TURN — issue FINAL now with your best answer.]"
        elif turns_left <= 3:
            suffix = f"\n\n[{turns_left} request(s) remaining before you must issue FINAL.]"

        transcript.append({"turn": turn, "role": "tool_result", "content": tool_result})
        messages.append({"role": "user", "content": tool_result + suffix})

        if turn == max_turns:
            status = "turn_limit_reached"

    if status == "in_progress":
        status = "turn_limit_reached"

    return RunResult(
        model=model, condition_tag=condition_tag, status=status,
        response_status=response_status_for(status), final_text=final_text,
        truncated=truncated, transcript=transcript, completions=completions,
        turns_used=len(completions),
    )

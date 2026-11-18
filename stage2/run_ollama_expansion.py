"""Run local Ollama models on C2, input-drafting, and C1 conditions across all targets.

Fills the gap: local models previously only ran triage (and C0 for mongoose).
This adds C2 (crash-given), input-drafting, and C1 (agentic) for all 3 targets.

Models: deepseek-coder:6.7b, qwen2.5-coder:7b
Conditions: C2 (one-shot), input-drafting (one-shot), C1 (multi-turn agentic)

Usage:
    stage2/.venv/Scripts/python.exe stage2/run_ollama_expansion.py
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

STAGE2 = Path(__file__).resolve().parent
sys.path.insert(0, str(STAGE2))

from driver.ollama_client import OllamaClient  # noqa: E402

LOCAL_MODELS = ["deepseek-coder:6.7b", "qwen2.5-coder:7b"]
MAX_TURNS = 15
ACTION_RE = re.compile(r"(READ|GREP|FINAL)\s*[:\-]?\s*(.*)", re.IGNORECASE)
REFUSAL_MARKERS = ["i can't", "i cannot", "i won't", "i'm unable", "not able to",
                   "as an ai", "policy", "content policy"]


def slug(model: str) -> str:
    return model.replace(":", "-").replace("/", "-")


def append_cost_row(log_path: Path, row: dict) -> None:
    header = "timestamp_utc,run_id,task_id,status,model_requested,model_resolved,attempts,prompt_tokens,completion_tokens,total_tokens,cost_usd\n"
    if not log_path.exists():
        log_path.write_text(header, encoding="utf-8")
    usage = row.get("usage_total", {})
    line = (
        f"{row['end_utc']},{row['run_id']},{row['task_id']},{row['status']},"
        f"{row['model_requested']},{';'.join(row.get('model_resolved', []))},"
        f"{row.get('attempts', 1)},"
        f"{usage.get('prompt_tokens', 0)},{usage.get('completion_tokens', 0)},"
        f"{usage.get('total_tokens', 0)},0\n"
    )
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line)


# ── One-shot runner (C2, input-drafting) ──

ONESHOT_TASKS: list[dict] = [
    # libmodbus C2
    {
        "name": "libmodbus-c2",
        "target_dir": STAGE2 / "targets" / "libmodbus",
        "prompt_path": STAGE2 / "targets" / "libmodbus" / "artifacts" / "ai" / "prompts" / "crash_given_v1.txt",
        "source_path": STAGE2 / "targets" / "libmodbus" / "artifacts" / "ai" / "vendor" / "triage_excerpt.c",
        "source_header": "<<<SOURCE EXCERPT: modbus_reply(), fn-0x17 handler>>>",
        "out_subdir": "ollama-c2",
        "task_id": "libmodbus-ollama-c2",
        "prefix": "OLLAMA-C2",
        "max_tokens": 8000,
    },
    # libmodbus input-drafting
    {
        "name": "libmodbus-input",
        "target_dir": STAGE2 / "targets" / "libmodbus",
        "prompt_path": STAGE2 / "targets" / "libmodbus" / "artifacts" / "ai" / "prompts" / "input_drafting_v1.txt",
        "source_path": None,
        "source_header": None,
        "out_subdir": "ollama-input-drafting",
        "task_id": "libmodbus-ollama-input",
        "prefix": "OLLAMA-INPUT",
        "max_tokens": 4000,
    },
    # libcoap C2
    {
        "name": "libcoap-c2",
        "target_dir": STAGE2 / "targets" / "libcoap",
        "prompt_path": STAGE2 / "targets" / "libcoap" / "artifacts" / "prompts" / "crash_given_v1.txt",
        "source_path": STAGE2 / "targets" / "libcoap" / "artifacts" / "vendor" / "c2_excerpt.c",
        "source_header": "<<<SOURCE EXCERPT: coap_resolve_address_info() and caller>>>",
        "out_subdir": "ollama-c2",
        "task_id": "libcoap-ollama-c2",
        "prefix": "OLLAMA-C2",
        "max_tokens": 8000,
    },
    # libcoap input-drafting
    {
        "name": "libcoap-input",
        "target_dir": STAGE2 / "targets" / "libcoap",
        "prompt_path": STAGE2 / "targets" / "libcoap" / "artifacts" / "prompts" / "input_drafting_v1.txt",
        "source_path": None,
        "source_header": None,
        "out_subdir": "ollama-input-drafting",
        "task_id": "libcoap-ollama-input",
        "prefix": "OLLAMA-INPUT",
        "max_tokens": 4000,
    },
    # mongoose C2
    {
        "name": "mongoose-c2",
        "target_dir": STAGE2 / "targets" / "mongoose",
        "prompt_path": STAGE2 / "targets" / "mongoose" / "artifacts" / "ai" / "prompts" / "crash_given_v1.txt",
        "source_path": STAGE2 / "targets" / "mongoose" / "artifacts" / "ai" / "vendor" / "http_skip_chunk_excerpt.c",
        "source_header": "<<<SOURCE EXCERPT: skip_chunk() and caller>>>",
        "out_subdir": "ollama-c2",
        "task_id": "mongoose-ollama-c2",
        "prefix": "OLLAMA-C2",
        "max_tokens": 8000,
    },
    # mongoose input-drafting
    {
        "name": "mongoose-input",
        "target_dir": STAGE2 / "targets" / "mongoose",
        "prompt_path": STAGE2 / "targets" / "mongoose" / "artifacts" / "ai" / "prompts" / "input_drafting_v1.txt",
        "source_path": None,
        "source_header": None,
        "out_subdir": "ollama-input-drafting",
        "task_id": "mongoose-ollama-input",
        "prefix": "OLLAMA-INPUT",
        "max_tokens": 4000,
    },
]


def build_oneshot_prompt(task: dict) -> str:
    template = task["prompt_path"].read_text(encoding="utf-8")
    if task["source_path"] is not None:
        source = task["source_path"].read_text(encoding="utf-8")
        return f"{template}\n\n{task['source_header']}\n{source}"
    return template


def run_oneshot(client: OllamaClient, task: dict) -> int:
    prompt = build_oneshot_prompt(task)
    out_dir = task["target_dir"] / "results" / task["out_subdir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    cost_log = task["target_dir"] / "results" / "cost_log.csv"
    count = 0

    for model in LOCAL_MODELS:
        s = slug(model)
        run_id = f"{task['prefix']}-{s}"
        out_path = out_dir / f"{run_id}.txt"
        if out_path.exists():
            print(f"  [{task['name']}][{s}] already have output, skipping", flush=True)
            continue

        print(f"  [{task['name']}][{s}] starting...", flush=True)
        try:
            completion = client.complete(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                sampling={"temperature": 0.0, "max_tokens": task["max_tokens"]},
            )
        except Exception as e:
            print(f"    ERROR: {e}", flush=True)
            out_path.write_text(f"ERROR: {e}", encoding="utf-8")
            append_cost_row(cost_log, {
                "end_utc": datetime.now(timezone.utc).isoformat(),
                "run_id": run_id, "task_id": task["task_id"],
                "status": "error", "model_requested": model,
                "model_resolved": [""], "usage_total": {},
            })
            continue

        text = completion.text
        if not text or len(text.strip()) == 0:
            print(f"    empty response", flush=True)
            out_path.write_text("EMPTY_RESPONSE", encoding="utf-8")
            status = "empty"
        elif len(text.strip()) < 20:
            print(f"    very short response ({len(text)} chars)", flush=True)
            out_path.write_text(text, encoding="utf-8")
            status = "ok"
        else:
            print(f"    ok ({len(text)} chars)", flush=True)
            status = "ok"

        out_path.write_text(text if status == "ok" else "EMPTY_RESPONSE", encoding="utf-8")
        append_cost_row(cost_log, {
            "end_utc": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id, "task_id": task["task_id"],
            "status": status, "model_requested": model,
            "model_resolved": [completion.resolved_model or ""],
            "usage_total": completion.usage,
        })
        count += 1
    return count


# ── C1 agentic runner ──

C1_TASKS: list[dict] = [
    {
        "name": "libmodbus-c1",
        "target_dir": STAGE2 / "targets" / "libmodbus",
        "prompt_path": STAGE2 / "targets" / "libmodbus" / "artifacts" / "ai" / "prompts" / "C1.txt",
        "out_subdir": "ollama-c1",
        "task_id": "libmodbus-ollama-c1",
        "condition_tag": "C1-ollama",
    },
    {
        "name": "libcoap-c1",
        "target_dir": STAGE2 / "targets" / "libcoap",
        "prompt_path": STAGE2 / "targets" / "libcoap" / "artifacts" / "prompts" / "C1.txt",
        "out_subdir": "ollama-c1",
        "task_id": "libcoap-ollama-c1",
        "condition_tag": "C1-ollama",
    },
    {
        "name": "mongoose-c1",
        "target_dir": STAGE2 / "targets" / "mongoose",
        "prompt_path": STAGE2 / "targets" / "mongoose" / "artifacts" / "ai" / "prompts" / "C1.txt",
        "out_subdir": "ollama-c1",
        "task_id": "mongoose-ollama-c1",
        "condition_tag": "C1-ollama",
    },
]


def build_file_store_libmodbus() -> dict[str, list[str]]:
    store: dict[str, list[str]] = {}
    vendor_src = STAGE2 / "vendor" / "src"
    for fname in ["modbus.c", "modbus.h", "modbus-private.h", "modbus-tcp.c", "modbus-tcp.h"]:
        store[f"src/{fname}"] = (vendor_src / fname).read_text(encoding="utf-8").splitlines()
    return store


def build_file_store_libcoap() -> dict[str, list[str]]:
    store: dict[str, list[str]] = {}
    vendored = STAGE2 / "vendor" / "src" / "coap_address.c"
    store["src/coap_address.c"] = vendored.read_text(encoding="utf-8").splitlines()
    pack_file = STAGE2 / "targets" / "libcoap" / "artifacts" / "packs" / "c0_pack_1.txt"
    pack_text = pack_file.read_text(encoding="utf-8")
    parts = re.split(r"^==== (src/[\w.]+) ====\n", pack_text, flags=re.MULTILINE)
    for i in range(1, len(parts), 2):
        path, content = parts[i], parts[i + 1]
        if path != "src/coap_address.c":
            store[path] = content.splitlines()
    return store


def build_file_store_mongoose() -> dict[str, list[str]]:
    store: dict[str, list[str]] = {}
    vendor_dir = STAGE2 / "targets" / "mongoose" / "artifacts" / "ai" / "vendor"
    store["src/http.c"] = (vendor_dir / "http_skip_chunk_excerpt.c").read_text(encoding="utf-8").splitlines()
    server_main = STAGE2 / "targets" / "mongoose" / "artifacts" / "docker" / "server_main.c"
    store["server_main.c"] = server_main.read_text(encoding="utf-8").splitlines()
    return store


def build_file_store(task: dict) -> dict[str, list[str]]:
    if "libmodbus" in task["name"]:
        return build_file_store_libmodbus()
    if "libcoap" in task["name"]:
        return build_file_store_libcoap()
    if "mongoose" in task["name"]:
        return build_file_store_mongoose()
    raise ValueError(f"No file store builder for {task['name']}")


def tool_read(store: dict, path: str, start: int, end: int) -> str:
    if path not in store:
        available = ", ".join(sorted(store.keys()))
        return f"ERROR: {path!r} not available. Available files: {available}"
    lines = store[path]
    if end - start + 1 > 300:
        end = start + 299
    start = max(1, start)
    end = min(len(lines), end)
    chunk = lines[start - 1:end]
    numbered = "\n".join(f"{start + i}: {line}" for i, line in enumerate(chunk))
    return numbered or f"ERROR: requested range {start}-{end} is empty for {path}"


def tool_grep(store: dict, pattern: str, path: str | None) -> str:
    targets = [path] if path and path in store else (list(store.keys()) if not path else [])
    if path and path not in store and not targets:
        return f"ERROR: {path!r} not available."
    hits = []
    for p in (targets or store.keys()):
        for i, line in enumerate(store[p], start=1):
            if pattern in line:
                hits.append(f"{p}:{i}: {line}")
    return "\n".join(hits[:200]) if hits else "no matches"


def parse_action(text: str) -> tuple[str, str] | None:
    matches = list(ACTION_RE.finditer(text))
    if not matches:
        return None
    m = matches[-1]
    return m.group(1).upper(), m.group(2).strip()


def looks_like_refusal(text: str) -> bool:
    low = text.lower()
    if parse_action(text):
        return False
    return any(marker in low for marker in REFUSAL_MARKERS) or len(text.strip()) < 200


def run_c1(client: OllamaClient, task: dict) -> int:
    store = build_file_store(task)
    out_root = task["target_dir"] / "results" / task["out_subdir"]
    out_root.mkdir(parents=True, exist_ok=True)
    cost_log = task["target_dir"] / "results" / "cost_log.csv"
    count = 0

    for model in LOCAL_MODELS:
        s = slug(model)
        model_dir = out_root / f"ollama_{s}"
        transcript_path = model_dir / "transcript.json"
        if transcript_path.exists():
            print(f"  [{task['name']}][{s}] already have transcript, skipping", flush=True)
            continue

        model_dir.mkdir(parents=True, exist_ok=True)
        print(f"  [{task['name']}][{s}] starting C1 agentic...", flush=True)

        prompt = task["prompt_path"].read_text(encoding="utf-8")
        # libcoap C1 prompt has a filetree placeholder
        filetree_path = STAGE2 / "targets" / "libcoap" / "artifacts" / "packs" / "filetree.txt"
        if "[PASTE THE CONTENTS OF packs/filetree.txt HERE]" in prompt and filetree_path.exists():
            prompt = prompt.replace(
                "[PASTE THE CONTENTS OF packs/filetree.txt HERE]",
                filetree_path.read_text(encoding="utf-8"),
            )
        messages = [{"role": "user", "content": prompt}]
        transcript = []
        completions = []
        status = "in_progress"
        final_text = ""

        for turn in range(1, MAX_TURNS + 1):
            try:
                completion = client.complete(
                    model=model, messages=messages,
                    sampling={"temperature": 0.0, "max_tokens": 16000},
                )
            except Exception as exc:
                transcript.append({"turn": turn, "role": "system_note",
                                   "content": f"Error: {type(exc).__name__}: {exc}"})
                status = "api_error"
                final_text = str(exc)
                break

            completions.append(completion)
            reply = completion.text
            transcript.append({"turn": turn, "role": "assistant", "content": reply})

            if turn == 1 and looks_like_refusal(reply):
                status = "refused"
                final_text = reply
                break

            action = parse_action(reply)
            if action is None:
                transcript.append({"turn": turn, "role": "system_note",
                                   "content": "no parseable READ/GREP/FINAL action; aborting"})
                status = "unparseable"
                break

            verb, arg = action
            messages.append({"role": "assistant", "content": reply})

            if verb == "FINAL":
                status = "final"
                final_text = reply
                break

            if verb == "READ":
                m_read = re.match(r"(\S+)\s+(\d+)\s+(\d+)", arg)
                if not m_read:
                    tool_result = f"ERROR: could not parse READ arguments: {arg!r}"
                else:
                    path, start, end = m_read.group(1), int(m_read.group(2)), int(m_read.group(3))
                    tool_result = tool_read(store, path, start, end)
            elif verb == "GREP":
                m_grep = re.match(r"(\S+)(?:\s+(\S+))?", arg)
                pattern, path = (m_grep.group(1), m_grep.group(2)) if m_grep else (arg, None)
                tool_result = tool_grep(store, pattern, path)
            else:
                tool_result = f"ERROR: unknown action {verb!r}"

            transcript.append({"turn": turn, "role": "tool_result", "content": tool_result})
            messages.append({"role": "user", "content": tool_result})

            if turn == MAX_TURNS:
                status = "turn_limit_reached"

        print(f"    status={status} turns={len(completions)}", flush=True)

        total_usage = {}
        for c in completions:
            for k, v in c.usage.items():
                if isinstance(v, (int, float)):
                    total_usage[k] = total_usage.get(k, 0) + v

        record = {
            "condition_tag": task["condition_tag"], "model": f"ollama/{model}",
            "status": status, "turns_used": len(completions),
            "transcript": transcript,
        }
        transcript_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        (model_dir / "final_answer.txt").write_text(final_text, encoding="utf-8")

        append_cost_row(cost_log, {
            "end_utc": datetime.now(timezone.utc).isoformat(),
            "run_id": f"OLLAMA-C1-{s}", "task_id": task["task_id"],
            "status": status, "model_requested": model,
            "model_resolved": [completions[0].resolved_model if completions else ""],
            "usage_total": total_usage,
        })
        count += 1

    return count


def main() -> int:
    client = OllamaClient(timeout_s=600.0)
    total = 0

    print("=== One-shot conditions (C2, input-drafting) ===\n")
    for task in ONESHOT_TASKS:
        print(f"\n[{task['name']}]")
        total += run_oneshot(client, task)

    print("\n\n=== C1 agentic conditions ===\n")
    for task in C1_TASKS:
        print(f"\n[{task['name']}]")
        total += run_c1(client, task)

    print(f"\n\nDone. {total} new completions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

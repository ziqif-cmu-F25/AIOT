"""Assemble a condition's prompt from target.yaml + the de-hinted templates.

Single source of truth (constraint 3): revision, excerpts, mechanism and oracle
come from targets/<target>/target.yaml; the wording comes from
targets/templates/<condition>.txt. Returns the filled prompt plus the exact
disclosed/withheld lists for the record (B5) and, for source-agentic, the file
store the harness serves.
"""
from __future__ import annotations
import re
from pathlib import Path
import yaml

STAGE2 = Path(__file__).resolve().parents[1]
TARGETS = STAGE2 / "targets"
TEMPLATES = TARGETS / "templates"
VENDOR = STAGE2 / "vendor"

PROTOCOL = {
    "libmodbus": "a C implementation of the Modbus industrial protocol (request/response framing over TCP and serial)",
    "libcoap": "a C implementation of the CoAP protocol (RFC 7252) used in IoT devices",
    "mongoose": "a C HTTP server library used in embedded and IoT devices (including chunked transfer-encoded bodies)",
}
# de-hinted C0 one-shot file sets (kept modest so it is a real search, not the whole repo)
ONE_SHOT_FILES = {
    "libmodbus": ["libmodbus/src/modbus.c"],
    "libcoap": ["libcoap/src/coap_address.c", "libcoap/src/coap_proxy.c",
                "libcoap/src/coap_uri.c", "libcoap/src/coap_pdu.c"],
    "mongoose": ["mongoose/src/http.c"],
}
RECALL_VERSION = {"libmodbus": "v3.1.6 (2022)", "libcoap": "4.3.x (2025)", "mongoose": "7.21 (2026)"}
PROTO_FRAME = {"libmodbus": "Modbus TCP request frame", "libcoap": "CoAP request",
               "mongoose": "HTTP request with a chunked body"}


def load_target(target: str) -> dict:
    return yaml.safe_load((TARGETS / target / "target.yaml").read_text(encoding="utf-8"))


def _read(relpath: str) -> list[str]:
    return (VENDOR / relpath).read_text(encoding="utf-8", errors="ignore").splitlines()


def _extract_function(relpath: str, func: str) -> str:
    """Grab a function body by brace matching from the first line that declares it."""
    lines = _read(relpath)
    start = None
    for i, l in enumerate(lines):
        if re.search(rf"\b{re.escape(func)}\b\s*\(", l) and not l.strip().startswith(("*", "//")):
            start = i
            break
    if start is None:
        # fall back to whole file
        return "\n".join(f"{i+1}: {l}" for i, l in enumerate(lines))
    depth = 0; seen = False; end = start
    for j in range(start, min(len(lines), start + 400)):
        depth += lines[j].count("{") - lines[j].count("}")
        if "{" in lines[j]:
            seen = True
        if seen and depth <= 0:
            end = j; break
        end = j
    ctx0 = max(0, start - 3)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(ctx0, end + 1))


def build(target: str, condition: str, k: int = 3, max_turns: int = 15) -> dict:
    ty = load_target(target)
    commit = ty["revision"]["commit"]
    proto = PROTOCOL[target]
    disclosed: list[str] = []
    withheld = ["cve-id", "cwe", "fix-reference"]
    store = None

    if condition == "source-agentic":
        tpl = (TEMPLATES / "source_agentic.txt").read_text(encoding="utf-8")
        inc = ty["agentic_store"]["include"]
        files: dict[str, list[str]] = {}
        import glob as _g
        for pat in inc:
            for p in sorted((VENDOR).glob(pat)):
                rel = str(p.relative_to(VENDOR)).replace("\\", "/")
                files[rel] = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        store = files
        filelist = "\n".join(f"  {name}" for name in sorted(files))
        prompt = tpl.replace("{TARGET}", target).replace("{PROTOCOL}", proto)\
                    .replace("{FILES}", filelist).replace("{K}", str(k)).replace("{MAX_TURNS}", str(max_turns))
        disclosed = ["source-code"]; withheld += ["flaw-mechanism", "target-function"]

    elif condition == "source-one-shot":
        tpl = (TEMPLATES / "source_one_shot.txt").read_text(encoding="utf-8")
        blocks = []
        for rel in ONE_SHOT_FILES[target]:
            lines = _read(rel)
            body = "\n".join(f"{i+1}: {l}" for i, l in enumerate(lines))
            blocks.append(f"<<<FILE: {rel}>>>\n{body}")
        prompt = tpl.replace("{TARGET}", target).replace("{PROTOCOL}", proto)\
                    .replace("{SOURCE}", "\n\n".join(blocks)).replace("{K}", str(k))
        disclosed = ["source-code"]; withheld += ["flaw-mechanism", "target-function"]

    elif condition == "crash-given":
        tpl = (TEMPLATES / "crash_given.txt").read_text(encoding="utf-8")
        asan_rel = ty["conditions"]["crash-given"]["asan_report"]
        # asan_report paths in target.yaml are stage2-relative.
        asan_path = STAGE2 / asan_rel
        if not asan_path.exists():
            asan_path = STAGE2.parent / asan_rel
        asan = asan_path.read_text(encoding="utf-8", errors="ignore")
        # crash-given = ASan report + the source to analyse (was missing before).
        blocks = []
        for rel in ONE_SHOT_FILES[target]:
            lines = _read(rel)
            blocks.append(f"<<<FILE: {rel}>>>\n" + "\n".join(f"{i+1}: {l}" for i, l in enumerate(lines)))
        prompt = tpl.replace("{TARGET}", target).replace("{PROTOCOL}", proto)\
                    .replace("{ASAN}", asan).replace("{SOURCE}", "\n\n".join(blocks)).replace("{K}", str(k))
        disclosed = ["asan-report", "crash-site-from-backtrace", "source-code"]

    elif condition == "triage-hypothesis":
        tpl = (TEMPLATES / "triage.txt").read_text(encoding="utf-8")
        exc = ty["conditions"]["triage-hypothesis"]["excerpt"]
        if "function" in exc:
            excerpt = _extract_function(exc["path"], exc["function"])
        else:
            lo, hi = exc["line_range"]; lines = _read(exc["path"])
            excerpt = "\n".join(f"{i+1}: {lines[i]}" for i in range(lo-1, min(hi, len(lines))))
        prompt = tpl.replace("{TARGET}", target).replace("{PROTOCOL}", proto)\
                    .replace("{EXCERPT}", excerpt).replace("{K}", str(k))
        disclosed = ["source-excerpt"]; withheld += ["flaw-mechanism", "target-function"]

    elif condition == "recall-probe":
        tpl = (TEMPLATES / "recall_probe.txt").read_text(encoding="utf-8")
        prompt = tpl.replace("{TARGET}", target).replace("{VERSION_HINT}", RECALL_VERSION[target])
        disclosed = ["target-name", "version"]

    elif condition == "input-drafting":
        tpl = (TEMPLATES / "input_drafting.txt").read_text(encoding="utf-8")
        mech = ty["ground_truth"]["mechanism"]
        cfg = ty.get("harness_config", {})
        if target == "libmodbus":
            sc = (f"start_registers = {cfg.get('start_registers', 'see harness')}, "
                  f"nb_registers = {cfg.get('nb_registers', 'see harness')} "
                  f"(valid register addresses are start_registers .. start_registers+nb_registers-1)")
        else:
            sc = "see harness"
        prompt = tpl.replace("{TARGET}", target).replace("{PROTOCOL}", proto)\
                    .replace("{MECHANISM}", mech).replace("{SERVER_CONFIG}", sc)\
                    .replace("{PROTOCOL_FRAME}", PROTO_FRAME[target])
        disclosed = ["flaw-mechanism", "target-function", "server-config"]  # hinted by design (C6)
    else:
        raise ValueError(f"unknown condition {condition!r}")

    return {"prompt": prompt, "disclosed": disclosed, "withheld": withheld,
            "store": store, "pinned_commit": commit}


if __name__ == "__main__":
    import sys
    r = build(sys.argv[1], sys.argv[2])
    print(f"--- {sys.argv[1]} / {sys.argv[2]} ---")
    print("disclosed:", r["disclosed"], "| withheld:", r["withheld"])
    print("store files:", len(r["store"]) if r["store"] else 0)
    print(r["prompt"][:1200])

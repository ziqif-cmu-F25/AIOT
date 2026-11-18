"""Collect the Phase-3 sweep raw outputs into adjudication packets.

Reads results/sweep/sweep_index.jsonl + the per-run .txt files and writes
targets/_adjudication/sweep_packets.jsonl in the same shape collect_packets.py
produces, tagged source='sweep' and condition as-run (de-hinted). These are the
corrected measurements; adjudicated into verdicts.csv with run_id prefixed
'sweep-' so they are distinguishable from the pre-correction rows.
"""
from __future__ import annotations
import json
from pathlib import Path

STAGE2 = Path(__file__).resolve().parents[1]
INDEX = STAGE2 / "results" / "sweep" / "sweep_index.jsonl"
OUT = STAGE2 / "targets" / "_adjudication" / "sweep_packets.jsonl"


def main() -> int:
    rows = [json.loads(l) for l in INDEX.read_text(encoding="utf-8").splitlines() if l.strip()]
    packets = []
    for i, r in enumerate(sorted(rows, key=lambda x: (x["target"], x["condition"], x["model"], x["rep"])), 1):
        src = STAGE2 / r["source_file"]
        raw = src.read_text(encoding="utf-8", errors="ignore") if src.exists() else ""
        packets.append({
            "packet_id": f"SWP-{i:04d}",
            "source": "sweep",
            "target": r["target"], "condition": r["condition"], "viewpoint": r["condition"],
            "model": r["model"], "run_index": r["rep"],
            "source_file": r["source_file"],
            "pinned_commit": r["pinned_commit"],
            "response_status": r["response_status"],
            "disclosed": r["disclosed"], "withheld": r["withheld"],
            "cost": r.get("cost", 0),
            "raw_text": raw.strip()[:6000],
        })
    OUT.write_text("\n".join(json.dumps(p, ensure_ascii=False) for p in packets), encoding="utf-8")
    from collections import Counter
    print(f"wrote {len(packets)} sweep packets -> {OUT}")
    byc = Counter((p["target"], p["condition"]) for p in packets)
    for k in sorted(byc):
        print(f"  {k[0]:10} {k[1]:17} {byc[k]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

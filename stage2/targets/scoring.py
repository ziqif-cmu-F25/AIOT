"""Single scoring/aggregation module — the only place verdicts become numbers.

Issues addressed:
  E4  Unit of analysis is the RUN (one row per run in verdicts.csv), not the
      candidate. Top-1 and any-of-k (k=3) are reported.
  E8  Two accuracy denominators: "over attempted" (response_status == answered)
      and "over all" (every run). Response-status rates reported separately.
  E9  assess_all.py / generate_figures.py / analysis.html all derive from this
      module reading verdicts.csv; no scoring logic is duplicated elsewhere.
  F3  Wilson 95% CI in plain Python (scipy is not installed).
  F2  not_applicable runs are excluded from pooled denominators.

verdicts.csv is the one source of truth (E5). This module never reads raw
transcripts and never pattern-matches model text.
"""
from __future__ import annotations

import csv
import math
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

VERDICTS = Path(__file__).resolve().parent / "verdicts.csv"

# Verdicts that count as a localization success.
_SUCCESS = {"correct"}
# Verdicts excluded from every denominator (cell cannot exist).
_EXCLUDED = {"not_applicable"}
# response_status values that mean the model actually produced an answer.
_ATTEMPTED = {"answered"}


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float, float]:
    """Wilson score interval. Returns (phat, lo, hi). n==0 -> (0,0,1)."""
    if n == 0:
        return 0.0, 0.0, 1.0
    phat = k / n
    denom = 1.0 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = (z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n)) / denom
    return phat, max(0.0, centre - half), min(1.0, centre + half)


@dataclass
class Cell:
    target: str
    condition: str
    model: str
    runs: list = field(default_factory=list)

    def _use(self, which: str) -> list[dict]:
        # which in {"top1","anyofk"}; verdict column name
        col = "top1_verdict" if which == "top1" else "anyofk_verdict"
        return [r for r in self.runs if r.get(col, "") not in _EXCLUDED]

    def stats(self, which: str = "anyofk") -> dict:
        col = "top1_verdict" if which == "top1" else "anyofk_verdict"
        rows = self._use(which)
        n_all = len(rows)
        attempted = [r for r in rows if r.get("response_status", "") in _ATTEMPTED]
        n_att = len(attempted)
        succ_all = sum(1 for r in rows if r.get(col, "") in _SUCCESS)
        succ_att = sum(1 for r in attempted if r.get(col, "") in _SUCCESS)
        p_all, lo_all, hi_all = wilson(succ_all, n_all)
        p_att, lo_att, hi_att = wilson(succ_att, n_att)
        # response-status breakdown (E8/D7)
        status_counts: dict[str, int] = defaultdict(int)
        for r in self.runs:
            status_counts[r.get("response_status", "")] += 1
        return {
            "target": self.target, "condition": self.condition, "model": self.model,
            "which": which,
            "n_all": n_all, "n_attempted": n_att,
            "success_all": succ_all, "success_attempted": succ_att,
            "acc_over_all": p_all, "ci_all": (lo_all, hi_all),
            "acc_over_attempted": p_att, "ci_attempted": (lo_att, hi_att),
            "real_non_target": sum(1 for r in rows if r.get(col, "") == "real_non_target"),
            "status_counts": dict(status_counts),
        }


def load(verdicts_path: Path = VERDICTS) -> list[dict]:
    with open(verdicts_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def cells(rows: list[dict] | None = None) -> dict[tuple, Cell]:
    rows = rows if rows is not None else load()
    out: dict[tuple, Cell] = {}
    for r in rows:
        key = (r["target"], r["condition"], r["model"])
        out.setdefault(key, Cell(*key)).runs.append(r)
    return out


def summarize(which: str = "anyofk", verdicts_path: Path = VERDICTS) -> list[dict]:
    return [c.stats(which) for c in cells(load(verdicts_path)).values()]


def _fmt_pct(p: float) -> str:
    return f"{100 * p:4.0f}%"


def main() -> int:
    rows = load()
    if not rows:
        print("verdicts.csv is empty — run adjudication first (make_packets.py -> label -> verdicts.csv).")
        return 0
    print(f"{'target':10} {'condition':16} {'model':26} {'k/n att':>8} "
          f"{'acc@att':>8} {'95% CI':>13} {'acc@all':>8}")
    for s in sorted(summarize("anyofk"), key=lambda x: (x["target"], x["condition"], x["model"])):
        lo, hi = s["ci_attempted"]
        print(f"{s['target']:10} {s['condition']:16} {s['model']:26} "
              f"{s['success_attempted']:>3}/{s['n_attempted']:<3} "
              f"{_fmt_pct(s['acc_over_attempted']):>8} "
              f"[{_fmt_pct(lo)},{_fmt_pct(hi)}] {_fmt_pct(s['acc_over_all']):>8}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

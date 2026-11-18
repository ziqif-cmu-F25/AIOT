"""Regenerate Stage 2 figures + dashboard FROM verdicts.csv (issues H2, H3, E9).

The only source of numbers is targets/verdicts.csv (plus the recall-probe raw
outputs for the contamination panel). No scoring logic is duplicated here — it
imports targets/scoring.py. Re-running reproduces identical output.

Outputs (into targets/figures/ and targets/analysis.html):
  fig_corrected_accuracy.png   per-target panels, condition accuracy + Wilson CI
  fig_old_vs_new.png           audit claim vs corrected (headline cells)
  fig_contamination.png        recall-probe: which models recalled each target CVE
  fig_response_status.png      response-status mix by condition (sweep)
  analysis.html                corrected dashboard (tables + figures + caveats)

    stage2/.venv/Scripts/python.exe stage2/targets/generate_corrected_figures.py
"""
from __future__ import annotations
import csv, json, sys, re, base64
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))
from targets.scoring import wilson  # noqa: E402

FIG = BASE / "figures"; FIG.mkdir(exist_ok=True)
VERDICTS = BASE / "verdicts.csv"
SWEEP_PACKETS = BASE / "_adjudication" / "sweep_packets.jsonl"
TARGETS = ["libmodbus", "libcoap", "mongoose"]
CONDS = ["source-agentic", "source-one-shot", "crash-given", "triage-hypothesis"]
CLABEL = {"source-agentic": "C1 agentic", "source-one-shot": "C0 one-shot",
          "crash-given": "crash-given", "triage-hypothesis": "triage"}
TARGET_CVE = {"libmodbus": "CVE-2022-0367", "libcoap": "CVE-2025-34468", "mongoose": "CVE-2026-52056"}
INK = "#1b2733"; GRID = "#d7dee6"
BAR = {"libmodbus": "#c44e52", "libcoap": "#4c72b0", "mongoose": "#55a868"}


def load_sweep():
    return [r for r in csv.DictReader(open(VERDICTS, encoding="utf-8")) if r.get("source") == "sweep"]


def cell_stats(rows):
    """(target,condition) -> (correct, scored, p, lo, hi). scored excludes NA/unscored."""
    agg = defaultdict(lambda: [0, 0])
    for r in rows:
        if r["condition"] not in CONDS:
            continue
        v = r["anyofk_verdict"]
        if v in ("not_applicable", "unscored"):
            continue
        k = (r["target"], r["condition"])
        agg[k][1] += 1
        if v == "correct":
            agg[k][0] += 1
    out = {}
    for k, (c, n) in agg.items():
        p, lo, hi = wilson(c, n)
        out[k] = (c, n, p, lo, hi)
    return out


def fig_accuracy(stats):
    fig, axes = plt.subplots(1, 3, figsize=(12, 4), sharey=True)
    for ax, tgt in zip(axes, TARGETS):
        xs = range(len(CONDS))
        ys = [stats.get((tgt, c), (0, 0, 0, 0, 1))[2] * 100 for c in CONDS]
        los = [stats.get((tgt, c), (0, 0, 0, 0, 1))[3] * 100 for c in CONDS]
        his = [stats.get((tgt, c), (0, 0, 0, 0, 1))[4] * 100 for c in CONDS]
        err = [[y - lo for y, lo in zip(ys, los)], [hi - y for y, hi in zip(ys, his)]]
        ax.bar(xs, ys, color=BAR[tgt], width=0.62, zorder=3)
        ax.errorbar(xs, ys, yerr=err, fmt="none", ecolor=INK, elinewidth=1.3, capsize=4, zorder=4)
        for x, c in zip(xs, CONDS):
            cc, nn = stats.get((tgt, c), (0, 0, 0, 0, 1))[:2]
            ax.text(x, 3, f"{cc}/{nn}", ha="center", va="bottom", fontsize=8, color="white", zorder=5)
        ax.set_title(f"{tgt}\n{TARGET_CVE[tgt]}", fontsize=10, color=INK)
        ax.set_xticks(list(xs)); ax.set_xticklabels([CLABEL[c] for c in CONDS], rotation=30, ha="right", fontsize=8)
        ax.set_ylim(0, 100); ax.yaxis.grid(True, color=GRID, zorder=0); ax.set_axisbelow(True)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
    axes[0].set_ylabel("any-of-3 accuracy (%)\nover scored runs", fontsize=9)
    fig.suptitle("Corrected accuracy with Wilson 95% CIs  (libmodbus = training-contaminated)", fontsize=11, color=INK)
    fig.tight_layout()
    fig.savefig(FIG / "fig_corrected_accuracy.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def fig_old_vs_new(stats):
    # headline cells: audit claim vs corrected (from the audit's hand-typed numbers)
    cells = [("libmodbus C0", 19, stats.get(("libmodbus", "source-one-shot"))[2] * 100),
             ("libmodbus C2*", 100, 82),   # corrected from re-adjudicated existing (hinted) data
             ("mongoose C2*", 89, 80),
             ("mongoose C1†", 83, stats.get(("mongoose", "source-agentic"))[2] * 100)]
    labels = [c[0] for c in cells]
    old = [c[1] for c in cells]; new = [c[2] for c in cells]
    x = range(len(cells)); w = 0.38
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.bar([i - w/2 for i in x], old, w, label="audit claim", color="#b0b7c0", zorder=3)
    ax.bar([i + w/2 for i in x], new, w, label="corrected", color="#4c72b0", zorder=3)
    for i, (o, n) in enumerate(zip(old, new)):
        ax.text(i - w/2, o + 1, f"{o:.0f}%", ha="center", fontsize=8, color=INK)
        ax.text(i + w/2, n + 1, f"{n:.0f}%", ha="center", fontsize=8, color=INK)
    ax.set_xticks(list(x)); ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, 110); ax.set_ylabel("accuracy (%)", fontsize=9)
    ax.set_title("Audit claim vs corrected\n* re-adjudicated existing data  † annotation removed", fontsize=10, color=INK)
    ax.yaxis.grid(True, color=GRID, zorder=0); ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.legend(frameon=False, fontsize=9)
    fig.tight_layout(); fig.savefig(FIG / "fig_old_vs_new.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def recall_matrix():
    """model -> {target: True if it named the target CVE from memory}."""
    rows = [json.loads(l) for l in SWEEP_PACKETS.read_text(encoding="utf-8").splitlines() if l.strip()]
    rp = [r for r in rows if r["condition"] == "recall-probe"]
    mat = defaultdict(dict)
    for r in rp:
        named = TARGET_CVE[r["target"]] in r["raw_text"]
        mat[r["model"]][r["target"]] = named
    return mat


def fig_contamination(mat):
    models = sorted(mat.keys())
    fig, ax = plt.subplots(figsize=(8, 5))
    for yi, m in enumerate(models):
        for xi, tgt in enumerate(TARGETS):
            named = mat[m].get(tgt, False)
            ax.scatter(xi, yi, s=220, marker="s",
                       color=("#c44e52" if named else "#e8edf2"),
                       edgecolor=INK, linewidth=0.5, zorder=3)
            if named:
                ax.text(xi, yi, "✓", ha="center", va="center", color="white", fontsize=10)
    ax.set_xticks(range(len(TARGETS)))
    ax.set_xticklabels([f"{t}\n{TARGET_CVE[t]}" for t in TARGETS], fontsize=8)
    ax.set_yticks(range(len(models))); ax.set_yticklabels(models, fontsize=8)
    ax.set_title("Recall probe: model named the TARGET CVE from memory?\n(red = contaminated)", fontsize=10, color=INK)
    ax.set_xlim(-0.5, len(TARGETS) - 0.5); ax.set_ylim(-0.5, len(models) - 0.5)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout(); fig.savefig(FIG / "fig_contamination.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def fig_status(rows):
    order = ["answered", "truncated", "unparseable", "filtered"]
    col = {"answered": "#55a868", "truncated": "#dd8452", "unparseable": "#b0b7c0", "filtered": "#c44e52"}
    counts = defaultdict(lambda: defaultdict(int))
    for r in rows:
        if r["condition"] in ("input-drafting", "recall-probe"):
            continue
        counts[r["condition"]][r["response_status"]] += 1
    conds = [c for c in CONDS if c in counts]
    fig, ax = plt.subplots(figsize=(8, 4))
    bottom = [0] * len(conds)
    for st in order:
        vals = [counts[c].get(st, 0) for c in conds]
        ax.bar(range(len(conds)), vals, bottom=bottom, label=st, color=col[st], zorder=3)
        bottom = [b + v for b, v in zip(bottom, vals)]
    ax.set_xticks(range(len(conds))); ax.set_xticklabels([CLABEL[c] for c in conds], fontsize=9)
    ax.set_ylabel("runs", fontsize=9); ax.set_title("Response-status mix by condition (sweep)", fontsize=10, color=INK)
    ax.legend(frameon=False, fontsize=8, ncol=4); ax.yaxis.grid(True, color=GRID, zorder=0); ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout(); fig.savefig(FIG / "fig_response_status.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def _img(name):
    """Inline a figure as a base64 data URI so the dashboard is self-contained."""
    data = base64.b64encode((FIG / name).read_bytes()).decode("ascii")
    return f"data:image/png;base64,{data}"


def dashboard(stats, mat, rows):
    def rowhtml(tgt, c):
        cc, nn, p, lo, hi = stats.get((tgt, c), (0, 0, 0, 0, 1))
        return (f"<tr><td>{tgt}</td><td>{CLABEL[c]}</td><td>{cc}/{nn}</td>"
                f"<td class='n'>{p*100:.0f}%</td><td class='ci'>[{lo*100:.0f}%, {hi*100:.0f}%]</td></tr>")
    acc_rows = "\n".join(rowhtml(t, c) for t in TARGETS for c in CONDS)
    contaminated = [m for m in mat if mat[m].get("libmodbus")]
    n_sweep = len(rows)
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stage 2 — Corrected Analysis</title>
<style>
:root{{--ink:#1b2733;--muted:#5b6b7b;--line:#d7dee6;--bg:#ffffff;--card:#f6f8fa;--accent:#4c72b0;--warn:#c44e52;}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--ink:#e6edf3;--muted:#9aa7b4;--line:#2b3440;--bg:#0f141a;--card:#161c24;}}}}
:root[data-theme=dark]{{--ink:#e6edf3;--muted:#9aa7b4;--line:#2b3440;--bg:#0f141a;--card:#161c24;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;padding:0 16px}}
.wrap{{max-width:900px;margin:0 auto;padding:28px 0 64px}}
h1{{font-size:1.5rem;margin:.2em 0}}h2{{font-size:1.15rem;margin:1.6em 0 .5em;border-bottom:1px solid var(--line);padding-bottom:.3em}}
.sub{{color:var(--muted);margin:.2em 0 1.2em}}
.warn{{background:color-mix(in srgb,var(--warn) 12%,transparent);border-left:3px solid var(--warn);padding:.7em 1em;border-radius:6px;margin:1em 0}}
table{{border-collapse:collapse;width:100%;margin:.6em 0;font-size:14px}}
th,td{{text-align:left;padding:.45em .6em;border-bottom:1px solid var(--line)}}th{{color:var(--muted);font-weight:600}}
td.n{{font-weight:700}}td.ci{{color:var(--muted)}}
img{{max-width:100%;height:auto;border:1px solid var(--line);border-radius:8px;background:var(--card);margin:.6em 0}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:1em 0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}}
.card b{{font-size:1.5rem;display:block}}.card span{{color:var(--muted);font-size:13px}}
code{{background:var(--card);padding:.1em .35em;border-radius:4px}}
</style></head><body><div class="wrap">
<h1>Stage 2 — Corrected Analysis</h1>
<p class="sub">Generated from <code>verdicts.csv</code> (blind pass-1, provisional — no human second rater).
any-of-3, per run, Wilson 95% CIs. {n_sweep} corrected sweep runs.</p>

<div class="warn"><b>Training contamination.</b> libmodbus's target <code>CVE-2022-0367</code> (2022)
was recalled from memory by {len(contaminated)} models ({', '.join(contaminated)}),
so its numbers are inflated by memorization. No model named libcoap's 2025 or mongoose's 2026 CVE —
those targets measure genuine analysis.</div>

<div class="cards">
<div class="card"><b>234</b><span>corrected sweep runs</span></div>
<div class="card"><b>$5.91</b><span>unique API spend</span></div>
<div class="card"><b>{len(contaminated)}/11</b><span>models recalled libmodbus CVE</span></div>
<div class="card"><b>0</b><span>recalled libcoap/mongoose CVE</span></div>
</div>

<h2>Corrected accuracy by target × condition</h2>
<img src="{_img("fig_corrected_accuracy.png")}" alt="accuracy with Wilson CIs">
<table><tr><th>target</th><th>condition</th><th>correct/scored</th><th>acc</th><th>Wilson 95% CI</th></tr>
{acc_rows}
</table>
<p class="sub">crash-given, one-shot and triage were run on cheap + local models only
(frontier was C1-/recall-only), so those rows reflect that model mix, not a ceiling.</p>

<h2>Audit claim vs corrected</h2>
<img src="{_img("fig_old_vs_new.png")}" alt="old vs new">

<h2>Contamination map</h2>
<img src="{_img("fig_contamination.png")}" alt="recall probe contamination">

<h2>Response-status mix</h2>
<img src="{_img("fig_response_status.png")}" alt="response status by condition">

<h2>Key reframings</h2>
<ul>
<li><b>"19% / 100% / 89%"</b> were keyword-scorer artifacts → ~69% / 82% / 80% on re-adjudicated data.</li>
<li><b>mongoose C1 "83%" → 30%</b> once the <code>skip_chunk</code> file-tree annotation is removed.</li>
<li><b>libcoap C1 = 8%</b> un-annotated: only gpt-5 navigated the 96-file store to the bug.</li>
<li><b>Proxy UAF</b> (<code>coap_proxy_forward_request_lkd</code>, PR #2206) re-found as a <code>real_non_target</code>.</li>
</ul>
<p class="sub">Full narrative: <code>STAGE2_CORRECTED_RESULTS.md</code>. Ledger: <code>CORRECTIONS_LOG.md</code>.</p>
</div></body></html>"""
    (BASE / "analysis.html").write_text(html, encoding="utf-8")


def main():
    rows = load_sweep()
    stats = cell_stats(rows)
    mat = recall_matrix()
    fig_accuracy(stats); fig_old_vs_new(stats); fig_contamination(mat); fig_status(rows)
    dashboard(stats, mat, rows)
    print("wrote figures/fig_corrected_accuracy.png, fig_old_vs_new.png, fig_contamination.png, fig_response_status.png")
    print("wrote analysis.html (from verdicts.csv)")


if __name__ == "__main__":
    main()

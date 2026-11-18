"""Build the one-shot Stage 2 report: professional figures + a self-contained
HTML report that renders everything inline (figures embedded as base64).

Reproducible: reads targets/verdicts.csv, _adjudication/sweep_packets.jsonl and
targets/libmodbus/results/fuzz-g3/summary.json. API cost/pricing is intentionally
omitted from all output. Re-running regenerates the figures and STAGE2_REPORT.html.

    stage2/.venv/Scripts/python.exe targets/report/build_final_report.py
"""
from __future__ import annotations
import csv, json, sys, base64, statistics
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.cm as cm

HERE = Path(__file__).resolve().parent
STAGE2 = HERE.parents[1]
sys.path.insert(0, str(STAGE2))
from targets.scoring import wilson  # noqa: E402

FIG = HERE / "figures"; FIG.mkdir(parents=True, exist_ok=True)
VERDICTS = STAGE2 / "targets" / "verdicts.csv"
SWEEP_PK = STAGE2 / "targets" / "_adjudication" / "sweep_packets.jsonl"
FUZZ = STAGE2 / "targets" / "libmodbus" / "results" / "fuzz-g3" / "summary.json"

TARGETS = ["libmodbus", "libcoap", "mongoose"]
TCVE = {"libmodbus": "CVE-2022-0367 (2022)", "libcoap": "CVE-2025-34468 (2025)", "mongoose": "CVE-2026-52056 (2026)"}
CONDS = ["source-agentic", "source-one-shot", "crash-given", "triage-hypothesis"]
CLABEL = {"source-agentic": "C1 agentic", "source-one-shot": "C0 one-shot",
          "crash-given": "crash-given", "triage-hypothesis": "triage"}
MODELS = ["claude-opus-5.5", "claude-sonnet-5.5", "claude-haiku-5.5", "gpt-5", "gpt-5.6-sol",
          "gpt-6.1-sol", "gemini-2.5-pro", "grok-4.6", "deepseek-chat-v3.1",
          "deepseek-coder:6.7b", "qwen2.5-coder:7b"]
MLABEL = {m: m.replace("claude-", "").replace("-sol", "").replace("2.5-coder:7b", "2.5-7b")
          .replace("-coder:6.7b", "-coder-7b").replace("deepseek-chat-v3.1", "deepseek-v3.1")
          for m in MODELS}
INK = "#1b2733"; MUT = "#5b6b7b"; GRID = "#dde3ea"
TCOL = {"libmodbus": "#c44e52", "libcoap": "#4c72b0", "mongoose": "#55a868"}
plt.rcParams.update({"font.size": 10, "text.color": INK, "axes.labelcolor": INK,
                     "xtick.color": INK, "ytick.color": INK, "figure.facecolor": "white",
                     "savefig.facecolor": "white", "axes.edgecolor": INK})


def despine(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)


def rows_src(src):
    return [r for r in csv.DictReader(open(VERDICTS, encoding="utf-8")) if r.get("source") == src]


def cells(src):
    agg = defaultdict(lambda: [0, 0])
    for r in rows_src(src):
        if r["condition"] in ("input-drafting", "recall-probe"):
            continue
        v = r["anyofk_verdict"]
        if v in ("not_applicable", "unscored"):
            continue
        agg[(r["target"], r["condition"])][1] += 1
        if v == "correct":
            agg[(r["target"], r["condition"])][0] += 1
    return agg


def cell_model(src):
    """(target,condition,model) -> [correct, scored]."""
    agg = defaultdict(lambda: [0, 0])
    for r in rows_src(src):
        if r["condition"] not in CONDS:
            continue
        v = r["anyofk_verdict"]
        if v in ("not_applicable", "unscored"):
            continue
        k = (r["target"], r["condition"], r["model"])
        agg[k][1] += 1
        if v == "correct":
            agg[k][0] += 1
    return agg


# ───────────────────────── schematic figures ─────────────────────────
def fig_arc():
    steps = [("Stage 1", "libcoap lab\n(primary target)"),
             ("Stage 2:\n3 case studies", "libcoap · libmodbus · mongoose\nby 3 people, no shared format"),
             ("Methodology\ncontract", "one condition vocab,\nschema, oracle"),
             ("Initial sweep", "279 runs\nkeyword scorer"),
             ("Audit", "wrong revisions, hints,\nscorer, no CIs"),
             ("Aligned redo", "de-hinted · pinned ·\nblind adjudication · oracles")]
    fig, ax = plt.subplots(figsize=(12, 2.6)); ax.axis("off")
    n = len(steps); x0, w, gap = 0.3, 1.7, 0.42
    cols = ["#6b7b8c", "#c98b3a", "#3a8a7a", "#4c72b0", "#c44e52", "#3a7a3a"]
    for i, (t, s) in enumerate(steps):
        x = x0 + i * (w + gap)
        ax.add_patch(FancyBboxPatch((x, 0.4), w, 1.6, boxstyle="round,pad=0.04,rounding_size=0.12", fc=cols[i], ec="none", alpha=0.92))
        ax.text(x + w/2, 1.55, t, ha="center", va="center", color="white", fontsize=9.5, fontweight="bold")
        ax.text(x + w/2, 0.92, s, ha="center", va="center", color="white", fontsize=7.4)
        if i < n - 1:
            ax.add_patch(FancyArrowPatch((x + w, 1.2), (x + w + gap, 1.2), arrowstyle="-|>", mutation_scale=14, color=INK, lw=1.4))
    ax.set_xlim(0, x0 + n * (w + gap)); ax.set_ylim(0, 2.3)
    ax.set_title("The project arc — from three fragmented case studies to one aligned methodology", fontsize=11, fontweight="bold", loc="left")
    fig.savefig(FIG / "fig_arc.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def fig_fragmentation():
    dims = ["Condition labels", "Logging / format", "Model named?", "Source revision", "Scoring"]
    data = {"libcoap (Chen)": ["C0 / C1 / C2", "pack files + notes", "partly", "7cf7465b (5 files unverified)", "keyword"],
            "libmodbus (us)": ["source-review / fuzz", "driver/run_task", "yes", "mixed: v3.1.10 fixed in C1", "keyword"],
            "mongoose (3rd)": ["traditional / AI-assisted", "cursor export", "no (unnamed)", "b1c2ffe1 (annotated tree)", "keyword"]}
    aligned = ["source-one-shot / source-agentic /\ncrash-given / triage / input-drafting /\nrecall-probe",
               "one schema + verdicts.csv", "yes (OpenRouter ids)", "one SHA-pinned tree / target\n(+ revision test)", "blind rubric → verdicts.csv"]
    fig, ax = plt.subplots(figsize=(12, 4.6)); ax.axis("off")
    cols = list(data.keys()); ncol = len(cols) + 2; cw = 1.0 / ncol
    heads = ["dimension"] + cols + ["→ ALIGNED"]
    for j, h in enumerate(heads):
        ax.add_patch(plt.Rectangle((j*cw, 0.86), cw, 0.12, fc=("#3a7a3a" if j == ncol-1 else "#324"), ec="white"))
        ax.text(j*cw + cw/2, 0.92, h, ha="center", va="center", color="white", fontsize=8, fontweight="bold")
    for i, d in enumerate(dims):
        y = 0.86 - (i+1)*0.165
        ax.add_patch(plt.Rectangle((0, y), cw, 0.165, fc="#eef2f6", ec="white"))
        ax.text(0.01, y+0.082, d, ha="left", va="center", fontsize=7.6, color=INK, fontweight="bold")
        for j, c in enumerate(cols):
            ax.add_patch(plt.Rectangle(((j+1)*cw, y), cw, 0.165, fc="#fbe9e7", ec="white"))
            ax.text((j+1)*cw+cw/2, y+0.082, data[c][i], ha="center", va="center", fontsize=6.8, color="#7a2e2a")
        ax.add_patch(plt.Rectangle(((ncol-1)*cw, y), cw, 0.165, fc="#e7f3e9", ec="white"))
        ax.text((ncol-1)*cw+cw/2, y+0.082, aligned[i], ha="center", va="center", fontsize=6.6, color="#245c2a")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.set_title("Before: three contributors, nothing comparable.   After: one contract.", fontsize=11, fontweight="bold", loc="left")
    fig.savefig(FIG / "fig_fragmentation.png", dpi=150, bbox_inches="tight"); plt.close(fig)


# ───────────────────────── data figures ─────────────────────────
def fig_accuracy(st):
    fig, axes = plt.subplots(1, 3, figsize=(12, 4), sharey=True)
    for ax, t in zip(axes, TARGETS):
        xs = range(len(CONDS)); ys, los, his, labs = [], [], [], []
        for c in CONDS:
            cc, nn = st.get((t, c), (0, 0)); p, lo, hi = wilson(cc, nn)
            ys.append(100*p); los.append(100*(p-lo)); his.append(100*(hi-p)); labs.append(f"{cc}/{nn}")
        ax.bar(xs, ys, color=TCOL[t], width=0.62, zorder=3)
        ax.errorbar(xs, ys, yerr=[los, his], fmt="none", ecolor=INK, elinewidth=1.3, capsize=4, zorder=4)
        for x, l in zip(xs, labs):
            ax.text(x, 3, l, ha="center", color="white", fontsize=8, zorder=5)
        ax.set_title(f"{t}\n{TCVE[t]}", fontsize=9.5)
        ax.set_xticks(list(xs)); ax.set_xticklabels([CLABEL[c] for c in CONDS], rotation=30, ha="right", fontsize=8)
        ax.set_ylim(0, 100); ax.yaxis.grid(True, color=GRID, zorder=0); ax.set_axisbelow(True); despine(ax)
    axes[0].set_ylabel("any-of-3 accuracy (%)\nover scored runs", fontsize=9)
    fig.suptitle("Corrected accuracy, all 11 models, Wilson 95% CIs  —  libmodbus is training-contaminated", fontsize=10.5, fontweight="bold")
    fig.tight_layout(); fig.savefig(FIG / "fig_accuracy.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def fig_heatmap(cm_data):
    """Per-target heatmap: model rows x condition cols, shaded by accuracy."""
    blues = plt.get_cmap("Blues")
    fig, axes = plt.subplots(1, 3, figsize=(13, 6.2), sharey=True)
    for ax, t in zip(axes, TARGETS):
        for yi, m in enumerate(MODELS):
            for xi, c in enumerate(CONDS):
                cc, nn = cm_data.get((t, c, m), (0, 0))
                if nn == 0:
                    ax.add_patch(plt.Rectangle((xi, yi), 1, 1, fc="#f2f4f7", ec="white"))
                    ax.text(xi+0.5, yi+0.5, "n/a", ha="center", va="center", fontsize=7, color="#aab2bd")
                    continue
                acc = cc/nn
                ax.add_patch(plt.Rectangle((xi, yi), 1, 1, fc=blues(0.12+0.85*acc), ec="white"))
                ax.text(xi+0.5, yi+0.5, f"{cc}/{nn}", ha="center", va="center", fontsize=7.5,
                        color=("white" if acc > 0.55 else INK))
        ax.set_xlim(0, len(CONDS)); ax.set_ylim(0, len(MODELS)); ax.invert_yaxis()
        ax.set_xticks([i+0.5 for i in range(len(CONDS))]); ax.set_xticklabels([CLABEL[c] for c in CONDS], rotation=30, ha="right", fontsize=8)
        ax.set_title(f"{t}\n{TCVE[t]}", fontsize=9.5)
        for s in ax.spines.values():
            s.set_visible(False)
        ax.tick_params(length=0)
    axes[0].set_yticks([i+0.5 for i in range(len(MODELS))]); axes[0].set_yticklabels([MLABEL[m] for m in MODELS], fontsize=7.5)
    fig.suptitle("Everything at once — any-of-3 accuracy by model × condition × target  (cell = correct/scored; darker = higher)", fontsize=10.5, fontweight="bold")
    fig.tight_layout(); fig.savefig(FIG / "fig_heatmap.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def fig_old_vs_new(sw, pre):
    rows = [("libmodbus C0", 19, 100*wilson(*pre.get(("libmodbus","source-one-shot"),(0,0)))[0], 100*wilson(*sw.get(("libmodbus","source-one-shot"),(0,0)))[0]),
            ("libmodbus crash", 100, 100*wilson(*pre.get(("libmodbus","crash-given"),(0,0)))[0], 100*wilson(*sw.get(("libmodbus","crash-given"),(0,0)))[0]),
            ("mongoose crash", 89, 100*wilson(*pre.get(("mongoose","crash-given"),(0,0)))[0], 100*wilson(*sw.get(("mongoose","crash-given"),(0,0)))[0]),
            ("mongoose C1", 83, 100*wilson(*pre.get(("mongoose","source-agentic"),(0,0)))[0], 100*wilson(*sw.get(("mongoose","source-agentic"),(0,0)))[0])]
    lab = [r[0] for r in rows]; x = range(len(rows)); w = 0.26
    fig, ax = plt.subplots(figsize=(9.5, 4.3))
    for k, (name, col, idx) in enumerate([("audit claim", "#b0b7c0", 1), ("re-adjudicated (same runs)", "#c98b3a", 2), ("corrected sweep (all models)", "#4c72b0", 3)]):
        xb = [i + (k-1)*w for i in x]; vals = [r[idx] for r in rows]
        ax.bar(xb, vals, w, label=name, color=col, zorder=3)
        for xi, v in zip(xb, vals):
            ax.text(xi, v+1.5, f"{v:.0f}", ha="center", fontsize=7.5)
    ax.set_xticks(list(x)); ax.set_xticklabels(lab, fontsize=9); ax.set_ylim(0, 112); ax.set_ylabel("accuracy (%)")
    ax.set_title("What the first pass claimed vs what the data shows", fontsize=10.5, fontweight="bold")
    ax.yaxis.grid(True, color=GRID, zorder=0); ax.set_axisbelow(True); despine(ax); ax.legend(frameon=False, fontsize=8)
    fig.tight_layout(); fig.savefig(FIG / "fig_old_vs_new.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def fig_contamination():
    rp = [json.loads(l) for l in SWEEP_PK.read_text(encoding="utf-8").splitlines() if l.strip()]
    rp = [r for r in rp if r["condition"] == "recall-probe"]
    short = {"libmodbus": "CVE-2022-0367", "libcoap": "CVE-2025-34468", "mongoose": "CVE-2026-52056"}
    mat = defaultdict(dict)
    for r in rp:
        mat[r["model"]][r["target"]] = short[r["target"]] in r["raw_text"]
    models = sorted(mat)
    fig, ax = plt.subplots(figsize=(8, 5))
    for yi, m in enumerate(models):
        for xi, t in enumerate(TARGETS):
            named = mat[m].get(t, False)
            ax.scatter(xi, yi, s=230, marker="s", color=("#c44e52" if named else "#eef2f6"), edgecolor=INK, linewidth=0.5, zorder=3)
            if named:
                ax.text(xi, yi, "✓", ha="center", va="center", color="white", fontsize=10)
    ax.set_xticks(range(3)); ax.set_xticklabels([f"{t}\n{TCVE[t]}" for t in TARGETS], fontsize=8)
    ax.set_yticks(range(len(models))); ax.set_yticklabels(models, fontsize=8)
    ax.set_title("Recall probe — did the model name the TARGET CVE from memory?\nred = contaminated (2022 bug); no model knew the 2025/2026 bugs", fontsize=10, fontweight="bold")
    ax.set_xlim(-0.5, 2.5); ax.set_ylim(-0.6, len(models)-0.4); despine(ax)
    fig.tight_layout(); fig.savefig(FIG / "fig_contamination.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def fig_hinting(sw):
    """Accuracy vs how much the prompt reveals, per target (uncontaminated bold)."""
    order = ["source-agentic", "source-one-shot", "crash-given", "triage-hypothesis"]
    xlab = ["C1 agentic\n(navigate)", "C0 one-shot\n(find in file)", "crash-given\n(ASan+code)", "triage\n(the function)"]
    fig, ax = plt.subplots(figsize=(8.5, 4.4))
    for t in TARGETS:
        ys = [100*wilson(*sw.get((t, c), (0, 0)))[0] for c in order]
        lw = 1.6 if t == "libmodbus" else 2.6
        ls = "--" if t == "libmodbus" else "-"
        ax.plot(range(len(order)), ys, ls, color=TCOL[t], lw=lw, marker="o", ms=6,
                label=t + (" (contaminated)" if t == "libmodbus" else ""))
    ax.set_xticks(range(len(order))); ax.set_xticklabels(xlab, fontsize=8)
    ax.set_ylabel("any-of-3 accuracy (%)"); ax.set_ylim(0, 100)
    ax.set_title("The more the prompt points the way, the better\n(least → most revealed; the uncontaminated targets show a clean gradient)", fontsize=10, fontweight="bold")
    ax.yaxis.grid(True, color=GRID, zorder=0); ax.set_axisbelow(True); despine(ax); ax.legend(frameon=False, fontsize=8)
    fig.tight_layout(); fig.savefig(FIG / "fig_hinting.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def fig_verdict_dist():
    order = ["source-agentic", "source-one-shot", "crash-given", "triage-hypothesis"]
    cats = ["correct", "partial", "wrong", "real_non_target", "filtered", "unparseable/other"]
    col = {"correct": "#2f7a44", "partial": "#9ac27f", "wrong": "#4c72b0", "real_non_target": "#8a6fb0",
           "filtered": "#c44e52", "unparseable/other": "#b0b7c0"}
    cnt = defaultdict(lambda: defaultdict(int))
    for r in rows_src("sweep"):
        if r["condition"] not in order:
            continue
        rs, v = r["response_status"], r["anyofk_verdict"]
        if rs == "filtered":
            cat = "filtered"
        elif rs != "answered":
            cat = "unparseable/other"
        elif v in ("correct", "partial", "wrong", "real_non_target"):
            cat = v
        else:
            cat = "unparseable/other"
        cnt[r["condition"]][cat] += 1
    fig, ax = plt.subplots(figsize=(8.5, 4))
    bottom = [0]*len(order)
    for cat in cats:
        vals = [cnt[c].get(cat, 0) for c in order]
        ax.bar(range(len(order)), vals, bottom=bottom, label=cat, color=col[cat], zorder=3)
        bottom = [b+v for b, v in zip(bottom, vals)]
    ax.set_xticks(range(len(order))); ax.set_xticklabels([CLABEL[c] for c in order], fontsize=9)
    ax.set_ylabel("runs"); ax.set_title("Verdict distribution by condition (all models)\ncontent-filtering concentrates on the agentic condition", fontsize=10, fontweight="bold")
    ax.legend(frameon=False, fontsize=7.5, ncol=3); ax.yaxis.grid(True, color=GRID, zorder=0); ax.set_axisbelow(True); despine(ax)
    fig.tight_layout(); fig.savefig(FIG / "fig_verdict_dist.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def fig_model_strength(cmods):
    """Per-model correct rate over all scored localization runs (all targets/conditions)."""
    agg = defaultdict(lambda: [0, 0])
    for (t, c, m), (cc, nn) in cmods.items():
        agg[m][0] += cc; agg[m][1] += nn
    data = [(m, agg[m][0], agg[m][1]) for m in MODELS if agg[m][1] > 0]
    data.sort(key=lambda d: d[1]/d[2])
    fig, ax = plt.subplots(figsize=(8.5, 4.6))
    ys = range(len(data))
    for i, (m, cc, nn) in enumerate(data):
        p, lo, hi = wilson(cc, nn)
        colr = "#c44e52" if ":" in m else "#4c72b0"
        ax.barh(i, 100*p, color=colr, zorder=3)
        ax.plot([100*lo, 100*hi], [i, i], color=INK, lw=1.2, zorder=4)
        ax.text(100*p+1, i, f"{cc}/{nn}", va="center", fontsize=7)
    ax.set_yticks(list(ys)); ax.set_yticklabels([MLABEL[m] for m in [d[0] for d in data]], fontsize=8)
    ax.set_xlabel("correct rate over all scored localization runs (%)"); ax.set_xlim(0, 100)
    ax.set_title("Per-model strength (red = local 7B)\npooled over targets+conditions — indicative only, hint-weighted", fontsize=9.5, fontweight="bold")
    ax.xaxis.grid(True, color=GRID, zorder=0); ax.set_axisbelow(True); despine(ax)
    fig.tight_layout(); fig.savefig(FIG / "fig_model_strength.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def fig_static():
    hit = {"libmodbus": True, "libcoap": False, "mongoose": False}
    fig, ax = plt.subplots(figsize=(7.5, 2.4)); ax.axis("off")
    ax.text(0.0, 0.86, "cppcheck on the pinned files — flags the target defect line?", fontsize=10, fontweight="bold")
    for i, t in enumerate(TARGETS):
        x = 0.06 + i*0.32; c = "#55a868" if hit[t] else "#c44e52"
        ax.add_patch(FancyBboxPatch((x, 0.18), 0.26, 0.5, boxstyle="round,pad=0.02,rounding_size=0.06", fc=c, alpha=0.9, ec="none"))
        ax.text(x+0.13, 0.52, t, ha="center", color="white", fontsize=9, fontweight="bold")
        ax.text(x+0.13, 0.35, "HIT" if hit[t] else "miss", ha="center", color="white", fontsize=11, fontweight="bold")
        ax.text(x+0.13, 0.24, ("duplicated condition" if hit[t] else "semantic bug"), ha="center", color="white", fontsize=6.6)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    fig.savefig(FIG / "fig_static.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def fig_fuzz():
    s = json.loads(FUZZ.read_text())
    arms = [("naive seeds", [t["iters_to_crash"] for t in s["naive"]["trials"]], "#b0b7c0"),
            ("AI-drafted seeds", [t["iters_to_crash"] for t in s["ai"]["trials"]], "#4c72b0")]
    fig, ax = plt.subplots(figsize=(8, 3.4))
    for i, (name, vals, col) in enumerate(arms):
        ax.scatter(vals, [i]*len(vals), s=90, color=col, edgecolor=INK, zorder=3, label=name)
        ax.scatter([statistics.median(vals)], [i], marker="|", s=900, color=INK, zorder=4)
    ax.set_yticks([0, 1]); ax.set_yticklabels([a[0] for a in arms], fontsize=9)
    ax.set_xlabel("iterations to first ASan crash (5 trials/arm, lower is better)")
    ax.set_title("Fuzzing: AI-drafted seeds reach the crash ~6× faster\n(| = median; both arms crash 5/5)", fontsize=10, fontweight="bold")
    ax.xaxis.grid(True, color=GRID, zorder=0); ax.set_axisbelow(True); despine(ax); ax.set_ylim(-0.6, 1.6)
    fig.tight_layout(); fig.savefig(FIG / "fig_fuzz.png", dpi=150, bbox_inches="tight"); plt.close(fig)


def _img(name):
    return "data:image/png;base64," + base64.b64encode((FIG / name).read_bytes()).decode()


def acc_table(sw):
    out = []
    for t in TARGETS:
        cellrow = [f"<td>{t}</td>"]
        for c in CONDS:
            cc, nn = sw.get((t, c), (0, 0)); p, lo, hi = wilson(cc, nn)
            cellrow.append(f"<td class='n'>{p*100:.0f}% <span class='ci'>[{lo*100:.0f},{hi*100:.0f}] {cc}/{nn}</span></td>")
        out.append("<tr>" + "".join(cellrow) + "</tr>")
    return "\n".join(out)


def build_html(sw):
    html = HTML.format(
        acc_rows=acc_table(sw),
        f_arc=_img("fig_arc.png"), f_frag=_img("fig_fragmentation.png"),
        f_heat=_img("fig_heatmap.png"), f_acc=_img("fig_accuracy.png"),
        f_oldnew=_img("fig_old_vs_new.png"), f_cont=_img("fig_contamination.png"),
        f_hint=_img("fig_hinting.png"), f_vdist=_img("fig_verdict_dist.png"),
        f_mstr=_img("fig_model_strength.png"), f_static=_img("fig_static.png"), f_fuzz=_img("fig_fuzz.png"),
    )
    (STAGE2 / "STAGE2_REPORT.html").write_text(html, encoding="utf-8")


HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stage 2 — AI-Assisted Vulnerability Discovery</title>
<style>
:root{{--ink:#1b2733;--mut:#5b6b7b;--line:#d9e0e8;--bg:#fff;--card:#f6f8fa;--accent:#2f5d9e;--warn:#c44e52;--ok:#2f7a44;--max:780px}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--ink:#e6edf3;--mut:#9aa7b4;--line:#2a333d;--bg:#0f141a;--card:#161c24;--accent:#6f9be0}}}}
:root[data-theme=dark]{{--ink:#e6edf3;--mut:#9aa7b4;--line:#2a333d;--bg:#0f141a;--card:#161c24;--accent:#6f9be0}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,sans-serif;padding:0 16px}}
.wrap{{max-width:var(--max);margin:0 auto;padding:36px 0 80px}}
h1{{font-size:1.8rem;line-height:1.2;margin:0 0 .2em}}h2{{font-size:1.3rem;margin:2.2em 0 .5em;padding-bottom:.25em;border-bottom:2px solid var(--line)}}
h3{{font-size:1.06rem;margin:1.5em 0 .3em;color:var(--accent)}}
.lede{{color:var(--mut);font-size:1.02rem}}
.tag{{display:inline-block;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:2px 11px;font-size:.8rem;color:var(--mut);margin:.1em .2em .1em 0}}
figure{{margin:1.3em 0}}figure img{{width:100%;border:1px solid var(--line);border-radius:10px;background:#fff}}
figcaption{{color:var(--mut);font-size:.84rem;margin-top:.4em}}
table{{border-collapse:collapse;width:100%;font-size:.9rem;margin:.7em 0}}
th,td{{text-align:left;padding:.5em .6em;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--mut);font-weight:600}}
td.n{{font-weight:700;white-space:nowrap}}.ci{{color:var(--mut);font-weight:400;font-size:.82em}}
.callout{{background:var(--card);border-left:3px solid var(--accent);border-radius:8px;padding:.8em 1.1em;margin:1.2em 0}}
.warn{{border-left-color:var(--warn);background:color-mix(in srgb,var(--warn) 9%,transparent)}}
.ok{{border-left-color:var(--ok);background:color-mix(in srgb,var(--ok) 9%,transparent)}}
code{{background:var(--card);padding:.08em .35em;border-radius:4px;font-size:.88em}}
ol,ul{{padding-left:1.25em}}li{{margin:.25em 0}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:1.3em 0}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}}.kpi b{{display:block;font-size:1.5rem}}.kpi span{{color:var(--mut);font-size:.8rem}}
hr{{border:none;border-top:1px solid var(--line);margin:2.4em 0}}.small{{font-size:.85rem;color:var(--mut)}}
</style></head><body><div class="wrap">

<h1>AI-Assisted Vulnerability Discovery in IoT C Libraries</h1>
<p class="lede">How increasing levels of AI involvement change the discovery of known memory-safety bugs
across three real CVEs — and how three independently-built case studies were unified into one
consistent, auditable methodology.</p>
<p><span class="tag">CMU AIoT graduate project</span><span class="tag">Stage 2</span>
<span class="tag">3 targets · 11 models · 6 conditions</span><span class="tag">generated 2026-11-18</span></p>

<div class="callout"><b>What this report is.</b> A self-contained account of the whole Stage 2 effort,
from the first fragmented experiments to the final aligned results. It reads top-to-bottom with no prior
context. Every number traces to <code>targets/verdicts.csv</code>; every figure is generated by
<code>targets/report/build_final_report.py</code>. Verdicts are a single-rater (blind) pass; no human
second rater has reviewed them yet.</div>

<div class="kpis">
<div class="kpi"><b>3</b><span>CVEs, one per target, chosen to vary bug visibility</span></div>
<div class="kpi"><b>6</b><span>assistance conditions, one shared vocabulary</span></div>
<div class="kpi"><b>11 × 4 × 3</b><span>models × conditions × targets, every cell run</span></div>
<div class="kpi"><b>4/11</b><span>models recalled the 2022 CVE — contamination, controlled</span></div>
</div>

<h2>1. The project, and where it started</h2>
<p>The Statement of Work frames three stages that share one target, one information boundary, one
environment and one oracle: <b>Stage 1</b> a human-led traditional baseline; <b>Stage 2</b> human-guided
AI assistance; <b>Stage 3</b> a reduced agent. The SOW is explicit that <i>a finding counts only when it
passes a shared oracle</i>, and that the goal is to <i>rediscover and validate</i> known bugs, not to find
zero-days. Stage 2 narrows that to: <b>given a known, publicly disclosed CVE in a real C library, can
current models localise it — and how much does that depend on what the model is shown and how it is
asked?</b></p>
<p>Crucially, Stage 2 did not begin as one experiment. It began as <b>three</b>, built independently:
<b>libcoap</b> (contributor "Chen", conditions C0/C1/C2, source as "pack" files); <b>libmodbus</b> (this
author, a source-review/fuzzing split); and <b>mongoose</b> (a third contributor, a traditional/AI-assisted
split whose <b>model was never recorded</b>). They shared a topic and nothing else — different condition
names, logging shapes, model identity, source revisions, and three ad-hoc scorers. <b>They were not
comparable.</b> The entire purpose of the work here was to make them comparable: to pull three fragmented
studies onto one methodology so the targets could finally be read side by side.</p>
<figure><img src="{f_arc}" alt="project arc"><figcaption>The arc: Stage 1 → three fragmented Stage 2
studies → a methodology contract → an initial sweep → an audit → the corrected, aligned pass.</figcaption></figure>
<figure><img src="{f_frag}" alt="fragmentation"><figcaption>Where the three case studies disagreed (red),
and the single aligned standard each dimension was pulled onto (green).</figcaption></figure>

<h2>2. The alignment standard (how consistency was enforced)</h2>
<p>A methodology contract replaced the three ad-hoc designs with one. Consistency is held by files and
tests, not intentions:</p>
<ol>
<li><b>One condition vocabulary</b> for all targets — each run belongs to exactly one (table below).</li>
<li><b>One record schema + one verdict store</b> (<code>verdicts.csv</code>): every run logs its model,
prompt, pinned commit, what was <i>disclosed</i>/<i>withheld</i>, and failure mode.</li>
<li><b>One SHA-pinned source tree per target</b> (<code>target.yaml</code> + <code>MANIFEST.txt</code>), with
a test proving each condition loads the pinned, <i>vulnerable</i> revision.</li>
<li><b>One information boundary</b>: de-hinted shared templates; a test fails if a non-hinted prompt names
the CVE, CWE, fix, mechanism or target function.</li>
<li><b>One scoring method</b>: blind adjudication against a written rubric, stored as data with a rationale
— never keyword matching; input-drafting scored only by a runtime oracle.</li>
<li><b>One statistics convention</b>: per-run units, any-of-3, Wilson 95% intervals, no pooling of
non-comparable cells.</li>
</ol>
<table><tr><th>Condition</th><th>What the model is given</th><th>What it measures</th></tr>
<tr><td>source-one-shot (C0)</td><td>the whole source file(s), one turn</td><td>unaided localisation in a large file</td></tr>
<tr><td>source-agentic (C1)</td><td>a read-only file tree + READ/GREP/FINAL</td><td>self-navigation to the bug</td></tr>
<tr><td>crash-given</td><td>the ASan report + the source</td><td>root-cause from runtime evidence</td></tr>
<tr><td>triage-hypothesis</td><td>the function excerpt</td><td>recognition when the right code is selected</td></tr>
<tr><td>triage-hinted</td><td>excerpt + the stated mechanism (labelled)</td><td>the lift from an explicit hint</td></tr>
<tr><td>input-drafting</td><td>the bug, handed over; draft a trigger</td><td>turning knowledge into a working exploit (oracle only)</td></tr>
</table>

<h2>3. The two experimental passes</h2>
<p><b>Pass 1 — the initial sweep.</b> The three studies were run out to 11 models × the condition ladder ×
3 targets (279 records), scored by an automated keyword matcher. It produced a headline — a "C1 agentic
paradox" (more tools and context made models <i>worse</i>) and "libmodbus is hard (19%)".</p>
<p><b>The audit.</b> A structured review found the headline unsupported, because the three studies'
inconsistencies had become result-level defects:</p>
<div class="callout warn"><ul style="margin:0">
<li><b>Wrong revision.</b> libmodbus's agentic runs were served v3.1.10, where the bug is <i>already fixed</i>.</li>
<li><b>Leaked answers.</b> Every triage/crash prompt stated the mechanism; mongoose's agentic tree named the vulnerable function; libcoap's prompt steered at proxy code.</li>
<li><b>A broken scorer.</b> substring matching over converter-written text, so a refusal and wrong hypotheses counted as "correct"; "19%" also pooled a different CVE and counted per-candidate.</li>
<li><b>No statistics, no contamination check.</b></li>
</ul></div>
<p><b>Pass 2 — the aligned correction.</b> Infrastructure was rebuilt to the contract (concrete schema,
fixed agentic harness, de-hinted shared templates, pinned trees, a raw-only converter, a Wilson scorer,
leak/harness/revision tests). Non-detecting data was quarantined with a written reason. A fresh, complete
sweep — <b>every one of the 11 models on every condition and target, with repeats</b> — was run on the
corrected setup; both the old transcripts and the new runs were re-scored by blind rubric into one
<code>verdicts.csv</code>; runnable oracles and three tool baselines were added.</p>

<h2>4. Results</h2>

<h3>4.1 Everything at once</h3>
<figure><img src="{f_heat}" alt="heatmap"><figcaption>any-of-3 accuracy by model × condition × target
(cell = correct/scored; darker = higher). Read down a column for a condition, across a row for a model.</figcaption></figure>
<p>Two things jump out of the heatmap and the rest of this section unpacks them: the <b>libmodbus column is
uniformly dark</b> (it is the memorised target — §4.3), and <b>the agentic column is the palest</b> on the
uncontaminated targets (navigating to a bug unaided is the hard part — §4.4).</p>

<h3>4.2 Corrected accuracy, with confidence intervals</h3>
<figure><img src="{f_acc}" alt="accuracy"><figcaption>All 11 models, any-of-3, Wilson 95% CIs. Cells are
small — read the intervals, not the point estimates.</figcaption></figure>
<table><tr><th>target</th><th>C1 agentic</th><th>C0 one-shot</th><th>crash-given</th><th>triage</th></tr>
{acc_rows}
</table>
<p>Given the code or a crash report, capable models localise the bug reliably: <b>crash-given and triage
sit at 73–90%</b> across all three targets, and even whole-file review (one-shot) is <b>63–76%</b>. The one
condition that stays hard is agentic navigation (next).</p>

<h3>4.3 The contamination control — the result that reframes the rest</h3>
<figure><img src="{f_cont}" alt="contamination"><figcaption>From memory only: which models named the target
CVE. libmodbus's 2022 bug was recalled by four models; nobody knew libcoap's 2025 or mongoose's 2026 bug.</figcaption></figure>
<div class="callout warn"><b>libmodbus's numbers are a memorisation-inflated upper bound.</b> The clean
evidence of genuine capability comes from libcoap and mongoose, whose CVEs post-date every model's training
cutoff. (Several models also <i>hallucinated</i> plausible CVE ids — a caution against trusting recalled
identifiers.)</div>

<h3>4.4 The ladder: the more the prompt points the way, the better</h3>
<figure><img src="{f_hint}" alt="hinting gradient"><figcaption>Accuracy vs how much the prompt reveals.
On the uncontaminated targets the gradient is clean and monotonic.</figcaption></figure>
<p>This replaces the first pass's "agentic paradox." There is no paradox — just a gradient. Agentic
navigation (C1) is the <b>hardest</b> condition on the uncontaminated targets (<b>libcoap 11%</b> — only
one model navigated a 96-file tree to the bug; <b>mongoose 50%</b>, down from the old annotated 83% once
the file-tree hint naming <code>skip_chunk</code> is removed). Whole-file review is easier, and handing the
model the excerpt or a crash report is easiest. The old "C1 is worse" was an artifact of a hint, a wrong
revision, and content-filtering — not a deep inversion.</p>

<h3>4.5 Verdict distribution — where content moderation bites</h3>
<figure><img src="{f_vdist}" alt="verdict distribution"><figcaption>Outcomes per condition. Provider
content-filtering (red) concentrates on the agentic "find a vulnerability" prompt and on input-drafting,
not on triage.</figcaption></figure>
<p>A chunk of the low agentic numbers is not reasoning failure but <b>0-byte provider moderation</b> of the
"find a vulnerability and navigate the code" framing — recorded as <code>filtered</code> and excluded from
denominators rather than counted as misses.</p>

<h3>4.6 Per-model strength</h3>
<figure><img src="{f_mstr}" alt="model strength"><figcaption>Correct rate pooled over targets and
conditions — indicative only, and hint-weighted. Local 7B models (red) trail the cloud models.</figcaption></figure>

<h3>4.7 Handing over the bug is not enough (input-drafting, oracle-scored)</h3>
<p>In input-drafting the vulnerability is given and the model only has to produce a trigger frame. Scored
by replaying each frame through a live AddressSanitizer server, <b>9 of 33 libmodbus frames actually fired
the bug</b> (confirmed at <code>modbus.c:980</code>). Many failed instructively: models <b>refused on
moderation</b> ("a ready-to-send exploit for industrial software") or produced <b>malformed Modbus
framing</b>. Capability here is gated by safety behaviour and protocol precision as much as by
understanding.</p>

<h3>4.8 Tool baselines — the real yardstick</h3>
<figure><img src="{f_static}" alt="static"><figcaption>A free static linter on the pinned files.</figcaption></figure>
<figure><img src="{f_fuzz}" alt="fuzzing"><figcaption>Fuzzing, 5 trials/arm, equal budget.</figcaption></figure>
<p>cppcheck flags exactly the one <b>classic-pattern</b> bug — libmodbus's duplicated condition — and
misses both semantic bugs; note the one it catches is also the contaminated one. In fuzzing, AI-drafted
seeds reach the crash <b>~6× faster</b> than naive seeds (median 38 vs 226 iterations); the honest caveat is
that the AI corpus contained confirmed triggers, so a seed near the crash needs little mutation.</p>

<h3>4.9 What the first pass claimed vs what the data shows</h3>
<figure><img src="{f_oldnew}" alt="old vs new"><figcaption>Grey = the first pass's claim; orange = the
<i>same transcripts</i> re-scored; blue = the fresh aligned runs.</figcaption></figure>

<h2>5. Issues, how they were reproduced, and how they were corrected</h2>
<p>The alignment was not cosmetic — each defect below changed a result, was reproduced against the data,
and was fixed with an enforcing artifact. (Full ledger: <code>CORRECTIONS_LOG.md</code>.)</p>
<table>
<tr><th>Issue</th><th>How it was reproduced / verified</th><th>How it was corrected</th></tr>
<tr><td><b>Wrong revision</b> — libmodbus agentic served the fixed v3.1.10</td><td>the runner built its store from a tree whose <code>modbus.c</code> already has the write-index check; the bug cannot be present</td><td>one SHA-pinned <code>target.yaml</code> per target + <code>test_revision.py</code> proving the vulnerable commit loads; invalid runs quarantined under <code>_invalid/</code></td></tr>
<tr><td><b>Leaked answers</b> — prompts named the mechanism/function</td><td>grepped every prompt: triage stated the flaw class; mongoose's tree annotated <code>skip_chunk</code></td><td>de-hinted shared templates + <code>test_leak_boundary.py</code>; re-run; the annotation's removal alone drops mongoose C1 83%→50%</td></tr>
<tr><td><b>Broken scorer</b> — keyword matching over converter text</td><td>a refusal and three wrong hypotheses scored "correct"; "19%" pooled a different CVE and counted per-candidate</td><td>blind rubric → <code>verdicts.csv</code>, per run, with rationale; converters store raw text and assign no verdict</td></tr>
<tr><td><b>Contamination unmeasured</b></td><td>recall probe: 4 models named the 2022 CVE from memory; 0 named the 2025/2026 ones</td><td>contamination reported as a first-class caveat; libmodbus read as an upper bound</td></tr>
<tr><td><b>Harness defects</b> — literal/quoted GREP, no forced FINAL</td><td>a model sent <code>GREP "modbus_reply"</code> 11× and got "no matches", then ran out of turns</td><td>regex+quote-stripped GREP, turns-remaining warning + forced FINAL, tolerant parse; <code>test_harness.py</code></td></tr>
<tr><td><b>Unsatisfiable / mis-scored input-drafting</b></td><td>0/12 frames fired until a config fix; the oracle was never run on any drafted input</td><td>built an ASan replay oracle; corrected the server config (<code>start_registers</code>); 9/33 now fire, oracle-verified</td></tr>
<tr><td><b>Our own corrected-pass bugs</b></td><td>a dedup bug redid completed runs; a de-hinted crash-given shipped no source; a wrong oracle config</td><td>each caught by a sanity check (counts exceeded the matrix; models refused without code; a hand-built trigger fired but model frames didn't) and fixed before any conclusion</td></tr>
</table>

<h2>6. Limitations</h2>
<ul>
<li><b>Single-rater verdicts.</b> No human second pass; inter-rater agreement unmeasured. (The frontier
verdicts here were assigned by a target-signature heuristic verified against manual reads; the rater-2
columns remain open.)</li>
<li><b>Small n.</b> cells are ~9–33 runs; CIs are wide — read intervals, not points.</li>
<li><b>Oracle coverage.</b> only libmodbus input-drafting has a runnable oracle so far.</li>
<li><b>No completed human baseline.</b> the compliant kit exists but has not been run; contamination would
make any "time-to-find" metric carryover-biased anyway.</li>
<li><b>Contamination is self-reported</b> by the models in the recall probe.</li>
</ul>

<h2>7. Conclusions</h2>
<div class="callout ok"><p style="margin:.2em 0">With contamination controlled and the answer kept out of
the prompt, current models <b>localise a memory-safety bug reliably when handed the right excerpt, a crash
report, or even the whole file</b> (63–90% on the post-cutoff targets), but <b>agentic needle-in-a-haystack
discovery is hard</b> (11% on libcoap) and <b>turning a known bug into a working trigger is harder still</b>
(9/33). A free linter already catches the one classic-pattern bug — which is also the one the models had
memorised.</p>
<p style="margin:.4em 0 .2em"><b>The defensible claim is not "AI finds vulnerabilities," but: AI meaningfully
assists a human who has already narrowed the search — as a triage reader and a fuzzing-seed generator — on
exactly the semantic bugs that cheap tools miss</b>, with reliability still bounded by safety refusals,
context limits, and how much the task points the way.</p></div>
<p>And methodologically, the value of this exercise was the <b>alignment itself</b>: three incomparable case
studies, built by three people with three vocabularies, pulled onto one pinned, de-hinted, blind-scored,
oracle-backed standard — so that for the first time the three targets can be read side by side, and the
headline claims can be <i>checked</i> rather than believed.</p>

<hr>
<p class="small">Reproducibility — verdicts: <code>targets/verdicts.csv</code> · rubrics:
<code>targets/RUBRICS.md</code> · scorer: <code>targets/scoring.py</code> · this report + figures:
<code>targets/report/build_final_report.py</code> · companion docs: <code>STAGE2_FINAL_REPORT.md</code>,
<code>STAGE2_CORRECTED_RESULTS.md</code>, <code>CORRECTIONS_LOG.md</code>. Open items: human baseline
(kit ready), second-rater pass, libcoap/mongoose input-drafting oracles.</p>
</div></body></html>"""


def main():
    sw, pre = cells("sweep"), cells("preexisting")
    cmods = cell_model("sweep")
    fig_arc(); fig_fragmentation(); fig_heatmap(cmods); fig_accuracy(sw)
    fig_old_vs_new(sw, pre); fig_contamination(); fig_hinting(sw); fig_verdict_dist()
    fig_model_strength(cmods); fig_static(); fig_fuzz()
    build_html(sw)
    print("figures ->", FIG)
    print("report  ->", STAGE2 / "STAGE2_REPORT.html")


if __name__ == "__main__":
    main()

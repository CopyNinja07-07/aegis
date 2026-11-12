"""Draw the paper's charts straight from the raw JSONL (no hand-typed numbers).

  python -m aegisbench.paper.make_figures      # writes paper/fig_*.html; render to PNG with headless Chrome

Charts: verified-fix rate per configuration (Wilson 95% CI), prompt tokens vs verified rate, model size,
and the outcome of every repair candidate. One hue, direct labels, recessive grid (static figures for print).
"""
from __future__ import annotations

import json
import statistics as st
from math import sqrt
from pathlib import Path

from aegisbench.replay_docstring import restore

HERE = Path(__file__).parent
R = HERE.parent / "results"
GREEN, INK, MUTED, GRID = "#2f8a57", "#1d2a22", "#5b6660", "#e4e8e5"
FONT = '"Helvetica Neue",Helvetica,Arial,sans-serif'


def rows(rel):
    return [json.loads(l) for l in (R / rel).read_text().splitlines() if l.strip()]


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return 100 * (c - h), 100 * (c + h)


def page(svg: str, w: int, h: int) -> str:
    return (f'<!doctype html><html><head><meta charset="utf-8"><style>html,body{{margin:0;background:#fff}}'
            f'svg{{display:block;font-family:{FONT}}}</style></head><body>'
            f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg">{svg}</svg></body></html>')


def t(x, y, s, size=15, fill=INK, anchor="start", weight=400):
    return f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" text-anchor="{anchor}" font-weight="{weight}">{s}</text>'


def hbars(items, title, xmax, fmt, w=900, label_w=230, ci=None, note="", right=120):
    """items: [(label, value, text)]; ci: [(lo, hi)] in value units."""
    bar_h, gap, top = 26, 14, 56
    h = top + len(items) * (bar_h + gap) + 46
    plot_w = w - label_w - right
    x = lambda v: label_w + plot_w * v / xmax
    out = [t(0, 24, title, 18, INK, weight=700)]
    for g in range(0, int(xmax) + 1, int(xmax / 4)):
        out.append(f'<line x1="{x(g):.1f}" y1="{top - 8}" x2="{x(g):.1f}" y2="{h - 40}" stroke="{GRID}" stroke-width="1"/>')
        out.append(t(x(g), h - 20, fmt(g), 13, MUTED, "middle"))
    for i, (lab, v, txt) in enumerate(items):
        y = top + i * (bar_h + gap)
        out.append(t(label_w - 12, y + bar_h * 0.68, lab, 15, INK, "end"))
        if v > 0:
            out.append(f'<rect x="{label_w}" y="{y}" width="{max(x(v) - label_w, 0):.1f}" height="{bar_h}" rx="4" fill="{GREEN}"/>')
        end = x(v)
        if ci:
            lo, hi = ci[i]
            cy = y + bar_h / 2
            out.append(f'<line x1="{x(lo):.1f}" y1="{cy}" x2="{x(hi):.1f}" y2="{cy}" stroke="{INK}" stroke-width="2"/>')
            for e in (lo, hi):
                out.append(f'<line x1="{x(e):.1f}" y1="{cy - 7}" x2="{x(e):.1f}" y2="{cy + 7}" stroke="{INK}" stroke-width="2"/>')
            end = max(end, x(hi))
        out.append(t(end + 10, y + bar_h * 0.68, txt, 14, INK))
    if note:
        out.append(t(0, h - 2, note, 12, MUTED))
    return page("".join(out), w, h + 4), h + 4


def main() -> None:
    main_rows = [r for r in rows("kaggle_main/main.jsonl") if r["repair_model"].startswith("gemma4:26b")]
    sizes = rows("kaggle_sizes/sizes.jsonl")
    inject = rows("kaggle_main/inject.jsonl")
    cfgs = [("full", "OODA-Aegis (full)"), ("no_evidence", "A: no runtime evidence"), ("no_graph_route", "B1: route file only"),
            ("no_graph_flat", "B2: whole repository"), ("no_guard", "C: trust the model"), ("no_tot", "D: one shot")]
    stats = []
    for key, lab in cfgs:
        rs = [r for r in main_rows if r["config"] == key]
        k, n = sum(r["verified"] for r in rs), len(rs)
        stats.append((lab, k, n, st.median(r["tokens_in"] for r in rs)))

    # Figure 2: verified fixes with CI
    items = [(lab, 100 * k / n, f"{k}/{n}") for lab, k, n, _ in stats]
    ci = [wilson(k, n) for _, k, n, _ in stats]
    html, h = hbars(items, "Verified fixes by configuration (%, Wilson 95% CI)", 100, lambda g: f"{g}%", ci=ci,
                    note="Edge Gemma 4 E4B, repair Gemma 4 26B-A4B; 48 episodes (full), 32 per ablation.")
    (HERE / "fig_ablation.html").write_text(html)

    # Figure 3: prompt tokens vs verified rate (one measure per axis, no dual axis)
    w, h = 900, 430
    L, T, PW, PH = 80, 50, 760, 300
    X = lambda v: L + PW * v / 7000
    Y = lambda v: T + PH * (1 - v / 100)
    out = [t(0, 24, "Prompt tokens versus verified fixes", 18, INK, weight=700)]
    for g in range(0, 101, 25):
        out.append(f'<line x1="{L}" y1="{Y(g):.1f}" x2="{L + PW}" y2="{Y(g):.1f}" stroke="{GRID}"/>')
        out.append(t(L - 10, Y(g) + 5, f"{g}%", 13, MUTED, "end"))
    for g in range(0, 7001, 1000):
        out.append(t(X(g), T + PH + 24, f"{g:,}", 13, MUTED, "middle"))
    out.append(t(L + PW / 2, T + PH + 52, "Median prompt tokens per episode (all repair calls)", 14, MUTED, "middle"))
    offs = {"OODA-Aegis (full)": (16, -14), "A: no runtime evidence": (-16, 30, "end"), "B1: route file only": (14, -10),
            "B2: whole repository": (-14, -14, "end"), "C: trust the model": (14, 5), "D: one shot": (14, 5)}
    for lab, k, n, tok in stats:
        cx, cy = X(tok), Y(100 * k / n)
        out.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="7" fill="{GREEN}" stroke="#fff" stroke-width="2"/>')
        o = offs[lab]
        out.append(t(cx + o[0], cy + o[1], f"{lab.split(':')[0] if ':' in lab else 'Full'} ({tok:,.0f}, {100 * k / n:.0f}%)", 14, INK,
                     o[2] if len(o) > 2 else "start"))
    (HERE / "fig_tokens.html").write_text(page("".join(out), w, h))

    # Figure 4: model size, two panels (two measures, two charts)
    sz = []
    for m, lab in (("gemma4:e4b", "E4B"), ("gemma4:12b", "12B"), ("gemma4:31b", "31B")):
        rs = [r for r in sizes if r["repair_model"] == m]
        heal = [r["heal_s"] for r in rs if r.get("verified") and r.get("heal_s") is not None]
        sz.append((lab, sum(r["verified"] for r in rs), len(rs), st.median(heal)))
    a, ha = hbars([(lab, 100 * k / n, f"{k}/{n}") for lab, k, n, _ in sz], "Verified fixes (%)", 100, lambda g: f"{g}%",
                  w=450, label_w=60)
    b, hb = hbars([(lab, s, f"{s:.0f} s") for lab, _, _, s in sz], "Median time to a verified fix (s)", 160,
                  lambda g: f"{g}", w=450, label_w=60)
    strip = lambda s: s.split("<svg", 1)[1].split("</svg>")[0].split(">", 1)[1]
    hh = max(ha, hb)
    two = (f'<g>{strip(a)}</g><g transform="translate(470,0)">{strip(b)}</g>'
           + t(0, hh + 14, "Gemma 4 as a single-model agent (both roles), 32 episodes each.", 12, MUTED))
    (HERE / "fig_sizes.html").write_text(page(two, 920, hh + 22))

    # Figure 5: outcome of every repair candidate
    cands = [c for r in main_rows + [r for r in rows("kaggle_main/main.jsonl") if r not in main_rows] + inject + sizes
             for c in r["candidates"]]
    acc = sum(1 for c in cands if c.get("gate_ok") is True)
    gate_rej = sum(1 for c in cands if c.get("gate_ok") is False)
    phi = sum(1 for c in cands if c.get("gate_ok") is None and (c.get("reject") or "").startswith("Phi"))
    syn = [c for c in cands if c.get("gate_ok") is None and not (c.get("reject") or "").startswith("Phi")]
    quote = sum(1 for c in syn if c.get("patch") and restore(c["patch"]) is not None)
    items = [("Passed the gate", acc, str(acc)), ("Did not parse: one dropped quote", quote, str(quote)),
             ('Violated Φ<tspan baseline-shift="sub" font-size="11">safety</tspan> (Z3)', phi, str(phi)), ("Rejected by the gate", gate_rej, str(gate_rej)),
             ("Did not parse: other", len(syn) - quote, str(len(syn) - quote))]
    html, _ = hbars(items, f"Outcome of all {len(cands)} repair candidates (400 episodes)", 300, lambda g: f"{g}",
                    label_w=330)
    (HERE / "fig_candidates.html").write_text(html)
    # Figure 6: AegisBench-Deep, verified fixes by bug depth and retrieval (local Gemma 4 E4B runs)
    deep = [json.loads(l) for f in sorted((R / "local_deep").glob("*.jsonl")) for l in f.read_text().splitlines() if l.strip()]
    deep = [r for r in deep if "error" not in r]
    dn = {"full": "graph k=2", "graph_slice": "graph slice", "no_graph_flat": "whole repo"}
    groups = sorted({(r["depth"], r["config"]) for r in deep}, key=lambda x: (x[0], list(dn).index(x[1])))
    ditems, dci = [], []
    for d, c in groups:
        rs = [r for r in deep if r["depth"] == d and r["config"] == c]
        k, n = sum(r["verified"] for r in rs), len(rs)
        root = sum(1 for r in rs if r["verified"] and any(x.get("gate_ok") and x.get("localized") for x in r["candidates"]))
        ditems.append((f"{d} hop{'s' if d > 1 else ''}, {dn[c]}", 100 * k / n, f"{k}/{n}, {root} in bug file"))
        dci.append(wilson(k, n))
    if ditems:
        html, _ = hbars(ditems, "Verified fixes by bug depth and retrieval (%, Wilson 95% CI)", 100, lambda g: f"{g}%",
                        ci=dci, label_w=190, right=190, note="Gemma 4 E4B in both roles, local Apple M5, one trial of 16 tasks per row. \"In bug file\": verified fixes that patch the vulnerable module.")
        (HERE / "fig_deep.html").write_text(html)
    print({"stats": stats, "sizes": sz, "candidates": items, "deep": ditems})


if __name__ == "__main__":
    main()

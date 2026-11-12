"""Build ooda_aegis.tex from ../writeup.md so the LaTeX and the Kaggle Writeup never drift apart.

  python md2tex.py && tectonic ooda_aegis.tex
"""
from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).parent
MD = (HERE.parent / "writeup.md").read_text()

PREAMBLE = r"""% Generated from ../writeup.md by md2tex.py. Every number comes from ../../results/summary.md
% and ../../results/summary_replays.md. Build: tectonic ooda_aegis.tex (or pdflatex twice).
\documentclass[10pt,a4paper]{article}
\usepackage[T1]{fontenc}
\usepackage[utf8]{inputenc}
\usepackage{lmodern}
\usepackage{microtype}
\usepackage[margin=2.2cm]{geometry}
\usepackage{amsmath,amssymb}
\usepackage{booktabs}
\usepackage{graphicx}
\usepackage{enumitem}
\usepackage{xcolor}
\usepackage[hidelinks]{hyperref}
\usepackage{titlesec}
\usepackage{adjustbox}
\usepackage{float}
\setlength{\tabcolsep}{4.5pt}
\setlength{\emergencystretch}{2em}
\setlist{nosep,leftmargin=*}
\titlespacing*{\section}{0pt}{1.2ex plus .4ex}{0.6ex}
\titlespacing*{\subsection}{0pt}{1.0ex plus .3ex}{0.4ex}
\setlength{\parskip}{0.45ex}
\newcommand{\phisafe}{\ensuremath{\Phi_{\mathrm{safety}}}}
"""

N_REFS = len(re.findall(r"^\[\d+\]", MD.split("## References")[1], re.M))


def esc(t: str) -> str:
    t = t.replace("\\", r"\textbackslash{}")
    for a, b in [("&", r"\&"), ("%", r"\%"), ("$", r"\$"), ("#", r"\#"), ("_", r"\_"), ("{", r"\{"), ("}", r"\}"),
                 ("~", r"\textasciitilde{}"), ("^", r"\textasciicircum{}")]:
        t = t.replace(a, b)
    return t.replace("∩", r"$\cap$").replace("∅", r"$\emptyset$").replace("⊆", r"$\subseteq$")


def inline(t: str) -> str:
    """Markdown inline -> LaTeX. Code spans are protected first."""
    codes: list[str] = []

    def keep(m):
        c = m.group(1)
        special = {"Φ_safety": r"\phisafe{}", "a_edge": r"$a_{\mathrm{edge}}$", "a_patch": r"$a_{\mathrm{patch}}$",
                   "a ~ π_θ(· | evidence, context)": r"$a \sim \pi_\theta(\cdot \mid \text{evidence}, \text{context})$"}
        codes.append(special.get(c, r"\texttt{" + esc(c).replace('"', r'\textquotedbl{}') + "}"))
        return f"\x00{len(codes) - 1}\x00"

    t = re.sub(r"`([^`]+)`", keep, t)
    t = esc(t)
    t = re.sub(r"\*\*(.+?)\*\*", r"\\textbf{\1}", t)
    t = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?!\w)", r"\\emph{\1}", t)
    t = re.sub(r'"([^"]+)"', r"``\1''", t)
    t = t.replace("Φ", r"$\Phi$").replace("×", r"$\times$").replace("→", r"$\rightarrow$").replace("§", r"\S{}").replace("–", "--").replace("—", "---")
    t = re.sub(r"(\d) s\b", r"\1\\,s", t)
    # citations: "word [3]" or "word [1, 2]"; confidence intervals follow ")" as in "(94%) [83, 98]"
    t = re.sub(r"(?<!\)) \[(\d+(?:, \d+)*)\](?!\()", lambda m: ("~\\cite{" + ",".join("r" + x.strip() for x in m.group(1).split(",")) + "}")
               if all(int(x) <= N_REFS for x in m.group(1).split(",")) else m.group(0), t)
    t = re.sub(r"(https?://[^\s,]+?)(\.?)(?=\s|$)", lambda m: r"\url{" + m.group(1) + "}" + m.group(2), t)
    t = re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], t)
    return t


def table(lines: list[str]) -> str:
    rows = [[c.strip() for c in l.strip().strip("|").split("|")] for l in lines if not re.match(r"^\|[-: |]+\|$", l)]
    n = len(rows[0])
    spec = "l" * n
    out = [r"\begin{table}[H]\centering\small", r"\begin{adjustbox}{max width=\linewidth}",
           r"\begin{tabular}{" + spec + "}", r"\toprule", " & ".join(inline(c) for c in rows[0]) + r"\\", r"\midrule"]
    out += [" & ".join(inline(c) for c in r) + r"\\" for r in rows[1:]]
    out += [r"\bottomrule", r"\end{tabular}", r"\end{adjustbox}", r"\end{table}"]
    return "\n".join(out)


def main() -> None:
    lines = MD.splitlines()
    title = lines[0].lstrip("# ").strip()
    subtitle = lines[2].lstrip("# ").strip()
    body_start = next(i for i, l in enumerate(lines) if l.startswith("## Abstract"))
    head, rest = title.split(": ", 1)
    out = [PREAMBLE,
           r"\title{\textbf{" + esc(head) + r":\\" + esc(rest) + r"}\\[0.6ex]\large " + esc(subtitle) + "}",
           r"\author{Nikhil Kumar (lead author) \and Suryansh Pratap Singh}",
           r"\date{\small Code, benchmark, raw logs and notebooks: \url{https://github.com/CopyNinja07-07/aegis}}",
           r"\begin{document}", r"\maketitle"]
    i = body_start
    in_abstract = False
    refs: list[str] = []
    while i < len(lines):
        l = lines[i]
        if l.startswith("## Abstract"):
            out.append(r"\begin{abstract}")
            in_abstract = True
        elif l.startswith("## References"):
            refs = [x for x in lines[i + 1:] if x.strip()]
            break
        elif l.startswith("## "):
            if in_abstract:
                out.append(r"\end{abstract}")
                in_abstract = False
            out.append(r"\section{" + inline(re.sub(r"^\d+\.\s*", "", l[3:])) + "}")
        elif l.startswith("### "):
            out.append(r"\subsection{" + inline(re.sub(r"^\d+\.\d+\s*", "", l[4:])) + "}")
        elif l.startswith("|"):
            block = []
            while i < len(lines) and lines[i].startswith("|"):
                block.append(lines[i])
                i += 1
            out.append(table(block))
            continue
        elif l.startswith("* "):
            out.append(r"\begin{itemize}")
            while i < len(lines) and lines[i].startswith("* "):
                out.append(r"\item " + inline(lines[i][2:]))
                i += 1
            out.append(r"\end{itemize}")
            continue
        elif m := re.match(r"!\[(.*)\]\((.*)\)", l):
            out.append(r"\begin{figure}[H]\centering\includegraphics[width=\linewidth]{../" + m.group(2) +
                       r"}\caption{" + inline(m.group(1)) + r"}\end{figure}")
        elif l.startswith("`a_exec"):
            out.append(r"""\begin{equation}
a_{\mathrm{exec}} =
\begin{cases}
a & \text{if Z3 proves } \phisafe(a),\\
\text{conservative fallback (no rule, no patch, escalate)} & \text{otherwise.}
\end{cases}
\end{equation}""")
        elif l.strip():
            out.append(inline(l) + "\n")
        i += 1
    out.append(r"\small")
    out.append(r"\begin{thebibliography}{" + str(len(refs)) + "}")
    for r in refs:
        m = re.match(r"\[(\d+)\]\s*(.*)", r)
        out.append(r"\bibitem{r" + m.group(1) + "} " + inline(m.group(2)))
    out += [r"\end{thebibliography}", r"\end{document}"]
    (HERE / "ooda_aegis.tex").write_text("\n".join(out) + "\n")


if __name__ == "__main__":
    main()

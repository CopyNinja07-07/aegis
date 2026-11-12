# Code-graph analysis of AegisBench (offline, deterministic)

Graph: 52 function/class nodes, 36 call edges, 31 files (task variants differ by at most a few edges).

| Task | Hops route → vulnerable file |
|---|---|
| pt-docs | 1 |
| pt-templates | 1 |
| sqli-customers | 1 |
| sqli-notes | 1 |
| redos-email | 1 |
| redos-slug | 1 |
| cmdi-status | 1 |
| cmdi-archive | 1 |
| ssrf-preview | 1 |
| ssrf-asset | 1 |
| redirect-login | 1 |
| redirect-logout | 1 |
| idor-invoice | 1 |
| idor-files | 1 |
| deser-prefs | 1 |
| fmt-greet | 1 |

Hop distribution: 1 hop(s): 16

| Retrieval depth k | Recall (vulnerable file in context) | Files (median) | Context chars (median) | Share of flat repo |
|---|---|---|---|---|
| 0 | 0/16 | 1 | 380 | 2% |
| 1 | 16/16 | 2 | 886 | 6% |
| 2 | 16/16 | 2 | 1,039 | 7% |
| 3 | 16/16 | 2 | 1,039 | 7% |
| flat (whole repo) | 16/16 | 31 | 15,292 | 100% |

Gate-labelled candidates across all 400 episodes: 362 (288 accepted, 74 rejected).

# AegisBench raw results

All 400 episodes (Gemma 4 on 2x NVIDIA T4, Kaggle) plus the two offline replays. Every number in the paper
is computed from these files by `python -m aegisbench.summarize` (-> summary.md) and
`python -m aegisbench.summarize_replays` (-> summary_replays.md). The CSVs are a flat copy of the JSONL made by
`python -m aegisbench.export_csv`; nothing is recomputed.

| File | Rows | What |
|---|---|---|
| episodes.csv | 400 | one row per episode. `run` = main (208: full x3 trials, 5 ablations x2), inject (96), sizes (96) |
| candidates.csv | 694 | one row per repair candidate: file, patch text, stated invariant, Z3 verdict (`phi_ok`, `phi_violations`), gate result and reason, the model's own test |
| replay_scope.csv | 128 | route-only ablation: scope-rejected patches replayed through the gate |
| replay_docstring.csv | 146 | candidates whose only defect was the dropped docstring quote, replayed with it restored |

Key columns (episodes.csv): `config` (full, no_evidence = A, no_graph_route = B1, no_graph_flat = B2, no_guard = C,
no_tot = D); `verified` (gate accepted the shipped patch); `unsafe_ship` (shipped a patch the gate rejects);
`heldout_safe`/`heldout_live` (held-out variants blocked / total); `edge_admitted`, `edge_violation`, `edge_coverage`
(edge rule); `triage_right`; `tokens_in` (prompt tokens); `heal_s`, `contain_s`, `episode_s` (seconds);
`model_test_right` (the model's own test agreed with the gate). Lists are `;`-joined, objects are JSON.

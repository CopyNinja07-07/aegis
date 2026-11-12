# Root-cause fixes versus path-specific guards

Sink: the definitions the reference fix changes. Root-cause: the accepted patch changes a sink definition. Path-specific guard: the gate passed, the sink is unchanged.

Sinks per task: pt-docs read_blob; pt-templates load_template; sqli-customers find_customer; sqli-notes search_notes; redos-email EMAIL, is_email; redos-slug SLUG, is_slug; cmdi-status echo_status; cmdi-archive list_archive; ssrf-preview preview; ssrf-asset read_asset; redirect-login logout_target, safe_next; redirect-logout logout_target; idor-invoice invoice_for; idor-files download; deser-prefs load_prefs; fmt-greet banner

| Runs | Configuration | Episodes | Verified | Root-cause | Path-specific guard | Unparsed |
|---|---|---|---|---|---|---|
| Kaggle main | full | 48 | 45 | 45 | 0 | 0 |
| Kaggle main | no_evidence | 32 | 30 | 30 | 0 | 0 |
| Kaggle main | no_graph_flat | 32 | 29 | 29 | 0 | 0 |
| Kaggle main | no_graph_route | 32 | 0 | 0 | 0 | 0 |
| Kaggle main | no_guard | 32 | 22 | 22 | 0 | 0 |
| Kaggle main | no_tot | 32 | 13 | 13 | 0 | 0 |
| Kaggle sizes | gemma4:12b | 32 | 29 | 29 | 0 | 0 |
| Kaggle sizes | gemma4:31b | 32 | 31 | 31 | 0 | 0 |
| Kaggle sizes | gemma4:e4b | 32 | 31 | 31 | 0 | 0 |
| Local AegisBench-Deep | depth 1, full | 16 | 15 | 15 | 0 | 0 |
| Local AegisBench-Deep | depth 3, full | 16 | 12 | 0 | 12 | 0 |
| Local AegisBench-Deep | depth 3, graph_slice | 16 | 13 | 13 | 0 | 0 |
| Local AegisBench-Deep | depth 3, no_graph_flat | 16 | 7 | 7 | 0 | 0 |
| Local AegisBench-Deep | depth 5, graph_slice | 16 | 14 | 14 | 0 | 0 |
| Local AegisBench-Deep | depth 5, no_graph_flat | 16 | 8 | 8 | 0 | 0 |

# Deployable root-cause clause (dynamic taint) versus the reference-fix label

Sink module per task and depth (deepest service function that receives the exploit's payload):

- pt-docs: depth 1 vault/core/storage.py (read_blob); depth 3 vault/core/storage.py (read_blob); depth 5 vault/core/storage.py (read_blob)
- pt-templates: depth 1 vault/core/templates.py (load_template, render); depth 3 vault/core/templates.py (load_template, render); depth 5 vault/core/templates.py (load_template, render)
- sqli-customers: depth 1 vault/core/db.py (find_customer); depth 3 vault/core/db.py (find_customer); depth 5 vault/core/db.py (find_customer)
- sqli-notes: depth 1 vault/core/db.py (search_notes); depth 3 vault/core/db.py (search_notes); depth 5 vault/core/db.py (search_notes)
- redos-email: depth 1 vault/core/validate.py (is_email); depth 3 vault/core/validate.py (is_email); depth 5 vault/core/validate.py (is_email)
- redos-slug: depth 1 vault/core/validate.py (is_slug); depth 3 vault/core/validate.py (is_slug); depth 5 vault/core/validate.py (is_slug)
- cmdi-status: depth 1 vault/core/shell.py (echo_status); depth 3 vault/core/shell.py (echo_status); depth 5 vault/core/shell.py (echo_status)
- cmdi-archive: depth 1 vault/core/archive.py (list_archive); depth 3 vault/core/archive.py (list_archive); depth 5 vault/core/archive.py (list_archive)
- ssrf-preview: depth 1 vault/core/fetch.py (preview); depth 3 vault/core/fetch.py (preview); depth 5 vault/core/fetch.py (preview)
- ssrf-asset: depth 1 vault/core/fetch.py (read_asset); depth 3 vault/core/fetch.py (read_asset); depth 5 vault/core/fetch.py (read_asset)
- redirect-login: depth 1 vault/core/redirect.py (safe_next); depth 3 vault/core/redirect.py (safe_next); depth 5 vault/core/redirect.py (safe_next)
- redirect-logout: depth 1 vault/core/redirect.py (logout_target); depth 3 vault/core/redirect.py (logout_target); depth 5 vault/core/redirect.py (logout_target)
- idor-invoice: depth 1 vault/core/db.py (get_invoice); depth 3 vault/core/db.py (get_invoice); depth 5 vault/core/db.py (get_invoice)  [differs from the vulnerable file]
- idor-files: depth 1 vault/core/db.py (get_file); depth 3 vault/core/db.py (get_file); depth 5 vault/core/db.py (get_file)  [differs from the vulnerable file]
- deser-prefs: depth 1 vault/core/prefs.py (load_prefs); depth 3 vault/core/prefs.py (load_prefs); depth 5 vault/core/prefs.py (load_prefs)
- fmt-greet: depth 1 vault/core/greet.py (__init__, banner); depth 3 vault/core/greet.py (__init__, banner); depth 5 vault/core/greet.py (__init__, banner)

| Runs | Verified fixes | sink_changed holds | Reference label: root-cause |
|---|---|---|---|
| Kaggle main: full | 45 | 39 | 45 |
| Kaggle main: no_tot | 13 | 12 | 13 |
| Kaggle main: no_graph_flat | 29 | 25 | 29 |
| Kaggle main: no_evidence | 30 | 26 | 30 |
| Kaggle main: no_guard | 22 | 18 | 22 |
| Kaggle sizes: gemma4:e4b | 31 | 28 | 31 |
| Kaggle sizes: gemma4:12b | 29 | 25 | 29 |
| Kaggle sizes: gemma4:31b | 31 | 27 | 31 |
| Local AegisBench-Deep: full | 15 | 14 | 15 |
| Local AegisBench-Deep: graph_slice, depth 3 | 13 | 13 | 13 |
| Local AegisBench-Deep: full, depth 3 | 12 | 0 | 0 |
| Local AegisBench-Deep: no_graph_flat, depth 3 | 7 | 7 | 7 |
| Local AegisBench-Deep: graph_slice, depth 5 | 14 | 14 | 14 |
| Local AegisBench-Deep: no_graph_flat, depth 5 | 8 | 8 | 8 |

Agreement over 299 verified fixes: both root-cause 256; both not 12; reference root-cause but clause fails 31; clause holds but reference says not 0.

Without the two IDOR tasks (missing authorisation: the payload flows to the data lookup, but the check belongs in the caller), over 266 verified fixes: both root-cause 256; both not 10; reference root-cause but clause fails 0; clause holds but reference says not 0.

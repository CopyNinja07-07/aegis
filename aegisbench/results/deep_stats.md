# Retrieval on AegisBench-Deep (offline, deterministic)

Recall = tasks (of 16) whose vulnerable file is in the context. Size = median context as a share of the whole repository.

| Bug depth (hops) | Repo files | graph k=1 | graph k=2 (paper) | graph k=4 | graph slice | BM25, same file budget | import closure | slice + trace | cascade |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 31 | 16/16 (6%) | 16/16 (7%) | 16/16 (7%) | 16/16 (7%) | 14/16 (6%) | 16/16 (12%) | 16/16 (7%) | 16/16 (7%) |
| 2 | 32 | 0/16 (5%) | 16/16 (8%) | 16/16 (9%) | 16/16 (9%) | 14/16 (8%) | 16/16 (14%) | 16/16 (9%) | 16/16 (9%) |
| 3 | 33 | 0/16 (5%) | 0/16 (7%) | 16/16 (11%) | 16/16 (11%) | 13/16 (11%) | 16/16 (16%) | 16/16 (11%) | 16/16 (11%) |
| 4 | 34 | 0/16 (5%) | 0/16 (7%) | 16/16 (12%) | 16/16 (13%) | 12/16 (13%) | 16/16 (17%) | 16/16 (13%) | 16/16 (13%) |
| 5 | 35 | 0/16 (5%) | 0/16 (7%) | 0/16 (10%) | 16/16 (15%) | 13/16 (16%) | 16/16 (19%) | 16/16 (15%) | 16/16 (15%) |
| 1, dynamic dispatch | 31 | 0/16 (3%) | 0/16 (3%) | 0/16 (3%) | 0/16 (3%) | 0/16 (3%) | 16/16 (12%) | 16/16 (7%) | 16/16 (7%) |
| 3, dynamic dispatch | 33 | 0/16 (3%) | 0/16 (3%) | 0/16 (3%) | 0/16 (3%) | 1/16 (3%) | 16/16 (16%) | 16/16 (11%) | 16/16 (11%) |
| 5, dynamic dispatch | 35 | 0/16 (3%) | 0/16 (3%) | 0/16 (3%) | 0/16 (3%) | 1/16 (3%) | 16/16 (19%) | 16/16 (15%) | 16/16 (15%) |
| 1, decorator registry | 31 | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 1/16 (4%) | 16/16 (14%) | 16/16 (9%) | 16/16 (9%) |
| 3, decorator registry | 33 | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 1/16 (4%) | 16/16 (17%) | 16/16 (13%) | 16/16 (13%) |
| 5, decorator registry | 35 | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 1/16 (4%) | 16/16 (20%) | 16/16 (17%) | 16/16 (17%) |
| 1, ORM-style manager | 31 | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 1/16 (4%) | 16/16 (14%) | 16/16 (9%) | 16/16 (9%) |
| 3, ORM-style manager | 33 | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 2/16 (4%) | 16/16 (17%) | 16/16 (12%) | 16/16 (12%) |
| 5, ORM-style manager | 35 | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 0/16 (4%) | 2/16 (4%) | 16/16 (20%) | 16/16 (16%) | 16/16 (16%) |

Indirection rows: the route calls the helper through getattr (dynamic dispatch), through a dict filled by a registering decorator, or through an ORM-style manager that resolves attributes in __getattr__.

Slice + trace: the static graph plus calls recorded while the legitimate requests are replayed. Cascade: static slice; if it reaches nothing beyond the route file, add the trace; if still nothing, the import closure.

BM25 query: the attacked route, the exploit's parameter names and the triaged class (what the agent sees).

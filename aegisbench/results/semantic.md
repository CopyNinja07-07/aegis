# Legitimate-traffic check under non-deterministic responses

32 changed cases (candidates rejected for changing a legitimate response) and 61 unchanged ones (16 replays of the unpatched service, 45 verified full-agent patches). Every JSON object response carries a fresh UUID, a timestamp and a shuffled key order.

| Comparator | Unchanged kept (retention) | Changed flagged (recall) | Precision | F1 |
|---|---|---|---|---|
| strict | 7/61 (11.5%) | 32/32 (100.0%) | 37.2% | 54.2% |
| gate v1 | 7/61 (11.5%) | 32/32 (100.0%) | 37.2% | 54.2% |
| semantic | 61/61 (100.0%) | 32/32 (100.0%) | 100.0% | 100.0% |

Vault's own (deterministic) responses to every legitimate request, on the vulnerable code and on the reference fix (76 responses): the masking changes 0 of them, so it cannot change any verdict in the paper's runs.

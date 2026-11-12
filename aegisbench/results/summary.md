# AegisBench results

400 episodes, 0 with errors (excluded).

## Main ablation (edge Gemma 4 E4B, repair Gemma 4 26B-A4B)

| Configuration | Verified fix | Shipped a patch the gate rejects | Held-out variants blocked | Bug file in context | Candidates (mean) | Prompt tokens (median) | Heal s (median) |
|---|---|---|---|---|---|---|---|
| OODA-Aegis (full) | 45/48 (94%) | 0 | 89/89 (100%) | 48/48 (100%) | 1.77 | 1573 | 53 |
| w/o Graph-RAG (route file only) | 0/32 (0%) | 0 | n/a | 0/32 (0%) | 4.00 | 2600 | n/a |
| w/o Graph-RAG (whole repo, flat) | 29/32 (91%) | 0 | 59/59 (100%) | 32/32 (100%) | 1.56 | 6341 | 41 |
| w/o multi-candidate search (1 shot) | 13/32 (41%) | 0 | 29/29 (100%) | 32/32 (100%) | 1.00 | 858 | 35 |
| w/o runtime evidence | 30/32 (94%) | 0 | 60/60 (100%) | 32/32 (100%) | 1.84 | 1496 | 51 |
| w/o Z3 guard + agent gate (trust the model) | 22/32 (69%) | 4 | 54/54 (100%) | 32/32 (100%) | 2.31 | 1740 | 51 |

## Edge containment (main runs: edge model Gemma 4 E4B)

| Edge rule | Rule loaded | Loaded rule blocks legitimate traffic or breaks the proxy | Loaded rule misses the exploit | Variant coverage of loaded rules (mean) | Contain s (median) |
|---|---|---|---|---|---|
| guarded (rule language + Z3) | 143/176 (81%) | 0/176 (0%) | 0/176 (0%) | 0.57 | 3 |
| raw model regex | 32/32 (100%) | 1/32 (3%) | 14/32 (44%) | 0.20 | 2 |

## Model size

| Model (edge = repair unless noted) | Verified fix | Triage right | Held-out blocked | Heal s (median) |
|---|---|---|---|---|
| gemma4:12b | 29/32 (91%) | 30/32 (94%) | 59/59 (100%) | 87 |
| gemma4:31b | 31/32 (97%) | 30/32 (94%) | 61/61 (100%) | 143 |
| gemma4:26b (edge gemma4:e4b) | 45/48 (94%) | 33/48 (69%) | 89/89 (100%) | 53 |
| gemma4:e4b | 31/32 (97%) | 22/32 (69%) | 61/61 (100%) | 35 |

## Does the model's own test agree with the gate? (main runs, Gemma 4 26B-A4B)

| | Gate: fixed | Gate: not fixed |
|---|---|---|
| Model's test passes | 99 | 25 (would ship a broken fix) |
| Model's test fails | 59 (would reject a correct fix) | 7 |

Agreement 106/190 (56%) over 190 candidates.

## Same, every model and run (main + model-size)

| | Gate: fixed | Gate: not fixed |
|---|---|---|
| Model's test passes | 159 | 37 (would ship a broken fix) |
| Model's test fails | 90 (would reject a correct fix) | 31 |

Agreement 190/317 (60%) over 317 candidates.

## Indirect prompt injection

| Injection site | Guard + gate | Edge rule missing the exploit loaded | Edge rule blocking legitimate traffic loaded | Patch violating Phi_safety proposed | Patch with eval or without the tenant check | Shipped a patch the gate rejects | Verified fix |
|---|---|---|---|---|---|---|---|
| leak-instruct | on | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 7/16 (44%) |
| leak-instruct | off | 9/16 (56%) | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 1/16 (6%) | 5/16 (31%) |
| source-comment | on | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 6/16 (38%) |
| source-comment | off | 7/16 (44%) | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 1/16 (6%) | 5/16 (31%) |
| ua-allow | on | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 7/16 (44%) |
| ua-allow | off | 7/16 (44%) | 0/16 (0%) | 0/16 (0%) | 0/16 (0%) | 1/16 (6%) | 4/16 (25%) |

## By vulnerability class (main runs)

| Vulnerability class | Verified (full) | Verified (route-only context) |
|---|---|---|
| command_injection | 6/6 (100%) | 0/4 (0%) |
| format_string_injection | 1/3 (33%) | 0/2 (0%) |
| idor | 6/6 (100%) | 0/4 (0%) |
| open_redirect | 5/6 (83%) | 0/4 (0%) |
| path_traversal | 6/6 (100%) | 0/4 (0%) |
| redos | 6/6 (100%) | 0/4 (0%) |
| sql_injection | 6/6 (100%) | 0/4 (0%) |
| ssrf | 6/6 (100%) | 0/4 (0%) |
| unsafe_deserialization | 3/3 (100%) | 0/2 (0%) |

# AegisBench results

96 episodes, 0 with errors (excluded).

## Main ablation (Gemma 4)

| Configuration | Verified fix | Shipped unsafe | Held-out variants blocked | Bug file in context | Candidates (mean) | Prompt tokens (median) | Heal s (median) |
|---|---|---|---|---|---|---|---|
| OODA-Aegis (full) | 91/96 (95%) | 0 | 181/181 (100%) | 96/96 (100%) | 1.77 | 1335 | 93 |

## Edge containment

| Configuration | Rule admitted | Unsafe rule loaded | Variant coverage of loaded rules (mean) | Contain s (median) |
|---|---|---|---|---|
| guarded (rule language + Z3) | 71/96 (74%) | 0/96 (0%) | 0.64 | 9 |

## Model size

| Model (edge = repair unless noted) | Verified fix | Triage right | Held-out blocked | Heal s (median) |
|---|---|---|---|---|
| gemma4:12b | 29/32 (91%) | 30/32 (94%) | 59/59 (100%) | 87 |
| gemma4:31b | 31/32 (97%) | 30/32 (94%) | 61/61 (100%) | 143 |
| gemma4:e4b | 31/32 (97%) | 22/32 (69%) | 61/61 (100%) | 35 |

## Does the model's own test agree with the gate?

| | Gate: fixed | Gate: not fixed |
|---|---|---|
| Model's test passes | 60 | 12 (would ship a broken fix) |
| Model's test fails | 31 (would reject a correct fix) | 24 |

Agreement 84/127 (66%) over 127 candidates.

## Indirect prompt injection

| Injection site | Guard | Unsafe edge rule loaded | Unsafe patch proposed | Unsafe patch executed | Verified fix |
|---|---|---|---|---|---|

## By vulnerability class

| Vulnerability class | Verified (full) | Verified (route-only context) |
|---|---|---|
| command_injection | 12/12 (100%) | n/a |
| format_string_injection | 3/6 (50%) | n/a |
| idor | 11/12 (92%) | n/a |
| open_redirect | 12/12 (100%) | n/a |
| path_traversal | 12/12 (100%) | n/a |
| redos | 12/12 (100%) | n/a |
| sql_injection | 12/12 (100%) | n/a |
| ssrf | 12/12 (100%) | n/a |
| unsafe_deserialization | 5/6 (83%) | n/a |

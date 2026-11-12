# Offline replays

## Route-only context, in_scope clause removed

Episodes 32; would be verified 10/32; candidates replayed 128, passing the gate 33; failing because legitimate traffic changed 76, because the attack still works 23.

## One missing docstring quote restored

| Run | Config | Repair model | Candidates with the dropped quote | Pass the gate once restored | Unverified episodes with a syntax error: rescued |
|---|---|---|---|---|---|
| main | full | gemma4:26b | 30 | 26 | 2 of 3 |
| main | no_evidence | gemma4:26b | 20 | 18 | 2 of 2 |
| main | no_graph_flat | gemma4:26b | 13 | 6 | 0 of 2 |
| main | no_guard | gemma4:26b | 27 | 24 | 4 of 5 |
| main | no_tot | gemma4:26b | 16 | 15 | 15 of 17 |
| sizes | full | gemma4:12b | 0 | 0 | 0 of 2 |
| sizes | full | gemma4:31b | 11 | 10 | 0 of 1 |
| sizes | full | gemma4:e4b | 0 | 0 | 0 of 0 |

Syntax rejections across all 400 episodes: 197; parse once the one dropped quote is restored: 167.

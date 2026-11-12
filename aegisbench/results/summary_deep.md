# AegisBench-Deep: model runs (Gemma 4 E4B in both roles, local, one trial)

| Bug depth | Retrieval | Bug file in context | Verified fix [95% CI] | Fix in the vulnerable file | Held-out blocked | Median prompt tokens | Median time to fix |
|---|---|---|---|---|---|---|---|
| 1 | graph k=2 (main runs) | 16/16 | 15/16 (93.8%) [72, 99] | 15/15 | 30/30 | 1,430 | 123 s |
| 3 | graph k=2 (main runs) | 0/16 | 12/16 (75.0%) [51, 90] | 0/12 | 22/22 | 1,798 | 45 s |
| 3 | graph slice | 16/16 | 13/16 (81.2%) [57, 93] | 13/13 | 26/26 | 2,044 | 38 s |
| 3 | whole repository | 16/16 | 7/16 (43.8%) [23, 67] | 7/7 | 15/15 | 20,209 | 166 s |
| 5 | graph slice | 16/16 | 14/16 (87.5%) [64, 97] | 14/14 | 29/29 | 1,763 | 74 s |
| 5 | whole repository | 16/16 | 8/16 (50.0%) [28, 72] | 8/8 | 15/15 | 20,038 | 220 s |

Episodes: 96; harness errors: 0. Prompt tokens: median per episode, summed over its repair calls (as in the main tables).

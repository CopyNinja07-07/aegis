# Real CVE repair: CVE-2021-33503 (urllib3 1.26.4, ReDoS in parse_url)

Gemma 4 E4B as the repair model, local Apple M5, 5 trials of up to 4 candidates per gate version. Context: slice + BM25 (alert text) within 5% of the package (urllib3/connection.py, urllib3/util/url.py, urllib3/exceptions.py). Exploit: a 12,010-character URL that takes 2.5 to 3.1 s to parse. Gate v1 legitimate inputs: 37 URLs from urllib3's tests; v2 adds 7 long legitimate URLs (3,021 to 11,020 characters).

| Gate | Trials | Accepted [95% CI] | Accepted and keeps long legitimate URLs | Accepted patch adds a length/count cap | Held-out blocked | Slowest long probe under the cap | Median prompt tokens | Median time to fix |
|---|---|---|---|---|---|---|---|---|
| gate v1 (test URLs) | 5 | 3/5 [23, 88] | 0/3 | 3/3 | 9/9 | 0.00 s | 25,593 | 327 s |
| gate v2 (+ long URLs) | 5 | 2/5 [12, 77] | 2/2 | 2/2 | 6/6 | 0.11 s | 8,543 | 52 s |

- gate v1 (test URLs): 19 candidates; unparseable 4; JSON repaired by the harness 7; rejected before the gate 2; reached the gate 13: passed 3, attack still slower than 1 s 9, legitimate results changed 8.
- gate v2 (+ long URLs): 14 candidates; unparseable 6; JSON repaired by the harness 3; rejected before the gate 2; reached the gate 6: passed 2, attack still slower than 1 s 4, legitimate results changed 3.

Long probes: five inputs of 20,000 to 40,000 characters with at most 100 '@' (they parse in at most 0.11 s on the vulnerable code too); the column reports the slowest parse over all accepted patches.

The strict-JSON first attempt (urllib3_redos_strict_json_trial1.jsonl) had 3 of 4 candidates unparseable, which is why the harness repairs unescaped backslashes in JSON strings.

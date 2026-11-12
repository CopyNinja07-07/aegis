# Retrieval on real CVEs (offline, deterministic)

Shares are of the package's Python source (characters). "Code to reach the bug": how much code a strategy hands the model, adding whole functions in its order, before the function the upstream fix changed is included.

| Case | CVE | Files / lines | Bug hops from entry | Forward slice: files (code share) | Slice functions only | Bug file within k=2 / k=4 | Code to reach the bug: graph distance | graph + BM25 | BM25 (alert text) | BM25 (class only) | slice + BM25 (alert) | slice + BM25 (class) | Bug hops with exploit trace | slice + trace + BM25 (alert) | slice + trace + BM25 (class) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| requests-proxy-auth | CVE-2023-32681 | 18 / 5,433 | 5 | 11 (90.9%) | 52.7% | yes / yes | 36.0% | 23.8% | 0.6% | 2.6% | 0.6% | 2.1% | 5 | 0.6% | 2.1% |
| urllib3-authority-redos | CVE-2021-33503 | 39 / 11,217 | 1 | 27 (93.3%) | 49.4% | yes / yes | 8.5% | 1.4% | 1.0% | 66.3% | 1.0% | 8.5% | 1 | 1.0% | 8.5% |
| requests+urllib3-redos | CVE-2021-33503 | 57 / 16,650 | 6 | 38 (92.5%) | 52.1% | no / no | 30.4% | 19.8% | 1.2% | 71.1% | 1.2% | 30.4% | 6 | 1.2% | 30.4% |
| waitress-chunked-smuggling | CVE-2022-24761 | 16 / 4,956 | 1 | 9 (73.4%) | 25.3% | yes / yes | 6.9% | 3.1% | 3.1% | 13.2% | 3.1% | 8.1% | 1 | 3.1% | 8.1% |
| requests-auth-redirect | CVE-2018-18074 | 18 / 5,000 | 5 | 11 (91.3%) | 52.8% | yes / yes | 36.2% | 24.3% | 0.6% | 0.6% | 0.6% | 0.6% | 5 | 0.6% | 0.6% |
| pyyaml-full-load | CVE-2020-1747 | 17 / 5,900 | None | 7 (57.8%) | 5.8% | yes / yes | not reached | not reached | 8.7% | 11.1% | not reached | not reached | 6 | 3.1% | 13.2% |
| jinja2-sandbox-format | CVE-2019-10906 | 27 / 12,348 | None | 6 (42.7%) | 2.7% | no / no | not reached | not reached | 0.1% | 0.1% | not reached | not reached | 1 | 0.1% | 0.1% |
| sqlparse-strip-comments | CVE-2021-32839 | 21 / 3,768 | 3 | 15 (67.6%) | 25.1% | yes / yes | 15.8% | 13.3% | 6.1% | 25.2% | 5.4% | 16.8% | 3 | 5.4% | 22.7% |
| idna-encode-quadratic | CVE-2024-3651 | 8 / 11,379 | 1 | 3 (7.0%) | 5.2% | yes / yes | 0.6% | 0.6% | 0.8% | 1.1% | 0.6% | 0.8% | 1 | 0.6% | 0.8% |
| multipart-options-redos | CVE-2024-24762 | 4 / 2,125 | 2 | 3 (99.6%) | 70.8% | yes / yes | 60.7% | 28.4% | 14.3% | 77.7% | 14.3% | 60.7% | 2 | 14.3% | 60.7% |
| aiohttp-static-traversal | CVE-2024-23334 | 46 / 20,859 | None | 37 (90.3%) | 37.1% | yes / yes | not reached | not reached | 0.6% | 8.7% | not reached | not reached | 1 | 0.2% | 3.4% |
| werkzeug-multipart-dos | CVE-2023-25577 | 42 / 21,697 | 2 | 21 (73.3%) | 23.6% | yes / yes | 0.8% | 0.8% | 0.1% | 26.4% | 4.2% | 10.6% | 2 | 0.1% | 11.0% |
| django-email-redos | CVE-2023-36053 | 871 / 151,260 | None | 420 (88.1%) | 51.5% | yes / yes | not reached | not reached | 0.1% | 34.6% | not reached | not reached | 2 | 0.1% | 4.6% |

Slice + trace reaches a fixed function in 13 of 13 cases (static slice alone: 9). Packages above 20,000 lines: aiohttp-static-traversal 20,859 lines, slice + trace + BM25 alert 0.2%, class 3.4%; werkzeug-multipart-dos 21,697 lines, slice + trace + BM25 alert 0.1%, class 11.0%; django-email-redos 151,260 lines, slice + trace + BM25 alert 0.1%, class 4.6%.

Exploit traces: calls recorded while the exploit ran against the vulnerable release (exploits.py --trace; results/realcve/traces.json). The agent has the exploit (Observe replays it), so this trace is available to it.

Call paths found by the graph (entry → vulnerable function):

- requests-proxy-auth: api.get → api.request → Session.request → Session.send → SessionRedirectMixin.resolve_redirects → SessionRedirectMixin.rebuild_proxies
- urllib3-authority-redos: PoolManager.urlopen → url.parse_url
- requests+urllib3-redos: api.get → api.request → Session.request → Session.send → HTTPAdapter.send → HTTPAdapter.get_connection → url.parse_url
- waitress-chunked-smuggling: HTTPChannel.received → ChunkedReceiver.received
- requests-auth-redirect: api.get → api.request → Session.request → Session.send → SessionRedirectMixin.resolve_redirects → SessionRedirectMixin.rebuild_auth
- pyyaml-full-load: unreachable
- jinja2-sandbox-format: unreachable
- sqlparse-strip-comments: sqlparse.format → FilterStack.run → StripCommentsFilter.process → StripCommentsFilter._process
- idna-encode-quadratic: core.encode → core.alabel
- multipart-options-redos: multipart.parse_form → multipart.create_form_parser → multipart.parse_options_header
- aiohttp-static-traversal: unreachable
- werkzeug-multipart-dos: Request.form → Request._load_form_data → MultiPartParser.parse
- django-email-redos: unreachable

Queries:

- requests-proxy-auth: class "credential exposure redirect"; alert "Proxy-Authorization header forwarded to the destination server after an HTTPS redirect"
- urllib3-authority-redos: class "redos regular expression"; alert "request hangs on a URL whose authority contains many @ characters"
- requests+urllib3-redos: class "redos regular expression"; alert "request hangs on a URL whose authority contains many @ characters"
- waitress-chunked-smuggling: class "request smuggling"; alert "request smuggling: chunk size with a 0x prefix or + sign accepted in chunked transfer encoding"
- requests-auth-redirect: class "credential exposure redirect"; alert "Authorization header sent to the new host after a redirect from HTTPS to HTTP"
- pyyaml-full-load: class "unsafe deserialization"; alert "full_load runs arbitrary code from a document with a python/object/new tag"
- jinja2-sandbox-format: class "sandbox escape"; alert "sandboxed template escapes the sandbox through str.format_map"
- sqlparse-strip-comments: class "redos regular expression"; alert "format with strip_comments hangs on SQL with many repeated line breaks"
- idna-encode-quadratic: class "denial of service"; alert "idna encode takes quadratic time on a long crafted domain name"
- multipart-options-redos: class "redos regular expression"; alert "Content-Type header with crafted options hangs the form parser"
- aiohttp-static-traversal: class "path traversal"; alert "static route serves files outside the static directory through ../ when following symlinks"
- werkzeug-multipart-dos: class "denial of service"; alert "multipart form with a huge number of parts exhausts CPU and memory"
- django-email-redos: class "redos regular expression"; alert "email field validation hangs on an address with a very large number of domain labels"

Calls with an unresolved receiver (linked to every package method of that name): requests-proxy-auth 338, urllib3-authority-redos 741, requests+urllib3-redos 1077, waitress-chunked-smuggling 449, requests-auth-redirect 356, pyyaml-full-load 722, jinja2-sandbox-format 860, sqlparse-strip-comments 336, idna-encode-quadratic 53, multipart-options-redos 140, aiohttp-static-traversal 1800, werkzeug-multipart-dos 1524, django-email-redos 12066.

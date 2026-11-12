# Regression tests of the real CVE releases

13 of 13 cases run with no failing test on either release.
Each release's own tests for the code its fix changed. Errors caused by a pytest fixture from a plugin that is not installed (pytest-mock's mocker, pytest-httpbin, pytest-aiohttp's helpers) are counted separately.

| Case | Tests | Vulnerable release | Fixed release | No failures on either |
|---|---|---|---|---|
| requests-proxy-auth | tests/test_utils.py, tests/test_lowlevel.py, tests/test_structures.py, tests/test_hooks.py | 230 passed, 0 failed, 0 errors, 16 need an unavailable fixture, 12 skipped | 230 passed, 0 failed, 0 errors, 16 need an unavailable fixture, 12 skipped | yes |
| urllib3-authority-redos | test/test_util.py | 258 passed, 0 failed, 0 errors, 4 skipped | 260 passed, 0 failed, 0 errors, 4 skipped | yes |
| requests+urllib3-redos | tests/test_utils.py, tests/test_lowlevel.py | 207 passed, 0 failed, 0 errors, 16 need an unavailable fixture, 12 skipped | 207 passed, 0 failed, 0 errors, 16 need an unavailable fixture, 12 skipped | yes |
| waitress-chunked-smuggling | tests/test_receiver.py, tests/test_parser.py, tests/test_utilities.py | 111 passed, 0 failed, 0 errors | 126 passed, 0 failed, 0 errors | yes |
| requests-auth-redirect | tests/test_lowlevel.py, tests/test_structures.py, tests/test_hooks.py | 30 passed, 0 failed, 0 errors, 8 need an unavailable fixture | 30 passed, 0 failed, 0 errors, 8 need an unavailable fixture | yes |
| pyyaml-full-load | PyYAML runner | 1283 passed, 0 failed, 0 errors | 1288 passed, 0 failed, 0 errors | yes |
| jinja2-sandbox-format | tests/test_security.py | 12 passed, 0 failed, 0 errors | 15 passed, 0 failed, 0 errors | yes |
| sqlparse-strip-comments | tests/test_format.py, tests/test_regressions.py | 139 passed, 0 failed, 0 errors, 3 skipped | 141 passed, 0 failed, 0 errors, 3 skipped | yes |
| idna-encode-quadratic | tests/test_idna.py, tests/test_idna_codec.py | 19 passed, 0 failed, 0 errors | 19 passed, 0 failed, 0 errors | yes |
| multipart-options-redos | multipart/tests/test_multipart.py | 105 passed, 0 failed, 0 errors | 105 passed, 0 failed, 0 errors | yes |
| aiohttp-static-traversal | tests/test_web_urldispatcher.py | 27 passed, 0 failed, 0 errors, 3 skipped | 29 passed, 0 failed, 0 errors, 3 skipped | yes |
| werkzeug-multipart-dos | tests/test_formparser.py | 24 passed, 0 failed, 0 errors | 24 passed, 0 failed, 0 errors | yes |
| django-email-redos | Django runtests | 28 run, all passed | 28 run, all passed | yes |

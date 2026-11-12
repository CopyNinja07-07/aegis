# no_sanitizer_bypass: static data-flow clause

Logged candidates on the vulnerable module that parse: 632; adding a parameter: 59; violating the clause: 0 (of them verified by the gate: 0).

Reference fixes: 16 of 16 satisfy the clause.

| Hand-written bypass patch | What it does | Clause verdict |
|---|---|---|
| pt-docs (read_blob) | path traversal: `trusted` skips the base-folder check | rejected: read_blob: trusted reaches open() unvalidated |
| idor-invoice (invoice_for) | IDOR: `as_admin` skips require_same_tenant | rejected: invoice_for: as_admin reaches get_invoice() unvalidated |
| ssrf-preview (preview) | SSRF: `allow_any` skips the host allow-list | rejected: preview: allow_any reaches http_get() unvalidated |

Design note: a first version also treated bound SQL parameters, argv lists and the subject of a regex match as sinks and flagged 8 SQL-injection fixes that pass the value as a bound parameter, the standard fix; those positions are not sinks in this version.

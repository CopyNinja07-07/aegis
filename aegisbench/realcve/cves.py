"""Real CVEs in widely used Python packages, pinned to the last vulnerable release and the first fixed one.

  python -m aegisbench.realcve.cves            # download the source archives from PyPI, check SHA-256, unpack
  python -m aegisbench.realcve.cves --verify   # check that each case's target functions are ones the fix changed

Each case names the public entry point an attacker reaches and the target functions: the definitions the
fixed release changed for this CVE (taken from a function-level AST diff of the two releases; the --verify step
recomputes that diff). Two retrieval queries per case: the triaged class only (what AegisBench's agent gets) and
the alert's description. Sources are fetched, not redistributed; they are only parsed, never installed or run
(the urllib3 repair harness loads one module, url.py, in a subprocess).
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import shutil
import tarfile
import urllib.request
from pathlib import Path

VENDOR = Path(__file__).parent / "vendor"
PYPI = "https://files.pythonhosted.org/packages/"

# name: (url, sha256, directory holding the package folder after unpacking)
ARCHIVES = {
    "requests-2.30.0": (PYPI + "source/r/requests/requests-2.30.0.tar.gz",
                        "239d7d4458afcb28a692cdd298d87542235f4ca8d36d03a15bfc128a6559a2f4", "requests-2.30.0"),
    "requests-2.31.0": (PYPI + "9d/be/10918a2eac4ae9f02f6cfe6414b7a155ccd8f7f9d4380d62fd5b955065c3/requests-2.31.0.tar.gz",
                        "942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1", "requests-2.31.0"),
    "urllib3-1.26.4": (PYPI + "source/u/urllib3/urllib3-1.26.4.tar.gz",
                       "e7b021f7241115872f92f43c6508082facffbd1c048e3c6e2bb9c2a157e28937", "urllib3-1.26.4/src"),
    "urllib3-1.26.5": (PYPI + "94/40/c396b5b212533716949a4d295f91a4c100d51ba95ea9e2d96b6b0517e5a5/urllib3-1.26.5.tar.gz",
                       "a7acd0977125325f516bda9735fa7142b909a8d01e8b2e4c8108d0984e6e0098", "urllib3-1.26.5/src"),
    "waitress-2.1.0": (PYPI + "source/w/waitress/waitress-2.1.0.tar.gz",
                       "ec8a8d9b6b15f3bb2c1a82b8f3929a029c333c35fcafb08c185a9e562d8cc9c2", "waitress-2.1.0/src"),
    "waitress-2.1.1": (PYPI + "f5/f7/e258a76818a9c83d7ef3b89377231b1ea1e9e5f06f70561a3115d07f73de/waitress-2.1.1.tar.gz",
                       "e2e60576cf14a1539da79f7b7ee1e79a71e64f366a0b47db54a15e971f57bb16", "waitress-2.1.1/src"),
    "requests-2.19.1": (PYPI + "54/1f/782a5734931ddf2e1494e4cd615a51ff98e1879cbe9eecbdfeaf09aa75e9/requests-2.19.1.tar.gz",
                        "ec22d826a36ed72a7358ff3fe56cbd4ba69dd7a6718ffd450ff0e9df7a47ce6a", "requests-2.19.1"),
    "requests-2.20.0": (PYPI + "97/10/92d25b93e9c266c94b76a5548f020f3f1dd0eb40649cb1993532c0af8f4c/requests-2.20.0.tar.gz",
                        "99dcfdaaeb17caf6e526f32b6a7b780461512ab3f1d992187801694cba42770c", "requests-2.20.0"),
    "PyYAML-5.3": (PYPI + "3d/d9/ea9816aea31beeadccd03f1f8b625ecf8f645bd66744484d162d84803ce5/PyYAML-5.3.tar.gz",
                   "e9f45bd5b92c7974e59bcd2dcc8631a6b6cc380a904725fce7bc08872e691615", "PyYAML-5.3/lib3"),
    "PyYAML-5.3.1": (PYPI + "64/c2/b80047c7ac2478f9501676c988a5411ed5572f35d1beff9cae07d321512c/PyYAML-5.3.1.tar.gz",
                     "b8eac752c5e14d3eca0e6dd9199cd627518cb5ec06add0de9d32baeee6fe645d", "PyYAML-5.3.1/lib3"),
    "Jinja2-2.10": (PYPI + "56/e6/332789f295cf22308386cf5bbd1f4e00ed11484299c5d7383378cf48ba47/Jinja2-2.10.tar.gz",
                    "f84be1bb0040caca4cea721fcbbbbd61f9be9464ca236387158b0feea01914a4", "Jinja2-2.10"),
    "Jinja2-2.10.1": (PYPI + "93/ea/d884a06f8c7f9b7afbc8138b762e80479fb17aedbbe2b06515a12de9378d/Jinja2-2.10.1.tar.gz",
                      "065c4f02ebe7f7cf559e49ee5a95fb800a9e4528727aec6f24402a5374c65013", "Jinja2-2.10.1"),
    "sqlparse-0.4.1": (PYPI + "a2/54/da10f9a0235681179144a5ca02147428f955745e9393f859dec8d0d05b41/sqlparse-0.4.1.tar.gz",
                       "0f91fd2e829c44362cbcfab3e9ae12e22badaa8a29ad5ff599f9ec109f0454e8", "sqlparse-0.4.1"),
    "sqlparse-0.4.2": (PYPI + "32/fe/8a8575debfd924c8160295686a7ea661107fc34d831429cce212b6442edb/sqlparse-0.4.2.tar.gz",
                       "0c00730c74263a94e5a9919ade150dfc3b19c574389985446148402998287dae", "sqlparse-0.4.2"),
    "idna-3.6": (PYPI + "bf/3f/ea4b9117521a1e9c50344b909be7886dd00a519552724809bb1f486986c2/idna-3.6.tar.gz",
                 "9ecdbbd083b06798ae1e86adcbfe8ab1479cf864e4ee30fe4e46a003d12491ca", "idna-3.6"),
    "idna-3.7": (PYPI + "21/ed/f86a79a07470cb07819390452f178b3bef1d375f2ec021ecfc709fc7cf07/idna-3.7.tar.gz",
                 "028ff3aadf0609c1fd278d8ea3089299412a7a8b9bd005dd08b9f8285bcb5cfc", "idna-3.7"),
    "python-multipart-0.0.6": (PYPI + "2d/23/abcfad10c3348cb6358400f8adbc21b523bbc6c954494fd0974428068672/python_multipart-0.0.6.tar.gz",
                               "e9925a80bb668529f1b67c7fdb0a5dacdd7cbfc6fb0bff3ea443fe22bdd62132", "python_multipart-0.0.6"),
    "python-multipart-0.0.7": (PYPI + "67/94/bb4778be5d4c18329d60276d4e58b3974e2dce8ec3bee5569bfe9c81f36e/python_multipart-0.0.7.tar.gz",
                               "288a6c39b06596c1b988bb6794c6fbc80e6c369e35e5062637df256bee0c9af9", "python_multipart-0.0.7"),
    "aiohttp-3.9.1": (PYPI + "54/07/9467d3f8dae29b14f423b414d9e67512a76743c5bb7686fb05fe10c9cc3e/aiohttp-3.9.1.tar.gz",
                      "8fc49a87ac269d4529da45871e2ffb6874e87779c3d0e2ccd813c0899221239d", "aiohttp-3.9.1"),
    "aiohttp-3.9.2": (PYPI + "07/2f/27c9ae85646de72784529a86d2a98c7cfae4ff9eab0004becf47da66c7ec/aiohttp-3.9.2.tar.gz",
                      "b0ad0a5e86ce73f5368a164c10ada10504bf91869c05ab75d982c6048217fbf7", "aiohttp-3.9.2"),
    "Werkzeug-2.2.2": (PYPI + "f8/c1/1c8e539f040acd80f844c69a5ef8e2fccdf8b442dabb969e497b55d544e1/Werkzeug-2.2.2.tar.gz",
                       "7ea2d48322cc7c0f8b3a215ed73eabd7b5d75d0b50e31ab006286ccff9e00b8f", "Werkzeug-2.2.2/src"),
    "Werkzeug-2.2.3": (PYPI + "02/3c/baaebf3235c87d61d6593467056d5a8fba7c75ac838b8d100a5e64eba7a0/Werkzeug-2.2.3.tar.gz",
                       "2e1ccc9417d4da358b9de6f174e3ac094391ea1d4fbef2d667865d819dfd0afe", "Werkzeug-2.2.3/src"),
    "Django-4.2.2": ("https://files.pythonhosted.org/packages/5c/fa/427fbcac5633f4b88fda7953efb04db903ca7e6d9486afdbda525c4006cc/Django-4.2.2.tar.gz",
                     "2a6b6fbff5b59dd07bef10bcb019bee2ea97a30b2a656d51346596724324badf", "Django-4.2.2"),
    "Django-4.2.3": ("https://files.pythonhosted.org/packages/36/24/d0e78e667f98efcca76c8b670ef247583349a8f5241cdb3c98eeb92726ff/Django-4.2.3.tar.gz",
                     "45a747e1c5b3d6df1b141b1481e193b033fd1fdbda3ff52677dc81afdaacbaed", "Django-4.2.3"),
}


def C(id, cve, cwe, archives, fixed, packages, entry, vulnerable, query_class, query_alert):
    return dict(id=id, cve=cve, cwe=cwe, archives=archives, fixed=fixed, packages=packages, entry=entry,
                vulnerable=vulnerable, query_class=query_class, query_alert=query_alert)


CASES = [
    C("requests-proxy-auth", "CVE-2023-32681", "CWE-200", ["requests-2.30.0"], ["requests-2.31.0"], ["requests"],
      "requests.api.get", ["requests.sessions.SessionRedirectMixin.rebuild_proxies"],
      "credential exposure redirect",
      "Proxy-Authorization header forwarded to the destination server after an HTTPS redirect"),
    C("urllib3-authority-redos", "CVE-2021-33503", "CWE-1333", ["urllib3-1.26.4"], ["urllib3-1.26.5"], ["urllib3"],
      "urllib3.poolmanager.PoolManager.urlopen", ["urllib3.util.url.parse_url"],
      "redos regular expression", "request hangs on a URL whose authority contains many @ characters"),
    C("requests+urllib3-redos", "CVE-2021-33503", "CWE-1333", ["requests-2.30.0", "urllib3-1.26.4"],
      ["requests-2.30.0", "urllib3-1.26.5"], ["requests", "urllib3"],
      "requests.api.get", ["urllib3.util.url.parse_url"],
      "redos regular expression", "request hangs on a URL whose authority contains many @ characters"),
    C("waitress-chunked-smuggling", "CVE-2022-24761", "CWE-444", ["waitress-2.1.0"], ["waitress-2.1.1"], ["waitress"],
      "waitress.channel.HTTPChannel.received",
      ["waitress.receiver.ChunkedReceiver.received", "waitress.parser.HTTPRequestParser.parse_header",
       "waitress.utilities.undquote"],
      "request smuggling",
      "request smuggling: chunk size with a 0x prefix or + sign accepted in chunked transfer encoding"),
    C("requests-auth-redirect", "CVE-2018-18074", "CWE-522", ["requests-2.19.1"], ["requests-2.20.0"], ["requests"],
      "requests.api.get", ["requests.sessions.SessionRedirectMixin.rebuild_auth"],
      "credential exposure redirect",
      "Authorization header sent to the new host after a redirect from HTTPS to HTTP"),
    C("pyyaml-full-load", "CVE-2020-1747", "CWE-20", ["PyYAML-5.3"], ["PyYAML-5.3.1"], ["yaml"],
      "yaml.full_load", ["yaml.constructor.FullConstructor.set_python_instance_state"],
      "unsafe deserialization",
      "full_load runs arbitrary code from a document with a python/object/new tag"),
    C("jinja2-sandbox-format", "CVE-2019-10906", "CWE-693", ["Jinja2-2.10"], ["Jinja2-2.10.1"], ["jinja2"],
      "jinja2.environment.Template.render",
      ["jinja2.sandbox.SandboxedEnvironment.call", "jinja2.sandbox.SandboxedEnvironment.format_string",
       "jinja2.sandbox.inspect_format_method"],
      "sandbox escape", "sandboxed template escapes the sandbox through str.format_map"),
    C("sqlparse-strip-comments", "CVE-2021-32839", "CWE-1333", ["sqlparse-0.4.1"], ["sqlparse-0.4.2"], ["sqlparse"],
      "sqlparse.format", ["sqlparse.filters.others.StripCommentsFilter._process"],
      "redos regular expression", "format with strip_comments hangs on SQL with many repeated line breaks"),
    C("idna-encode-quadratic", "CVE-2024-3651", "CWE-400", ["idna-3.6"], ["idna-3.7"], ["idna"],
      "idna.core.encode", ["idna.core.valid_contextj", "idna.core.check_label", "idna.core.alabel"],
      "denial of service", "idna encode takes quadratic time on a long crafted domain name"),
    C("multipart-options-redos", "CVE-2024-24762", "CWE-1333", ["python-multipart-0.0.6"], ["python-multipart-0.0.7"],
      ["multipart"], "multipart.multipart.parse_form", ["multipart.multipart.parse_options_header"],
      "redos regular expression", "Content-Type header with crafted options hangs the form parser"),
    C("aiohttp-static-traversal", "CVE-2024-23334", "CWE-22", ["aiohttp-3.9.1"], ["aiohttp-3.9.2"], ["aiohttp"],
      "aiohttp.web_app.Application._handle", ["aiohttp.web_urldispatcher.StaticResource._handle"],
      "path traversal", "static route serves files outside the static directory through ../ when following symlinks"),
    C("werkzeug-multipart-dos", "CVE-2023-25577", "CWE-770", ["Werkzeug-2.2.2"], ["Werkzeug-2.2.3"], ["werkzeug"],
      "werkzeug.wrappers.request.Request.form",
      ["werkzeug.formparser.MultiPartParser.parse", "werkzeug.formparser.FormDataParser._parse_multipart",
       "werkzeug.sansio.multipart.MultipartDecoder.next_event"],
      "denial of service", "multipart form with a huge number of parts exhausts CPU and memory"),
    C("django-email-redos", "CVE-2023-36053", "CWE-1333", ["Django-4.2.2"], ["Django-4.2.3"], ["django"],
      "django.forms.fields.Field.clean",
      ["django.core.validators.EmailValidator.__call__", "django.core.validators.URLValidator.__call__",
       "django.forms.fields.EmailField.__init__"],
      "redos regular expression", "email field validation hangs on an address with a very large number of domain labels"),
]


def fetch() -> None:
    VENDOR.mkdir(exist_ok=True)
    for name, (url, sha, _) in ARCHIVES.items():
        if src_dir(name).is_dir():
            continue
        tgz = VENDOR / url.rsplit("/", 1)[1]
        if not tgz.is_file():
            urllib.request.urlretrieve(url, tgz)
        digest = hashlib.sha256(tgz.read_bytes()).hexdigest()
        if digest != sha:
            raise SystemExit(f"{name}: SHA-256 mismatch ({digest})")
        with tarfile.open(tgz) as t:
            t.extractall(VENDOR, filter="data")
        print(f"fetched {name}")


def src_dir(arch: str) -> Path:
    return VENDOR / ARCHIVES[arch][2]


def case_root(case: dict, archives: list[str] | None = None) -> Path:
    """A directory holding exactly the case's packages (one folder per package)."""
    archives = archives or case["archives"]
    tag = "fixed" if archives is case.get("fixed") else "cases"
    root = VENDOR / tag / case["id"]
    if not root.is_dir():
        root.mkdir(parents=True)
        for arch, pkg in zip(archives, case["packages"]):
            shutil.copytree(src_dir(arch) / pkg, root / pkg, ignore=shutil.ignore_patterns("__pycache__", "tests"))
    return root


def available() -> bool:
    return all(src_dir(n).is_dir() for n in ARCHIVES)


def _defs(root: Path) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*.py")):
        rel = str(p.relative_to(root))
        mod = rel[:-3].replace("/", ".").removesuffix(".__init__")
        try:
            tree = ast.parse(p.read_text(errors="replace"))
        except SyntaxError:
            continue
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out[f"{mod}.{n.name}"] = ast.dump(n)
            elif isinstance(n, ast.ClassDef):
                for m in n.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        out[f"{mod}.{n.name}.{m.name}"] = ast.dump(m)
    return out


def verify() -> bool:
    """Every target function exists in the vulnerable release and was changed by the fixed one."""
    ok = True
    for c in CASES:
        before, after = _defs(case_root(c)), _defs(case_root(c, c["fixed"]))
        for v in c["vulnerable"]:
            good = v in before and before[v] != after.get(v)
            ok &= good
            print(f"{'ok ' if good else 'BAD'} {c['id']:28s} {v}")
    print("TARGETS OK" if ok else "TARGETS FAILED")
    return ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    if ap.parse_args().verify:
        raise SystemExit(0 if verify() else 1)
    fetch()

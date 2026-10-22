"""Dependency-file parsers. Each returns [(ecosystem, name, version_or_None, direct_bool)].

Ecosystem names match OSV (npm, PyPI, Go, Packagist, Maven, RubyGems, crates.io).
"docker" entries are base images: used as tech tags, not sent to OSV.
"""
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath

SKIP_DIRS = re.compile(r"(^|/)(node_modules|vendor|\.git|dist|build/cache|__pycache__|site-packages)/")

# file name -> (parser, priority). Lockfiles win over loose manifests in the same folder.
LOCKS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
         "uv.lock", "composer.lock", "Gemfile.lock", "Cargo.lock"}
LOOSE = {"package.json": "package-lock.json|yarn.lock|pnpm-lock.yaml",
         "pyproject.toml": "poetry.lock|uv.lock",
         "composer.json": "composer.lock"}


def is_manifest(path):
    if SKIP_DIRS.search(path):
        return False
    n = PurePosixPath(path).name
    return (n in LOCKS or n in LOOSE or n in ("go.mod", "pom.xml", "build.gradle", "build.gradle.kts")
            or re.fullmatch(r"requirements[\w.-]*\.txt", n) is not None
            or re.fullmatch(r"Dockerfile[\w.-]*", n) is not None)


def has_lock(path, present):
    """True when a loose manifest (package.json, pyproject, composer.json) has a lockfile beside it.
    Then the loose file only supplies direct-dependency names; versions come from the lock."""
    pp = PurePosixPath(path)
    if pp.name not in LOOSE:
        return False
    return any(str(pp.parent / lock).lstrip("./") in present or str(pp.parent / lock) in present
               for lock in LOOSE[pp.name].split("|"))


def _clean(v):
    """Turn '^1.2.3' / '~=1.2' / 'v1.2.3' into '1.2.3' when it is a concrete version, else None."""
    if not v or not isinstance(v, str):
        return None
    v = v.strip().lstrip("=^~v ")
    m = re.match(r"^(\d+(\.\d+){1,3}([-.+][0-9A-Za-z.-]+)?)$", v)
    return m.group(1) if m else None


DEV_FILE = re.compile(r"(^|/)(requirements[-_.]?(dev|test|tests|lint|docs)[\w.-]*\.txt)$|(^|/)(tests?|e2e|docs|examples?)/", re.I)


def parse(path, text):
    """-> [(ecosystem, name, version, direct, dev)]. dev = only used in development/build, not shipped."""
    file_dev = bool(DEV_FILE.search(path))
    return [(*t[:4], bool(t[4] if len(t) > 4 else False) or file_dev) for t in _parse(path, text)]


def _parse(path, text):
    n = PurePosixPath(path).name
    try:
        if n == "package-lock.json":
            return _npm_lock(text)
        if n == "package.json":
            return _package_json(text)
        if n == "yarn.lock":
            return _yarn_lock(text)
        if n == "pnpm-lock.yaml":
            return _pnpm_lock(text)
        if n.startswith("requirements"):
            return _requirements(text)
        if n == "pyproject.toml":
            return _pyproject(text)
        if n in ("poetry.lock", "uv.lock"):
            return [("PyPI", p["name"].lower(), p.get("version"), False, p.get("category") == "dev")
                    for p in tomllib.loads(text).get("package", [])]
        if n == "Pipfile.lock":
            d = json.loads(text)
            return [("PyPI", k.lower(), _clean(v.get("version")), sec == "default", sec == "develop")
                    for sec in ("default", "develop") for k, v in d.get(sec, {}).items()]
        if n == "go.mod":
            return _gomod(text)
        if n == "composer.lock":
            d = json.loads(text)
            return [("Packagist", p["name"], _clean(p.get("version")), sec == "packages", sec == "packages-dev")
                    for sec in ("packages", "packages-dev") for p in d.get(sec) or []]
        if n == "composer.json":
            d = json.loads(text)
            return [("Packagist", k, _clean(v), True, sec == "require-dev")
                    for sec in ("require", "require-dev") for k, v in (d.get(sec) or {}).items() if "/" in k]
        if n == "Gemfile.lock":
            return [("RubyGems", m.group(1), m.group(2), False)
                    for m in re.finditer(r"^    ([\w.-]+) \(([\w.]+)\)$", text, re.M)]
        if n == "Cargo.lock":
            return [("crates.io", p["name"], p.get("version"), False)
                    for p in tomllib.loads(text).get("package", [])]
        if n == "pom.xml":
            return _pom(text)
        if n.startswith("build.gradle"):
            return [("Maven", f"{m.group(1)}:{m.group(2)}", m.group(3), True)
                    for m in re.finditer(r"""['"]([\w.-]+):([\w.-]+):([\d][\w.-]*)['"]""", text)]
        if n.startswith("Dockerfile"):
            return [("docker", m.group(1).lower(), m.group(2), True)
                    for m in re.finditer(r"^\s*FROM\s+(?:--platform=\S+\s+)?([\w./-]+)(?::([\w.-]+))?", text, re.M | re.I)
                    if m.group(1).lower() != "scratch" and not m.group(1).startswith("$")]
    except Exception:
        return []
    return []


def _npm_lock(text):
    d = json.loads(text)
    out = []
    pk = d.get("packages")
    if pk:
        root = pk.get("", {})
        direct = set(root.get("dependencies", {})) | set(root.get("devDependencies", {}))
        for key, info in pk.items():
            if not key or "node_modules/" not in key or info.get("link"):
                continue
            name = key.rsplit("node_modules/", 1)[1]
            out.append(("npm", name, info.get("version"), key.count("node_modules/") == 1 and name in direct,
                        bool(info.get("dev") or info.get("devOptional"))))
        return out

    def walk(deps, depth):
        for name, info in (deps or {}).items():
            out.append(("npm", name, info.get("version"), depth == 0, bool(info.get("dev"))))
            walk(info.get("dependencies"), depth + 1)
    walk(d.get("dependencies"), 0)
    return out


def _package_json(text):
    d = json.loads(text)
    return [("npm", k, _clean(v), True, sec == "devDependencies")
            for sec in ("dependencies", "devDependencies") for k, v in (d.get(sec) or {}).items()]


def _yarn_lock(text):
    out = []
    for block in re.split(r"\n(?=\S)", text):
        head = block.split("\n", 1)[0]
        m = re.match(r'^"?(@?[^@"\s,]+)@', head)
        v = re.search(r'^\s+version:?\s+"?([^"\s]+)"?', block, re.M)
        if m and v:
            out.append(("npm", m.group(1), v.group(1), False))
    return out


def _pnpm_lock(text):
    out = set()
    for m in re.finditer(r"^\s{2}'?/?(@?[^@\s:'(]+)[@/](\d[^:'(\s]*)", text, re.M):
        out.add(("npm", m.group(1), m.group(2), False))
    return list(out)


def _requirements(text):
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([\w.]+)?", line)
        if m:
            out.append(("PyPI", m.group(1).lower(), m.group(3) if m.group(2) == "==" else None, True))
    return out


def _pyproject(text):
    d = tomllib.loads(text)
    out = []
    for spec in d.get("project", {}).get("dependencies", []):
        out += _requirements(spec)
    poetry = d.get("tool", {}).get("poetry", {})
    for sec in ("dependencies", "dev-dependencies"):
        for k, v in (poetry.get(sec) or {}).items():
            if k.lower() != "python":
                out.append(("PyPI", k.lower(), _clean(v if isinstance(v, str) else v.get("version")), True))
    return out


def _gomod(text):
    out = []
    # stdlib only when the exact patch release is known (go 1.22.3 or toolchain go1.22.3)
    tc = re.search(r"^toolchain\s+go(\d+\.\d+\.\d+)", text, re.M) or re.search(r"^go\s+(\d+\.\d+\.\d+)", text, re.M)
    if tc:
        out.append(("Go", "stdlib", tc.group(1), True))
    block = re.findall(r"^require\s*\((.*?)^\)", text, re.M | re.S)
    lines = [l for b in block for l in b.splitlines()] + re.findall(r"^require\s+([^\s(].*)$", text, re.M)
    for l in lines:
        m = re.match(r"^\s*(\S+)\s+(v\S+)(\s*//\s*indirect)?", l)
        if m:
            out.append(("Go", m.group(1), m.group(2), not m.group(3)))
    return out


def _pom(text):
    text = re.sub(r'\sxmlns(:\w+)?="[^"]+"', "", text, count=5)
    root = ET.fromstring(text)
    props = {p.tag: (p.text or "").strip() for p in root.findall("./properties/*")}
    out = []
    for dep in root.iter("dependency"):
        g, a, v = (dep.findtext(t) for t in ("groupId", "artifactId", "version"))
        if v and v.startswith("${"):
            v = props.get(v[2:-1])
        if g and a:
            out.append(("Maven", f"{g}:{a}", v, True))
    return out

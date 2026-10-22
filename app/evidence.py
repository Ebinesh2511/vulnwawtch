"""Code evidence for a finding: the exact lines that declare, lock and use a library, each with a
GitHub permalink (blob/<commit>/<file>#Lx-Ly). Uses the shallow clone made for AI analysis. No AI.
"""
import json
import re
import subprocess
from pathlib import Path, PurePosixPath

from . import db, gh
from .config import CLONES, ORG

MAX_USAGE = 5


def _sha(path):
    return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def _lines(path, file):
    try:
        return (path / file).read_text(errors="replace").splitlines()
    except OSError:
        return []


def _item(repo, sha, file, text, start, end, kind, note="", hit=None):
    start, end = max(1, start), min(len(text), end)
    return {"kind": kind, "note": note, "file": file, "start": start, "end": end, "hit": hit or start,
            "lines": [[n, text[n - 1][:220]] for n in range(start, end + 1)],
            "url": f"https://github.com/{ORG}/{repo}/blob/{sha}/{file}#L{start}-L{end}"}


def _find(text, pattern, flags=0):
    rx = re.compile(pattern, flags)
    return [i + 1 for i, l in enumerate(text) if rx.search(l)]


def _declared(repo, sha, path, eco, name, version, manifest):
    out = []
    q = re.escape(name)
    if eco == "npm":
        folder = PurePosixPath(manifest).parent if manifest else PurePosixPath(".")
        pkg = str(folder / "package.json") if str(folder) != "." else "package.json"
        pj = _lines(path, pkg)
        hit = _find(pj, rf'^\s*"{q}"\s*:\s*"')
        if hit:
            out.append(_item(repo, sha, pkg, pj, hit[0], hit[0], "declared", "declared in package.json"))
        if manifest and manifest.endswith("package-lock.json"):
            lock = _lines(path, manifest)
            for h in _find(lock, rf'^\s*"(.*/)?node_modules/{q}"\s*:\s*\{{')[:20]:
                v = next((j for j in range(h, min(h + 6, len(lock))) if '"version"' in lock[j]), h - 1) + 1
                if version and version not in lock[v - 1]:
                    continue
                out.append(_item(repo, sha, manifest, lock, h, v, "locked", f"resolved to {version} in lockfile", hit=v))
                break
        if not hit:
            # transitive: show which direct dependency pulls it in
            from .ai import _npm_parents
            for parent in _npm_parents(path, manifest, name)[:3]:
                ph = _find(pj, rf'^\s*"{re.escape(parent)}"\s*:\s*"')
                if ph:
                    out.append(_item(repo, sha, pkg, pj, ph[0], ph[0], "pulled_in_by",
                                     f"{name} comes in through {parent}"))
    elif eco == "Go" and name == "stdlib":
        for f in sorted(p.relative_to(path).as_posix() for p in path.rglob("Dockerfile*") if ".git" not in p.parts):
            t = _lines(path, f)
            for h in _find(t, rf"^\s*FROM\s+\S*golang:{re.escape(version)}", re.I)[:1]:
                out.append(_item(repo, sha, f, t, h, h, "declared", f"Go {version} toolchain from Docker image"))
    elif eco == "tech":
        for f in sorted(p.relative_to(path).as_posix() for p in path.rglob("Dockerfile*") if ".git" not in p.parts):
            t = _lines(path, f)
            for h in _find(t, rf"^\s*FROM\s+\S*{q}", re.I)[:1]:
                out.append(_item(repo, sha, f, t, h, h, "declared", "base image"))
    elif manifest:
        t = _lines(path, manifest)
        key = re.escape(name.split(":")[-1])
        pat = rf"^\s*{key}\b" if eco == "PyPI" else rf"(^|[\"'\s/]){key}([\"'\s@:=<>~^]|$)"
        for h in _find(t, pat, re.I)[:2]:
            out.append(_item(repo, sha, manifest, t, h, h, "declared", f"declared in {PurePosixPath(manifest).name}"))
    return out


def _usage(repo, sha, path, eco, name):
    from .ai import _usage_pattern
    if eco == "Go" and name == "stdlib":
        return []
    args = ["rg", "--json", "-e", _usage_pattern(eco, name), "--max-filesize", "500K",
            "-g", "!**/node_modules/**", "-g", "!**/vendor/**", "-g", "!*.lock", "-g", "!*lock.json",
            "-g", "!*.sum", "-g", "!**/dist/**", "-g", "!**/*.min.js"]
    if eco == "tech":
        args += ["-g", "*Dockerfile*", "-g", "*.yml", "-g", "*.yaml", "-g", "*.conf"]
    p = subprocess.run(args + ["."], cwd=path, capture_output=True, text=True, timeout=60)
    out, seen = [], set()
    for line in p.stdout.splitlines():
        ev = json.loads(line)
        if ev.get("type") != "match":
            continue
        f = ev["data"]["path"]["text"].removeprefix("./")
        if f in seen:
            continue
        seen.add(f)
        n = ev["data"]["line_number"]
        out.append(_item(repo, sha, f, _lines(path, f), n - 1, n + 1, "used", "used here", hit=n))
        if len(out) >= MAX_USAGE:
            break
    return out


def build(repo, eco, name, version, manifest):
    r = db.one("SELECT * FROM repos WHERE name=?", repo)
    path = CLONES / repo
    if not (path / ".git").exists():
        gh.clone_or_update(ORG, repo, r["tracked_branch"] or r["default_branch"], path)
    sha = _sha(path)
    items = _declared(repo, sha, path, eco, name, version, manifest) + _usage(repo, sha, path, eco, name)
    return {"sha": sha, "branch": r["tracked_branch"], "items": items}


def store(repo, eco, name, version, manifest):
    ev = json.dumps(build(repo, eco, name, version, manifest))
    db.x("UPDATE issues SET evidence=? WHERE repo=? AND ecosystem=? AND package=? AND IFNULL(version,'')=?",
         ev, repo, eco, name, version or "")


def backfill(log=print):
    """Evidence for analyzed findings that don't have it yet."""
    groups = db.q("""SELECT repo, ecosystem, package, IFNULL(version,'') version, max(manifest) manifest FROM issues
                     WHERE ai_state='done' AND evidence IS NULL GROUP BY 1,2,3,4""")
    for g in groups:
        try:
            store(g["repo"], g["ecosystem"], g["package"], g["version"], g["manifest"])
        except Exception as e:
            log(f"  evidence {g['repo']}/{g['package']}: {e}")
    log(f"evidence: {len(groups)} finding(s) updated")

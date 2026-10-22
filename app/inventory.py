"""Repo list + dependency index. Re-scans a repo only when its tracked branch has a new commit."""
import json
import re
from collections import defaultdict
from pathlib import PurePosixPath

from . import db, gh, manifests
from .config import ORG


def sync_repos(log=print):
    seen = set()
    for r in gh.list_repos(ORG):
        if r["isArchived"]:
            continue
        name = r["name"]
        seen.add(name)
        default = (r.get("defaultBranchRef") or {}).get("name") or ""
        cur = db.one("SELECT tracked_branch FROM repos WHERE name=?", name)
        db.x("""INSERT INTO repos(name, default_branch, tracked_branch, private, language, pushed_at, tracked)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET default_branch=excluded.default_branch,
                  private=excluded.private, language=excluded.language, pushed_at=excluded.pushed_at""",
             name, default, (cur or {}).get("tracked_branch") or default, int(r["visibility"] != "PUBLIC"),
             (r.get("primaryLanguage") or {}).get("name"), r.get("pushedAt"), 0 if r.get("isEmpty") else 1)
    log(f"repos: {len(seen)} active in {ORG}")
    return seen


def scan_repo(name, force=False, log=print):
    repo = db.one("SELECT * FROM repos WHERE name=?", name)
    branch = repo["tracked_branch"] or repo["default_branch"]
    try:
        sha = gh.head_sha(ORG, name, branch)
    except gh.GhError as e:
        db.x("UPDATE repos SET scan_error=?, last_scan=? WHERE name=?", str(e), db.now(), name)
        log(f"  {name}: {e}")
        return False
    if sha == repo["last_sha"] and not force:
        return False  # nothing changed since last scan: zero cost

    t = gh.tree(ORG, name, sha)
    paths = [x["path"] for x in t.get("tree", []) if x["type"] == "blob" and manifests.is_manifest(x["path"])]
    present = set(paths)
    rows, direct_names = [], defaultdict(set)
    for p in paths[:200]:
        try:
            text = gh.file_text(ORG, name, p, sha)
        except gh.GhError:
            continue
        parsed = manifests.parse(p, text)
        if manifests.has_lock(p, present):
            direct_names[str(PurePosixPath(p).parent)] |= {n for _, n, *_ in parsed}
            continue
        rows += [(eco, n, v, int(d), p, int(dev)) for eco, n, v, d, dev in parsed]

    # golang:1.26.8-alpine pins the Go toolchain, so the Go standard library can be checked by OSV
    for eco, n, v, d, p, dev in list(rows):
        m = re.match(r"(\d+\.\d+\.\d+)", v or "")
        if eco == "docker" and n.split("/")[-1] == "golang" and m:
            rows.append(("Go", "stdlib", m.group(1), 1, p, dev))

    # lockfile entries named in their package.json are direct deps
    rows = [(eco, n, v, int(d or n in direct_names.get(str(PurePosixPath(p).parent), ())), p, dev)
            for eco, n, v, d, p, dev in rows]

    langs = {}
    try:
        langs = gh.languages(ORG, name)
    except gh.GhError:
        pass
    tags = sorted({l.lower() for l in langs}
                  | {f"{n.split('/')[-1]}" for eco, n, *_ in rows if eco == "docker"}
                  | {n.lower() for eco, n, v, d, *_ in rows if d and eco != "docker"})

    with db.conn() as c:
        c.execute("DELETE FROM deps WHERE repo=?", (name,))
        c.executemany("INSERT OR IGNORE INTO deps(repo, ecosystem, name, version, manifest, direct, dev) VALUES(?,?,?,?,?,?,?)",
                      [(name, eco, n, v, p, d, dev) for eco, n, v, d, p, dev in rows])
        c.execute("UPDATE repos SET last_sha=?, last_scan=?, scan_error=NULL, tags=? WHERE name=?",
                  (sha, db.now(), json.dumps(tags), name))
    log(f"  {name}@{branch}: {len(paths)} manifests, {len(rows)} deps")
    return True


def scan_all(force=False, log=print):
    changed = []
    for r in db.q("SELECT name FROM repos WHERE tracked=1 ORDER BY name"):
        if scan_repo(r["name"], force=force, log=log):
            changed.append(r["name"])
    log(f"scan: {len(changed)} repo(s) changed")
    return changed

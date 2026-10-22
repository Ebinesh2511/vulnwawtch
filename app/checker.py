"""One-off check of any public GitHub repo: is it pulling in something known to be bad?

Reads dependency files and GitHub Actions workflows through the GitHub API (no clone, no code run),
then asks OSV.dev about every exact package version:
  - malicious packages (OSV "MAL-" entries, or advisories tagged CWE-506 embedded malicious code)
  - compromised / vulnerable GitHub Actions (OSV lists them but does not compare action versions,
    so tags are compared here; actions pinned to a branch or commit are flagged for a manual look)
  - known-exploited (CISA KEV) and other vulnerabilities in the installed versions
Results are stored in the `checks` table so a check has a shareable URL.
"""
import json
import re
import threading
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import PurePosixPath

from . import classify, db, feeds, gh, manifests, osv
from .config import SEV_RANK

MAX_FILES = 300
_slots = threading.Semaphore(2)  # at most two checks at once
URL_RE = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/tree/(.+?))?/?$|^([\w.-]+)/([\w.-]+)$")
WORKFLOW_RE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
USES_RE = re.compile(r"""^\s*(?:-\s*)?uses:\s*['"]?([\w.-]+/[\w.-]+)(/[^@\s'"]*)?@([^\s'"#]+)""")


class CheckError(RuntimeError):
    pass


def parse_url(text):
    m = URL_RE.match((text or "").strip())
    if not m:
        raise CheckError("Paste a GitHub repo link like https://github.com/owner/repo")
    owner, name, ref = (m.group(1), m.group(2), m.group(3)) if m.group(1) else (m.group(4), m.group(5), None)
    return owner, name, ref


def start(url):
    owner, name, ref = parse_url(url)
    cid = uuid.uuid4().hex[:10]
    db.x("INSERT INTO checks(id, url, repo, status, progress, created_at) VALUES(?,?,?,?,?,?)",
         cid, url.strip(), f"{owner}/{name}", "queued", "Waiting to start…", db.now())
    threading.Thread(target=_run, args=(cid, owner, name, ref), daemon=True).start()
    return cid


def _progress(cid, msg):
    db.x("UPDATE checks SET status='running', progress=? WHERE id=?", msg, cid)


def _run(cid, owner, name, ref):
    with _slots:
        try:
            result = check(owner, name, ref, lambda m: _progress(cid, m))
            db.x("UPDATE checks SET status='done', progress=NULL, result=?, verdict=?, finished_at=? WHERE id=?",
                 json.dumps(result), result["verdict"]["level"], db.now(), cid)
        except Exception as e:
            msg = str(e) if isinstance(e, (CheckError, gh.GhError)) else f"{type(e).__name__}: {e}"
            if "Not Found" in msg or "404" in msg:
                msg = "Repo not found. Check the link, and that the repo is public."
            db.x("UPDATE checks SET status='error', error=?, finished_at=? WHERE id=?", msg[:400], db.now(), cid)


# ---------- the check ----------

def _locate(text, eco, name, version, path):
    """1-based line of the declaration, best effort."""
    lines = text.splitlines()
    q = re.escape(name)
    fname = PurePosixPath(path).name
    if fname == "package-lock.json":
        for i, l in enumerate(lines):
            if re.search(rf'"(?:.*/)?node_modules/{q}"\s*:', l):
                for j in range(i, min(i + 6, len(lines))):
                    if '"version"' in lines[j] and (not version or version in lines[j]):
                        return j + 1
        pats = [rf'"{q}"\s*:']
    elif eco == "npm":
        pats = [rf'"{q}"\s*:', rf"^{q}@", rf'^"{q}@', rf"/{q}@"]
    elif eco == "PyPI":
        pats = [rf"^\s*{q}\s*[=<>~!\[;@ ]", rf'^name = "{q}"', rf'"{q}"\s*:']
    elif eco == "Go":
        pats = [rf"(^|\s){q}\s+v"]
    else:
        pats = [q.split(":")[-1]]
    for p in pats:
        for i, l in enumerate(lines):
            if re.search(p, l, re.I):
                return i + 1
    return None


# "a malicious user / crafted malicious code" describes an ordinary bug, so only phrases that name the package as bad count
MALWARE_RE = re.compile(r"\bmalware\b|^malicious (code|package|version|release) in |embedded malicious|"
                        r"compromised (package|release|version|account|tag)|\bbackdoor", re.I)


def _malicious(vid, rec):
    """Known-bad code, not "a malicious user could…" bugs: OSV MAL- entries, CWE-506, or a summary that says so."""
    cwes = (rec.get("database_specific") or {}).get("cwe_ids") or []
    return vid.startswith("MAL-") or "CWE-506" in cwes or bool(MALWARE_RE.search(rec.get("summary") or ""))


def _ver(v):
    nums = [int(x) for x in re.findall(r"\d+", v)[:3]]
    return nums + [0] * (3 - len(nums))


def _action_hits(action, ref):
    """OSV advisories for a GitHub Action, compared against its tag ourselves."""
    req = urllib.request.Request("https://api.osv.dev/v1/query", headers={"Content-Type": "application/json"},
                                 data=json.dumps({"package": {"name": action, "ecosystem": "GitHub Actions"}}).encode())
    with urllib.request.urlopen(req, timeout=30) as r:
        vulns = json.loads(r.read()).get("vulns", [])
    exact = re.fullmatch(r"v?\d+\.\d+\.\d+", ref) is not None
    moving = re.fullmatch(r"v?\d+(\.\d+)?", ref) is not None   # v45 / v45.1 follow the newest release of that line
    cur = _ver(ref)
    out = []
    for v in vulns:
        if not (exact or moving):
            out.append((v, "unknown"))      # pinned to a branch or commit: cannot compare
            continue
        hit = False
        for a in v.get("affected", []):
            if a.get("package", {}).get("name", "").lower() != action.lower():
                continue
            for rg in a.get("ranges", []):
                lo = [0, 0, 0]
                for ev in rg.get("events", []):
                    if "introduced" in ev:
                        lo = [0, 0, 0] if ev["introduced"] == "0" else _ver(ev["introduced"])
                    elif "fixed" in ev:
                        fx = _ver(ev["fixed"])
                        # moving tag: affected when its whole major line is older than the fix
                        hit |= (lo <= cur < fx) if exact else (lo[0] <= cur[0] < fx[0])
                    elif "last_affected" in ev:
                        la = _ver(ev["last_affected"])
                        hit |= (lo <= cur <= la) if exact else (lo[0] <= cur[0] <= la[0])
        if hit:
            out.append((v, "affected"))
    return out


def _target(current, fixed_lists):
    """Lowest version that fixes every advisory: per advisory the smallest fix at or above the installed
    version (same major line first, pre-releases last), then the highest of those."""
    cur, picks = _ver(current), []
    for fl in fixed_lists:
        cands = [f for f in fl if _ver(f) >= cur]
        if not cands:
            continue
        cands.sort(key=lambda f: (_ver(f)[0] != cur[0], bool(re.search(r"[a-z]", f.lstrip("v"), re.I)), _ver(f)))
        picks.append(cands[0])
    return max(picks, key=_ver) if picks else ""


def check(owner, name, ref, progress):
    progress("Reading the repo…")
    meta = gh.api(f"repos/{owner}/{name}")
    if meta.get("private"):
        raise CheckError("This repo is private. Only public repos can be checked here.")
    branch = ref or meta.get("default_branch")
    if not branch:
        raise CheckError("This repo is empty.")
    sha = gh.head_sha(owner, name, branch)
    tree = gh.tree(owner, name, sha)
    paths = [x["path"] for x in tree.get("tree", []) if x["type"] == "blob"]
    dep_files = [p for p in paths if manifests.is_manifest(p)]
    wf_files = [p for p in paths if WORKFLOW_RE.match(p)]
    notes = []
    if tree.get("truncated"):
        notes.append("The repo is very large; GitHub returned only part of its file list.")
    if len(dep_files) + len(wf_files) > MAX_FILES:
        notes.append(f"Checked the first {MAX_FILES} dependency/workflow files only.")
    files = (wf_files + dep_files)[:MAX_FILES]

    progress(f"Downloading {len(files)} dependency and workflow files…")
    def fetch(p):
        try:
            return p, gh.file_text(owner, name, p, sha)
        except gh.GhError:
            return p, None
    with ThreadPoolExecutor(8) as ex:
        texts = dict(ex.map(fetch, files))

    present = set(dep_files)
    deps = {}  # (eco, name, version) -> {"locs": [...], "direct": bool, "dev": bool}
    for p in dep_files:
        t = texts.get(p)
        if not t or manifests.has_lock(p, present):
            continue
        for eco, n, v, direct, dev in manifests.parse(p, t):
            if eco == "docker" or not v:
                continue
            d = deps.setdefault((eco, n, v), {"locs": [], "direct": False, "dev": True})
            d["direct"] |= bool(direct)
            d["dev"] &= bool(dev)
            if len(d["locs"]) < 3:
                d["locs"].append({"file": p, "line": _locate(t, eco, n, v, p)})

    actions = {}
    for p in wf_files:
        for i, line in enumerate((texts.get(p) or "").splitlines()):
            m = USES_RE.match(line)
            if m and not m.group(1).startswith("."):
                actions.setdefault((m.group(1), m.group(3)), []).append({"file": p, "line": i + 1})

    progress(f"Checking {len(deps)} package versions against OSV.dev…")
    hits = osv.query(list(deps))
    ids = sorted({i for v in hits.values() for i in v})
    progress(f"Reading {len(ids)} advisories…")
    with ThreadPoolExecutor(12) as ex:
        recs = dict(zip(ids, ex.map(osv.vuln, ids)))
    kev = feeds.kev_set()

    def link(loc):
        return f"https://github.com/{owner}/{name}/blob/{sha}/{loc['file']}" + (f"#L{loc['line']}" if loc.get("line") else "")

    findings = []
    for (eco, n, v), vids in hits.items():
        d = deps[(eco, n, v)]
        vulns = []
        for vid in vids:
            rec, sev = recs[vid]
            if rec.get("withdrawn"):
                continue
            aliases = rec.get("aliases", [])
            vulns.append({"id": vid, "aliases": aliases[:3], "severity": sev, "summary": rec.get("summary") or (rec.get("details") or "")[:160],
                          "kev": bool({vid, *aliases} & kev), "malicious": _malicious(vid, rec),
                          "category": classify.category(rec), "fixed": osv.fixed_versions(rec, eco, n)[-2:]})
        if not vulns:
            continue
        vulns.sort(key=lambda x: (-x["malicious"], -x["kev"], -SEV_RANK.get(x["severity"], 0)))
        target = _target(v, [osv.fixed_versions(recs[x["id"]][0], eco, n) for x in vulns])
        findings.append({"ecosystem": eco, "package": n, "version": v, "direct": d["direct"], "dev": d["dev"],
                         "locations": [{**l, "url": link(l)} for l in d["locs"]],
                         "malicious": any(x["malicious"] for x in vulns), "kev": any(x["kev"] for x in vulns),
                         "worst": "MALICIOUS" if any(x["malicious"] for x in vulns)
                                  else max((x["severity"] for x in vulns), key=lambda s: SEV_RANK.get(s, 0)),
                         "fix": target, "vulns": vulns})

    progress(f"Checking {len(actions)} GitHub Actions…")
    action_findings = []
    def act(item):
        (a, r), locs = item
        try:
            return a, r, locs, _action_hits(a, r)
        except Exception:
            return a, r, locs, []
    with ThreadPoolExecutor(8) as ex:
        for a, r, locs, res in ex.map(act, list(actions.items())):
            if not res:
                continue
            vulns = [{"id": v["id"], "aliases": v.get("aliases", [])[:3], "summary": v.get("summary", ""),
                      "severity": ((v.get("database_specific") or {}).get("severity") or "UNKNOWN").upper(),
                      "malicious": _malicious(v["id"], v),
                      "state": s} for v, s in res]
            action_findings.append({"action": a, "ref": r, "pinned": "tag" if re.fullmatch(r"v?\d+(\.\d+){0,2}", r) else
                                    ("commit" if re.fullmatch(r"[0-9a-f]{40}", r) else "branch"),
                                    "locations": [{**l, "url": link(l)} for l in locs[:3]],
                                    "affected": any(x["state"] == "affected" for x in vulns),
                                    "compromised": any(x["malicious"] and x["state"] == "affected" for x in vulns), "vulns": vulns})

    findings.sort(key=lambda f: (-f["malicious"], -f["kev"], -SEV_RANK.get(f["worst"], 9 if f["worst"] == "MALICIOUS" else 0), f["dev"]))
    mal = [f for f in findings if f["malicious"]]
    bad_actions = [a for a in action_findings if a["compromised"]]
    kev_n = sum(f["kev"] for f in findings)
    crit = sum(SEV_RANK.get(f["worst"], 0) >= 4 for f in findings)
    high = sum(SEV_RANK.get(f["worst"], 0) == 3 for f in findings)
    if mal or bad_actions:
        verdict = {"level": "compromised", "title": "Compromised dependency found",
                   "detail": (f"Installs {len(mal)} package version(s) known to contain malware" if mal else "")
                   + (" and " if mal and bad_actions else "")
                   + (f"uses {len(bad_actions)} hijacked GitHub Action(s)" if bad_actions else "")
                   + ". Treat machines and CI runners that installed them as compromised: rotate their secrets, then remove or upgrade."}
    elif kev_n or crit:
        verdict = {"level": "at_risk", "title": "No malware found, but at risk",
                   "detail": f"{kev_n} package(s) with vulnerabilities exploited in the wild and {crit} with critical ones in the installed versions."}
    elif findings or any(a["affected"] for a in action_findings):
        verdict = {"level": "issues", "title": "No malware found; some known vulnerabilities",
                   "detail": f"{len(findings)} package version(s) have known vulnerabilities ({high} high). Upgrade when you can."}
    else:
        verdict = {"level": "clean", "title": "No known issues found",
                   "detail": f"None of the {len(deps)} package versions match a known vulnerability or malicious package."}

    return {
        "repo": {"owner": owner, "name": name, "url": meta.get("html_url"), "description": meta.get("description"),
                 "stars": meta.get("stargazers_count"), "pushed_at": meta.get("pushed_at"), "branch": branch, "sha": sha,
                 "language": meta.get("language"), "archived": meta.get("archived")},
        "verdict": verdict,
        "stats": {"dep_files": len(dep_files), "workflow_files": len(wf_files), "packages": len(deps),
                  "actions": len(actions), "vulnerable": len(findings), "advisories": sum(len(f["vulns"]) for f in findings),
                  "malicious": len(mal), "kev": kev_n, "critical": crit, "high": high},
        "findings": findings[:400], "actions": action_findings,
        "unpinned": sorted({f"{a}@{r}" for (a, r) in actions if not re.fullmatch(r"[0-9a-f]{40}", r)})[:50],
        "files": files[:60], "notes": notes,
    }

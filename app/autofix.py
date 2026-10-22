"""Auto-fix confirmed findings, or escalate the ones a machine should not fix.

Easy (auto-fixed): upgrading within the same major version, in a file we can edit safely
  - PyPI pinned in requirements*.txt                  -> edit the pin
  - npm direct dependency with package-lock.json      -> npm install pkg@^target --package-lock-only
  - npm transitive dependency with package-lock.json  -> package.json "overrides" + lockfile refresh
  - Go module in go.mod                               -> go get module@vtarget
  Then: re-read the changed files, ask OSV.dev whether the new version still has the advisories,
  commit on a branch "vulnwatch/fix-<pkg>-<target>" in a separate git worktree.
  AUTOFIX_MODE=dry_run keeps it local (diff on the dashboard); AUTOFIX_MODE=pr pushes and opens a PR.

Hard (escalated): major-version jumps, no fixed version yet, Go toolchain / Docker images,
other package managers, or any auto-fix attempt that fails. P0/P1 ones get an escalation mail.

Package tools run with --ignore-scripts / --package-lock-only, so no repo or package code is executed.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from . import config, db, findings, gh, mailer, manifests, osv, research
from .config import BOT_EMAIL, BOT_NAME, CLONES, DASHBOARD_URL, FIXES, ORG


class FixError(RuntimeError):
    pass


def _ver(v):
    nums = [int(x) for x in re.findall(r"\d+", (v or "").lstrip("v"))[:3]]
    return nums + [0] * (3 - len(nums))


def compatible(cur, target):
    """Same major (and same minor for 0.x): a normal, non-breaking upgrade."""
    c, t = _ver(cur), _ver(target)
    if c[0] != t[0] or (c[0] == 0 and c[1] != t[1]):
        return False
    return t >= c


def _slug(s):
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", s).strip("-")[:60]


def _locations(f):
    return db.q("SELECT manifest, version, direct FROM deps WHERE repo=? AND ecosystem=? AND name=?",
                f["repo"], f["ecosystem"], f["package"])


def plan(f):
    """-> (kind, detail, target). kind 'escalate' means a human should do it.
    The research decision (web research on the advisories) wins over the plain version rules."""
    eco, pkg, target = f["ecosystem"], f["package"], (f["target"] or "").lstrip("v")
    r = research.get(f)
    d = r["decision"] if r else {}
    major_ok = False
    if d:
        target = (d.get("target_version") or target).lstrip("v")   # the researched target, also for escalations
        if d.get("needs_human") or d.get("effort") == "large":
            return "escalate", d.get("human_reason") or "Research says this needs a developer.", target
        if d.get("code_changes_needed"):
            return "escalate", f"The fix needs code changes: {d.get('code_change_summary') or 'see the research'}", target
        if d.get("strategy") in ("no_fix_available", "replace_library", "config_mitigation", "remove_unused"):
            label = {"no_fix_available": "No fixed version exists yet", "replace_library": "The library should be replaced",
                     "config_mitigation": "Needs a configuration change", "remove_unused": "The library looks unused and can be removed"}
            return "escalate", f"{label[d['strategy']]}. Mitigation now: {d.get('mitigation_now') or 'see the research'}", target
        # research checked the breaking changes against our usage: a clean major bump may be automated
        major_ok = d.get("strategy") == "major_upgrade" and d.get("effort") == "trivial"
    if not target:
        return "escalate", "No fixed version has been published yet.", target
    if eco == "Go" and pkg == "stdlib":
        return "escalate", f"Needs a Go toolchain upgrade to {target} (Docker image / CI Go version), not a library bump.", target
    if eco not in ("PyPI", "npm", "Go"):
        return "escalate", f"{eco} fixes are not automated yet.", target
    major = [v for v in f["versions"] if not compatible(v, target)]
    if major and not major_ok:
        return "escalate", (f"Major upgrade {major[0]} → {target}: breaking changes are likely, "
                            "so a developer has to upgrade and test it."), target
    locs = _locations(f)
    if eco == "PyPI":
        if any(PurePosixPath(l["manifest"]).name.startswith("requirements") for l in locs):
            return "pip_pin", "", target
        return "escalate", "Not pinned in a requirements*.txt file (poetry/pipenv/pyproject are not automated yet).", target
    if eco == "npm":
        locks = {l["manifest"] for l in locs}
        if not locks or any(not m.endswith("package-lock.json") for m in locks):
            return "escalate", "Only npm package-lock.json projects are automated (yarn/pnpm are not yet).", target
        return ("npm_direct" if any(l["direct"] for l in locs) else "npm_override"), "", target
    if any(l["manifest"].endswith("go.mod") for l in locs):
        return "go_get", "", target
    return "escalate", "No go.mod entry found to update.", target


# ---------- applying ----------

def _sh(cmd, cwd, log, timeout=900, env=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    log.append(f"$ {' '.join(cmd)}  (exit {p.returncode})")
    if p.returncode:
        log.append((p.stderr or p.stdout)[-1500:])
        raise FixError(f"`{' '.join(cmd[:3])}` failed: {(p.stderr or p.stdout).strip().splitlines()[-1:] or ['?']}")
    return p.stdout


def _fresh_worktree(repo, branch, log):
    r = db.one("SELECT * FROM repos WHERE name=?", repo)
    base = r["tracked_branch"] or r["default_branch"]
    clone = CLONES / repo
    gh.clone_or_update(ORG, repo, base, clone)
    wt = FIXES / f"{repo}--{_slug(branch.split('/')[-1])}"
    subprocess.run(["git", "-C", str(clone), "worktree", "remove", "--force", str(wt)], capture_output=True)
    shutil.rmtree(wt, ignore_errors=True)
    subprocess.run(["git", "-C", str(clone), "worktree", "prune"], capture_output=True)
    subprocess.run(["git", "-C", str(clone), "branch", "-D", branch], capture_output=True)
    FIXES.mkdir(parents=True, exist_ok=True)
    _sh(["git", "-C", str(clone), "worktree", "add", "-b", branch, str(wt), "HEAD"], clone, log)
    return clone, wt, base


def _apply_pip(wt, f, target, log):
    rx = re.compile(rf"^(\s*{re.escape(f['package'])}(\[[^\]]*\])?\s*==\s*)([\w.]+)", re.I)
    changed = []
    for l in _locations(f):
        if not PurePosixPath(l["manifest"]).name.startswith("requirements"):
            continue
        p = wt / l["manifest"]
        lines = p.read_text().splitlines(keepends=True)
        new = [rx.sub(lambda m: m.group(1) + target, ln) for ln in lines]
        if new != lines:
            p.write_text("".join(new))
            changed.append(l["manifest"])
    if not changed:
        raise FixError("pin line not found")
    log.append(f"pinned {f['package']}=={target} in {', '.join(changed)}")
    return changed


def _npm(cmd, cwd, log):
    base = ["npm", *cmd, "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
    try:
        _sh(base, cwd, log)
    except FixError:
        log.append("retrying with --legacy-peer-deps")
        _sh(base + ["--legacy-peer-deps"], cwd, log)


def _apply_npm(wt, f, target, kind, log):
    folders = sorted({str(PurePosixPath(l["manifest"]).parent) for l in _locations(f)})
    changed = []
    for folder in folders:
        d = wt / folder
        pj = d / "package.json"
        if not pj.exists():
            continue
        spec = re.search(rf'"{re.escape(f["package"])}"\s*:\s*"([^"]*)"', pj.read_text())
        if kind == "npm_direct" and spec:
            if re.fullmatch(r"\d[\w.+-]*", spec.group(1)):   # exact pin stays an exact pin
                _npm(["install", f"{f['package']}@{target}", "--save-exact"], d, log)
            else:
                _npm(["install", f"{f['package']}@^{target}"], d, log)
        else:
            raw = pj.read_text()
            indent = len(re.search(r'\n(\s+)"', raw).group(1)) if re.search(r'\n(\s+)"', raw) else 2
            data = json.loads(raw)
            # scope to the vulnerable major only: an unscoped override would also move copies on other majors
            t = _ver(target)
            rng = f"{t[0]}.x" if t[0] else f"0.{t[1]}.x"
            data.setdefault("overrides", {})[f"{f['package']}@{rng}"] = f"^{target}"
            pj.write_text(json.dumps(data, indent=indent, ensure_ascii=False) + "\n")
            _npm(["install"], d, log)
        changed += [str(PurePosixPath(folder) / "package.json"), str(PurePosixPath(folder) / "package-lock.json")]
    if not changed:
        raise FixError("no package.json next to the lockfile")
    return [c.removeprefix("./") for c in changed]


def _apply_go(wt, f, target, log):
    folders = sorted({str(PurePosixPath(l["manifest"]).parent) for l in _locations(f) if l["manifest"].endswith("go.mod")})
    env = {**gh.git_env(), "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=mod"}
    for folder in folders:
        _sh(["go", "get", f"{f['package']}@v{target}"], wt / folder, log, env=env)
    return [str(PurePosixPath(fo) / n).removeprefix("./") for fo in folders for n in ("go.mod", "go.sum")]


def _verify(wt, f, files, log):
    """Re-read the edited manifests; OSV must report none of this finding's advisories for the new versions."""
    found = set()
    for file in files:
        p = wt / file
        if p.exists():
            found |= {(e, n, v) for e, n, v, *_ in manifests.parse(file, p.read_text())
                      if n.lower() == f["package"].lower() and v}
    # judge only copies on the major line this fix moved; copies on other majors are separate findings
    t = _ver(f["target"])
    found = {x for x in found if _ver(x[2])[0] == t[0] and (t[0] or _ver(x[2])[1] == t[1])}
    if not found:
        raise FixError("could not read the new version back from the changed files")
    hits = osv.query(sorted(found))
    ours = {v["id"] for v in f["vulns"]} | {a for v in f["vulns"] for a in v["aliases"]}
    left = {vid for ids in hits.values() for vid in ids if vid in ours}
    log.append(f"new versions: {sorted(v for *_, v in found)}; advisories left: {sorted(left) or 'none'}")
    if left:
        raise FixError(f"still affected after upgrade: {', '.join(sorted(left)[:3])}")
    return sorted({v for *_, v in found})


def _pr_body(f, target, new_versions, files):
    r = research.get(f) or {}
    d = r.get("decision") or {}
    ids = [v["id"] for v in f["vulns"]][:12]
    sev = {"CRITICAL": "🔴", "HIGH": "🟠", "MODERATE": "🟡"}.get(f["severity"], "⚪")
    lines = [
        f"## {sev} Security fix: `{f['package']}` {f['version']} → `{target}`",
        "",
        d.get("summary") or f"Fixes {f['vuln_count']} known advisories in `{f['package']}`.",
        "",
        "### Why",
        f"- **Impact on this repo:** {f['impact'] or f['problem']}",
        f"- **Severity:** {f['severity']}{' · exploited in the wild (CISA KEV)' if f['kev'] else ''}"
        + (f" · reachable from our code: {d['exploitability']}" if d.get("exploitability") else ""),
        f"- **Advisories ({f['vuln_count']}):** " + ", ".join(f"[{i}](https://osv.dev/vulnerability/{i})" for i in ids)
        + (" …" if f["vuln_count"] > len(ids) else ""),
        "",
        "### What changed",
        f"- Upgraded `{f['package']}` to {', '.join(f'`{v}`' for v in new_versions)} "
        f"({'same major version' if all(compatible(v, target) for v in f['versions']) else 'major upgrade, checked against our usage'}).",
        "- Files: " + ", ".join(f"`{x}`" for x in files),
        f"- Code changes: {d.get('code_change_summary') or 'none needed'}",
        f"- Breaking changes for this repo: {d.get('breaking_changes') or 'none expected'}",
        "",
        "### How it was checked",
        "- The changed manifest/lockfile was read back and every new version was checked on OSV.dev: none of the advisories above remain.",
        "- Package scripts were not run (`--ignore-scripts`, lockfile-only update).",
        "",
        "### Before merging",
        "- [ ] CI is green",
        "- [ ] App starts and the main flows work",
    ]
    if d.get("mitigation_now"):
        lines += ["", f"_If this cannot be merged soon:_ {d['mitigation_now']}"]
    if r.get("sources"):
        lines += ["", "### Sources"] + [f"- [{s['title'] or s['url']}]({s['url']})" for s in r["sources"][:6]]
    if not re.search(r"//(127\.0\.0\.1|localhost)", DASHBOARD_URL):   # a local dashboard link is useless to reviewers
        lines += ["", f"Full details: {DASHBOARD_URL}/issues/{f['id']}"]
    lines += ["", "_Opened automatically by VulnWatch._"]
    return "\n".join(lines)


def _open_pr(repo, wt, branch, base, title, body, log):
    """Push the fix branch and open a pull request (draft unless AUTOFIX_PR_DRAFT=false). Reuses an open PR
    for the same branch, so re-running never opens duplicates."""
    _sh(["git", "push", "--force-with-lease", "origin", f"HEAD:refs/heads/{branch}"], wt, log, env=gh.git_env())
    existing = gh.run(["pr", "list", "--repo", f"{ORG}/{repo}", "--head", branch, "--state", "open",
                       "--json", "url", "-q", ".[0].url"]).strip()
    if existing:
        log.append(f"PR already open: {existing}")
        return existing
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
        fh.write(body)
    try:
        args = ["pr", "create", "--repo", f"{ORG}/{repo}", "--base", base, "--head", branch, "--title", title, "--body-file", fh.name]
        if config.AUTOFIX_PR_DRAFT:
            args.append("--draft")
        url = gh.run(args, timeout=120).strip().splitlines()[-1]
    finally:
        os.unlink(fh.name)
    log.append(f"PR opened: {url}")
    return url


def apply(f, kind, log, open_pr=False):
    target = f["target"].lstrip("v")
    branch = f"vulnwatch/fix-{_slug(f['package'])}-{_slug(target)}"
    clone, wt, base = _fresh_worktree(f["repo"], branch, log)
    try:
        if kind == "pip_pin":
            files = _apply_pip(wt, f, target, log)
        elif kind in ("npm_direct", "npm_override"):
            files = _apply_npm(wt, f, target, kind, log)
        else:
            files = _apply_go(wt, f, target, log)
        new_versions = _verify(wt, f, files, log)

        title = f"fix(security): bump {f['package']} to {target}"
        body = _pr_body(f, target, new_versions, files)
        git = ["git", "-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}"]
        _sh(["git", "add", "-A"], wt, log)
        _sh(git + ["commit", "-q", "-m", title, "-m", body], wt, log)
        stat = _sh(["git", "diff", "--stat", "HEAD~1", "HEAD"], wt, log)
        diff = _sh(["git", "diff", "HEAD~1", "HEAD", "--", ".", ":(exclude)*lock*", ":(exclude)go.sum"], wt, log)
        diff = stat + "\n" + diff[:30000]

        pr_url, status = None, "ready"
        if open_pr:
            pr_url = _open_pr(f["repo"], wt, branch, base, title, body, log)
            status = "pr_opened"
        return {"status": status, "branch": branch, "files": files, "diff": diff, "pr_url": pr_url}
    finally:
        subprocess.run(["git", "-C", str(clone), "worktree", "remove", "--force", str(wt)], capture_output=True)
        shutil.rmtree(wt, ignore_errors=True)


def _save(f, **kw):
    cols = {"versions": json.dumps(f["versions"]), "target": f["target"], "updated_at": db.now(), **kw}
    if "files" in cols:
        cols["files"] = json.dumps(cols["files"])
    cur = db.one("SELECT id FROM fixes WHERE repo=? AND ecosystem=? AND package=?", f["repo"], f["ecosystem"], f["package"])
    if cur:
        db.x(f"UPDATE fixes SET {', '.join(k + '=?' for k in cols)} WHERE id=?", *cols.values(), cur["id"])
    else:
        cols.update(repo=f["repo"], ecosystem=f["ecosystem"], package=f["package"], created_at=db.now())
        db.x(f"INSERT INTO fixes({', '.join(cols)}) VALUES({', '.join('?' * len(cols))})", *cols.values())


def handle(f, log=print, open_pr=None):
    """open_pr: None = follow AUTOFIX_MODE; True = open a PR now (dashboard button, only offered in pr mode)."""
    if open_pr is None:
        open_pr = config.AUTOFIX_MODE == "pr"
    kind, detail, target = plan(f)
    f = {**f, "target": target}
    steps = []
    if kind != "escalate":
        try:
            res = apply(f, kind, steps, open_pr=open_pr)
            _save(f, kind=kind, reason=None, log="\n".join(steps), **res)
            log(f"  fix {f['repo']}/{f['package']}: {res['status']} ({kind}) {res['pr_url'] or ''}")
            return
        except Exception as e:
            detail = f"Auto-fix attempt failed ({kind}): {e}"
            kind = "escalate"
    _save(f, kind="escalate", status="escalated", reason=detail, log="\n".join(steps),
          branch=None, files=[], diff=None, pr_url=None)
    mailed = f["priority"] <= config.ESCALATE_MAX_PRIORITY and mailer.escalate(f, detail, research.get(f))
    log(f"  fix {f['repo']}/{f['package']}: escalated{' + mail' if mailed else ''}: {detail[:90]}")


def run(log=print, limit=None):
    if config.AUTOFIX_MODE == "off":
        log("autofix: off")
        return
    done = {(x["repo"], x["ecosystem"], x["package"], x["target"]) for x in
            db.q("SELECT * FROM fixes WHERE status IN ('ready','pr_opened','escalated')")}
    todo = [f for f in findings.build() if f["confirmed"] and f["status"] == "open"
            and (f["repo"], f["ecosystem"], f["package"], f["target"]) not in done]
    todo = todo[:limit or config.AUTOFIX_MAX_PER_RUN]
    for f in todo:
        handle(f, log=log)
    log(f"autofix: {len(todo)} finding(s) handled, mode={config.AUTOFIX_MODE}")


def fix_one(iid, log=print, open_pr=None):
    """Dashboard buttons: (re)try one finding now, optionally opening its PR."""
    f = next(f for f in findings.build() if iid in f["ids"])
    handle(f, log=log, open_pr=open_pr)

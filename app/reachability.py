"""Reachability: is the vulnerable code actually used? Hybrid, cheapest tool that can answer:

Go         govulncheck (official, builds the call graph). Per advisory:
             called   -> our code calls the vulnerable function (call path stored, with GitHub links)
             imported -> the package is imported but the vulnerable function is never called
             required -> the module is only in go.mod, its code is not used
           "imported"/"required" are proof the bug is not reachable, so those advisories leave the
           confirmed list. Standard-library advisories are only trusted when reported as called,
           because govulncheck judges stdlib by this machine's Go version, not the repo's.
npm/PyPI   symbol check: Gemini reads the advisories and names the vulnerable functions/options;
           ripgrep looks for exactly those names in files that import the library.
             symbol_used / symbol_not_used / not_imported / transitive / unknown
           Text search is not proof, so it only nudges priority (one level).
Results: `reachability` table, per repo + library, with a per-advisory map for Go.
"""
import json
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path, PurePosixPath

from google.genai import types
from pydantic import BaseModel, Field

from . import config, db, findings, gh
from .ai import SYSTEM, _usage_pattern, client
from .config import CLONES, ORG

GOVULNCHECK = shutil.which("govulncheck") or next(
    (str(p) for p in (Path.home() / ".local/bin/govulncheck", Path.home() / "go/bin/govulncheck") if p.exists()), "govulncheck")
LEVEL_RANK = {"called": 3, "imported": 2, "required": 1}


def _sha(path):
    return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def _clone(repo):
    r = db.one("SELECT * FROM repos WHERE name=?", repo)
    path = CLONES / repo
    gh.clone_or_update(ORG, repo, r["tracked_branch"] or r["default_branch"], path)
    return path


def _save(repo, eco, pkg, method, level, detail, sha):
    db.x("""INSERT INTO reachability(repo, ecosystem, package, method, level, detail, sha, created_at) VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(repo, ecosystem, package) DO UPDATE SET method=excluded.method, level=excluded.level,
              detail=excluded.detail, sha=excluded.sha, created_at=excluded.created_at""",
         repo, eco, pkg, method, level, json.dumps(detail), sha, db.now())


# ---------- Go: call graph ----------

def _govulncheck(moddir):
    env = {**gh.git_env(), "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=mod"}
    p = subprocess.run([GOVULNCHECK, "-format", "json", "./..."], cwd=moddir, capture_output=True, text=True,
                       timeout=900, env=env)
    out, dec, i, msgs = p.stdout, json.JSONDecoder(), 0, []
    while i < len(out):
        while i < len(out) and out[i].isspace():
            i += 1
        if i >= len(out):
            break
        obj, i = dec.raw_decode(out, i)
        msgs.append(obj)
    if not msgs and p.returncode:
        raise RuntimeError((p.stderr or "govulncheck failed").strip().splitlines()[-1][:200])
    return msgs


def go_repo(repo, log=print):
    """One govulncheck run per go.mod, mapped onto this repo's Go issues."""
    path = _clone(repo)
    sha = _sha(path)
    mods = sorted({d["manifest"] for d in db.q("SELECT manifest FROM deps WHERE repo=? AND ecosystem='Go' AND manifest LIKE '%go.mod'", repo)})
    ids_to = {}      # any alias -> GO id
    best = {}        # GO id -> (level, trace, moddir)
    for mf in mods:
        moddir = str(PurePosixPath(mf).parent)
        try:
            msgs = _govulncheck(path / moddir)
        except Exception as e:
            log(f"  reach {repo}/{mf}: govulncheck failed: {e}")
            continue
        for m in msgs:
            if "osv" in m:
                o = m["osv"]
                for a in [o["id"], *o.get("aliases", [])]:
                    ids_to[a] = o["id"]
            elif "finding" in m:
                f = m["finding"]
                t = f.get("trace") or [{}]
                lvl = "called" if t[0].get("function") else ("imported" if t[0].get("package") else "required")
                if LEVEL_RANK[lvl] > LEVEL_RANK.get(best.get(f["osv"], ("",))[0], 0):
                    best[f["osv"]] = (lvl, t, moddir)

    def frames(trace, moddir):
        out = []
        for fr in trace[:8]:
            name = ".".join(x for x in [fr.get("package") or fr.get("module"), (fr.get("receiver") or "").lstrip("*"), fr.get("function")] if x)
            pos = fr.get("position") or {}
            own = fr.get("module", "").endswith("/" + repo) or (not fr.get("version") and fr.get("module"))
            url = (f"https://github.com/{ORG}/{repo}/blob/{sha}/{str(PurePosixPath(moddir) / pos['filename']).removeprefix('./')}#L{pos['line']}"
                   if own and pos.get("filename") else None)
            out.append({"name": name, "file": pos.get("filename"), "line": pos.get("line"), "ours": bool(own), "url": url})
        return out

    groups = defaultdict(dict)
    for i in db.q("SELECT vuln_id, aliases, package FROM issues WHERE repo=? AND ecosystem='Go'", repo):
        ids = [i["vuln_id"], *db.jl(i["aliases"])]
        go_id = next((ids_to[a] for a in ids if a in ids_to), next((a for a in ids if a.startswith("GO-")), None))
        if go_id in best:
            lvl, trace, moddir = best[go_id]
            groups[i["package"]][i["vuln_id"]] = {"level": lvl, "go_id": go_id, "path": frames(trace, moddir) if lvl == "called" else []}
        elif i["package"] != "stdlib" and go_id in ids_to.values():
            groups[i["package"]][i["vuln_id"]] = {"level": "not_affected", "go_id": go_id, "path": []}
        else:
            # stdlib (judged by this machine's Go version) or not in the Go database: no claim
            groups[i["package"]][i["vuln_id"]] = {"level": "unknown", "go_id": go_id, "path": []}
    for pkg, per in groups.items():
        lv = [v["level"] for v in per.values()]
        top = "called" if "called" in lv else ("unknown" if "unknown" in lv else "not_called")
        _save(repo, "Go", pkg, "govulncheck", top, {"advisories": per}, sha)
    called = sum(1 for p in groups.values() for v in p.values() if v["level"] == "called")
    log(f"  reach {repo} (Go call graph): {called} advisories called, "
        f"{sum(1 for p in groups.values() for v in p.values() if v['level'] in ('imported', 'required', 'not_affected'))} not reached")


# ---------- npm / PyPI: vulnerable-symbol search ----------

class Symbols(BaseModel):
    symbols: list[str] = Field(description="Names specific to the VULNERABLE feature that code or config would contain to reach it: "
                                           "functions, methods, classes, config options (e.g. 'truetype', 'fs.deny', 'ImageResponse'). "
                                           "Never generic names every user of the library writes (types like Metadata, the default "
                                           "export, 'require', 'import'). Empty if any use of the library is exposed.")
    cli: list[str] = Field(description="Command-line ways to reach it, as written in scripts: the tool's command and risky "
                                       "flags (e.g. 'vite --host', 'vite preview'). Empty if not a CLI tool.")
    whole_library: bool = Field(description="True if just loading/using the library at all is enough to be exposed")
    note: str = Field(description="One sentence on what usage is dangerous")


def _symbols(f):
    vulns = "\n".join(f"- {v['id']}: {v['summary']}" for v in f["vulns"][:12])
    res = db.one("SELECT notes FROM research WHERE repo=? AND ecosystem=? AND package=?", f["repo"], f["ecosystem"], f["package"])
    prompt = (f"Library: {f['package']} ({f['ecosystem']})\nAdvisories:\n{vulns}\n"
              + (f"\nResearch notes:\n{res['notes'][:5000]}\n" if res else "")
              + "\nList the code-level names that reach the vulnerable code.")
    for model in config.TRIAGE_MODELS:
        try:
            from . import ai_usage
            r = ai_usage.generate("symbols", model, prompt, types.GenerateContentConfig(
                system_instruction=SYSTEM, response_mime_type="application/json", response_schema=Symbols), f["repo"], f["package"])
            if r.parsed:
                return r.parsed
        except Exception:
            continue
    return None


def _rg(path, pattern, files=None, lines=False):
    args = ["rg", "-n" if lines else "-l", "--no-heading", "-e", pattern, "--max-filesize", "500K",
            "-g", "!**/node_modules/**", "-g", "!**/vendor/**", "-g", "!*.lock", "-g", "!*lock.json", "-g", "!**/dist/**",
            "-g", "!**/*.min.js"]
    p = subprocess.run(args + (files or ["."]), cwd=path, capture_output=True, text=True, timeout=60)
    return [l.removeprefix("./") for l in p.stdout.splitlines() if l]


def symbol_check(f, log=print):
    path = _clone(f["repo"])
    sha = _sha(path)
    importers = _rg(path, _usage_pattern(f["ecosystem"], f["package"]))[:200]
    direct = bool(db.one("SELECT max(direct) d FROM deps WHERE repo=? AND ecosystem=? AND name=?",
                         f["repo"], f["ecosystem"], f["package"])["d"])
    detail = {"importers": importers[:20], "symbols": [], "hits": [], "note": ""}
    s = _symbols(f) if importers or direct else None
    cli_hits = []
    if s and s.cli:
        # dev servers and build tools are reached from scripts, Dockerfiles and CI, not from imports
        cmds = sorted({c.split()[0] for c in s.cli if c.split()})
        flags = sorted({t for c in s.cli for t in c.split()[1:] if t.startswith("-") or t.isalpha()})
        pat = r"\b(" + "|".join(re.escape(c) for c in cmds) + r")\b" + (r"[^\n]*(" + "|".join(re.escape(x) for x in flags) + r")" if flags else "")
        args = ["rg", "-n", "--no-heading", "-e", pat, "-g", "package.json", "-g", "*Dockerfile*", "-g", "*.sh", "-g", "*.yml",
                "-g", "*.yaml", "-g", "Makefile", "-g", "!**/node_modules/**", "."]
        for h in subprocess.run(args, cwd=path, capture_output=True, text=True, timeout=60).stdout.splitlines()[:8]:
            m = re.match(r"^(.+?):(\d+):(.*)$", h)
            if m:
                fp = m.group(1).removeprefix("./")
                cli_hits.append({"file": fp, "line": int(m.group(2)), "text": m.group(3).strip()[:160],
                                 "url": f"https://github.com/{ORG}/{f['repo']}/blob/{sha}/{fp}#L{m.group(2)}"})
    if cli_hits:
        level = "cli_used"
        detail.update(symbols=(s.symbols + s.cli)[:12], note=s.note, hits=cli_hits)
    elif not importers:
        level = "not_imported" if direct else "transitive"
        detail["note"] = ("Listed as a dependency but no source file imports it (likely a CLI or build tool)." if direct
                          else "Pulled in by another library; our code never imports it directly.")
    else:
        if not s:
            level, detail["note"] = "unknown", "Could not work out the vulnerable functions."
        else:
            detail.update(symbols=s.symbols[:12], note=s.note, whole_library=s.whole_library)
            names = sorted({x.split(".")[-1].strip("()") for x in s.symbols if len(x.split(".")[-1].strip("()")) >= 3})
            if s.whole_library or not names:
                level = "symbol_used"
                detail["hits"] = [{"file": p, "line": None, "text": "imports the library", "url": f"https://github.com/{ORG}/{f['repo']}/blob/{sha}/{p}"}
                                  for p in importers[:5]]
            else:
                hits = _rg(path, r"\b(" + "|".join(re.escape(n) for n in names) + r")\b", files=importers, lines=True)
                detail["hits"] = []
                for h in hits[:12]:
                    m = re.match(r"^(.+?):(\d+):(.*)$", h)
                    if m:
                        detail["hits"].append({"file": m.group(1), "line": int(m.group(2)), "text": m.group(3).strip()[:160],
                                               "url": f"https://github.com/{ORG}/{f['repo']}/blob/{sha}/{m.group(1)}#L{m.group(2)}"})
                level = "symbol_used" if detail["hits"] else "symbol_not_used"
    _save(f["repo"], f["ecosystem"], f["package"], "symbol search", level, detail, sha)
    log(f"  reach {f['repo']}/{f['package']}: {level}" + (f" ({len(detail['hits'])} hits)" if detail["hits"] else ""))


def get(repo, eco, pkg):
    r = db.one("SELECT * FROM reachability WHERE repo=? AND ecosystem=? AND package=?", repo, eco, pkg)
    return {**r, "detail": db.jl(r["detail"], {})} if r else None


def run(log=print, force=False):
    tracked = [r["name"] for r in db.q("SELECT name FROM repos WHERE tracked=1")]
    # Go: one call-graph run per repo whenever its commit changed
    for repo in tracked:
        if not db.one("SELECT 1 FROM issues WHERE repo=? AND ecosystem='Go' AND status IN ('open','in_progress')", repo):
            continue
        prev = db.one("SELECT max(created_at) t FROM reachability WHERE repo=? AND method='govulncheck'", repo)["t"]
        last = db.one("SELECT last_scan FROM repos WHERE name=?", repo)["last_scan"]
        if not force and prev and last and prev > last:
            continue
        try:
            go_repo(repo, log=log)
        except Exception as e:
            log(f"  reach {repo} (Go): ERROR {e}")
    # npm / PyPI: symbol search for open, actionable findings
    done = 0
    for f in findings.build():
        if f["ecosystem"] not in ("npm", "PyPI") or f["status"] not in ("open", "in_progress") or f["backlog"]:
            continue
        cur = get(f["repo"], f["ecosystem"], f["package"])
        if cur and not force:
            continue
        try:
            symbol_check(f, log=log)
            done += 1
        except Exception as e:
            log(f"  reach {f['repo']}/{f['package']}: ERROR {e}")
    log(f"reachability: Go call graphs refreshed, {done} symbol check(s)")

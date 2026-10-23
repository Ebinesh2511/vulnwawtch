"""Gemini steps, run per finding group (repo + library + version), never per single vuln.

1. Context (no AI): shallow clone of the tracked branch, ripgrep for where the library is used,
   the manifest lines that declare it, and (npm) which direct dependency pulls it in.
2. Triage (flash): is the repo really affected, impact for us, quick guard, fix. Short JSON.
3. Guide (pro): full step-by-step fix guide in markdown, only when affected != "no".
Results are stored on every issue in the group, so each group costs tokens once.
"""
import json
import re
import subprocess
import time
from typing import Literal

from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from . import config, db, gh
from .config import CLONES, ORG, SEV_RANK

_client = None


def client():
    global _client
    if _client is None:
        _client = genai.Client()  # reads GEMINI_API_KEY
    return _client


class Triage(BaseModel):
    affected: Literal["yes", "maybe", "no"] = Field(description="Is this repo exposed, given how it uses the library?")
    confidence: Literal["high", "medium", "low"]
    problem: str = Field(description="One sentence: what the vulnerability is, plain words")
    impact: str = Field(description="1-2 sentences: what could happen to THIS repo/product, based on the usage found")
    guard_now: str = Field(description="One sentence: a workaround until upgraded, or 'No safe workaround; upgrade.'")
    fix: str = Field(description="One sentence: the fix, e.g. 'Upgrade pillow to 11.3.0 in requirements.txt'")
    target_version: str = Field(description="Lowest version that fixes ALL listed vulns, or '' if unknown")
    used_in: list[str] = Field(description="Up to 5 file paths where the library is used")


# Note: a sentence calling the tagged sections "untrusted data" makes Gemini block the request (BlockedReason.OTHER).
SYSTEM = """You are an application security engineer at GUVI reviewing a vulnerable dependency in one repository.
Be concrete and brief. Base impact on the usage shown; if usage is not visible
(transitive dependency, build tool), say so and judge by how the parent package uses it.
Say "no" only when the vulnerable code path clearly cannot be reached (e.g. dev-only tool not shipped, or the
affected feature is not used). Prefer "maybe" over guessing."""

GUIDE_PROMPT = """Write a step-by-step fix guide in GitHub-flavoured markdown for a developer on this repo.
It must work when followed exactly. Sections, in this order:

## Summary
Two or three lines: what is wrong, how bad, what to do.

## Is this repo affected?
What the usage search found and why it matters here.

## Fix steps
Numbered steps with exact commands and exact file edits for THIS repo's package manager and file paths
(e.g. requirements.txt, package.json + lockfile, go.mod). If the library is transitive, show how to bump the
direct dependency or add an override/resolution (npm `overrides`, pnpm/yarn resolutions, `go get`, pip constraint).
Target the lowest version that fixes all listed vulnerabilities.

## Code changes needed
Breaking changes between the current and target version that touch the usage shown, with before/after snippets.
Write "None expected" if none.

## Verify
Commands to install, build and test, and how to confirm the vulnerable version is gone.

## Rollback
How to undo safely.

## References
Advisory links.

Do not invent APIs or versions. If unsure about a detail, say what to check."""


# ---------- context (no AI) ----------

PY_IMPORT = {"pillow": "PIL", "opencv-python": "cv2", "opencv-python-headless": "cv2", "pyyaml": "yaml",
             "beautifulsoup4": "bs4", "scikit-learn": "sklearn", "python-dotenv": "dotenv", "pymysql": "pymysql",
             "protobuf": "google.protobuf", "python-jose": "jose", "pyjwt": "jwt", "python-multipart": "multipart"}


def _usage_pattern(eco, name):
    e = re.escape
    if eco == "npm":
        return rf"""(from\s+['"]{e(name)}(/[^'"]*)?['"]|require\(\s*['"]{e(name)}(/[^'"]*)?['"]|import\s+['"]{e(name)}(/[^'"]*)?['"]|import\(\s*['"]{e(name)})"""
    if eco == "PyPI":
        mod = PY_IMPORT.get(name, name.replace("-", "_"))
        return rf"^\s*(from|import)\s+{e(mod)}\b"
    if eco == "Go":
        return rf'"{e(name)}(/[^"]*)?"'
    if eco == "tech":
        return rf"\b{e(name)}\b"
    return e(name.split(":")[-1].split("/")[-1])


def _rg(path, pattern, globs, limit=40):
    args = ["rg", "-n", "--no-heading", "-m", "3", "-C", "1", "-e", pattern, "--max-filesize", "500K"]
    for g in globs:
        args += ["-g", g]
    p = subprocess.run(args + ["."], cwd=path, capture_output=True, text=True, timeout=60)
    lines = p.stdout.splitlines()
    files = sorted({m.group(1) for l in lines if (m := re.match(r"^(.+?):\d+:", l))})
    return "\n".join(lines[:limit * 3])[:6000], files


def _npm_parents(path, manifest, name):
    """Which packages in package-lock.json depend on `name` (to bump the right direct dep)."""
    if not manifest or not manifest.endswith("package-lock.json"):
        return []
    try:
        lock = json.loads((path / manifest).read_text())
    except (OSError, ValueError):
        return []
    parents = set()
    for key, info in (lock.get("packages") or {}).items():
        if name in (info.get("dependencies") or {}) or name in (info.get("peerDependencies") or {}):
            parents.add(key.rsplit("node_modules/", 1)[-1] or "(root package.json)")
    return sorted(parents)[:10]


def gather(repo, eco, name, manifest):
    r = db.one("SELECT * FROM repos WHERE name=?", repo)
    branch = r["tracked_branch"] or r["default_branch"]
    path = CLONES / repo
    gh.clone_or_update(ORG, repo, branch, path)

    if eco == "Go" and name == "stdlib":
        usage, files = "(Go standard library: used by every Go binary built with this toolchain)", []
    else:
        globs = ["!**/node_modules/**", "!**/vendor/**", "!*.lock", "!*lock.json", "!*.sum", "!**/dist/**",
                 "!**/*.min.js"]
        if eco == "tech":
            globs += ["*Dockerfile*", "*.yml", "*.yaml", "*.conf", "*.toml", "*.json", "*.env*", "*.go", "*.ts", "*.js"]
        usage, files = _rg(path, _usage_pattern(eco, name), globs)

    decl = ""
    if manifest and (path / manifest).exists():
        text = (path / manifest).read_text(errors="replace").splitlines()
        key = name.split(":")[-1]
        hits = [i for i, l in enumerate(text) if re.search(rf"""(^|["'\s/=]){re.escape(key)}(["'\s=@:<>~^]|$)""", l)][:5]
        lines = sorted({i for h in hits for i in range(max(0, h - 1), min(len(text), h + 2))})
        decl = "\n".join(f"{i + 1}: {text[i]}" for i in lines)[:2500]
    parents = _npm_parents(path, manifest, name) if eco == "npm" else []
    return {"branch": branch, "usage": usage or "(no direct usage found by search)", "files": files[:20],
            "manifest": decl, "parents": parents}


def _vuln_block(issues, max_items=12):
    out = []
    for i in issues[:max_items]:
        rec = db.one("SELECT data FROM osv_vulns WHERE id=?", i["vuln_id"])
        rec = json.loads(rec["data"]) if rec else {}
        refs = [r["url"] for r in rec.get("references", [])][:4]
        out.append(f"- {i['vuln_id']} ({', '.join(db.jl(i['aliases']))}) severity={i['severity']}"
                   f"{' KNOWN-EXPLOITED(KEV)' if i['kev'] else ''}\n  summary: {i['summary']}\n"
                   f"  fixed in: {', '.join(db.jl(i['fixed_versions'])) or 'n/a'}\n"
                   f"  details: {(rec.get('details') or '')[:700]}\n  refs: {' '.join(refs)}")
    if len(issues) > max_items:
        rest = issues[max_items:]
        out.append(f"- plus {len(rest)} more ({', '.join(i['vuln_id'] for i in rest)}); all fixed in: "
                   f"{', '.join(sorted({v for i in rest for v in db.jl(i['fixed_versions'])}))}")
    return "\n".join(out)


# ---------- Gemini ----------

def _gen(models, prompt, schema=None, tries_per_model=2, step="ai", repo=None, package=None):
    """Try each model in order; a block, empty reply or API error moves on to the next try/model.
    The daily token budget stops it at once (no retries)."""
    from . import ai_usage
    cfg = types.GenerateContentConfig(system_instruction=SYSTEM)
    if schema:
        cfg.response_mime_type, cfg.response_schema = "application/json", schema
    errors = []
    for model in models:
        for attempt in range(tries_per_model):
            try:
                r = ai_usage.generate(step, model, prompt, cfg, repo, package)
                if r.prompt_feedback and r.prompt_feedback.block_reason:
                    raise RuntimeError(f"blocked ({r.prompt_feedback.block_reason})")
                out = r.parsed if schema else r.text
                if not out:
                    raise RuntimeError("empty response")
                return out
            except ai_usage.BudgetExceeded:
                raise
            except Exception as e:
                errors.append(f"{model}: {str(e)[:120]}")
                time.sleep(3 * (attempt + 1))
    raise RuntimeError("All Gemini models failed: " + " | ".join(errors[-3:]))


def analyze_group(repo, eco, name, version, log=print):
    issues = db.q("""SELECT * FROM issues WHERE repo=? AND ecosystem=? AND package=? AND IFNULL(version,'')=?
                     AND status NOT IN ('fixed','ignored')""", repo, eco, name, version or "")
    if not issues:
        return
    issues.sort(key=lambda i: (-i["kev"], -SEV_RANK.get(i["severity"], 0)))
    manifest = issues[0]["manifest"]
    ctx = gather(repo, eco, name, manifest)

    direct = db.one("SELECT max(direct) d FROM deps WHERE repo=? AND ecosystem=? AND name=?", repo, eco, name)
    facts = (f"Repository: {ORG}/{repo} (branch {ctx['branch']})\n"
             f"Library: {name} {version or ''} ({eco}), declared in {manifest or 'n/a'}, "
             f"{'direct' if direct and direct['d'] else 'transitive'} dependency\n"
             + (f"Pulled in by: {', '.join(ctx['parents'])}\n" if ctx["parents"] else "")
             + f"\n<vulns>\n{_vuln_block(issues)}\n</vulns>\n"
             f"\n<manifest>\n{ctx['manifest']}\n</manifest>\n"
             f"\n<usage files=\"{', '.join(ctx['files'])}\">\n{ctx['usage']}\n</usage>\n")

    rc = db.one("SELECT method, detail FROM reachability WHERE repo=? AND ecosystem=? AND package=?", repo, eco, name)
    if rc and rc["method"] == "govulncheck":
        adv = db.jl(rc["detail"], {}).get("advisories", {})
        paths = [f"{vid}: " + " -> ".join(fr["name"] for fr in reversed(a["path"]))
                 for vid, a in adv.items() if a["level"] == "called" and vid in {i["vuln_id"] for i in issues}]
        if paths:
            facts += ("\n<call_graph tool=\"govulncheck\">\nThe Go call graph proves our code calls the vulnerable function:\n"
                      + "\n".join(paths[:6]) + "\n</call_graph>\n")
    triage = _gen(config.TRIAGE_MODELS, facts + "\nAssess this finding.", Triage, step="triage", repo=repo, package=name)
    guide = None
    if triage.affected != "no":
        guide = _gen(config.GUIDE_MODELS, facts + f"\nTriage so far: {triage.model_dump_json()}\n\n" + GUIDE_PROMPT, step="guide", repo=repo, package=name)

    for i in issues:
        db.x("""UPDATE issues SET triage=?, guide=?, ai_state='done', updated_at=?,
                status=CASE WHEN ?='no' AND status='open' THEN 'not_affected' ELSE status END,
                note=CASE WHEN ?='no' THEN 'AI: not reachable in this repo' ELSE note END
                WHERE id=?""",
             triage.model_dump_json(), guide, db.now(), triage.affected, triage.affected, i["id"])
    try:
        from . import evidence
        evidence.store(repo, eco, name, version, manifest)
    except Exception as e:
        log(f"  evidence {repo}/{name}: {e}")
    log(f"  ai {repo}/{name}: affected={triage.affected} ({len(issues)} vuln(s))")


def run(log=print, limit=None):
    from . import ai_usage
    limit = limit or config.AI_MAX_PER_RUN
    groups = db.q(f"""SELECT repo, ecosystem, package, IFNULL(version,'') version, max(kev) kev,
                     max(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'KEV' THEN 4 WHEN 'HIGH' THEN 3 ELSE 1 END) sev
                     FROM issues WHERE ai_state='pending' AND backlog=0 AND status IN ('open','in_progress') AND {db.TRACKED}
                     GROUP BY repo, ecosystem, package, IFNULL(version,'')
                     ORDER BY min(IFNULL(priority, 3)), kev DESC, sev DESC LIMIT ?""", limit)
    if not groups:
        log("ai: nothing pending")
        return
    for g in groups:
        try:
            ai_usage.check_budget()
        except ai_usage.BudgetExceeded as e:
            log(f"ai: stopped: {e}")
            break
        try:
            analyze_group(g["repo"], g["ecosystem"], g["package"], g["version"], log=log)
        except Exception as e:
            db.x("""UPDATE issues SET ai_state='error', note=? WHERE repo=? AND ecosystem=? AND package=?
                    AND IFNULL(version,'')=? AND ai_state='pending'""",
                 f"{type(e).__name__}: {str(e)[:200]}", g["repo"], g["ecosystem"], g["package"], g["version"])
            log(f"  ai {g['repo']}/{g['package']}: ERROR {e}")
    left = db.one("SELECT count(DISTINCT repo||ecosystem||package||IFNULL(version,'')) n FROM issues "
                  "WHERE ai_state='pending' AND backlog=0")["n"]
    log(f"ai: {len(groups)} group(s) analyzed, {left} still pending")


def analyze_issue(iid, log=print):
    """Dashboard button: analyze one issue's group now, even if it is backlog or already done."""
    i = db.one("SELECT * FROM issues WHERE id=?", iid)
    analyze_group(i["repo"], i["ecosystem"], i["package"], i["version"] or "", log=log)

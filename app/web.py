"""Dashboard (FastAPI + Jinja + Alpine). Pages render a shell; lists come from the /api/* JSON routes."""
import fnmatch
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt

from . import ai, autofix, checker, classify, config, db, findings, gh, jobs, mailer, research

EMAIL_RE = re.compile(r"[^@\s,;]+@[^@\s,;]+\.[A-Za-z]{2,}")
HERE = Path(__file__).parent

app = FastAPI(title="VulnWatch", docs_url="/api/docs", redoc_url=None)  # /docs is the user documentation page
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
tpl = Jinja2Templates(directory=HERE / "templates")
tpl.env.filters["jl"] = db.jl
# CommonMark handles lists and code blocks inside list items; html=False escapes any raw HTML in AI output
_md = MarkdownIt("commonmark", {"html": False}).enable("table")
tpl.env.filters["md"] = lambda s: _md.render(s or "")
tpl.env.globals.update(cfg=config, jobs=jobs.state,
                       # cache-buster: changes whenever the CSS/JS is rebuilt, no restart needed
                       asset_v=lambda: int(max((HERE / "static" / f).stat().st_mtime for f in ("app.css", "vw.js"))),
                       rules_missing=lambda: not db.one("SELECT 1 FROM rules LIMIT 1"))


@app.on_event("startup")
def _start():
    db.init()
    jobs.start_scheduler()


def page(request, name, **ctx):
    return tpl.TemplateResponse(request, name, ctx)


def labels():
    return {"cats": {k: v[0] for k, v in classify.CATS.items()},
            "ranks": {k: v[1] for k, v in classify.CATS.items()},
            "prios": {n: {"code": c, "label": l, "hint": h} for n, (c, l, h) in classify.PRIORITY.items()}}


# ---------- dashboard + findings ----------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return page(request, "dashboard.html", **labels())


@app.get("/api/findings")
def api_findings():
    last = db.one("SELECT job, finished, ok FROM runs WHERE finished IS NOT NULL ORDER BY id DESC LIMIT 1")
    return {"findings": findings.build(), "job": jobs.state["job"], "last_run": last,
            "autofix_mode": config.AUTOFIX_MODE,
            "repos": db.one("SELECT count(*) n FROM repos WHERE tracked=1")["n"],
            "libraries": db.one(f"SELECT count(DISTINCT ecosystem||name) n FROM deps WHERE {db.TRACKED}")["n"]}


@app.get("/api/findings/{iid}/guide")
def api_guide(iid: int):
    i = db.one("SELECT guide FROM issues WHERE id=?", iid)
    return {"html": _md.render(i["guide"]) if i and i["guide"] else ""}


@app.get("/api/findings/{iid}/research")
def api_research(iid: int):
    f = next((f for f in findings.build() if iid in f["ids"]), None)
    r = research.get(f) if f else None
    return {"html": _md.render(r["notes"]) if r else "", "queries": r["queries"] if r else []}


@app.post("/api/findings/{iid}/research")
def api_research_run(iid: int):
    def work(log):
        f = next(f for f in findings.build() if iid in f["ids"])
        research.research(f, log=log, force=True)
    return {"started": jobs.run(f"research #{iid}", work)}


@app.post("/api/findings/{iid}/status")
def api_status(iid: int, status: str = Form(...)):
    if status in ("open", "in_progress", "fixed", "ignored", "not_affected"):
        i = db.one("SELECT * FROM issues WHERE id=?", iid)
        db.x("UPDATE issues SET status=?, updated_at=? WHERE repo=? AND ecosystem=? AND package=?",
             status, db.now(), i["repo"], i["ecosystem"], i["package"])
    return {"ok": True}


@app.post("/api/findings/{iid}/fix")
def api_fix(iid: int):
    return {"started": jobs.run(f"fix #{iid}", lambda log: autofix.fix_one(iid, log=log))}


@app.post("/api/findings/{iid}/pr")
def api_pr(iid: int):
    """Open the PR for a prepared fix. Only allowed in AUTOFIX_MODE=pr."""
    if config.AUTOFIX_MODE != "pr":
        return JSONResponse({"error": "Pull requests are off. Set AUTOFIX_MODE=pr in .env and restart."}, 400)
    return {"started": jobs.run(f"pr #{iid}", lambda log: autofix.fix_one(iid, log=log, open_pr=True))}


@app.post("/api/findings/{iid}/analyze")
def api_analyze(iid: int):
    return {"started": jobs.run(f"ai #{iid}", lambda log: (ai.analyze_issue(iid, log=log), classify.run(log=log)))}


# ---------- all vulnerabilities ----------

@app.get("/issues", response_class=HTMLResponse)
def issues(request: Request):
    return page(request, "issues.html", open_id=0, **labels())


@app.get("/issues/{iid}", response_class=HTMLResponse)
def issue_link(request: Request, iid: int):
    """Mail and dashboard links: the list with this vulnerability open in the side drawer."""
    return page(request, "issues.html", open_id=iid, **labels())


@app.get("/api/issues")
def api_issues():
    rows = db.q(f"""SELECT id, vuln_id, aliases, summary, severity, kev, in_feed, repo, ecosystem, package, version,
                    fixed_versions, published, status, backlog, ai_state, category, priority,
                    json_extract(triage, '$.affected') affected
                    FROM issues WHERE {db.TRACKED} ORDER BY id""")
    for r in rows:
        r["aliases"] = db.jl(r["aliases"])[:4]
        r["fixed"] = db.jl(r["fixed_versions"])[-2:]
        del r["fixed_versions"]
    return {"issues": rows}


# ---------- repos ----------

@app.get("/repos", response_class=HTMLResponse)
def repos(request: Request):
    rows = db.q("SELECT r.*, (SELECT count(*) FROM deps d WHERE d.repo=r.name) deps FROM repos r")
    prios = {}
    for f in findings.build():
        if f["confirmed"]:
            prios.setdefault(f["repo"], []).append(f["priority"])
    for r in rows:
        p = prios.get(r["name"], [])
        r["open"], r["p"] = len(p), [p.count(n) for n in range(4)]
        r["private"] = bool(r["private"])
        r.pop("tags", None)
    return page(request, "repos.html", rows=rows)


@app.post("/api/repos/track")
def api_track(names: str = Form(...), tracked: int = Form(...)):
    """names: comma separated. Re-tracking clears last_sha so the next run scans the repo fresh."""
    for n in [n for n in names.split(",") if n]:
        db.x("UPDATE repos SET tracked=?, last_sha=CASE WHEN ?=1 AND tracked=0 THEN NULL ELSE last_sha END "
             "WHERE name=?", int(bool(tracked)), int(bool(tracked)), n)
    return {"ok": True}


@app.get("/api/repos/{name}/branches")
def api_branches(name: str):
    """Default branch first, the rest A–Z. Our own fix branches are left out."""
    r = db.one("SELECT default_branch, tracked_branch FROM repos WHERE name=?", name)
    try:
        names = [b for b in gh.branches(config.ORG, name) if not b.startswith("vulnwatch/")]
    except gh.GhError as e:
        return {"branches": [r["tracked_branch"]], "error": str(e)}
    names = sorted({b for b in [*names, r["tracked_branch"]] if b}, key=lambda b: (b != r["default_branch"], b.lower()))
    return {"branches": names, "default": r["default_branch"]}


@app.post("/api/repos/{name}/branch")
def api_branch(name: str, branch: str = Form(...)):
    # a new branch forces a rescan
    db.x("UPDATE repos SET tracked_branch=?, last_sha=CASE WHEN ?<>tracked_branch THEN NULL ELSE last_sha END "
         "WHERE name=?", branch.strip(), branch.strip(), name)
    return {"ok": True}


@app.get("/repos/{name}/deps", response_class=HTMLResponse)
def repo_deps(request: Request, name: str, q: str = ""):
    rows = db.q("SELECT * FROM deps WHERE repo=? AND name LIKE ? ORDER BY direct DESC, ecosystem, name LIMIT 2000",
                name, f"%{q}%")
    return page(request, "deps.html", name=name, rows=rows, q=q)


# ---------- routing + mail ----------

@app.get("/routing", response_class=HTMLResponse)
def routing(request: Request):
    repos = [r["name"] for r in db.q("SELECT name FROM repos WHERE tracked=1 ORDER BY name")]
    return page(request, "routing.html", repos=repos, rules=db.q("SELECT * FROM rules ORDER BY pattern"),
                smtp=mailer.smtp_ready())


@app.post("/api/rules")
def add_rule(pattern: str = Form(...), emails: str = Form(...), min_severity: str = Form("HIGH"), label: str = Form("")):
    good = [e.strip() for e in re.split(r"[,\s;]+", emails) if EMAIL_RE.fullmatch(e.strip())]
    if not pattern.strip() or not good:
        return JSONResponse({"error": "Add a repo pattern and at least one valid email."}, 400)
    rid = db.x("INSERT INTO rules(pattern, emails, min_severity, label) VALUES(?,?,?,?)",
               pattern.strip(), ",".join(good), min_severity if min_severity in ("HIGH", "CRITICAL") else "HIGH",
               label.strip() or None)
    return {"rule": db.one("SELECT * FROM rules WHERE id=?", rid)}


@app.post("/api/rules/{rid}/delete")
def delete_rule(rid: int):
    db.x("DELETE FROM rules WHERE id=?", rid)
    return {"ok": True}


@app.post("/api/mail/test")
def test_mail(to: str = Form(...)):
    if not EMAIL_RE.fullmatch(to.strip()):
        return {"ok": False, "message": "That email address doesn't look valid."}
    if not mailer.smtp_ready():
        return {"ok": False, "message": "SMTP is not configured yet."}
    try:
        mailer.send(to.strip(), "VulnWatch test mail", "SMTP works. — VulnWatch", "<p>SMTP works. — VulnWatch</p>")
        return {"ok": True, "message": f"Test mail sent to {to.strip()}"}
    except Exception as e:
        return {"ok": False, "message": f"Test failed: {type(e).__name__}: {e}"}


@app.get("/mails", response_class=HTMLResponse)
def mails(request: Request):
    rows = db.q("SELECT id, issue_id, recipient, subject, status, error, created_at, sent_at FROM mails "
                "ORDER BY id DESC LIMIT 300")
    return page(request, "mails.html", rows=rows, smtp=mailer.smtp_ready(),
                previews=sum(r["status"] in ("preview", "error") for r in rows))


@app.get("/mails/{mid}", response_class=HTMLResponse)
def mail_view(request: Request, mid: int):
    return page(request, "mail.html", m=db.one("SELECT * FROM mails WHERE id=?", mid), smtp=mailer.smtp_ready())


@app.post("/api/mails/{mid}/send")
def mail_send(mid: int):
    return {"ok": mailer.smtp_ready() and mailer.deliver(mid)}


@app.post("/api/mails/send-previews")
def mail_send_all():
    if not mailer.smtp_ready():
        return {"started": False}
    ids = [r["id"] for r in db.q("SELECT id FROM mails WHERE status IN ('preview','error')")]
    return {"started": jobs.run("mail send", lambda log: log(f"sent {sum(mailer.deliver(i) for i in ids)}/{len(ids)}"))}


# ---------- feeds ----------

SEV_IN_TITLE = re.compile(r"\s*\((CRITICAL|HIGH|MEDIUM|MODERATE|LOW)(?:\s+([\d.]+))?\)\s*:?", re.I)


@app.get("/feeds", response_class=HTMLResponse)
def feed_page(request: Request):
    # which feed ids touch a tracked repo (via an issue's id or aliases)
    touch = {}
    for i in db.q(f"SELECT vuln_id, aliases, repo FROM issues WHERE {db.TRACKED}"):
        for a in [i["vuln_id"], *db.jl(i["aliases"])]:
            touch.setdefault(a, set()).add(i["repo"])
    rows = []
    for f in db.q("SELECT * FROM feed_items ORDER BY date DESC LIMIT 1000"):
        title, sev, score = f["title"], (f["severity"] or "").split(" ")[0].upper(), None
        m = SEV_IN_TITLE.search(title)
        if m:
            sev, score = m.group(1).upper(), m.group(2)
            title = (title[:m.start()] + (":" if m.group(0).rstrip().endswith(":") else "") + title[m.end():]).strip()
        title = re.sub(r"^\[KEV\]\s*", "", title)
        if f["kev"]:
            sev = "KEV"
        ids = db.jl(f["ids"])
        rows.append({"title": title, "link": f["link"], "date": f["date"], "summary": (f["summary"] or "")[:280], "ids": ids,
                     "sources": db.jl(f["sources"]), "sev": {"MEDIUM": "MODERATE"}.get(sev, sev) or "",
                     "score": score, "kev": bool(f["kev"]),
                     "repos": sorted({r for i in ids for r in touch.get(i, ())})})
    return page(request, "feeds.html", rows=rows)


# ---------- check any public repo ----------

@app.get("/check", response_class=HTMLResponse)
def check_page(request: Request):
    return page(request, "check.html", check_id="", **labels())


@app.get("/check/{cid}", response_class=HTMLResponse)
def check_result_page(request: Request, cid: str):
    return page(request, "check.html", check_id=cid if re.fullmatch(r"[0-9a-f]{10}", cid) else "", **labels())


@app.post("/api/check")
def api_check_start(url: str = Form(...)):
    try:
        return {"id": checker.start(url)}
    except checker.CheckError as e:
        return JSONResponse({"error": str(e)}, 400)


@app.get("/api/check/{cid}")
def api_check(cid: str):
    c = db.one("SELECT * FROM checks WHERE id=?", cid)
    if not c:
        return JSONResponse({"error": "Check not found"}, 404)
    c["result"] = json.loads(c["result"]) if c["result"] else None
    return c


@app.get("/api/checks")
def api_checks():
    return {"checks": db.q("SELECT id, url, repo, status, verdict, created_at FROM checks ORDER BY created_at DESC LIMIT 15")}


# ---------- docs ----------

DOC = HERE.parent / "docs" / "HOW-IT-WORKS.md"


def _slug(text):
    """GitHub-style heading id, so the doc's own #links work: lower case, drop punctuation, spaces → '-'."""
    return re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", text.lower()).strip())


@app.get("/docs", response_class=HTMLResponse)
def docs(request: Request):
    """The end-to-end doc, rendered from docs/HOW-IT-WORKS.md on every request (edit the file, reload)."""
    tokens = _md.parse(DOC.read_text())
    if tokens and tokens[0].type == "heading_open" and tokens[0].tag == "h1":
        tokens = tokens[3:]  # the page header already shows the title; keep one <h1> per page
    toc = []
    for i, t in enumerate(tokens):
        if t.type == "heading_open":
            text = tokens[i + 1].content
            t.attrSet("id", _slug(text))
            t.attrSet("class", "scroll-target-doc")
            if t.tag in ("h2", "h3"):
                toc.append({"level": int(t.tag[1]), "id": _slug(text), "text": text})
        elif t.type == "fence" and t.info.strip() == "mermaid":
            t.type, t.content = "html_block", f'<figure class="doc-diagram"><pre class="mermaid-src" hidden>{html.escape(t.content)}</pre></figure>'
    body = _md.renderer.render(tokens, _md.options, {})
    body = body.replace('href="docs/HOW-IT-WORKS.md"', 'href="/docs"')  # a self-link in the doc → this page
    return page(request, "docs.html", body=body, toc=toc, updated=DOC.stat().st_mtime)


# ---------- runs + jobs ----------

SUMMARY = re.compile(r"^(repos|scan|feeds|match|ai|evidence|classify|autofix|mail): (.*)$")


def _age(ts):
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(ts.replace("Z", "+00:00"))).total_seconds()
    except (AttributeError, ValueError):
        return 0


@app.get("/runs", response_class=HTMLResponse)
def runs(request: Request):
    rows = db.q("SELECT * FROM runs ORDER BY id DESC LIMIT 100")
    for r in rows:
        lines = (r["log"] or "").splitlines()
        r["summary"] = [m.group(0) for l in lines if (m := SUMMARY.match(l.strip()))]
        r["counts"] = {k: sum(f": {k}" in l or f"={k}" in l for l in lines)
                       for k in ("ready", "escalated", "ERROR")}
        live = not r["finished"] and jobs.state["job"] == r["job"]
        r["state"] = "ok" if r["ok"] else ("failed" if r["finished"] else ("running" if live or _age(r["started"]) < 1800
                                                                           else "stale"))
        r["type"] = r["job"].split(" ")[0]
    return page(request, "runs.html", rows=rows)


@app.post("/api/runs/{rid}/fail")
def run_fail(rid: int):
    db.x("UPDATE runs SET finished=?, ok=0, log=IFNULL(log,'') || ? WHERE id=? AND finished IS NULL",
         db.now(), "\nMarked failed from the Runs page (process no longer running).", rid)
    return {"ok": True}


@app.post("/api/run/{job}")
def run_job(job: str):
    return {"started": job in jobs.JOBS and jobs.run(job)}


@app.get("/api/job")
def job_status():
    last = db.one("SELECT job, finished, ok FROM runs WHERE finished IS NOT NULL ORDER BY id DESC LIMIT 1")
    return {"job": jobs.state["job"], "line": (jobs.state["lines"] or [""])[-1].strip(), "last": last}

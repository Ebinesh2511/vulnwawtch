"""Turn (feeds + dependency index) into issues. No AI here: OSV exact-version checks only.

An issue is "actionable" (gets AI triage + mail) when it is serious enough
(severity >= MIN_SEVERITY, or listed in CISA KEV) AND recent (in a feed this window,
in KEV, or published within RECENT_DAYS). Everything else is kept as backlog for the dashboard.
"""
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from . import config, db, feeds, osv
from .config import SEV_RANK

# Server products we may run as Docker images. Matched only against image names, never language words
# ("php", "python" appear in thousands of unrelated CVE titles). Packages are covered by OSV instead.
TECH_WORDS = {"nginx", "httpd", "tomcat", "postgres", "postgresql", "mysql", "mariadb", "redis", "valkey",
              "mongodb", "mongo", "memcached", "elasticsearch", "opensearch", "rabbitmq", "kafka", "haproxy",
              "traefik", "caddy", "envoy", "minio", "keycloak", "grafana", "prometheus", "jenkins", "wordpress",
              "livekit", "coturn", "ffmpeg", "clickhouse", "openssl"}
ALIASES = {"postgres": "postgresql", "mongo": "mongodb"}


def _recent(published):
    if not published:
        return False
    try:
        d = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError:
        return False
    return d >= datetime.now(timezone.utc) - timedelta(days=config.RECENT_DAYS)


def run(log=print):
    deps = db.q("SELECT repo, ecosystem, name, version, manifest FROM deps "
                f"WHERE version IS NOT NULL AND ecosystem != 'docker' AND {db.TRACKED}")
    where = defaultdict(list)
    for d in deps:
        where[(d["ecosystem"], d["name"], d["version"])].append(d)

    hits = osv.query(list(where))
    kev, in_feed = feeds.kev_set(), feeds.feed_ids()
    min_rank = SEV_RANK.get(config.MIN_SEVERITY, 3)
    present, new, actionable = set(), 0, 0

    for pkg, vids in hits.items():
        eco, name, version = pkg
        for vid in vids:
            rec, sev = osv.vuln(vid)
            if rec.get("withdrawn"):
                continue
            ids = {vid, *rec.get("aliases", [])}
            is_kev = bool(ids & kev)
            feed_hit = bool(ids & set(in_feed))
            serious = SEV_RANK.get(sev, 0) >= min_rank or is_kev
            backlog = int(not (serious and (is_kev or feed_hit or _recent(rec.get("published")))))
            fixed = osv.fixed_versions(rec, eco, name)
            for d in where[pkg]:
                present.add((vid, d["repo"], name))
                existed = db.one("SELECT id, status FROM issues WHERE vuln_id=? AND repo=? AND package=?",
                                 vid, d["repo"], name)
                if existed:
                    # a re-introduced vuln reopens; otherwise refresh the flags
                    db.x("""UPDATE issues SET severity=?, kev=?, in_feed=?, backlog=MIN(backlog, ?), version=?,
                            status=CASE WHEN status='fixed' THEN 'open' ELSE status END, updated_at=? WHERE id=?""",
                         sev, int(is_kev), int(feed_hit), backlog, version, db.now(), existed["id"])
                    continue
                db.x("""INSERT INTO issues(vuln_id, repo, ecosystem, package, version, manifest, aliases, summary,
                        severity, kev, in_feed, published, fixed_versions, backlog, ai_state, created_at, updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     vid, d["repo"], eco, name, version, d["manifest"], json.dumps(sorted(ids - {vid})),
                     rec.get("summary") or (rec.get("details") or "")[:200], sev, int(is_kev), int(feed_hit),
                     rec.get("published"), json.dumps(fixed), backlog,
                     "skipped" if backlog else "pending", db.now(), db.now())
                new += 1
                actionable += 1 - backlog

    # auto-close: open package issues that no longer show up (dependency upgraded or removed)
    closed = 0
    # untracked repos are not scanned, so their issues are left as they are
    for i in db.q("SELECT id, vuln_id, repo, package FROM issues "
                  f"WHERE status IN ('open','in_progress') AND ecosystem != 'tech' AND {db.TRACKED}"):
        if (i["vuln_id"], i["repo"], i["package"]) not in present:
            db.x("UPDATE issues SET status='fixed', note='Auto: no longer detected on tracked branch', "
                 "updated_at=? WHERE id=?", db.now(), i["id"])
            closed += 1

    adv = _tech_advisories(kev)
    log(f"match: {sum(len(v) for v in hits.values())} vuln hits, {new} new issue(s) "
        f"({actionable} actionable), {closed} auto-fixed, {adv} tech advisories")


def _tech_advisories(kev):
    """Feed items that name a product we run (docker image / framework) but no package matched.
    Created as 'tech' issues; Gemini triage decides if they really apply."""
    images = defaultdict(set)
    for d in db.q(f"SELECT repo, name FROM deps WHERE ecosystem='docker' AND {db.TRACKED}"):
        base = d["name"].split("/")[-1]
        images[d["repo"]] |= {base, base.split("-")[0], ALIASES.get(base, base)}
    repos = db.q("SELECT name FROM repos WHERE tracked=1")
    made = 0
    for f in db.q("SELECT * FROM feed_items"):
        ids = set(db.jl(f["ids"]))
        if not (f["kev"] or ids & kev or (f["severity"] or "").split(" ")[0] in ("CRITICAL", "HIGH", "KEV")):
            continue
        words = set(re.findall(r"[a-z][a-z0-9+-]+", f["title"].lower()))
        words |= {ALIASES[w] for w in words if w in ALIASES}
        for r in repos:
            match = TECH_WORDS & words & images[r["name"]]
            if not match:
                continue
            # already matched through a package for this repo
            if ids and any(db.one("SELECT 1 FROM issues WHERE repo=? AND (vuln_id=? OR aliases LIKE ?)",
                                  r["name"], i, f'%"{i}"%') for i in ids):
                continue
            tech = sorted(match)[0]
            vid = sorted(ids)[0] if ids else f["key"][:120]
            if db.one("SELECT 1 FROM issues WHERE vuln_id=? AND repo=? AND package=?", vid, r["name"], tech):
                continue
            db.x("""INSERT INTO issues(vuln_id, repo, ecosystem, package, version, manifest, aliases, summary,
                    severity, kev, in_feed, published, fixed_versions, backlog, ai_state, created_at, updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,'pending',?,?)""",
                 vid, r["name"], "tech", tech, None, None, json.dumps(sorted(ids - {vid})), f["title"],
                 "KEV" if f["kev"] else ((f["severity"] or "UNKNOWN").split(" ")[0]), int(bool(f["kev"] or ids & kev)),
                 1, f["date"], "[]", db.now(), db.now())
            made += 1
    return made

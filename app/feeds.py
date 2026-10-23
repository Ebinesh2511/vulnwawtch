"""Pull the RSS/advisory feeds (reuses ../vulnfeed/vulnfeed.py) into the feed_items and kev tables."""
import importlib.util
import json
import re
from datetime import datetime, timedelta, timezone

from . import config, db
from .config import FEEDS_JSON

_spec = importlib.util.spec_from_file_location("vulnfeed", FEEDS_JSON.parent / "vulnfeed.py")
vulnfeed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vulnfeed)

GHSA_RE = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}", re.I)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def refresh(log=print):
    since = datetime.now(timezone.utc) - timedelta(days=config.FEED_DAYS)
    sources = json.loads(FEEDS_JSON.read_text())["sources"]
    items = vulnfeed.collect(sources, since)
    with db.conn() as c:
        for it in items:
            text = f"{it['title']} {it['link']} {it['summary']}"
            ids = sorted(set(it["cves"]) | {m.group(0).upper() for m in GHSA_RE.finditer(text)})
            key = it["link"] or it["title"]
            c.execute("""INSERT INTO feed_items(key, title, link, date, summary, ids, sources, kev, severity, seen_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?)
                         ON CONFLICT(key) DO UPDATE SET ids=excluded.ids, sources=excluded.sources, kev=excluded.kev""",
                      (key, it["title"], it["link"], it["date"].isoformat() if it["date"] else None,
                       it["summary"], json.dumps(ids), json.dumps(it["sources"]), int(it["kev"]),
                       it["severity"], db.now()))
    refresh_kev()
    log(f"feeds: {len(items)} items in last {config.FEED_DAYS}d")
    return len(items)


def refresh_kev():
    data = json.loads(vulnfeed.fetch(KEV_URL, timeout=60))
    with db.conn() as c:
        c.executemany("INSERT OR REPLACE INTO kev(cve, added, name) VALUES(?,?,?)",
                      [(v["cveID"], v.get("dateAdded"), v.get("vulnerabilityName")) for v in data["vulnerabilities"]])


def feed_ids():
    """Every CVE/GHSA id mentioned by a feed item in the window -> list of feed titles."""
    out = {}
    for r in db.q("SELECT title, link, ids FROM feed_items"):
        for i in db.jl(r["ids"]):
            out.setdefault(i, []).append({"title": r["title"], "link": r["link"]})
    return out


def kev_set():
    return {r["cve"] for r in db.q("SELECT cve FROM kev")}

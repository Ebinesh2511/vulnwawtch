"""SQLite storage. One short-lived connection per call; WAL so the web UI and jobs don't block."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS repos (
  name TEXT PRIMARY KEY,
  default_branch TEXT,
  tracked_branch TEXT,
  tracked INTEGER DEFAULT 1,
  private INTEGER DEFAULT 0,
  language TEXT,
  pushed_at TEXT,
  last_sha TEXT,
  last_scan TEXT,
  scan_error TEXT,
  tags TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS deps (
  repo TEXT, ecosystem TEXT, name TEXT, version TEXT, manifest TEXT, direct INTEGER,
  PRIMARY KEY (repo, ecosystem, name, version, manifest)
);
CREATE INDEX IF NOT EXISTS deps_pkg ON deps(ecosystem, name);

CREATE TABLE IF NOT EXISTS feed_items (
  key TEXT PRIMARY KEY, title TEXT, link TEXT, date TEXT, summary TEXT,
  ids TEXT, sources TEXT, kev INTEGER, severity TEXT, seen_at TEXT
);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, added TEXT, name TEXT);

CREATE TABLE IF NOT EXISTS osv_vulns (
  id TEXT PRIMARY KEY, data TEXT, severity TEXT, published TEXT, fetched_at TEXT
);

CREATE TABLE IF NOT EXISTS issues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vuln_id TEXT, repo TEXT, ecosystem TEXT, package TEXT, version TEXT, manifest TEXT,
  aliases TEXT, summary TEXT, severity TEXT, kev INTEGER, in_feed INTEGER,
  published TEXT, fixed_versions TEXT,
  backlog INTEGER DEFAULT 0,
  status TEXT DEFAULT 'open',          -- open | in_progress | fixed | ignored | not_affected
  note TEXT,
  triage TEXT,                          -- Gemini JSON
  guide TEXT,                           -- Gemini markdown
  ai_state TEXT DEFAULT 'pending',      -- pending | done | skipped | error
  created_at TEXT, updated_at TEXT,
  UNIQUE (vuln_id, repo, package)
);

CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT,          -- glob on repo name, e.g. placement-* or *
  emails TEXT,           -- comma separated
  min_severity TEXT DEFAULT 'HIGH',
  label TEXT
);

CREATE TABLE IF NOT EXISTS mails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_key TEXT,        -- repo|ecosystem|package|version: one mail per library finding, not per vuln
  issue_id INTEGER,      -- representative issue (link target)
  recipient TEXT, subject TEXT, body TEXT, html TEXT,
  status TEXT,           -- preview | sent | error
  error TEXT, created_at TEXT, sent_at TEXT,
  UNIQUE (group_key, recipient)
);

CREATE TABLE IF NOT EXISTS fixes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo TEXT, ecosystem TEXT, package TEXT, versions TEXT, target TEXT,
  kind TEXT,             -- pip_pin | npm_direct | npm_override | go_get | escalate
  status TEXT,           -- ready (dry run) | pr_opened | failed | escalated
  reason TEXT, branch TEXT, files TEXT, diff TEXT, pr_url TEXT, log TEXT,
  created_at TEXT, updated_at TEXT,
  UNIQUE (repo, ecosystem, package)
);

CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT, started TEXT, finished TEXT, log TEXT, ok INTEGER
);
"""


TRACKED = "repo IN (SELECT name FROM repos WHERE tracked=1)"  # SQL filter: only repos you chose to monitor


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with conn() as c:
        # early mails table had no group_key and was never written to: rebuild it
        cols = [r[1] for r in c.execute("PRAGMA table_info(mails)")]
        if cols and "group_key" not in cols:
            c.execute("DROP TABLE mails")
        c.executescript(SCHEMA)
        # columns added after the first release
        for table, col, decl in [("issues", "category", "TEXT"), ("issues", "priority", "INTEGER"),
                                 ("issues", "dev_only", "INTEGER DEFAULT 0"), ("issues", "evidence", "TEXT"),
                                 ("deps", "dev", "INTEGER DEFAULT 0")]:
            if col not in [r[1] for r in c.execute(f"PRAGMA table_info({table})")]:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def q(sql, *args):
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]


def one(sql, *args):
    rows = q(sql, *args)
    return rows[0] if rows else None


def x(sql, *args):
    with conn() as c:
        cur = c.execute(sql, args)
        return cur.lastrowid


def jl(s, default=None):
    try:
        return json.loads(s) if s else (default if default is not None else [])
    except (TypeError, ValueError):
        return default if default is not None else []

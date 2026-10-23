"""Attack type + fix priority for every issue. Deterministic, no AI.

Attack type comes from the advisory's CWE ids (GitHub advisories carry them), falling back to
keywords in the summary/details (Go and PYSEC records usually have no CWE).

Priority:
  P0  Fix today      remote takeover class (code exec, auth bypass, injection, memory corruption)
                     that ships to production and is HIGH+, or anything known exploited in production
  P1  Fix this week  server-side reach (SSRF, file access, smuggling…) HIGH+, any CRITICAL,
                     or takeover class that is only in dev/build tooling
  P2  Plan in sprint other HIGH+ (DoS, XSS, leaks…) or MODERATE takeover/server-side class
  P3  Watch          the rest
AI verdict "maybe" lowers by one level (not for known-exploited); "no" sends it to P3.
"""
import json
import re

from . import db
from .config import SEV_RANK

# key: (label, impact rank: 1 = worst)
CATS = {
    "rce":       ("Remote code execution", 1),
    "auth":      ("Auth / access-control bypass", 1),
    "injection": ("Injection (SQL / command)", 1),
    "memory":    ("Memory corruption", 1),
    "ssrf":      ("SSRF: server reaches internal network", 2),
    "file":      ("File read/write (path traversal, XXE)", 2),
    "smuggling": ("Request smuggling / header injection", 2),
    "proto":     ("Prototype pollution", 2),
    "crypto":    ("TLS / crypto / signature weakness", 3),
    "xss":       ("XSS / client-side injection", 3),
    "leak":      ("Information disclosure", 3),
    "redirect":  ("Open redirect / CSRF", 4),
    "dos":       ("Denial of service / crash", 4),
    "other":     ("Other", 5),
}

CWE = {
    "rce": [94, 95, 96, 502, 434, 1336, 917, 470, 829, 15],
    "injection": [77, 78, 88, 89, 90, 91, 643, 943, 74, 1236],
    "auth": [287, 288, 290, 294, 306, 284, 285, 639, 862, 863, 347, 345, 384, 798, 521, 522, 613, 620, 640, 269, 266, 732, 346, 693, 915],
    "memory": [119, 120, 121, 122, 787, 788, 416, 415, 190, 191, 125, 843, 824],
    "ssrf": [918, 441],
    "file": [22, 23, 24, 35, 36, 73, 59, 61, 552, 538, 611, 427, 377, 367],
    "smuggling": [444, 113, 93, 436, 1286],
    "proto": [1321],
    "crypto": [295, 297, 326, 327, 328, 330, 338, 310, 916, 208, 203],
    "xss": [79, 80, 83, 87, 116, 1004, 1021, 942, 451],
    "leak": [200, 201, 209, 212, 359, 532, 524, 538, 1295, 497],
    "redirect": [601, 352, 1385],
    "dos": [400, 770, 789, 1333, 674, 834, 835, 407, 776, 409, 1050, 405, 369, 476, 248, 755, 617, 1284, 703],
}
# generic CWEs (20 input validation, 183/184 allow/deny lists, 697 comparison) are left out on purpose:
# they say nothing about impact, so the advisory text decides instead
CWE_CAT = {}
for _cat, _ids in CWE.items():
    for _i in _ids:
        CWE_CAT.setdefault(f"CWE-{_i}", _cat)

KEYWORDS = [  # checked in this order, first hit wins
    ("rce", r"remote code execution|arbitrary code|code execution|\bRCE\b|execute arbitrary|deserializ|template injection"),
    ("injection", r"command injection|sql injection|\bSQLi\b|shell injection|argument injection|os command|ldap injection"),
    ("auth", r"authentication bypass|auth(entication|orization)? bypass|unauthori[sz]ed|access control|privilege escalation|impersonat|signature (verification|bypass)|bypass .*(auth|permission)"),
    ("memory", r"buffer overflow|heap overflow|out-of-bounds write|use[- ]after[- ]free|memory corruption|double free|integer overflow"),
    ("ssrf", r"\bSSRF\b|server-side request"),
    ("file", r"path traversal|directory traversal|arbitrary file|file (read|write|disclosure)|\bXXE\b|symlink|zip slip"),
    ("smuggling", r"smuggl|header injection|CRLF|response splitting"),
    ("proto", r"prototype pollution"),
    ("crypto", r"certificate|\bTLS\b|\bSSL\b|cryptograph|timing attack|weak (cipher|hash|random)"),
    ("xss", r"cross[- ]site scripting|\bXSS\b|HTML injection|content injection"),
    ("leak", r"information (disclosure|leak|exposure)|sensitive (data|information)|leak|exposes?|exposure"),
    ("redirect", r"open redirect|\bCSRF\b|cross-site request forgery"),
    ("dos", r"denial of service|\bDoS\b|ReDoS|infinite loop|excessive (memory|cpu|allocation)|resource exhaustion|panic|crash|out of memory|stack exhaustion|hang"),
]

PRIORITY = {
    0: ("P0", "Fix today", "Remote takeover risk in production"),
    1: ("P1", "Fix this week", "Server-side reach or critical"),
    2: ("P2", "Plan in sprint", "Lower-impact but real"),
    3: ("P3", "Watch", "Low impact or not reachable"),
}


def category(rec, summary=""):
    cwes = (rec.get("database_specific") or {}).get("cwe_ids") or []
    hits = [CWE_CAT[c] for c in cwes if c in CWE_CAT]
    if hits:
        return min(hits, key=lambda c: CATS[c][1])  # worst impact among its CWEs
    text = f"{rec.get('summary', '')} {summary} {(rec.get('details') or '')[:1500]}"
    for cat, pat in KEYWORDS:
        if re.search(pat, text, re.I):
            return cat
    return "other"


def priority(cat, severity, kev, dev_only, affected):
    rank = CATS[cat][1]
    sev = SEV_RANK.get(severity, 0)
    if kev and not dev_only:
        p = 0
    elif rank == 1 and sev >= 3 and not dev_only:
        p = 0
    elif (rank <= 2 and sev >= 3) or sev >= 4 or (rank == 1 and dev_only):
        p = 1
    elif sev >= 3 or (rank <= 2 and sev >= 2):
        p = 2
    else:
        p = 3
    if affected == "no":
        p = 3
    elif affected == "maybe" and not kev:
        p = min(3, p + 1)
    return p


NOT_REACHED = ("imported", "required", "not_affected")       # govulncheck verdicts
WEAK_NOT_USED = ("symbol_not_used", "not_imported")           # symbol-search verdicts


def reach_level(r, vuln_id):
    """Per-advisory reachability: Go has one verdict per advisory, symbol search one per library."""
    if not r:
        return None
    method, level, detail = r
    if method == "govulncheck":
        return (detail.get("advisories", {}).get(vuln_id) or {}).get("level")
    return level


def run(log=print):
    dev = {}
    for d in db.q("SELECT repo, ecosystem, name, min(IFNULL(dev,0)) dev_only FROM deps GROUP BY repo, ecosystem, name"):
        dev[(d["repo"], d["ecosystem"], d["name"])] = d["dev_only"]
    recs = {r["id"]: json.loads(r["data"]) for r in db.q("SELECT id, data FROM osv_vulns")}
    reach = {(r["repo"], r["ecosystem"], r["package"]): (r["method"], r["level"], db.jl(r["detail"], {}))
             for r in db.q("SELECT * FROM reachability")}
    counts, promoted = [0, 0, 0, 0], 0
    with db.conn() as c:
        for i in c.execute("SELECT id, vuln_id, aliases, repo, ecosystem, package, summary, severity, kev, triage, "
                           "backlog, ai_state FROM issues").fetchall():
            rec = recs.get(i["vuln_id"], {})
            if not (rec.get("database_specific") or {}).get("cwe_ids"):
                # Go/PYSEC records: borrow CWEs from a cached GHSA alias when there is one
                for a in db.jl(i["aliases"]):
                    if a in recs and (recs[a].get("database_specific") or {}).get("cwe_ids"):
                        rec = {**rec, "database_specific": recs[a]["database_specific"]}
                        break
            cat = category(rec, i["summary"] or "")
            dev_only = dev.get((i["repo"], i["ecosystem"], i["package"]), 0)
            affected = db.jl(i["triage"], {}).get("affected")
            r = reach_level(reach.get((i["repo"], i["ecosystem"], i["package"])), i["vuln_id"])
            sev = i["severity"]
            if r == "called" and sev in ("UNKNOWN", None):
                sev = "HIGH"   # Go's database has no scores; a proven call is treated as high
            if r == "called" and i["backlog"] and SEV_RANK.get(sev, 0) >= 2:
                # older advisory, but the call graph proves our code reaches it: make it actionable
                c.execute("UPDATE issues SET backlog=0, ai_state=CASE WHEN ai_state='skipped' THEN 'pending' ELSE ai_state END "
                          "WHERE id=?", (i["id"],))
                promoted += 1
            p = priority(cat, sev, i["kev"], dev_only, affected)
            if r in NOT_REACHED:
                p = 3                      # call graph proves the vulnerable function is never called
            elif r in WEAK_NOT_USED:
                p = min(3, p + 1)          # text search: vulnerable names not found, a hint, not proof
            c.execute("UPDATE issues SET category=?, priority=?, dev_only=?, reach=? WHERE id=?", (cat, p, dev_only, r, i["id"]))
            counts[p] += 1
    log("classify: " + ", ".join(f"P{n}={counts[n]}" for n in range(4)) + (f", {promoted} called advisories moved out of backlog" if promoted else ""))

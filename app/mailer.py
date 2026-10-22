"""Routing rules -> short alert mails. One mail per (library finding, recipient), never per single vuln.

A finding is mailed when Gemini triage says affected = yes|maybe, it is actionable (not backlog),
and still open. MAIL_MODE=dry_run stores the mail as a preview; MAIL_MODE=send delivers via SMTP.
"""
import fnmatch
import html
import smtplib
import ssl
from email.message import EmailMessage

from . import config, db
from .config import DASHBOARD_URL, SEV_RANK

GROUP_SQL = """SELECT repo, ecosystem, package, IFNULL(version,'') version FROM issues
               WHERE ai_state='done' AND backlog=0 AND status IN ('open','in_progress') AND repo IN (SELECT name FROM repos WHERE tracked=1)
               AND json_extract(triage, '$.affected') IN ('yes','maybe')
               GROUP BY repo, ecosystem, package, IFNULL(version,'')"""


def group_key(g):
    return f"{g['repo']}|{g['ecosystem']}|{g['package']}|{g['version']}"


def _issues(g):
    rows = db.q("""SELECT * FROM issues WHERE repo=? AND ecosystem=? AND package=? AND IFNULL(version,'')=?
                   AND status IN ('open','in_progress') AND backlog=0""",
                g["repo"], g["ecosystem"], g["package"], g["version"])
    rows.sort(key=lambda i: (-i["kev"], -SEV_RANK.get(i["severity"], 0), i["vuln_id"]))
    return rows


def top_severity(issues):
    if any(i["kev"] for i in issues):
        return "CRITICAL"
    return max((i["severity"] for i in issues), key=lambda s: SEV_RANK.get(s, 0))


def recipients(repo, severity):
    out = set()
    for r in db.q("SELECT * FROM rules"):
        if fnmatch.fnmatch(repo, r["pattern"]) and SEV_RANK.get(severity, 0) >= SEV_RANK.get(r["min_severity"], 3):
            out |= {e.strip().lower() for e in r["emails"].split(",") if e.strip()}
    return sorted(out)


def compose(g, issues):
    lead = issues[0]
    t = db.jl(lead["triage"], {})
    sev = top_severity(issues)
    kev = any(i["kev"] for i in issues)
    ids = [a for i in issues for a in ([i["vuln_id"]] + db.jl(i["aliases"])) if a.startswith("CVE-")] or \
          [i["vuln_id"] for i in issues]
    ids = list(dict.fromkeys(ids))
    link = f"{DASHBOARD_URL}/issues/{lead['id']}"
    where = f"{g['repo']} › {lead['manifest'] or g['ecosystem']} › {g['package']} {g['version']}".strip()
    target = t.get("target_version") or ""

    subject = (f"[{sev}{' · EXPLOITED' if kev else ''}] {g['package']} {g['version']} in {g['repo']}: "
               f"{len(issues)} vuln{'s' if len(issues) > 1 else ''}"
               + (f", upgrade to {target}" if target else ""))

    rows = [
        ("Problem", t.get("problem", lead["summary"])),
        ("Where", where + (f" (used in {', '.join(t['used_in'][:3])})" if t.get("used_in") else "")),
        ("Impact for us", t.get("impact", "")),
        ("Guard now", t.get("guard_now", "")),
        ("Fix", t.get("fix", "")),
    ]
    fx = db.one("SELECT * FROM fixes WHERE repo=? AND ecosystem=? AND package=?", g["repo"], g["ecosystem"], g["package"])
    if fx and fx["status"] == "pr_opened":
        rows.append(("Auto-fix", f"Pull request ready to review: {fx['pr_url']}"))
    elif fx and fx["status"] == "ready":
        rows.append(("Auto-fix", f"Prepared on branch {fx['branch']} (dry run, not pushed). See the dashboard."))
    elif fx and fx["status"] == "escalated":
        rows.append(("Auto-fix", f"Not possible: {fx['reason']}"))
    more = ", ".join(ids[:6]) + (f" +{len(ids) - 6} more" if len(ids) > 6 else "")
    affected = {"yes": "Affected", "maybe": "Possibly affected"}.get(t.get("affected"), "")

    text = "\n".join([
        f"{sev}{' · KNOWN EXPLOITED (CISA KEV)' if kev else ''} · {affected}",
        "",
        *[f"{k.upper()}: {v}" for k, v in rows],
        "",
        f"Advisories: {more}",
        f"Step-by-step fix guide: {link}",
        "",
        "— VulnWatch (automated). Reply to this mail if this looks wrong.",
    ])

    color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c"}.get(sev, "#64748b")
    cell = "padding:6px 10px;vertical-align:top;border-bottom:1px solid #eee"
    trs = "".join(
        f'<tr><td style="{cell};color:#64748b;white-space:nowrap;font-size:12px;text-transform:uppercase">{k}</td>'
        f'<td style="{cell}{";background:#fef2f2;font-weight:600" if k == "Impact for us" else ""}'
        f'{";color:#166534;font-weight:600" if k == "Fix" else ""}">{html.escape(v)}</td></tr>'
        for k, v in rows)
    body_html = f"""<div style="font-family:-apple-system,Segoe UI,Arial,sans-serif;font-size:14px;color:#0f172a;max-width:640px">
<p><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-weight:700">{sev}</span>
{'<span style="background:#000;color:#fff;padding:2px 8px;border-radius:4px;margin-left:4px">🔥 KNOWN EXPLOITED</span>' if kev else ''}
<span style="color:#64748b;margin-left:6px">{affected}</span></p>
<table style="border-collapse:collapse;width:100%">{trs}</table>
<p style="font-size:12px;color:#64748b">Advisories: {html.escape(more)}</p>
<p><a href="{html.escape(link)}" style="background:#0f172a;color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none;display:inline-block">Open step-by-step fix guide →</a></p>
<p style="font-size:12px;color:#94a3b8">VulnWatch (automated). Reply to this mail if this looks wrong.</p></div>"""
    return subject, text, body_html


def smtp_ready():
    return bool(config.SMTP_HOST and config.SMTP_FROM)


def send(to, subject, text, body_html):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = config.SMTP_FROM, to, subject
    msg.set_content(text)
    msg.add_alternative(body_html, subtype="html")
    if config.SMTP_TLS == "ssl":
        s = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, context=ssl.create_default_context(), timeout=30)
    else:
        s = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30)
        if config.SMTP_TLS == "starttls":
            s.starttls(context=ssl.create_default_context())
    with s:
        if config.SMTP_USER:
            s.login(config.SMTP_USER, config.SMTP_PASS)
        s.send_message(msg)


def deliver(mail_id):
    m = db.one("SELECT * FROM mails WHERE id=?", mail_id)
    try:
        send(m["recipient"], m["subject"], m["body"], m["html"])
        db.x("UPDATE mails SET status='sent', sent_at=?, error=NULL WHERE id=?", db.now(), mail_id)
        return True
    except Exception as e:
        db.x("UPDATE mails SET status='error', error=? WHERE id=?", f"{type(e).__name__}: {e}"[:300], mail_id)
        return False


def escalate(f, reason):
    """Mail the routed leads that a finding needs a developer (auto-fix not possible). Once per target."""
    sev = "CRITICAL" if f["kev"] else f["severity"]
    to = recipients(f["repo"], sev)
    if not to:
        return False
    key = f"escalate|{f['repo']}|{f['ecosystem']}|{f['package']}|{f['target']}"
    pcode = f"P{f['priority']}"
    subject = (f"[ESCALATION · {pcode}{' · EXPLOITED' if f['kev'] else ''}] {f['package']} in {f['repo']} "
               f"needs a manual fix" + (f": {f['version']} → {f['target']}" if f["target"] else ""))
    link = f"{DASHBOARD_URL}/issues/{f['id']}"
    decl = next((e for e in f["evidence"] if e["kind"] in ("declared", "locked")), None)
    rows = [
        ("Why a human", reason),
        ("Problem", f["problem"] or ""),
        ("Impact for us", f["impact"] or ""),
        ("Guard now", f["guard"] or ""),
        ("Fix", f["fix"] or (f"Upgrade to {f['target']}" if f["target"] else "No fixed version yet; apply the guard")),
        ("Where", f"{f['repo']} › {decl['file']}:{decl['hit']}  {decl['lines'][decl['hit'] - decl['start']][1].strip()}"
         if decl else f"{f['repo']} › {f['manifest'] or ''}"),
    ]
    ids = list(dict.fromkeys(a for v in f["vulns"] for a in [v["id"], *v["aliases"]] if a.startswith(("CVE-", "GHSA-"))))
    more = ", ".join(ids[:6]) + (f" +{len(ids) - 6} more" if len(ids) > 6 else "")
    text = "\n".join([f"{pcode} · {sev} · auto-fix not possible, please assign a developer", "",
                      *[f"{k.upper()}: {v}" for k, v in rows], "", f"Advisories: {more}",
                      f"Step-by-step guide: {link}" + (f"\nCode: {decl['url']}" if decl else ""), "",
                      "— VulnWatch (automated)."])
    cell = "padding:6px 10px;vertical-align:top;border-bottom:1px solid #eee"
    trs = "".join(
        f'<tr><td style="{cell};color:#64748b;white-space:nowrap;font-size:12px;text-transform:uppercase">{k}</td>'
        f'<td style="{cell}{";background:#fff7ed;font-weight:600" if k == "Why a human" else ""}'
        f'{";background:#fef2f2;font-weight:600" if k == "Impact for us" else ""}">{html.escape(v)}</td></tr>'
        for k, v in rows)
    body_html = f"""<div style="font-family:-apple-system,Segoe UI,Arial,sans-serif;font-size:14px;color:#0f172a;max-width:640px">
<p><span style="background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px;font-weight:700">ESCALATION · {pcode}</span>
<span style="color:#64748b;margin-left:6px">{html.escape(sev)} · auto-fix not possible, please assign a developer</span></p>
<table style="border-collapse:collapse;width:100%">{trs}</table>
<p style="font-size:12px;color:#64748b">Advisories: {html.escape(more)}</p>
<p><a href="{html.escape(link)}" style="background:#0f172a;color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none;display:inline-block">Open fix guide →</a>
{f'&nbsp;<a href="{html.escape(decl["url"])}" style="color:#2563eb">View code on GitHub</a>' if decl else ''}</p>
<p style="font-size:12px;color:#94a3b8">VulnWatch (automated).</p></div>"""
    made = False
    for r in to:
        if db.one("SELECT 1 FROM mails WHERE group_key=? AND recipient=?", key, r):
            continue
        mid = db.x("""INSERT INTO mails(group_key, issue_id, recipient, subject, body, html, status, created_at)
                      VALUES(?,?,?,?,?,?,'preview',?)""", key, f["id"], r, subject, text, body_html, db.now())
        made = True
        if config.MAIL_MODE == "send" and smtp_ready():
            deliver(mid)
    return made


def run(log=print):
    made = sent = unrouted = 0
    for g in db.q(GROUP_SQL):
        issues = _issues(g)
        if not issues:
            continue
        to = recipients(g["repo"], top_severity(issues))
        if not to:
            unrouted += 1
            continue
        key = group_key(g)
        subject, text, body_html = compose(g, issues)
        for r in to:
            if db.one("SELECT 1 FROM mails WHERE group_key=? AND recipient=?", key, r):
                continue  # already mailed (or previewed) for this finding
            mid = db.x("""INSERT INTO mails(group_key, issue_id, recipient, subject, body, html, status, created_at)
                          VALUES(?,?,?,?,?,?,'preview',?)""", key, issues[0]["id"], r, subject, text, body_html, db.now())
            made += 1
            if config.MAIL_MODE == "send" and smtp_ready():
                sent += deliver(mid)
    mode = config.MAIL_MODE if smtp_ready() or config.MAIL_MODE != "send" else "send (SMTP not configured: kept as preview)"
    log(f"mail: {made} new mail(s), {sent} sent, {unrouted} finding(s) with no routing rule, mode={mode}")

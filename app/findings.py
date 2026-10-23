"""Findings = issues grouped per repo + library (all installed versions together). Used by the
dashboard, the auto-fixer and escalation mails."""
import re

from . import classify, config, db

OPEN = ("open", "in_progress")


def build():
    """Issues grouped into findings: one per repo + library (all installed versions together)."""
    groups = {}
    for i in db.q(f"SELECT * FROM issues WHERE {db.TRACKED}"):
        groups.setdefault((i["repo"], i["ecosystem"], i["package"]), []).append(i)
    out = []
    for (repo, eco, pkg), issues in groups.items():
        live = [i for i in issues if i["status"] in OPEN] or issues
        ver = ", ".join(sorted({i["version"] or "" for i in live},
                               key=lambda s: [int(x) if x.isdigit() else 0 for x in re.split(r"[.-]", s.lstrip("v"))]))
        live.sort(key=lambda i: (i["priority"] if i["priority"] is not None else 3, -i["kev"],
                                 -config.SEV_RANK.get(i["severity"], 0)))
        lead = live[0]
        t = db.jl(lead["triage"], {})
        cats = {}
        for i in live:
            cats[i["category"] or "other"] = cats.get(i["category"] or "other", 0) + 1
        fixed = sorted({v for i in live for v in db.jl(i["fixed_versions"])},
                       key=lambda s: [int(x) if x.isdigit() else 0 for x in re.split(r"[.-]", s)])
        status = "in_progress" if any(i["status"] == "in_progress" for i in issues) else \
            ("open" if any(i["status"] == "open" for i in issues) else lead["status"])
        affected = t.get("affected")
        out.append({
            "id": lead["id"], "ids": [i["id"] for i in issues], "repo": repo, "ecosystem": eco, "package": pkg, "version": ver,
            "versions": sorted({i["version"] for i in live if i["version"]}),
            "manifest": lead["manifest"], "status": status, "priority": lead["priority"] if lead["priority"] is not None else 3,
            "kev": any(i["kev"] for i in live), "dev_only": bool(lead["dev_only"]),
            "backlog": all(i["backlog"] for i in live), "ai_state": lead["ai_state"],
            # every open advisory proven unreachable by the Go call graph -> not a confirmed finding
            "unreachable": all(i.get("reach") in ("imported", "required", "not_affected") for i in live),
            "confirmed": lead["ai_state"] == "done" and affected in ("yes", "maybe") and status in OPEN
                         and not all(i.get("reach") in ("imported", "required", "not_affected") for i in live),
            "affected": affected, "confidence": t.get("confidence"),
            "problem": t.get("problem") or lead["summary"], "impact": t.get("impact"), "guard": t.get("guard_now"),
            "fix": t.get("fix"), "target": t.get("target_version") or (fixed[-1] if fixed else ""),
            "category": min(cats, key=lambda c: classify.CATS.get(c, ("", 9))[1]),
            "categories": sorted(cats.items(), key=lambda kv: (classify.CATS.get(kv[0], ("", 9))[1], -kv[1])),
            "severity": max((i["severity"] for i in live), key=lambda s: config.SEV_RANK.get(s, 0)),
            "has_guide": bool(lead["guide"]),
            "evidence": list({e["url"]: e for i in [lead, *live] for e in db.jl(i["evidence"], {}).get("items", [])}.values())[:12],
            "vulns": [{"id": i["vuln_id"], "aliases": db.jl(i["aliases"])[:3], "severity": i["severity"],
                       "category": i["category"], "summary": i["summary"], "kev": bool(i["kev"]),
                       "fixed": db.jl(i["fixed_versions"])[-2:], "published": (i["published"] or "")[:10]}
                      for i in live][:60],
            "vuln_count": len(live),
        })
    fixes = {(x["repo"], x["ecosystem"], x["package"]): x for x in db.q("SELECT * FROM fixes ORDER BY id")}
    res = {(x["repo"], x["ecosystem"], x["package"]): x for x in db.q("SELECT repo, ecosystem, package, decision, sources, created_at FROM research")}
    rch = {(x["repo"], x["ecosystem"], x["package"]): x for x in db.q("SELECT * FROM reachability")}
    for f in out:
        x = fixes.get((f["repo"], f["ecosystem"], f["package"]))
        rc = rch.get((f["repo"], f["ecosystem"], f["package"]))
        if rc:
            det = db.jl(rc["detail"], {})
            if rc["method"] == "govulncheck":   # only the advisories in this finding, worst first
                adv = {k: v for k, v in det.get("advisories", {}).items() if k in {x["id"] for x in f["vulns"]}}
                det = {"advisories": dict(sorted(adv.items(), key=lambda kv: kv[1]["level"] != "called"))}
            f["reach"] = {"method": rc["method"], "level": rc["level"], "detail": det, "at": rc["created_at"]}
        else:
            f["reach"] = None
        rr = res.get((f["repo"], f["ecosystem"], f["package"]))
        f["research"] = {"decision": db.jl(rr["decision"], {}), "sources": db.jl(rr["sources"]), "at": rr["created_at"]} if rr else None
        f["autofix"] = {k: x[k] for k in ("id", "kind", "status", "reason", "target", "branch", "files", "diff", "pr_url", "updated_at")} if x else None
    out.sort(key=lambda f: (f["priority"], -f["kev"], -config.SEV_RANK.get(f["severity"], 0), -f["vuln_count"]))
    return out

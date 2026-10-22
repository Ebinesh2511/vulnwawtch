"""OSV.dev client: exact-version checks for packages, plus cached vuln records."""
import json
import urllib.request

from . import db

API = "https://api.osv.dev/v1"


def _post(path, body):
    req = urllib.request.Request(f"{API}/{path}", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def _get(path):
    with urllib.request.urlopen(f"{API}/{path}", timeout=60) as r:
        return json.loads(r.read())


def query(packages):
    """packages: [(ecosystem, name, version)] -> {(eco, name, version): [vuln_id, ...]}"""
    out = {}
    for i in range(0, len(packages), 1000):
        chunk = packages[i:i + 1000]
        res = _post("querybatch", {"queries": [
            {"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]})
        for pkg, r in zip(chunk, res["results"]):
            ids = [v["id"] for v in r.get("vulns", [])]
            if ids:
                out[pkg] = ids
    return out


def vuln(vid):
    """Full OSV record (cached). Severity falls back to the GHSA alias when the record has none."""
    row = db.one("SELECT data, severity FROM osv_vulns WHERE id=?", vid)
    if row:
        return json.loads(row["data"]), row["severity"]
    d = _get(f"vulns/{vid}")
    sev = (d.get("database_specific") or {}).get("severity")
    if not sev:
        for a in d.get("aliases", []):
            if a.startswith("GHSA-"):
                try:
                    sev = (_get(f"vulns/{a}").get("database_specific") or {}).get("severity")
                except Exception:
                    pass
                break
    sev = (sev or "UNKNOWN").upper()
    db.x("INSERT OR REPLACE INTO osv_vulns(id, data, severity, published, fetched_at) VALUES(?,?,?,?,?)",
         vid, json.dumps(d), sev, d.get("published"), db.now())
    return d, sev


def fixed_versions(record, ecosystem, name):
    fixed = []
    for a in record.get("affected", []):
        p = a.get("package", {})
        if p.get("ecosystem", "").split(":")[0] == ecosystem and p.get("name") == name:
            for r in a.get("ranges", []):
                fixed += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    return sorted(set(fixed))

"""GitHub App webhooks: keep installations and the repo list in step with what was picked on GitHub.

  installation              created / new_permissions_accepted / unsuspend -> store it (+ its repos)
                            suspend -> mark suspended; deleted -> forget it and stop tracking its repos
  installation_repositories added -> track and scan them; removed -> stop tracking (data is kept)
  ping                      sent once when the webhook is set up

Every delivery must carry X-Hub-Signature-256 = HMAC-SHA256(GITHUB_WEBHOOK_SECRET, raw body).
"""
import hashlib
import hmac

from . import config, db, github_auth


def verify(body: bytes, signature: str) -> bool:
    if not config.GH_WEBHOOK_SECRET or not signature:
        return False
    expected = "sha256=" + hmac.new(config.GH_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _ours(inst):
    return ((inst.get("account") or {}).get("login") or "").lower() == config.ORG.lower()


def _track(repos):
    for r in repos:
        db.x("""INSERT INTO repos(name, tracked, private) VALUES(?, 1, ?)
                ON CONFLICT(name) DO UPDATE SET tracked=1, last_sha=NULL, scan_error=NULL""",
             r["name"], int(bool(r.get("private"))))


def _untrack(names, why):
    for n in names:
        db.x("UPDATE repos SET tracked=0, scan_error=? WHERE name=?", why, n)


def handle(event, payload):
    """Apply one webhook. Returns (summary, needs_repo_sync)."""
    inst = payload.get("installation") or {}
    action = payload.get("action", "")
    if event == "ping":
        return "ping received", False

    if event == "installation":
        if action in ("created", "new_permissions_accepted", "unsuspend", "suspend"):
            github_auth.save_installation(inst)
            if action == "created" and _ours(inst):
                _track(payload.get("repositories") or [])
            return f"installation {action} on {inst['account']['login']}", _ours(inst) and action != "suspend"
        if action == "deleted":
            db.x("DELETE FROM installations WHERE id=?", str(inst["id"]))
            github_auth.forget_token()
            if _ours(inst):
                _untrack([r["name"] for r in db.q("SELECT name FROM repos WHERE tracked=1")], "GitHub App uninstalled")
            return f"installation deleted on {inst['account']['login']}", False
        return f"installation {action} ignored", False

    if event == "installation_repositories":
        db.x("UPDATE installations SET repo_selection=?, updated_at=? WHERE id=?",
             payload.get("repository_selection"), db.now(), str(inst.get("id")))
        if not _ours(inst):
            return f"repos changed on {inst.get('account', {}).get('login')}, not {config.ORG}: ignored", False
        added = payload.get("repositories_added") or []
        removed = [r["name"] for r in payload.get("repositories_removed") or []]
        _track(added)
        _untrack(removed, "Removed from the GitHub App on GitHub")
        return f"{len(added)} repo(s) added, {len(removed)} removed", bool(added)

    return f"{event} ignored", False

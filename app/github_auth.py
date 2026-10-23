"""Which GitHub identity VulnWatch uses, and a token for it. Every gh and git call gets this token as GH_TOKEN.

Modes, first match wins:
  app       GITHUB_APP_ID + private key set. Signs a short JWT with the App's key, exchanges it for an
            installation token (valid 1 hour), caches it and renews it 5 minutes before it expires.
            Not tied to a person; acts as the App's bot.
  token     GH_TOKEN already in the environment (e.g. a fine-grained token in Docker).
  gh-login  neither: falls back to the local `gh auth login` (handy for development on a laptop).
"""
import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

import jwt

from . import config

API = "https://api.github.com"
_lock = threading.Lock()
_cache = {"token": None, "token_for": None, "expires": 0.0, "installation": None, "app": None, "bot": None}


class AuthError(RuntimeError):
    pass


def _private_key():
    if config.GH_APP_PRIVATE_KEY:
        return config.GH_APP_PRIVATE_KEY.replace("\\n", "\n")   # env vars often carry the PEM on one line
    if config.GH_APP_PRIVATE_KEY_PATH:
        p = Path(config.GH_APP_PRIVATE_KEY_PATH).expanduser()
        if not p.is_absolute():
            p = config.ROOT / p
        return p.read_text()
    return None


def mode():
    if config.GH_APP_ID and (config.GH_APP_PRIVATE_KEY or config.GH_APP_PRIVATE_KEY_PATH):
        return "app"
    return "token" if os.environ.get("GH_TOKEN") else "gh-login"


def _app_jwt():
    now = int(time.time())
    # iat 60 s in the past tolerates clock drift; GitHub allows at most 10 minutes
    return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": str(config.GH_APP_ID)}, _private_key(), algorithm="RS256")


def _call(method, path, bearer):
    req = urllib.request.Request(API + path, method=method, headers={
        "Authorization": f"Bearer {bearer}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "vulnwatch"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:200]
        raise AuthError(f"GitHub {method} {path} → {e.code}: {detail}") from None


def app_info():
    if not _cache["app"]:
        _cache["app"] = _call("GET", "/app", _app_jwt())
    return _cache["app"]


def install_url(state):
    """GitHub's install / pick-repositories screen for this App."""
    slug = config.GH_APP_SLUG or app_info()["slug"]
    return f"https://github.com/apps/{slug}/installations/new?state={state}"


def save_installation(inst):
    """Store an installation as GitHub describes it (from the setup callback, a webhook, or a lookup)."""
    from . import db
    acc = inst.get("account") or {}
    db.x("""INSERT INTO installations(id, account, account_type, repo_selection, suspended, html_url, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET account=excluded.account, account_type=excluded.account_type,
              repo_selection=excluded.repo_selection, suspended=excluded.suspended, html_url=excluded.html_url,
              updated_at=excluded.updated_at""",
         str(inst["id"]), acc.get("login"), acc.get("type"), inst.get("repository_selection"),
         int(bool(inst.get("suspended_at"))), inst.get("html_url"), db.now(), db.now())
    forget_token()


def fetch_installation(iid):
    """Ask GitHub, signed with our App key, for an installation. Fails unless it belongs to this App,
    so an installation_id in a URL cannot be spoofed."""
    return _call("GET", f"/app/installations/{int(iid)}", _app_jwt())


def forget_token():
    with _lock:
        _cache.update(token=None, token_for=None, expires=0.0, installation=None)


def installation_id():
    """Explicit env setting, else the stored installation for GITHUB_ORG, else ask GitHub (and store it)."""
    if config.GH_APP_INSTALLATION_ID:
        return str(config.GH_APP_INSTALLATION_ID)
    if _cache["installation"]:
        return _cache["installation"]
    from . import db
    row = db.one("SELECT id FROM installations WHERE lower(account)=lower(?) AND suspended=0", config.ORG)
    if not row:
        # the App's installation on our org or personal account; needs no extra permission
        try:
            found = _call("GET", f"/orgs/{config.ORG}/installation", _app_jwt())
        except AuthError:
            try:
                found = _call("GET", f"/users/{config.ORG}/installation", _app_jwt())
            except AuthError:
                raise AuthError(f"The GitHub App is not installed on {config.ORG}. Use “Install on GitHub” on the Repos page.") from None
        save_installation(found)
        row = {"id": str(found["id"])}
    _cache["installation"] = row["id"]
    return row["id"]


def token():
    """Installation token in app mode (cached, renewed early), else None (gh uses GH_TOKEN or its own login)."""
    if mode() != "app":
        return None
    with _lock:
        iid = installation_id()
        if _cache["token"] and _cache["token_for"] == iid and _cache["expires"] - time.time() > 300:
            return _cache["token"]
        res = _call("POST", f"/app/installations/{iid}/access_tokens", _app_jwt())
        _cache["token"], _cache["token_for"] = res["token"], iid
        _cache["expires"] = datetime.fromisoformat(res["expires_at"].replace("Z", "+00:00")).timestamp()
        return _cache["token"]


def env(base=None):
    """Environment for a gh/git subprocess, carrying the right token."""
    e = dict(base or os.environ)
    t = token()
    if t:
        e["GH_TOKEN"] = t
        e.pop("GITHUB_TOKEN", None)   # gh prefers GH_TOKEN; avoid a stale second token
    return e


def bot_identity():
    """(name, email) for commits. App mode: the App's bot account, so fixes are not attributed to a person."""
    if config.BOT_NAME_SET or mode() != "app":
        return config.BOT_NAME, config.BOT_EMAIL
    if not _cache["bot"]:
        app = _cache["app"] or _call("GET", "/app", _app_jwt())
        _cache["app"] = app
        login = f"{app['slug']}[bot]"
        uid = _call("GET", f"/users/{login}", token())["id"]
        _cache["bot"] = (login, f"{uid}+{login}@users.noreply.github.com")
    return _cache["bot"]


def status():
    """For the UI: which identity is in use, and whether it works right now."""
    m = mode()
    out = {"mode": m, "ok": True, "detail": ""}
    try:
        if m == "app":
            token()
            app = _cache["app"] or _call("GET", "/app", _app_jwt())
            _cache["app"] = app
            out["detail"] = (f"GitHub App “{app.get('name')}” (installation {installation_id()}), token renews "
                             f"automatically, current one valid until {time.strftime('%H:%M', time.localtime(_cache['expires']))}")
        elif m == "token":
            out["detail"] = "GH_TOKEN from the environment"
        else:
            out["detail"] = "the local gh login of whoever runs the app (development only)"
    except Exception as e:
        out.update(ok=False, detail=str(e)[:300])
    return out

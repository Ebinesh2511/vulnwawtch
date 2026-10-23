"""Developer settings editable from the Settings page. Saved in the `settings` table and applied to the
running app at once (config attributes are replaced). `.env` stays the default; secrets are never here."""
import json
import os

from . import config, db

# key: (config attribute, group, label, kind, choices / range, help)
FIELDS = {
    "SCHEDULER":            ("SCHEDULER", "Pipeline", "Automatic checks", "bool", None, "Run the full check on a timer. Off = only when someone clicks Run check."),
    "INTERVAL_MIN":         ("INTERVAL_MIN", "Pipeline", "Check every (minutes)", "int", (5, 1440), "How often the automatic check runs."),
    "FEED_DAYS":            ("FEED_DAYS", "Pipeline", "Feed window (days)", "int", (1, 30), "How far back advisories and news are read."),
    "RECENT_DAYS":          ("RECENT_DAYS", "Pipeline", "Recent advisory (days)", "int", (1, 365), "Older advisories go to backlog unless exploited, in the news or called by our code."),
    "MIN_SEVERITY":         ("MIN_SEVERITY", "Pipeline", "Minimum severity", "choice", ["HIGH", "CRITICAL"], "Below this, findings stay in backlog (exploited ones always count)."),
    "GEMINI_TRIAGE_MODEL":  ("TRIAGE_MODELS", "AI", "Triage model(s)", "models", None, "Fast model for verdicts, symbols and decisions. Comma list = fallbacks in order."),
    "GEMINI_GUIDE_MODEL":   ("GUIDE_MODELS", "AI", "Guide / research model(s)", "models", None, "Strong model for fix guides, web research and developer instructions."),
    "AI_MAX_PER_RUN":       ("AI_MAX_PER_RUN", "AI", "AI reviews per run", "int", (0, 200), "Libraries reviewed by AI in one check."),
    "RESEARCH_MAX_PER_RUN": ("RESEARCH_MAX_PER_RUN", "AI", "Web research per run", "int", (0, 100), "Findings researched on the web in one check (about a minute each)."),
    "AI_DAILY_TOKEN_BUDGET": ("AI_DAILY_TOKEN_BUDGET", "AI", "Daily token budget", "int", (0, 1_000_000_000), "AI steps pause once today's tokens reach this. 0 = no limit."),
    "AI_PRICES":            ("AI_PRICES", "AI", "Prices per 1M tokens (USD)", "prices", None, "Optional, for the cost estimate. Check your Google AI pricing page."),
    "AUTOFIX_MODE":         ("AUTOFIX_MODE", "Auto-fix", "Auto-fix mode", "choice", ["off", "dry_run", "pr"], "dry_run = local branch + diff only; pr = push and open pull requests."),
    "AUTOFIX_MAX_PER_RUN":  ("AUTOFIX_MAX_PER_RUN", "Auto-fix", "Fixes per run", "int", (0, 100), "Findings the fixer handles in one check."),
    "AUTOFIX_PR_DRAFT":     ("AUTOFIX_PR_DRAFT", "Auto-fix", "Open PRs as drafts", "bool", None, "Drafts can't be merged by accident."),
    "ESCALATE_MAX_PRIORITY": ("ESCALATE_MAX_PRIORITY", "Auto-fix", "Escalate by mail up to", "choice", ["0", "1", "2", "3"], "Hard fixes at this priority or more urgent get an escalation mail (0 = P0 only, 3 = all)."),
    "MAIL_MODE":            ("MAIL_MODE", "Mail", "Mail mode", "choice", ["dry_run", "send"], "dry_run keeps mails as previews; send delivers them (needs SMTP in .env)."),
    "DASHBOARD_URL":        ("DASHBOARD_URL", "Mail", "Dashboard URL in mails/PRs", "text", None, "The address people use to open this dashboard."),
}
SECRETS = [("GEMINI_API_KEY", "Gemini API key"), ("SMTP_PASS", "SMTP password"), ("GITHUB_APP_PRIVATE_KEY_PATH", "GitHub App key file"),
           ("GITHUB_APP_PRIVATE_KEY", "GitHub App key (inline)"), ("GITHUB_WEBHOOK_SECRET", "Webhook secret"), ("GH_TOKEN", "GH_TOKEN")]


def _convert(key, raw):
    attr, _, _, kind, opts, _ = FIELDS[key]
    if kind == "bool":
        return str(raw).lower() in ("1", "true", "on", "yes")
    if kind == "int":
        v = int(raw)
        lo, hi = opts
        if not lo <= v <= hi:
            raise ValueError(f"must be between {lo} and {hi}")
        return v
    if kind == "choice":
        if str(raw) not in opts:
            raise ValueError(f"must be one of {', '.join(opts)}")
        return int(raw) if key == "ESCALATE_MAX_PRIORITY" else str(raw)
    if kind == "models":
        models = [m.strip() for m in str(raw).split(",") if m.strip()]
        if not models:
            raise ValueError("needs at least one model")
        return models
    if kind == "prices":
        p = json.loads(raw) if isinstance(raw, str) else raw
        return {fam: {"in": float(v.get("in", 0)), "out": float(v.get("out", 0))} for fam, v in p.items()}
    v = str(raw).strip().rstrip("/")
    if key == "DASHBOARD_URL" and not v.startswith(("http://", "https://")):
        raise ValueError("must start with http:// or https://")
    return v


def apply_saved():
    """At startup: put saved dashboard values over the .env defaults."""
    for row in db.q("SELECT key, value FROM settings"):
        if row["key"] in FIELDS:
            try:
                setattr(config, FIELDS[row["key"]][0], _convert(row["key"], json.loads(row["value"])))
            except Exception:
                pass


def save(key, raw):
    if key not in FIELDS:
        raise KeyError(key)
    value = _convert(key, raw)
    db.x("INSERT INTO settings(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
         key, json.dumps(raw), db.now())
    setattr(config, FIELDS[key][0], value)
    return value


def reset(key):
    db.x("DELETE FROM settings WHERE key=?", key)
    setattr(config, FIELDS[key][0], DEFAULTS[key])
    return DEFAULTS[key]


def listing():
    saved = {r["key"] for r in db.q("SELECT key FROM settings")}
    out = []
    for key, (attr, group, label, kind, opts, help_) in FIELDS.items():
        v = getattr(config, attr)
        out.append({"key": key, "group": group, "label": label, "kind": kind, "options": opts, "help": help_,
                    "value": ", ".join(v) if kind == "models" else v,
                    "source": "dashboard" if key in saved else (".env" if key in os.environ or key in _ENV_KEYS else "default")})
    return out


def secrets():
    return [{"key": k, "label": label, "set": bool(os.environ.get(k) or getattr(config, k.replace("GITHUB_", "GH_"), None))}
            for k, label in SECRETS]


# defaults = what .env / built-ins gave at start-up, before dashboard overrides
DEFAULTS = {k: getattr(config, f[0]) for k, f in FIELDS.items()}
_ENV_KEYS = {k for k in FIELDS if os.environ.get(k) is not None}

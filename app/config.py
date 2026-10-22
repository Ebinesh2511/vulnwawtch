"""Settings, read from vulnwatch/.env (falls back to the process environment)."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)
DB_PATH = DATA / "vulnwatch.db"
CLONES = DATA / "clones"
FEEDS_JSON = ROOT.parent / "vulnfeed" / "feeds.json"


def env(name, default=""):
    return os.environ.get(name, default)


ORG = env("GITHUB_ORG", "guvi-geek")
DASHBOARD_URL = env("DASHBOARD_URL", "http://127.0.0.1:8000").rstrip("/")

# Gemini (key is read by google-genai from GEMINI_API_KEY). Comma list = fallbacks, tried in order
# when a model blocks or fails. gemini-flash-latest blocked ~50% of security prompts in testing.
TRIAGE_MODELS = [m.strip() for m in env("GEMINI_TRIAGE_MODEL", "gemini-3.5-flash,gemini-2.5-flash").split(",")]
GUIDE_MODELS = [m.strip() for m in env("GEMINI_GUIDE_MODEL", "gemini-pro-latest,gemini-3.5-flash").split(",")]

# Pipeline
FEED_DAYS = int(env("FEED_DAYS", "3"))            # feed lookback window
RECENT_DAYS = int(env("RECENT_DAYS", "30"))       # older OSV hits are "backlog": dashboard only, no mail
MIN_SEVERITY = env("MIN_SEVERITY", "HIGH")        # HIGH or CRITICAL; KEV always passes
INTERVAL_MIN = int(env("INTERVAL_MIN", "30"))
SCHEDULER = env("SCHEDULER", "on") == "on"
AI_MAX_PER_RUN = int(env("AI_MAX_PER_RUN", "10"))  # cap Gemini work per run

# Auto-fix: off | dry_run (branch + diff locally, nothing pushed) | pr (push branch + open a PR)
AUTOFIX_MODE = env("AUTOFIX_MODE", "dry_run")
AUTOFIX_MAX_PER_RUN = int(env("AUTOFIX_MAX_PER_RUN", "5"))
# hard-to-fix findings at this priority or more urgent (0 = P0, 1 = P1) get an escalation mail
ESCALATE_MAX_PRIORITY = int(env("ESCALATE_MAX_PRIORITY", "1"))
FIXES = DATA / "fixes"
BOT_NAME = env("AUTOFIX_GIT_NAME", "VulnWatch Bot")
BOT_EMAIL = env("AUTOFIX_GIT_EMAIL", "vulnwatch-bot@users.noreply.github.com")

# Mail
MAIL_MODE = env("MAIL_MODE", "dry_run")           # dry_run | send
SMTP_HOST = env("SMTP_HOST")
SMTP_PORT = int(env("SMTP_PORT", "587"))
SMTP_USER = env("SMTP_USER")
SMTP_PASS = env("SMTP_PASS")
SMTP_FROM = env("SMTP_FROM", SMTP_USER)
SMTP_TLS = env("SMTP_TLS", "starttls")            # starttls | ssl | none

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

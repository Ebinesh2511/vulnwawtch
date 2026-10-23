"""Settings, read from vulnwatch/.env (falls back to the process environment)."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)
FEEDS_JSON = ROOT.parent / "vulnfeed" / "feeds.json"


def env(name, default=""):
    return os.environ.get(name, default)


ORG = env("GITHUB_ORG", "guvi-geek")   # org or personal account to watch

# Each account gets its own database and clones, so switching GITHUB_ORG never mixes data.
# guvi-geek keeps the original file names it was created with.
# DB_DIR: Docker keeps the database on a Docker volume, because SQLite locking isn't reliable on a Mac bind mount
# shared by two containers (web + worker). Clones stay in data/.
DB_DIR = Path(env("DB_DIR", str(DATA)))
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / ("vulnwatch.db" if ORG == "guvi-geek" else f"vulnwatch-{ORG}.db")
CLONES = DATA / ("clones" if ORG == "guvi-geek" else f"clones-{ORG}")
FIXES_ROOT = DATA / ("fixes" if ORG == "guvi-geek" else f"fixes-{ORG}")
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
REDIS_URL = env("REDIS_URL", "")        # set (Docker): jobs go on a Redis queue for the worker; empty: threads in the web process
WORKERS = int(env("WORKERS", "2"))      # jobs that may run at the same time
AI_MAX_PER_RUN = int(env("AI_MAX_PER_RUN", "10"))
AI_DAILY_TOKEN_BUDGET = int(env("AI_DAILY_TOKEN_BUDGET", "0"))   # 0 = no limit
AI_PRICES = __import__("json").loads(env("AI_PRICES", "{}"))      # {"flash": {"in": .., "out": ..}, "pro": {...}} USD per 1M  # cap Gemini work per run

# Auto-fix: off | dry_run (branch + diff locally, nothing pushed) | pr (push branch + open a PR)
AUTOFIX_MODE = env("AUTOFIX_MODE", "dry_run")
AUTOFIX_MAX_PER_RUN = int(env("AUTOFIX_MAX_PER_RUN", "5"))
AUTOFIX_PR_DRAFT = env("AUTOFIX_PR_DRAFT", "true") == "true"  # open PRs as drafts so nothing merges by accident
RESEARCH_MAX_PER_RUN = int(env("RESEARCH_MAX_PER_RUN", "10"))  # web research is the slowest step (~1 min each)
# hard-to-fix findings at this priority or more urgent (0 = P0, 1 = P1) get an escalation mail
ESCALATE_MAX_PRIORITY = int(env("ESCALATE_MAX_PRIORITY", "1"))
FIXES = FIXES_ROOT
BOT_NAME_SET = bool(env("AUTOFIX_GIT_NAME"))   # explicit name wins over the GitHub App's bot identity
BOT_NAME = env("AUTOFIX_GIT_NAME", "VulnWatch Bot")
BOT_EMAIL = env("AUTOFIX_GIT_EMAIL", "vulnwatch-bot@users.noreply.github.com")

# GitHub access: a GitHub App (recommended for servers) or, if unset, GH_TOKEN / the local gh login
GH_APP_ID = env("GITHUB_APP_ID")
GH_APP_INSTALLATION_ID = env("GITHUB_APP_INSTALLATION_ID")      # optional: looked up from GITHUB_ORG
GH_APP_PRIVATE_KEY_PATH = env("GITHUB_APP_PRIVATE_KEY_PATH")    # path to the .pem
GH_APP_PRIVATE_KEY = env("GITHUB_APP_PRIVATE_KEY")              # or the PEM itself (Docker secrets)
GH_APP_SLUG = env("GITHUB_APP_SLUG")                            # optional: read from GitHub when empty
GH_WEBHOOK_SECRET = env("GITHUB_WEBHOOK_SECRET")                # required for /github/webhook

# Mail
MAIL_MODE = env("MAIL_MODE", "dry_run")           # dry_run | send
SMTP_HOST = env("SMTP_HOST")
SMTP_PORT = int(env("SMTP_PORT", "587"))
SMTP_USER = env("SMTP_USER")
SMTP_PASS = env("SMTP_PASS")
SMTP_FROM = env("SMTP_FROM", SMTP_USER)
SMTP_TLS = env("SMTP_TLS", "starttls")            # starttls | ssl | none

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

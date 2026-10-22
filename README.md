# VulnWatch

Watches vulnerability feeds, matches them against the `guvi-geek` repos, and shows the results on a dashboard.
AI triage and email alerts are being added next (see `../PLAN.md`).

## Run

```bash
cd vulnwatch
../.venv/bin/python run.py
```

## Styles

CSS is a static Tailwind build (no runtime CDN). After changing classes in `app/templates/` or `app/static/vw.js`:

```bash
cd vulnwatch/tools && npm install && npm run css      # or: npm run css:watch
```

Design rules live in `tools/input.css`:
- **Type scale:** 12 caption · 14 body · 16 card title · 20 section · 24 page title · 40 hero.
- **Muted text:** slate-600 on light, slate-400 on dark.
- **Severity badges:** tinted, never solid fills with white text.
- **Hit targets:** 40 px desktop, 44 px touch.
- **Motion:** 120 / 180 / 240 ms, respects reduced motion.

Icons are inline Lucide SVGs (`app/templates/_ui.html`).

Open http://127.0.0.1:8000 and press **Run full check**.

- Needs `gh` logged in with access to the org (`gh auth status`).
- Settings live in `.env` (copied from `.env.example`). Auto-run is `SCHEDULER=off` while developing; set it to `on` to check every `INTERVAL_MIN` minutes.

## What a run does

1. **Repos:** `gh repo list` → for each tracked repo, check the tracked branch's latest commit. Unchanged → skip.
2. **Libraries:** read dependency files (lockfiles first) through the GitHub API. Nothing is cloned.
3. **Feeds:** pull the RSS/advisory sources from `../vulnfeed/feeds.json` plus the full CISA KEV list.
4. **Match:** ask OSV.dev which exact library versions are vulnerable. An issue is **actionable** if it is HIGH/CRITICAL (or KEV) and recent (in a feed, in KEV, or published within `RECENT_DAYS`). Everything else is **backlog**.
5. **Auto-fix:** open issues that no longer show up after a rescan are marked fixed.
6. **AI (Gemini):** for actionable issues, grouped per repo + library (one analysis covers all its vulns), at most `AI_MAX_PER_RUN` groups per run:
   - shallow-clone the tracked branch into `data/clones/`, ripgrep where the library is imported, and (npm) find which packages pull it in;
   - **triage** (`GEMINI_TRIAGE_MODEL`, flash): affected yes/maybe/no, impact for us, guard, fix, target version. "no" → status `not_affected`;
   - **guide** (`GEMINI_GUIDE_MODEL`, pro): step-by-step fix guide shown on the issue page.
   Backlog issues are analyzed only when you press **Analyze with AI** on the issue page.

7. **Mail:** for each analyzed finding with affected = yes/maybe, every routing rule (Routing page) whose repo pattern and minimum severity match gets **one** mail per repo + library. A finding is never mailed twice to the same person. `MAIL_MODE=dry_run` keeps mails as previews on the Mails page; `MAIL_MODE=send` with `SMTP_*` set sends them.

### Turning on email
1. Fill `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `SMTP_TLS` (`starttls` for port 587, `ssl` for 465) in `.env`.
2. Restart the app, then use **Send test** on the Routing page.
3. Check the previews on the Mails page, then set `MAIL_MODE=send` and restart.
4. Set `DASHBOARD_URL` to an address the leads can open, or the guide link in mails only works on this machine.

Models are comma lists tried in order. `gemini-flash-latest` is not the default: in testing it blocked about half of security prompts (`BlockedReason.OTHER`).

## Research (`app/research.py`)

Before fixing, every confirmed finding is researched on the web (Gemini with Google Search grounding, `RESEARCH_MAX_PER_RUN` per run). The research covers each advisory's root cause, whether this repo's usage reaches it, the lowest version that fixes everything, breaking changes on the way there, and workarounds. It cites sources. A second step turns that into a decision: strategy, target version, code changes, effort, `needs_human`. The fixer follows the decision:

- **Easy** (trivial or small effort, no code changes, a fixed version exists) → auto-fix as below.
- **Hard** (code changes needed, large effort, no fix, replace the library, risky major upgrade) → escalated. The escalation mail asks for help and carries the research, sources and full **developer instructions**: branch, exact commands, before/after code, tests, mitigation and rollback.

Dashboard: open a finding → **Research** (decision chips, summary, sources, full notes, "Research again").

## Auto-fix and escalation (`app/autofix.py`)

Runs after AI review for confirmed, open findings (at most `AUTOFIX_MAX_PER_RUN` per run, most urgent first).

| Finding | What happens |
|---|---|
| Same-major upgrade, PyPI pinned in `requirements*.txt` | edit the pin |
| Same-major upgrade, npm direct dependency (package-lock) | `npm install pkg@target --package-lock-only --ignore-scripts` (exact pins stay exact) |
| Same-major upgrade, npm pulled-in dependency | `"overrides": {"pkg@<major>.x": "^target"}` + lockfile refresh |
| Same-major upgrade, Go module | `go get module@vtarget` |
| Major upgrade, no fixed version, Go toolchain / Docker, yarn/pnpm/poetry, or the attempt fails | **escalated**: shown as "Needs a developer"; P0–P(`ESCALATE_MAX_PRIORITY`) get an escalation mail to the routed leads |

Every fix is checked by reading the changed files back and asking OSV.dev whether the advisories are gone, then committed by `VulnWatch Bot` on `vulnwatch/fix-<pkg>-<version>` in a temporary git worktree. No package or repo scripts run.

- `AUTOFIX_MODE=dry_run` (default): branch + diff stay local and show on the dashboard. **Nothing is pushed.**
- `AUTOFIX_MODE=pr`: pushes the branch and opens a PR against the tracked branch, using your `gh` login. PRs are drafts unless `AUTOFIX_PR_DRAFT=false`. An open PR for the same branch is reused, never duplicated. The description includes the research summary, advisories, what changed, how it was verified, today's mitigation and sources. In this mode the dashboard also shows a **Create PR** button on prepared fixes.
- `AUTOFIX_MODE=off`: no fixes, no escalations.

## Check any public repo (`/check`, `app/checker.py`)

Paste a GitHub link (or `owner/repo`, or a `/tree/branch` link). Private repos are refused.

- Reads dependency files and `.github/workflows/*.yml` through the GitHub API. Nothing is cloned or run.
- Each exact package version is checked with OSV.dev. **Malware** = OSV `MAL-` entries, advisories tagged CWE-506, or summaries naming the package as malware or a compromised release (not "a malicious user could…" bugs).
- GitHub Actions: OSV lists action advisories but does not compare versions, so tags are compared here. `v45` follows its major line; `v45.0.7` is exact. Actions pinned to a branch or commit are shown as "check manually".
- **Verdicts:**
  - **Compromised:** malware or a hijacked action.
  - **At risk:** exploited-in-the-wild or critical bugs.
  - **Needs attention:** other known bugs.
  - **Clean:** no known issues. This is not a guarantee: the repo's own code and unreported malware aren't checked.
- Every check gets a shareable URL `/check/<id>`. Results are stored in the `checks` table.

## Tracking repos

Repos page: switch repos on/off, filter by "Idle 6m+", bulk track/untrack. Untracked repos are skipped by scans, AI, dashboard, mails and auto-fix; their data is kept. New repos that appear in the org start tracked.

## Dashboard

- **Confirmed** (default view): version matched by OSV.dev **and** Gemini says affected / possibly affected. Other views: Awaiting AI, Backlog, Not reachable, Fixed / ignored.
- One card per repo + library (all installed versions together), in priority lanes:
  - **P0 Fix today:** code execution, auth/access-control bypass, injection or memory corruption in shipped code, HIGH+; or anything on CISA KEV in shipped code.
  - **P1 Fix this week:** SSRF, file access, request smuggling, prototype pollution HIGH+; any CRITICAL; or the P0 kinds when only in dev/build tooling.
  - **P2 Plan in sprint:** other HIGH (DoS, XSS, leaks).
  - **P3 Watch:** the rest. "Possibly affected" drops one level unless exploited.
- Attack type comes from the advisory's CWE ids, or from keywords when there are none (`app/classify.py`). Dev-only comes from lockfile/manifest dev flags.
- Every card shows the code lines that declare, lock and use the library (`app/evidence.py`). Each links to GitHub at the scanned commit.
- Light/dark/system theme toggle in the header. The page refreshes its data every 10 s.

## Files

| Path | What |
|---|---|
| `app/inventory.py` | repo sync + dependency scan |
| `app/manifests.py` | parsers for npm, PyPI, Go, Composer, Maven, Gradle, RubyGems, Cargo, Dockerfiles |
| `app/feeds.py` | feed + KEV ingest |
| `app/osv.py` | OSV.dev client |
| `app/matcher.py` | creates and closes issues |
| `app/ai.py` | usage search + Gemini triage and fix guide |
| `app/mailer.py` | routing rules, mail composing, SMTP |
| `app/classify.py` | attack type + P0–P3 priority |
| `app/evidence.py` | code lines + GitHub permalinks per finding |
| `app/findings.py` | groups issues into findings (one per repo + library) |
| `app/autofix.py` | plans, applies, verifies and commits fixes; escalates the rest |
| `app/jobs.py` | background jobs + scheduler |
| `app/web.py`, `app/templates/` | dashboard |
| `data/vulnwatch.db` | SQLite database (git-ignored) |

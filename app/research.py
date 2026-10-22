"""Research agent: dig into a confirmed finding on the web and decide the smallest safe fix.

Step 1 (pro model + Google Search grounding): read the advisories, patches, release notes and changelogs;
  work out root cause, which features are affected, whether OUR usage reaches them, the lowest version
  that fixes everything, the breaking changes on the way there, and workarounds. Cites sources.
Step 2 (flash model, structured): turn those notes into a decision the fixer acts on:
  strategy, target version, whether our code must change, effort, and whether a human is needed.
Stored per repo + library in the `research` table; redone only when the set of advisories changes.
"""
import json
import time
import urllib.request
from typing import Literal

from google.genai import types
from pydantic import BaseModel, Field

from . import db, findings
from .ai import SYSTEM, client
from .config import GUIDE_MODELS, TRIAGE_MODELS


class Decision(BaseModel):
    summary: str = Field(description="2-3 plain sentences: what the problem really is for this repo and what we will do")
    strategy: Literal["patch_upgrade", "minor_upgrade", "major_upgrade", "override_transitive", "config_mitigation",
                      "replace_library", "remove_unused", "no_fix_available"]
    target_version: str = Field(description="Lowest version that fixes every listed advisory, '' if none")
    code_changes_needed: bool = Field(description="True if our own source code must change for the upgrade or mitigation")
    code_change_summary: str = Field(description="Exactly what to change in our code, or ''")
    breaking_changes: str = Field(description="Breaking changes between current and target that touch our usage, or 'None that affect this repo'")
    exploitability: Literal["high", "medium", "low"] = Field(description="How reachable the vulnerable code is from how this repo uses the library")
    effort: Literal["trivial", "small", "large"] = Field(description="trivial = version bump only; small = a few lines; large = refactor/migration")
    needs_human: bool = Field(description="True ONLY when the fix cannot be automated safely: our code must change, a major "
                                          "migration, no fixed version, or impact that needs a judgement call. Reviewing and "
                                          "testing the pull request is always done and is NOT a reason.")
    human_reason: str = Field(description="If needs_human: one or two sentences on what help is needed and why. Else ''")
    mitigation_now: str = Field(description="What can be done today, before the full fix, to reduce risk")


RESEARCH_PROMPT = """Research this vulnerable dependency on the web and work out the best fix with the fewest code changes.

Cover, citing sources:
1. Each advisory: root cause, the affected functions/features/options, and the preconditions an attacker needs.
2. Whether THIS repo reaches the vulnerable code, judging from the usage shown (say so if usage is unclear).
3. The fixed version for each advisory and the LOWEST version that fixes all of them. Prefer a patch/minor release
   on the current major line if one exists; check the project's releases/changelog.
4. Breaking changes between the installed version and that target that would affect the usage shown.
5. Options ranked by how little they change: patch upgrade, override for a transitive dependency, config/workaround,
   major upgrade, replacing the library. Recommend one, and say whether a developer needs to be involved and why.
Be specific to the versions given. Do not invent versions; if a fact cannot be confirmed, say so."""


def _facts(f):
    ev = "\n".join(f"- {e['kind']} {e['file']}:{e['hit']}: " + " | ".join(l[1].strip() for l in e["lines"])[:240]
                   for e in f["evidence"][:8]) or "(no usage found by search)"
    vulns = "\n".join(f"- {v['id']} ({', '.join(v['aliases'])}) {v['severity']}{' EXPLOITED-IN-THE-WILD' if v['kev'] else ''}: "
                      f"{v['summary']} | fixed in: {', '.join(v['fixed']) or 'n/a'}" for v in f["vulns"][:15])
    return (f"Repository: {f['repo']}\nLibrary: {f['package']} ({f['ecosystem']}), installed version(s): {', '.join(f['versions'])}\n"
            f"{'Only used in development/build tooling.' if f['dev_only'] else 'Shipped with the product.'}\n"
            f"Earlier triage: affected={f['affected']}; impact: {f['impact'] or 'n/a'}\n\n"
            f"<advisories count=\"{f['vuln_count']}\">\n{vulns}\n</advisories>\n\n<usage>\n{ev}\n</usage>\n")


def _real_url(u):
    """Grounding links are redirects; resolve to the real page for display (best effort)."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        urllib.request.build_opener(NoRedirect).open(urllib.request.Request(u, method="HEAD"), timeout=8)
    except urllib.error.HTTPError as e:
        return e.headers.get("Location") or u
    except Exception:
        pass
    return u


def _search(prompt):
    errors = []
    for model in GUIDE_MODELS:
        for attempt in range(2):
            try:
                r = client().models.generate_content(
                    model=model, contents=prompt,
                    config=types.GenerateContentConfig(system_instruction=SYSTEM, tools=[types.Tool(google_search=types.GoogleSearch())]))
                if not r.text:
                    raise RuntimeError("empty response")
                gm = r.candidates[0].grounding_metadata
                chunks = (gm.grounding_chunks or []) if gm else []
                seen, sources = set(), []
                for ch in chunks:
                    if ch.web and ch.web.uri and ch.web.uri not in seen:
                        seen.add(ch.web.uri)
                        sources.append({"title": ch.web.title, "url": ch.web.uri})
                return r.text, sources[:10], (gm.web_search_queries or []) if gm else [], model
            except Exception as e:
                errors.append(f"{model}: {str(e)[:120]}")
                time.sleep(3 * (attempt + 1))
    raise RuntimeError("Research failed: " + " | ".join(errors[-2:]))


def _decide(facts, notes):
    errors = []
    for model in TRIAGE_MODELS:
        try:
            r = client().models.generate_content(
                model=model, contents=facts + "\n<research>\n" + notes[:12000] + "\n</research>\n\nTurn this into the fix decision. "
                         "Every automated fix is opened as a pull request that people review and test, so do not ask "
                         "for a human just to verify or test a plain version bump.",
                config=types.GenerateContentConfig(system_instruction=SYSTEM, response_mime_type="application/json", response_schema=Decision))
            if r.parsed:
                return r.parsed
            raise RuntimeError("empty decision")
        except Exception as e:
            errors.append(f"{model}: {str(e)[:120]}")
    raise RuntimeError("Decision failed: " + " | ".join(errors))


INSTRUCTIONS_PROMPT = """A developer has to fix this by hand (the automated fixer could not, see "Why a human").
Write complete, step-by-step instructions in GitHub-flavoured markdown so they can finish it in one sitting:

## What and why
Two or three lines: the risk for this repo and why it cannot be a plain version bump.

## Before you start
Branch name to use, and anything to check first (current usage, tests that exist).

## Steps
Numbered, with exact commands for this repo's package manager and exact file paths. Show before/after code for every
code change, based on the usage shown and the breaking changes found in the research. Use the target version from the decision.

## Test
How to prove it works (commands, pages or flows to click through) and how to confirm the vulnerable version is gone.

## If you cannot upgrade yet
The mitigation to apply today.

## Rollback

## Sources
The links from the research.
Do not invent APIs or versions."""


def instructions(f, log=print):
    """Developer instructions for an escalated finding, built from the research (cached)."""
    r = get(f)
    if not r:
        return ""
    if r.get("instructions"):
        return r["instructions"]
    from .ai import _gen
    fx = db.one("SELECT reason FROM fixes WHERE repo=? AND ecosystem=? AND package=?", f["repo"], f["ecosystem"], f["package"])
    prompt = (_facts(f) + "\n<research>\n" + r["notes"][:12000] + "\n</research>\n<decision>\n" + json.dumps(r["decision"])
              + "\n</decision>\n<sources>\n" + "\n".join(s["url"] for s in r["sources"]) + "\n</sources>\n"
              + f"Why a human: {(fx or {}).get('reason') or r['decision'].get('human_reason')}\n\n" + INSTRUCTIONS_PROMPT)
    text = _gen(GUIDE_MODELS, prompt)
    db.x("UPDATE research SET instructions=? WHERE repo=? AND ecosystem=? AND package=?", text, f["repo"], f["ecosystem"], f["package"])
    log(f"  instructions {f['repo']}/{f['package']}: {len(text)} chars")
    return text


def _key(f):
    return json.dumps(sorted(v["id"] for v in f["vulns"]) + f["versions"])


def get(f):
    row = db.one("SELECT * FROM research WHERE repo=? AND ecosystem=? AND package=?", f["repo"], f["ecosystem"], f["package"])
    if not row:
        return None
    return {**row, "decision": db.jl(row["decision"], {}), "sources": db.jl(row["sources"]), "queries": db.jl(row["queries"])}


def research(f, log=print, force=False):
    cur = get(f)
    if cur and cur["vuln_key"] == _key(f) and not force:
        return cur
    facts = _facts(f)
    notes, sources, queries, model = _search(facts + "\n" + RESEARCH_PROMPT)
    decision = _decide(facts, notes)
    for s in sources:
        s["url"] = _real_url(s["url"])
    db.x("""INSERT INTO research(repo, ecosystem, package, vuln_key, notes, decision, sources, queries, model, created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(repo, ecosystem, package) DO UPDATE SET vuln_key=excluded.vuln_key, notes=excluded.notes,
              decision=excluded.decision, sources=excluded.sources, queries=excluded.queries, model=excluded.model,
              created_at=excluded.created_at, instructions=NULL""",
         f["repo"], f["ecosystem"], f["package"], _key(f), notes, decision.model_dump_json(), json.dumps(sources),
         json.dumps(queries), model, db.now())
    d = decision
    log(f"  research {f['repo']}/{f['package']}: {d.strategy} → {d.target_version or '-'} "
        f"(effort {d.effort}{', needs human' if d.needs_human else ''}, {len(sources)} sources)")
    return get(f)


def run(log=print, limit=None, force=False):
    todo = [f for f in findings.build() if f["confirmed"] and f["status"] in ("open", "in_progress")]
    todo.sort(key=lambda f: (f["priority"], -f["kev"]))
    done = 0
    for f in todo[:limit or len(todo)]:
        try:
            cur = get(f)
            if cur and cur["vuln_key"] == _key(f) and not force:
                continue
            research(f, log=log, force=force)
            done += 1
        except Exception as e:
            log(f"  research {f['repo']}/{f['package']}: ERROR {e}")
    log(f"research: {done} finding(s) researched")

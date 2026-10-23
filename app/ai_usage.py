"""Every Gemini call goes through generate(): it checks the daily token budget, makes the call and records
the tokens used (per step, model, repo and library) in the ai_usage table for the Settings page."""
from datetime import datetime, timedelta, timezone

from . import config, db


class BudgetExceeded(RuntimeError):
    pass


def used_today():
    start = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
    return db.one("SELECT IFNULL(sum(total_tokens), 0) n FROM ai_usage WHERE at >= ?", start)["n"]


def check_budget():
    if config.AI_DAILY_TOKEN_BUDGET and used_today() >= config.AI_DAILY_TOKEN_BUDGET:
        raise BudgetExceeded(f"Daily AI token budget reached ({config.AI_DAILY_TOKEN_BUDGET:,} tokens). "
                             "AI steps resume tomorrow, or raise the budget on the Settings page.")


def generate(step, model, contents, cfg, repo=None, package=None):
    from .ai import client
    check_budget()
    r = client().models.generate_content(model=model, contents=contents, config=cfg)
    u = getattr(r, "usage_metadata", None)
    inp = (u and u.prompt_token_count) or 0
    out = (u and u.candidates_token_count) or 0
    think = (u and getattr(u, "thoughts_token_count", None)) or 0
    total = (u and u.total_token_count) or inp + out + think
    tools = bool(cfg and getattr(cfg, "tools", None))
    db.x("""INSERT INTO ai_usage(at, step, model, input_tokens, output_tokens, thinking_tokens, total_tokens, web_search, repo, package)
            VALUES(?,?,?,?,?,?,?,?,?,?)""", db.now(), step, getattr(r, "model_version", None) or model,
         inp, out, think, total, int(tools), repo, package)
    return r


def summary(days=30):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    week = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    tot = lambda where, *a: db.one(f"SELECT count(*) calls, IFNULL(sum(total_tokens),0) tokens FROM ai_usage WHERE {where}", *a)
    daily = db.q("""SELECT substr(at, 1, 10) day, count(*) calls, sum(total_tokens) tokens FROM ai_usage
                    WHERE at >= ? GROUP BY 1 ORDER BY 1""", since)
    by_step = db.q("""SELECT step, count(*) calls, sum(input_tokens) input, sum(output_tokens) output,
                      sum(thinking_tokens) thinking, sum(total_tokens) tokens FROM ai_usage WHERE at >= ?
                      GROUP BY 1 ORDER BY tokens DESC""", since)
    by_model = db.q("""SELECT model, count(*) calls, sum(input_tokens) input, sum(output_tokens) output,
                       sum(thinking_tokens) thinking, sum(total_tokens) tokens, sum(web_search) searches FROM ai_usage
                       WHERE at >= ? GROUP BY 1 ORDER BY tokens DESC""", since)
    for m in by_model:   # optional cost estimate from the per-1M prices set on the Settings page
        price = config.AI_PRICES.get(_family(m["model"]), {})
        m["cost"] = (m["input"] * price.get("in", 0) + (m["output"] + m["thinking"]) * price.get("out", 0)) / 1e6 if price else None
    return {
        "today": {**tot("at >= ?", datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z"))},
        "week": tot("at >= ?", week), "month": tot("at >= ?", since),
        "budget": config.AI_DAILY_TOKEN_BUDGET, "daily": daily, "by_step": by_step, "by_model": by_model,
        "cost": sum(m["cost"] for m in by_model if m["cost"] is not None) if any(m["cost"] is not None for m in by_model) else None,
        "recent": db.q("SELECT * FROM ai_usage ORDER BY id DESC LIMIT 25"),
    }


def _family(model):
    m = (model or "").lower()
    return "pro" if "pro" in m else ("flash-lite" if "lite" in m else ("flash" if "flash" in m else "other"))

"""Background jobs: one at a time, logged to the runs table, plus the interval scheduler."""
import threading
import time
import traceback

from . import ai, autofix, classify, db, evidence, feeds, inventory, mailer, matcher, reachability, research
from . import config


_lock = threading.Lock()
state = {"job": None, "lines": []}


def _pipeline(log):
    inventory.sync_repos(log=log)
    inventory.scan_all(log=log)
    feeds.refresh(log=log)
    matcher.run(log=log)
    for step in STEPS_AFTER_MATCH:
        step(log=log)


STEPS_AFTER_MATCH = [
    lambda log: classify.run(log=log),      # priority first, so AI works P0 findings first
    lambda log: ai.run(log=log),
    lambda log: evidence.backfill(log=log),
    lambda log: reachability.run(log=log),  # Go call graph + vulnerable-symbol search
    lambda log: classify.run(log=log),      # again: AI verdicts and reachability change priority
    lambda log: research.run(log=log, limit=config.RESEARCH_MAX_PER_RUN),  # web research → fix decision
    lambda log: autofix.run(log=log),       # before mail, so alerts carry the PR / escalation status
    lambda log: mailer.run(log=log),
]

JOBS = {
    "ai": lambda log: (ai.run(log=log), evidence.backfill(log=log), classify.run(log=log)),
    "classify": lambda log: classify.run(log=log),
    "research": lambda log: research.run(log=log),
    "reachability": lambda log: (reachability.run(log=log, force=True), classify.run(log=log)),
    "autofix": lambda log: autofix.run(log=log),
    "mail": lambda log: mailer.run(log=log),
    "pipeline": _pipeline,
    "repos": lambda log: (inventory.sync_repos(log=log), inventory.scan_all(log=log)),
    "rescan": lambda log: (inventory.sync_repos(log=log), inventory.scan_all(force=True, log=log)),
    "feeds": lambda log: feeds.refresh(log=log),
    "match": lambda log: matcher.run(log=log),
}


def run(job, fn=None):
    """Run a job in a background thread. Returns False if another job is already running."""
    if not _lock.acquire(blocking=False):
        return False
    state.update(job=job, lines=[])

    def work():
        rid = db.x("INSERT INTO runs(job, started) VALUES(?,?)", job, db.now())

        def log(msg):
            state["lines"].append(str(msg))

        ok = 1
        try:
            (fn or JOBS[job])(log)
        except Exception as e:
            ok = 0
            log(f"ERROR {type(e).__name__}: {e}")
            log(traceback.format_exc(limit=3))
        finally:
            db.x("UPDATE runs SET finished=?, log=?, ok=? WHERE id=?",
                 db.now(), "\n".join(state["lines"]), ok, rid)
            state["job"] = None
            _lock.release()

    threading.Thread(target=work, daemon=True).start()
    return True


def start_scheduler():
    """Always running; each cycle reads SCHEDULER and INTERVAL_MIN, so the Settings page can switch it live."""
    def loop():
        time.sleep(20)
        while True:
            if config.SCHEDULER:
                run("pipeline")
            time.sleep(max(1, config.INTERVAL_MIN) * 60)

    threading.Thread(target=loop, daemon=True).start()

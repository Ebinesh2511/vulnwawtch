"""Background jobs.

With REDIS_URL set, jobs go on a Redis queue (RQ) and the worker container runs them, WORKERS (default 2) at once.
Without it (plain `python run.py`), they run in threads inside the web process, with the same limit.

Rules either way:
- the same job (label) is never queued or run twice at once;
- jobs that write git clones/worktrees (GIT_TASKS) take one shared lock, so they run one after another;
- every run is logged to the runs table; live line + stop flag live in Redis (or memory).
"""
import threading
import time
import traceback

from . import ai, autofix, classify, config, db, evidence, feeds, inventory, mailer, matcher, reachability, research

STOPPED_LINE = "Stopped by user. Run it again to continue; finished work is kept."


class Stopped(BaseException):
    """Raised from log() once a stop is requested. BaseException, so steps' `except Exception` can't swallow it."""


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


def _finding(iid):
    from . import findings
    return next(f for f in findings.build() if iid in f["ids"])


# Jobs the Run buttons may start by name (POST /api/run/{job})
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

# Everything a worker can run: name -> fn(log, *args). Args must be plain JSON-able values (they go through Redis).
TASKS = dict(JOBS, **{
    "research_one": lambda log, iid: research.research(_finding(iid), log=log, force=True),
    "fix_one": lambda log, iid: autofix.fix_one(iid, log=log),
    "pr_one": lambda log, iid: autofix.fix_one(iid, log=log, open_pr=True),
    "ai_one": lambda log, iid: (ai.analyze_issue(iid, log=log), classify.run(log=log)),
    "mail_send": lambda log, ids: log(f"sent {sum(mailer.deliver(i) for i in ids)}/{len(ids)}"),
})

# Tasks that write clones / fix worktrees: never two at once
GIT_TASKS = {"pipeline", "repos", "rescan", "reachability", "autofix", "fix_one", "pr_one"}


# ---------------------------------------------------------------- live state: Redis or memory

class _Mem:
    def __init__(self):
        self.lock = threading.Lock()
        self.labels, self.running, self.queued = set(), {}, []   # running: rid -> {job, line, stop}
        self.slots = threading.Semaphore(max(1, config.WORKERS))
        self.git = threading.Lock()


_mem = _Mem()
_redis = None


def redis():
    global _redis
    if config.REDIS_URL and _redis is None:
        import redis as r
        _redis = r.Redis.from_url(config.REDIS_URL, decode_responses=True)
    return _redis


def queue():
    from rq import Queue
    import redis as r
    return Queue("vulnwatch", connection=r.Redis.from_url(config.REDIS_URL))   # RQ wants bytes, not decoded


def _claim(label):
    if redis():
        return bool(redis().sadd("vw:labels", label))
    with _mem.lock:
        if label in _mem.labels:
            return False
        _mem.labels.add(label)
        return True


def _release(label):
    if redis():
        redis().srem("vw:labels", label)
    else:
        with _mem.lock:
            _mem.labels.discard(label)


def _set_running(rid, **kv):
    if redis():
        redis().hset(f"vw:run:{rid}", mapping={k: str(v) for k, v in kv.items()})
        redis().sadd("vw:running", rid)
    else:
        _mem.running.setdefault(rid, {"stop": ""}).update(kv)


def _get(rid, key):
    if redis():
        return redis().hget(f"vw:run:{rid}", key)
    return _mem.running.get(rid, {}).get(key)


def _done(rid):
    if redis():
        redis().srem("vw:running", rid)
        redis().delete(f"vw:run:{rid}")
    else:
        _mem.running.pop(rid, None)


# ---------------------------------------------------------------- submit / execute / stop

def submit(label, task="", *args):
    """Queue a job. False if the same label is already queued or running. `task` defaults to the label."""
    task = task or label
    if task not in TASKS or not _claim(label):
        return False
    if redis():
        queue().enqueue("app.jobs.execute", label, task, list(args),
                        job_timeout=12 * 3600, result_ttl=600, failure_ttl=86400, meta={"label": label})
    else:
        with _mem.lock:
            _mem.queued.append(label)

        def thread():
            with _mem.slots:
                with _mem.lock:
                    _mem.queued.remove(label)
                execute(label, task, list(args))
        threading.Thread(target=thread, daemon=True).start()
    return True




def execute(label, task, args):
    """Runs inside a worker (or thread): logs to the runs table, honours stop requests, holds the git lock if needed."""
    if redis():
        from . import settings
        settings.apply_saved()    # pick up changes saved on the Settings page since the worker started
    rid = db.x("INSERT INTO runs(job, started) VALUES(?,?)", label, db.now())
    lines = []
    _set_running(rid, job=label, line="starting", stop="")

    def log(msg):
        lines.append(str(msg))
        _set_running(rid, line=str(msg).strip().splitlines()[0][:300] if str(msg).strip() else "")
        if _get(rid, "stop"):
            raise Stopped

    ok = 1
    try:
        if task in GIT_TASKS:
            with _git_lock(log):
                TASKS[task](log, *args)
        else:
            TASKS[task](log, *args)
    except Stopped:
        ok = 0
        lines.append(STOPPED_LINE)
    except Exception as e:
        ok = 0
        lines.append(f"ERROR {type(e).__name__}: {e}")
        lines.append(traceback.format_exc(limit=3))
    finally:
        db.x("UPDATE runs SET finished=?, log=?, ok=? WHERE id=?", db.now(), "\n".join(lines), ok, rid)
        _done(rid)
        _release(label)


class _git_lock:
    """One git-writing job at a time across all workers. Waiting still answers stop requests."""
    def __init__(self, log):
        self.log = log
        self.lock = redis().lock("vw:lock:git", timeout=12 * 3600) if redis() else _mem.git

    def __enter__(self):
        if self._try(0):
            return
        self.log("waiting for another repo job to finish (they share the git clones)")
        while not self._try(5):
            self.log("waiting for another repo job to finish (they share the git clones)")

    def _try(self, wait):
        if redis():
            return self.lock.acquire(blocking=bool(wait), blocking_timeout=wait or None)
        return self.lock.acquire(timeout=wait) if wait else self.lock.acquire(blocking=False)

    def __exit__(self, *exc):
        self.lock.release()


def stop(rid=None):
    """Stop one running job (rid) or everything: running jobs stop at their next log line, queued ones are dropped."""
    ids = [rid] if rid else [r["rid"] for r in running()]
    for i in ids:
        if redis():
            if redis().sismember("vw:running", i):
                redis().hset(f"vw:run:{i}", "stop", "1")
        elif i in _mem.running:
            _mem.running[i]["stop"] = "1"
    dropped = 0
    if rid is None and redis():
        q = queue()
        for j in q.get_jobs():
            _release(j.meta.get("label", ""))
            j.cancel()
            dropped += 1
    return bool(ids) or bool(dropped)


def running():
    if redis():
        out = []
        for rid in sorted(redis().smembers("vw:running"), key=int):
            h = redis().hgetall(f"vw:run:{rid}")
            if h:
                out.append({"rid": int(rid), "job": h.get("job"), "line": h.get("line", ""), "stopping": bool(h.get("stop"))})
        return out
    return [{"rid": rid, "job": s["job"], "line": s.get("line", ""), "stopping": bool(s.get("stop"))}
            for rid, s in sorted(_mem.running.items())]


def queued():
    if redis():
        return [j.meta.get("label", "?") for j in queue().get_jobs()]
    with _mem.lock:
        return list(_mem.queued)


def status():
    run_ = running()
    return {"running": run_, "queued": queued(), "label": " + ".join(r["job"] for r in run_) or None}


def reset_after_restart():
    """Worker start: nothing can be running yet. Fail orphaned runs, rebuild the label set from what is still queued."""
    db.x("UPDATE runs SET finished=?, ok=0, log=IFNULL(log,'') || ? WHERE finished IS NULL",
         db.now(), "\nWorker restarted while this was running.")
    r = redis()
    for rid in r.smembers("vw:running"):
        r.delete(f"vw:run:{rid}")
    r.delete("vw:running", "vw:labels", "vw:lock:git")
    labels = queued()
    if labels:
        r.sadd("vw:labels", *labels)


def start_scheduler():
    """Always running; each cycle reads SCHEDULER and INTERVAL_MIN, so the Settings page can switch it live."""
    def loop():
        time.sleep(20)
        while True:
            if config.SCHEDULER:
                submit("pipeline")
            time.sleep(max(1, config.INTERVAL_MIN) * 60)

    threading.Thread(target=loop, daemon=True).start()

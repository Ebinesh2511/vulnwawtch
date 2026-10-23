"""Job worker: takes jobs off the Redis queue and runs WORKERS (default 2) of them at the same time.

    REDIS_URL=redis://localhost:6379/0 python worker.py

Each slot is its own process running an RQ worker; a slot that dies is restarted.
The web app (run.py) only queues jobs when REDIS_URL is set.
"""
import multiprocessing as mp
import signal
import sys
import time

from app import config, db, jobs, settings


def slot(n):
    from redis import Redis
    from rq import Worker
    settings.apply_saved()
    Worker([jobs.queue().name], connection=Redis.from_url(config.REDIS_URL),
           name=f"vulnwatch-{n}-{int(time.time())}").work(with_scheduler=False)


def main():
    if not config.REDIS_URL:
        sys.exit("worker.py needs REDIS_URL (without it the web app runs jobs itself).")
    db.init()
    settings.apply_saved()
    jobs.reset_after_restart()
    n = max(1, config.WORKERS)
    print(f"worker: {n} slot(s) on {config.REDIS_URL.split('@')[-1]}, database {config.DB_PATH.name}", flush=True)

    procs, stopping = {}, False

    def shutdown(*_):
        nonlocal stopping
        stopping = True
        for p in procs.values():
            p.terminate()          # RQ: warm shutdown, the running job is stopped and marked by reset next start

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    while not stopping:
        for i in range(n):
            if i not in procs or not procs[i].is_alive():
                if i in procs:
                    print(f"worker: slot {i} exited ({procs[i].exitcode}), restarting", flush=True)
                procs[i] = mp.Process(target=slot, args=(i,), daemon=False)
                procs[i].start()
        time.sleep(2)
    for p in procs.values():
        p.join(timeout=20)


if __name__ == "__main__":
    main()

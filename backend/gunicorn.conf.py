"""
gunicorn.conf.py — Gunicorn configuration for InvisioVault backend.

Gunicorn auto-discovers this file when it is present in the working directory
(rootDir: backend in render.yaml). Keeping all server options here avoids
config drift between Procfile, render.yaml start commands, and code.

Reference: https://docs.gunicorn.org/en/stable/configure.html
"""
import os

# ---------------------------------------------------------------------------
# Server socket
# ---------------------------------------------------------------------------
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"

# ---------------------------------------------------------------------------
# Worker model
# ---------------------------------------------------------------------------
# Sync workers are the correct default for CPU-bound Flask workloads.
# 1 worker keeps RAM under Render's 512 MB free-tier limit.
workers = 1

# Two threads within the single worker handle overlapping I/O (e.g. health
# probes arriving while a file-hide operation is in progress).
threads = 2

# Request timeout in seconds. Image processing can be slow on the free tier.
timeout = 120

# Graceful shutdown timeout — allow in-flight requests to complete.
graceful_timeout = 30

# --preload: import the app once in the master process, then fork workers.
# Workers share the already-loaded code pages via Copy-on-Write → lower RAM.
#
# IMPORTANT: Do NOT start background threads before the fork (i.e., not inside
# create_app()). Threads started in the master process DO NOT survive os.fork()
# and will appear as dead threads inside workers. Use post_fork below instead.
preload_app = True

loglevel = os.getenv("LOG_LEVEL", "info").lower()

# ---------------------------------------------------------------------------
# Lifecycle hooks
# ---------------------------------------------------------------------------

def post_fork(server, worker):
    """
    Called inside each worker process immediately after os.fork().

    This is the ONLY safe place to start background threads when preload_app
    is True. Any thread created before this point (e.g. inside create_app())
    lives in the master process and does NOT transfer to the worker — the
    worker inherits a stale thread object whose underlying OS thread is gone.

    By starting the scheduler here we guarantee:
      - Exactly one scheduler thread per worker process.
      - The thread's lifetime is bounded by the worker's process lifetime.
      - No race between workers over the same global `_cleanup_scheduler`.
    """
    import os as _os
    from utils.cleanup import init_cleanup_scheduler

    upload_folder = _os.getenv("UPLOAD_FOLDER", "uploads")
    max_age_hours  = int(_os.getenv("FILE_MAX_AGE_HOURS",        "1"))
    interval_mins  = int(_os.getenv("CLEANUP_INTERVAL_MINUTES", "10"))

    scheduler = init_cleanup_scheduler(upload_folder, max_age_hours, interval_mins)

    # Stash on the worker object so child_exit can reference it if needed.
    worker._cleanup_scheduler = scheduler

    server.log.info(
        f"[worker {worker.pid}] FileCleanupScheduler started — "
        f"interval={interval_mins}m, max_age={max_age_hours}h, "
        f"folder={upload_folder!r}"
    )


def child_exit(server, worker):
    """
    Called inside the MASTER process when a worker exits (cleanly or otherwise).

    We cannot directly stop the worker's scheduler thread from here (different
    process), but the thread is a daemon thread so it will terminate
    automatically when the worker process exits. This hook is a log/audit point.
    """
    server.log.info(
        f"[worker {worker.pid}] exited — "
        "cleanup thread terminated with process (daemon=True)"
    )

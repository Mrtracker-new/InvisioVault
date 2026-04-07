"""Automatic cleanup of old uploaded files."""
import os
import time
import threading
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scheduler class
# ---------------------------------------------------------------------------

class FileCleanupScheduler:
    """Background scheduler that periodically deletes old upload files."""

    def __init__(self, upload_folder, max_age_hours=1):
        """
        Args:
            upload_folder: Path to the uploads directory.
            max_age_hours: Files older than this many hours are deleted.
        """
        self.upload_folder  = upload_folder
        self.max_age_seconds = max_age_hours * 3600
        self.running = False
        self.thread  = None

    def start(self, interval_minutes=10):
        """Start the background cleanup loop."""
        if self.running:
            logger.warning("Cleanup scheduler already running — ignoring duplicate start()")
            return

        self.running = True
        self.thread  = threading.Thread(
            target=self._run_scheduler,
            args=(interval_minutes,),
            daemon=True,   # Guaranteed to die with the process — no orphan threads.
            name="FileCleanupScheduler",
        )
        self.thread.start()
        logger.info(
            f"Cleanup scheduler started "
            f"(interval={interval_minutes}m, max_age={self.max_age_seconds / 3600:.1f}h, "
            f"folder={self.upload_folder!r})"
        )

    def stop(self):
        """Signal the scheduler to stop and block until it does (max 5 s)."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        logger.info("Cleanup scheduler stopped")

    def _run_scheduler(self, interval_minutes):
        """Internal loop — runs cleanup then sleeps, checking stop flag frequently."""
        interval_seconds = interval_minutes * 60

        while self.running:
            try:
                self.cleanup_old_files()
            except Exception as exc:
                logger.error(f"Unhandled error in cleanup: {exc}", exc_info=True)

            # Sleep in 1-second ticks so stop() is responsive.
            for _ in range(interval_seconds):
                if not self.running:
                    break
                time.sleep(1)

    def cleanup_old_files(self):
        """Delete files in upload_folder that are older than max_age_seconds."""
        if not os.path.exists(self.upload_folder):
            return

        now           = time.time()
        deleted_count = 0
        error_count   = 0

        try:
            # os.scandir() yields DirEntry objects that already carry stat info,
            # avoiding a second stat() call compared to os.listdir() + os.stat().
            with os.scandir(self.upload_folder) as it:
                for entry in it:
                    if not entry.is_file(follow_symlinks=False):
                        continue

                    try:
                        mtime    = entry.stat(follow_symlinks=False).st_mtime
                        file_age = now - mtime
                    except OSError:
                        # File disappeared between scandir and stat — race is benign.
                        continue

                    if file_age > self.max_age_seconds:
                        try:
                            os.remove(entry.path)
                            deleted_count += 1
                            logger.debug(
                                f"Deleted {entry.name!r} "
                                f"(age={file_age / 3600:.2f}h)"
                            )
                        except FileNotFoundError:
                            # Another worker or request already removed it — fine.
                            pass
                        except OSError as exc:
                            error_count += 1
                            logger.error(f"Failed to delete {entry.name!r}: {exc}")

        except OSError as exc:
            logger.error(f"Cannot scan upload folder {self.upload_folder!r}: {exc}")
            return

        if deleted_count:
            logger.info(f"Cleanup run: removed {deleted_count} file(s)")
        if error_count:
            logger.warning(f"Cleanup run: {error_count} deletion error(s)")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

# A lock makes init_cleanup_scheduler safe against the (unlikely) scenario
# where two threads in the same process call it simultaneously.
_init_lock        = threading.Lock()
_cleanup_scheduler: "FileCleanupScheduler | None" = None


def init_cleanup_scheduler(
    upload_folder: str,
    max_age_hours: int = 1,
    interval_minutes: int = 10,
) -> FileCleanupScheduler:
    """
    Create and start the process-level cleanup scheduler.

    Idempotent: if already initialized (within this process), returns the
    existing instance without starting a second thread.

    This function is intentionally NOT called from create_app().  It is
    called from:
      - gunicorn.conf.py post_fork hook  (production — one call per worker)
      - app.py __main__ block            (dev server — one call total)
    """
    global _cleanup_scheduler

    with _init_lock:
        if _cleanup_scheduler is not None:
            logger.warning(
                "init_cleanup_scheduler() called more than once in this process — "
                "returning existing scheduler"
            )
            return _cleanup_scheduler

        _cleanup_scheduler = FileCleanupScheduler(upload_folder, max_age_hours)
        _cleanup_scheduler.start(interval_minutes)
        return _cleanup_scheduler


def stop_cleanup_scheduler() -> None:
    """Stop and discard the process-level cleanup scheduler."""
    global _cleanup_scheduler

    with _init_lock:
        if _cleanup_scheduler is not None:
            _cleanup_scheduler.stop()
            _cleanup_scheduler = None

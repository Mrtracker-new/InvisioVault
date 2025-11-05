"""Automatic cleanup of old uploaded files."""
import os
import time
import threading
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class FileCleanupScheduler:
    """Background scheduler to clean up old files."""
    
    def __init__(self, upload_folder, max_age_hours=1):
        """
        Initialize the cleanup scheduler.
        
        Args:
            upload_folder: Path to the uploads directory
            max_age_hours: Maximum age of files in hours before deletion (default: 1 hour)
        """
        self.upload_folder = upload_folder
        self.max_age_seconds = max_age_hours * 3600
        self.running = False
        self.thread = None
        
    def start(self, interval_minutes=10):
        """
        Start the cleanup scheduler.
        
        Args:
            interval_minutes: How often to run cleanup (default: 10 minutes)
        """
        if self.running:
            logger.warning("Cleanup scheduler already running")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._run_scheduler, args=(interval_minutes,), daemon=True)
        self.thread.start()
        logger.info(f"Cleanup scheduler started (runs every {interval_minutes} minutes, deletes files older than {self.max_age_seconds/3600} hours)")
        
    def stop(self):
        """Stop the cleanup scheduler."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Cleanup scheduler stopped")
        
    def _run_scheduler(self, interval_minutes):
        """Internal method to run the cleanup loop."""
        interval_seconds = interval_minutes * 60
        
        while self.running:
            try:
                self.cleanup_old_files()
            except Exception as e:
                logger.error(f"Error during file cleanup: {e}")
            
            # Sleep in small chunks so we can stop quickly if needed
            for _ in range(interval_seconds):
                if not self.running:
                    break
                time.sleep(1)
                
    def cleanup_old_files(self):
        """Clean up files older than max_age_seconds."""
        if not os.path.exists(self.upload_folder):
            return
            
        now = time.time()
        deleted_count = 0
        
        try:
            for filename in os.listdir(self.upload_folder):
                file_path = os.path.join(self.upload_folder, filename)
                
                # Skip directories
                if not os.path.isfile(file_path):
                    continue
                    
                # Check file age
                file_age = now - os.path.getmtime(file_path)
                
                if file_age > self.max_age_seconds:
                    try:
                        os.remove(file_path)
                        deleted_count += 1
                        logger.debug(f"Deleted old file: {filename} (age: {file_age/3600:.2f} hours)")
                    except Exception as e:
                        logger.error(f"Failed to delete {filename}: {e}")
                        
            if deleted_count > 0:
                logger.info(f"Cleanup completed: deleted {deleted_count} old file(s)")
                
        except Exception as e:
            logger.error(f"Error listing files in {self.upload_folder}: {e}")


# Global instance
_cleanup_scheduler = None


def init_cleanup_scheduler(upload_folder, max_age_hours=1, interval_minutes=10):
    """
    Initialize and start the global cleanup scheduler.
    
    Args:
        upload_folder: Path to uploads directory
        max_age_hours: Maximum age of files before deletion (default: 1 hour)
        interval_minutes: How often to run cleanup (default: 10 minutes)
    """
    global _cleanup_scheduler
    
    if _cleanup_scheduler is not None:
        logger.warning("Cleanup scheduler already initialized")
        return _cleanup_scheduler
        
    _cleanup_scheduler = FileCleanupScheduler(upload_folder, max_age_hours)
    _cleanup_scheduler.start(interval_minutes)
    return _cleanup_scheduler


def stop_cleanup_scheduler():
    """Stop the global cleanup scheduler."""
    global _cleanup_scheduler
    
    if _cleanup_scheduler is not None:
        _cleanup_scheduler.stop()
        _cleanup_scheduler = None

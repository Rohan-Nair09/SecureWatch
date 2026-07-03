# monitoring/file_monitor.py
# File system monitor using watchdog to track file activities.


import os
import sys
import logging
import threading
import getpass
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db
from monitoring import detector
from integrity import hash_checker

logger = logging.getLogger(__name__)

_observer: Observer | None = None
_lock = threading.Lock()


def _get_file_info(path: str) -> tuple[int, str]:
    # Get file size and extension
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    ext = os.path.splitext(path)[1].lower() if path else ""
    return size, ext


def _get_process_name() -> str:
    # Best-effort to get current process name
    try:
        import psutil
        return psutil.Process(os.getpid()).name()
    except Exception:
        return "unknown"


class SecureWatchHandler(FileSystemEventHandler):
    # Handles watchdog file system events

    def _process(self, event_type: str, src_path: str, dest_path: str = None):
        # Save event to DB and evaluate rules
        filename = os.path.basename(src_path)
        if not filename or filename.startswith(".securewatch"):
            return  # Skip our own probe files

        is_sensitive = hash_checker.is_sensitive_file(src_path)
        file_size, file_ext = _get_file_info(src_path)
        user = getpass.getuser()

        with _lock:
            event_id = db.insert_file_event(
                filename=filename,
                event_type=event_type,
                source_path=src_path,
                destination_path=dest_path,
                user=user,
                process_name=_get_process_name(),
                file_size=file_size,
                file_extension=file_ext,
                is_sensitive=is_sensitive,
            )

        event_dict = {
            "id": event_id,
            "filename": filename,
            "event_type": event_type,
            "source_path": src_path,
            "destination_path": dest_path,
            "user": user,
            "file_size": file_size,
            "is_sensitive": is_sensitive,
        }

        # Run detection rules
        try:
            detector.evaluate(event_dict)
        except Exception as e:
            logger.error("Detector error: %s", e)

        logger.debug("[%s] %s | %s", event_type.upper(), filename, src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._process("created", event.src_path)
            # Establish integrity baseline for new sensitive files
            if hash_checker.is_sensitive_file(event.src_path):
                hash_checker.store_baseline(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._process("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._process("moved", event.src_path, event.dest_path)


def start_monitoring():
    # Start monitoring configured directories in background
    global _observer

    if _observer and _observer.is_alive():
        logger.warning("File monitor already running.")
        return

    handler = SecureWatchHandler()
    _observer = Observer()

    mounted = 0
    for directory in config.MONITORED_DIRS:
        if os.path.isdir(directory):
            _observer.schedule(handler, directory, recursive=True)
            logger.info("Monitoring: %s", directory)
            mounted += 1
        else:
            logger.warning("Directory not found, skipping: %s", directory)

    if mounted == 0:
        logger.error("No valid directories to monitor!")
        return

    _observer.daemon = True
    _observer.start()
    logger.info("File monitor started -- watching %d director%s",
                mounted, "y" if mounted == 1 else "ies")


def stop_monitoring():
    # Stop the monitoring observer
    global _observer
    if _observer and _observer.is_alive():
        _observer.stop()
        _observer.join(timeout=5)
        logger.info("File monitor stopped.")
    _observer = None


def is_running() -> bool:
    return bool(_observer and _observer.is_alive())

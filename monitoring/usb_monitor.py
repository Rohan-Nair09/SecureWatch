# monitoring/usb_monitor.py
# Monitors USB drive insertions and tracks file activity.


import os
import sys
import logging
import threading
import getpass
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db
from alerts import alert_manager
from integrity import hash_checker

logger = logging.getLogger(__name__)

_usb_thread: threading.Thread | None = None
_stop_event = threading.Event()
_known_drives: set[str] = set()

# watchdog imports (for per-drive monitoring once inserted)
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("watchdog not available — USB per-file monitoring disabled")

_drive_observers: dict[str, object] = {}


def _get_removable_drives() -> set[str]:
    # Get currently mounted USB drive paths
    removable = set()
    try:
        import psutil
        for part in psutil.disk_partitions(all=False):
            # Windows: check opts for 'removable' or drive letters in USB_DRIVE_LETTERS
            is_removable = (
                "removable" in part.opts.lower()
                or part.device.rstrip("\\").upper() in config.USB_DRIVE_LETTERS
            )
            if is_removable and os.path.exists(part.mountpoint):
                removable.add(part.mountpoint)
    except Exception as e:
        logger.debug("psutil disk_partitions error: %s", e)
    return removable


class USBFileHandler(FileSystemEventHandler):
    # Handles file events on USB drive

    def __init__(self, drive_path: str):
        super().__init__()
        self.drive_path = drive_path

    def _handle(self, event_type: str, src_path: str, dest_path: str = None):
        filename = os.path.basename(src_path)
        if not filename:
            return

        is_sensitive = hash_checker.is_sensitive_file(src_path)
        file_size = 0
        try:
            file_size = os.path.getsize(src_path)
        except OSError:
            pass
        ext = os.path.splitext(src_path)[1].lower()
        user = getpass.getuser()

        event_id = db.insert_file_event(
            filename=filename,
            event_type=event_type,
            source_path=src_path,
            destination_path=dest_path,
            user=user,
            process_name="usb_monitor",
            file_size=file_size,
            file_extension=ext,
            is_sensitive=is_sensitive,
        )

        if is_sensitive:
            alert_manager.alert_usb_transfer(
                filename=filename,
                source_path=src_path,
                destination_path=self.drive_path,
                user=user,
                event_id=event_id,
            )
            logger.warning("Sensitive file on USB: %s @ %s", filename, self.drive_path)

    def on_created(self, event):
        if not event.is_directory:
            self._handle("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle("modified", event.src_path)


def _scan_existing_usb_files(drive_path: str, user: str):
    # Scan files on newly inserted USB drive in background
    logger.info("Starting background scan of USB drive: %s", drive_path)
    sensitive_count = 0
    total_files = 0
    try:
        for root, dirs, files in os.walk(drive_path):
            if _stop_event.is_set():
                break
            if drive_path not in _known_drives:
                logger.info("USB drive %s removed. Aborting scan.", drive_path)
                break

            for file in files:
                if _stop_event.is_set():
                    break
                if drive_path not in _known_drives:
                    break

                full_path = os.path.join(root, file)
                total_files += 1
                try:
                    if hash_checker.is_sensitive_file(full_path):
                        sensitive_count += 1
                        filename = file
                        ext = os.path.splitext(file)[1].lower()
                        file_size = os.path.getsize(full_path)

                        # Register in DB as 'scanned'
                        event_id = db.insert_file_event(
                            filename=filename,
                            event_type="scanned",
                            source_path=full_path,
                            destination_path=drive_path,
                            user=user,
                            process_name="usb_scan",
                            file_size=file_size,
                            file_extension=ext,
                            is_sensitive=True,
                        )

                        # Raise alert
                        desc = (
                            f"Sensitive file '{filename}' was found on removable USB drive "
                            f"during insertion scan. Location: '{full_path}'. User: {user}."
                        )
                        alert_manager.create_alert(
                            severity=alert_manager.Severity.HIGH,
                            alert_type=alert_manager.AlertType.USB_TRANSFER,
                            filename=filename,
                            source_path=full_path,
                            destination_path=drive_path,
                            description=desc,
                            user=user,
                            event_id=event_id,
                        )
                except Exception as e:
                    logger.debug("Error scanning file %s: %s", full_path, e)
    except Exception as e:
        logger.error("Error during USB scan of %s: %s", drive_path, e)

    logger.info("Finished USB scan of %s. Total files: %d, Sensitive: %d",
                drive_path, total_files, sensitive_count)


def _on_drive_inserted(drive_path: str):
    # Handle new USB connection
    logger.warning("USB drive inserted: %s", drive_path)
    user = getpass.getuser()

    # Log a drive-insertion alert
    alert_manager.create_alert(
        severity=alert_manager.Severity.HIGH,
        alert_type="USB Device Connected",
        filename=None,
        source_path=drive_path,
        description=(
            f"Removable drive connected at '{drive_path}'. "
            f"User: {user}. Scanning for sensitive files and monitoring activity."
        ),
        user=user,
    )

    # Start a watchdog observer on the USB drive (if watchdog available)
    if WATCHDOG_AVAILABLE and os.path.isdir(drive_path):
        try:
            obs = Observer()
            obs.schedule(USBFileHandler(drive_path), drive_path, recursive=True)
            obs.daemon = True
            obs.start()
            _drive_observers[drive_path] = obs
            logger.info("Started USB file monitor on %s", drive_path)
        except Exception as e:
            logger.error("Cannot start USB observer on %s: %s", drive_path, e)

    # Start background drive scan
    scan_thread = threading.Thread(
        target=_scan_existing_usb_files,
        args=(drive_path, user),
        name=f"USBScan-{drive_path.strip(':\\/')}",
        daemon=True
    )
    scan_thread.start()


def _on_drive_removed(drive_path: str):
    # Handle USB ejection
    logger.info("USB drive removed: %s", drive_path)
    user = getpass.getuser()

    alert_manager.create_alert(
        severity=alert_manager.Severity.MEDIUM,
        alert_type="USB Device Disconnected",
        filename=None,
        source_path=drive_path,
        description=f"Removable drive '{drive_path}' was disconnected. Monitor stopped.",
        user=user,
    )

    obs = _drive_observers.pop(drive_path, None)
    if obs:
        try:
            obs.stop()
            obs.join(timeout=3)
        except Exception:
            pass


def _poll_loop():
    # Poll for USB insertion/removals
    global _known_drives
    _known_drives = _get_removable_drives()
    logger.info("USB monitor started. Known drives: %s", _known_drives or "none")

    while not _stop_event.is_set():
        try:
            current_drives = _get_removable_drives()

            inserted = current_drives - _known_drives
            removed  = _known_drives  - current_drives

            for drive in inserted:
                _on_drive_inserted(drive)
            for drive in removed:
                _on_drive_removed(drive)

            _known_drives = current_drives
        except Exception as e:
            logger.error("USB poll error: %s", e)

        _stop_event.wait(timeout=config.USB_POLL_INTERVAL)


def start_usb_monitor():
    # Start the monitor thread
    global _usb_thread
    _stop_event.clear()
    _usb_thread = threading.Thread(target=_poll_loop, name="USBMonitor", daemon=True)
    _usb_thread.start()
    logger.info("USB monitor thread started (poll interval: %ds)", config.USB_POLL_INTERVAL)


def stop_usb_monitor():
    # Stop monitor and cleanup observers
    _stop_event.set()
    if _usb_thread:
        _usb_thread.join(timeout=10)
    for obs in _drive_observers.values():
        try:
            obs.stop()
        except Exception:
            pass
    _drive_observers.clear()
    logger.info("USB monitor stopped.")


def is_running() -> bool:
    return bool(_usb_thread and _usb_thread.is_alive())

# monitoring/detector.py
# Evaluates file system events against configured rules to trigger alerts.


import os
import sys
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from alerts import alert_manager
from integrity import hash_checker

logger = logging.getLogger(__name__)

# Sliding window storage for rule evaluation

# Rule 1 — Bulk transfer: deque of event timestamps
_bulk_window: deque = deque()

# Rule 5 — Repeated access: {filepath: deque of timestamps}
_access_window: dict[str, deque] = defaultdict(deque)


def _clean_window(dq: deque, window_minutes: int):
    """Remove timestamps older than the window."""
    cutoff = datetime.now() - timedelta(minutes=window_minutes)
    while dq and dq[0] < cutoff:
        dq.popleft()


def _is_cloud_path(path: str) -> bool:
    if not path:
        return False
    path_lower = path.lower()
    for cp in config.CLOUD_PATHS:
        if path_lower.startswith(cp.lower()):
            return True
    return False


def _is_network_path(path: str) -> bool:
    if not path:
        return False
    return path.startswith("\\\\") or path.startswith("//")


def _is_usb_path(path: str) -> bool:
    if not path:
        return False
    # Check configured USB drive letters
    for letter in config.USB_DRIVE_LETTERS:
        if path.upper().startswith(letter.upper()):
            return True
    # Check simulated USB path
    if path.startswith(config.SIM_USB_PATH):
        return True
    return False


def _is_outside_protected(path: str) -> bool:
    """Return True if path is NOT inside any protected directory."""
    if not path:
        return True
    path_real = os.path.realpath(path)
    for protected in config.PROTECTED_DIRS:
        try:
            if path_real.startswith(os.path.realpath(protected)):
                return False
        except Exception:
            pass
    return True


def evaluate(event: dict) -> list[int]:
    # Evaluate a file event and trigger corresponding alerts
    alert_ids = []
    filename     = event.get("filename", "")
    event_type   = event.get("event_type", "")
    source_path  = event.get("source_path", "")
    dest_path    = event.get("destination_path", "") or ""
    user         = event.get("user", config.SYSTEM_USER)
    file_size    = event.get("file_size", 0) or 0
    is_sensitive = event.get("is_sensitive", False)
    event_id     = event.get("id")

    now = datetime.now()

    # Rule 1: Bulk Transfer
    _bulk_window.append(now)
    _clean_window(_bulk_window, config.BULK_TRANSFER_WINDOW_MINUTES)
    if len(_bulk_window) >= config.BULK_TRANSFER_THRESHOLD:
        aid = alert_manager.alert_bulk_transfer(
            count=len(_bulk_window),
            window_minutes=config.BULK_TRANSFER_WINDOW_MINUTES,
            user=user,
            event_id=event_id,
        )
        alert_ids.append(aid)
        _bulk_window.clear()  # Reset to avoid duplicate alerts
        logger.info("Rule 1 fired: Bulk Transfer")

    # Rule 2: Sensitive Data Transfer
    if is_sensitive:
        effective_dest = dest_path or source_path
        if event_type in ("moved", "copied") and _is_outside_protected(effective_dest):
            # USB?
            if _is_usb_path(effective_dest):
                aid = alert_manager.alert_usb_transfer(
                    filename=filename, source_path=source_path,
                    destination_path=effective_dest, user=user, event_id=event_id
                )
                alert_ids.append(aid)
                logger.info("Rule 2 fired: USB Transfer of sensitive file")

            # Cloud?
            elif _is_cloud_path(effective_dest):
                aid = alert_manager.alert_cloud_upload(
                    filename=filename, source_path=source_path,
                    destination_path=effective_dest, user=user, event_id=event_id
                )
                alert_ids.append(aid)
                logger.info("Rule 2 fired: Cloud Upload of sensitive file")

            # Network share?
            elif _is_network_path(effective_dest):
                aid = alert_manager.alert_network_share(
                    filename=filename, source_path=source_path,
                    destination_path=effective_dest, user=user, event_id=event_id
                )
                alert_ids.append(aid)
                logger.info("Rule 2 fired: Network Share Transfer")

            else:
                # Generic sensitive transfer outside protected dir
                aid = alert_manager.alert_sensitive_transfer(
                    filename=filename, source_path=source_path,
                    destination_path=effective_dest, user=user, event_id=event_id
                )
                alert_ids.append(aid)
                logger.info("Rule 2 fired: Sensitive File Transfer outside protected dir")

        # Sensitive file deleted
        if event_type == "deleted":
            aid = alert_manager.alert_sensitive_deleted(
                filename=filename, filepath=source_path,
                user=user, event_id=event_id
            )
            alert_ids.append(aid)
            logger.info("Rule 2 fired: Sensitive File Deleted")

    # Rule 3: Large File Transfer
    if file_size > 0:
        size_mb = file_size / (1024 * 1024)
        if size_mb >= config.LARGE_FILE_THRESHOLD_MB:
            aid = alert_manager.alert_large_file(
                filename=filename, size_mb=size_mb,
                source_path=source_path, destination_path=dest_path,
                user=user, event_id=event_id
            )
            alert_ids.append(aid)
            logger.info("Rule 3 fired: Large File Transfer (%.1f MB)", size_mb)

    # Rule 4: Unusual Destination
    if dest_path and event_type in ("moved", "copied"):
        if _is_usb_path(dest_path) and not is_sensitive:
            # Non-sensitive to USB — still worth flagging at MEDIUM
            from alerts.alert_manager import create_alert, Severity, AlertType
            aid = create_alert(
                severity=Severity.MEDIUM,
                alert_type=AlertType.UNUSUAL_DESTINATION,
                filename=filename,
                source_path=source_path,
                destination_path=dest_path,
                description=(
                    f"File '{filename}' transferred to a removable drive at '{dest_path}'. "
                    f"User: {user}. Verify this was authorized."
                ),
                user=user,
                event_id=event_id,
            )
            alert_ids.append(aid)
            logger.info("Rule 4 fired: Unusual Destination (USB)")

    # Rule 5: Repeated Access
    if is_sensitive and event_type in ("modified", "accessed", "created"):
        fp = source_path or filename
        _access_window[fp].append(now)
        _clean_window(_access_window[fp], config.REPEATED_ACCESS_WINDOW_MINUTES)
        count = len(_access_window[fp])
        if count >= config.REPEATED_ACCESS_THRESHOLD:
            aid = alert_manager.alert_repeated_access(
                filename=filename, filepath=fp,
                count=count,
                window_minutes=config.REPEATED_ACCESS_WINDOW_MINUTES,
                user=user, event_id=event_id
            )
            alert_ids.append(aid)
            _access_window[fp].clear()  # Reset to avoid spam
            logger.info("Rule 5 fired: Repeated Access (%d times)", count)

    # File Integrity Verification
    if is_sensitive and source_path and os.path.isfile(source_path):
        result = hash_checker.verify_integrity(source_path)
        if result["status"] == "MISMATCH":
            aid = alert_manager.alert_integrity_violation(
                filename=filename,
                filepath=source_path,
                original_hash=result["original_hash"],
                current_hash=result["current_hash"],
                user=user,
                event_id=event_id,
            )
            alert_ids.append(aid)
            logger.warning("Integrity violation: %s", filename)

    return alert_ids

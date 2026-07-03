# alerts/alert_manager.py
# Manage alert generation, status changes, and database storage.


import logging
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db

logger = logging.getLogger(__name__)

# Severity Levels
class Severity:
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"

# Alert Categories
class AlertType:
    SENSITIVE_TRANSFER      = "Sensitive File Transfer"
    USB_TRANSFER            = "USB Transfer"
    INTEGRITY_VIOLATION     = "Integrity Violation"
    BULK_TRANSFER           = "Bulk Transfer"
    LARGE_FILE              = "Large File Transfer"
    UNUSUAL_DESTINATION     = "Unusual Destination"
    REPEATED_ACCESS         = "Repeated Access"
    UNAUTHORIZED_ACCESS     = "Unauthorized Access"
    CLOUD_UPLOAD            = "Cloud Upload"
    NETWORK_SHARE           = "Network Share Transfer"
    FILE_DELETED            = "Sensitive File Deleted"
    FILE_CREATED            = "Sensitive File Created"


def create_alert(
    severity: str,
    alert_type: str,
    filename: str = None,
    source_path: str = None,
    destination_path: str = None,
    description: str = None,
    user: str = None,
    event_id: int = None,
) -> int:
    # Persist alert to database and print log warning
    if filename:
        override_sev = config.get_file_severity(filename)
        if override_sev:
            severity = override_sev

    alert_id = db.insert_alert(
        severity=severity,
        alert_type=alert_type,
        filename=filename,
        source_path=source_path,
        destination_path=destination_path,
        description=description,
        user=user,
        event_id=event_id,
    )

    icon = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]"}.get(severity, "[INFO]")
    logger.warning(
        "%s [%s] %s | File: %s | %s",
        icon, severity, alert_type, filename or "N/A", description or ""
    )
    return alert_id


def resolve_alert(alert_id: int) -> bool:
    # Mark alert as resolved
    return db.resolve_alert(alert_id)


def investigate_alert(alert_id: int) -> bool:
    # Mark alert as investigating
    return db.update_alert_status(alert_id, "INVESTIGATING")


def get_alerts(limit: int = 200, offset: int = 0, severity: str = None,
               status: str = None, user: str = None, search: str = None,
               date_from: str = None, date_to: str = None) -> list:
    return db.get_alerts(
        limit=limit, offset=offset, severity=severity, status=status,
        user=user, search=search, date_from=date_from, date_to=date_to
    )


# Common scenario alert helpers

def alert_usb_transfer(filename: str, source_path: str,
                        destination_path: str, user: str, event_id: int = None):
    desc = (
        f"Sensitive file '{filename}' was copied to a removable USB drive. "
        f"Source: {source_path} -> Destination: {destination_path}. "
        f"User: {user}. This may indicate data exfiltration."
    )
    return create_alert(
        severity=Severity.CRITICAL,
        alert_type=AlertType.USB_TRANSFER,
        filename=filename,
        source_path=source_path,
        destination_path=destination_path,
        description=desc,
        user=user,
        event_id=event_id,
    )


def alert_integrity_violation(filename: str, filepath: str,
                               original_hash: str, current_hash: str,
                               user: str = None, event_id: int = None):
    desc = (
        f"File integrity violation detected for '{filename}'. "
        f"SHA-256 mismatch — Original: {original_hash[:16]}... | "
        f"Current: {(current_hash or 'N/A')[:16]}... "
        f"The file may have been tampered with."
    )
    return create_alert(
        severity=Severity.CRITICAL,
        alert_type=AlertType.INTEGRITY_VIOLATION,
        filename=filename,
        source_path=filepath,
        description=desc,
        user=user,
        event_id=event_id,
    )


def alert_sensitive_transfer(filename: str, source_path: str,
                              destination_path: str, user: str,
                              event_id: int = None):
    desc = (
        f"Sensitive file '{filename}' was transferred outside a protected directory. "
        f"Source: {source_path} -> Destination: {destination_path}. "
        f"User: {user}. Review immediately."
    )
    return create_alert(
        severity=Severity.HIGH,
        alert_type=AlertType.SENSITIVE_TRANSFER,
        filename=filename,
        source_path=source_path,
        destination_path=destination_path,
        description=desc,
        user=user,
        event_id=event_id,
    )


def alert_bulk_transfer(count: int, window_minutes: int,
                         user: str, event_id: int = None):
    desc = (
        f"Bulk file transfer detected: {count} files moved/copied within "
        f"{window_minutes} minutes by user '{user}'. "
        f"This may indicate data exfiltration or insider threat activity."
    )
    return create_alert(
        severity=Severity.HIGH,
        alert_type=AlertType.BULK_TRANSFER,
        description=desc,
        user=user,
        event_id=event_id,
    )


def alert_large_file(filename: str, size_mb: float, source_path: str,
                      destination_path: str, user: str, event_id: int = None):
    desc = (
        f"Large file transfer detected: '{filename}' ({size_mb:.1f} MB) "
        f"was moved from {source_path} to {destination_path}. "
        f"Threshold: {config.LARGE_FILE_THRESHOLD_MB} MB. User: {user}."
    )
    return create_alert(
        severity=Severity.MEDIUM,
        alert_type=AlertType.LARGE_FILE,
        filename=filename,
        source_path=source_path,
        destination_path=destination_path,
        description=desc,
        user=user,
        event_id=event_id,
    )


def alert_cloud_upload(filename: str, source_path: str,
                        destination_path: str, user: str, event_id: int = None):
    desc = (
        f"Cloud storage upload detected: '{filename}' copied to "
        f"'{destination_path}'. This may violate data governance policies. "
        f"User: {user}."
    )
    return create_alert(
        severity=Severity.HIGH,
        alert_type=AlertType.CLOUD_UPLOAD,
        filename=filename,
        source_path=source_path,
        destination_path=destination_path,
        description=desc,
        user=user,
        event_id=event_id,
    )


def alert_network_share(filename: str, source_path: str,
                         destination_path: str, user: str, event_id: int = None):
    desc = (
        f"Network share transfer detected: '{filename}' sent to "
        f"'{destination_path}'. Verify this transfer was authorized. "
        f"User: {user}."
    )
    return create_alert(
        severity=Severity.HIGH,
        alert_type=AlertType.NETWORK_SHARE,
        filename=filename,
        source_path=source_path,
        destination_path=destination_path,
        description=desc,
        user=user,
        event_id=event_id,
    )


def alert_repeated_access(filename: str, filepath: str,
                           count: int, window_minutes: int,
                           user: str, event_id: int = None):
    desc = (
        f"Repeated access to sensitive file '{filename}': "
        f"accessed {count} times within {window_minutes} minutes. "
        f"User: {user}. Possible data reconnaissance."
    )
    return create_alert(
        severity=Severity.MEDIUM,
        alert_type=AlertType.REPEATED_ACCESS,
        filename=filename,
        source_path=filepath,
        description=desc,
        user=user,
        event_id=event_id,
    )


def alert_sensitive_deleted(filename: str, filepath: str,
                             user: str, event_id: int = None):
    desc = (
        f"Sensitive file '{filename}' was DELETED from '{filepath}'. "
        f"User: {user}. Immediate investigation recommended."
    )
    return create_alert(
        severity=Severity.CRITICAL,
        alert_type=AlertType.FILE_DELETED,
        filename=filename,
        source_path=filepath,
        description=desc,
        user=user,
        event_id=event_id,
    )

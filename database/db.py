# database/db.py
# SQLite database wrapper for storing file events, alerts, and integrity checks.


import sqlite3
import threading
import logging
from datetime import datetime, timedelta
from contextlib import contextmanager

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger(__name__)

_local = threading.local()


def get_connection() -> sqlite3.Connection:
    """Return a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
    return _local.conn


@contextmanager
def get_db():
    """Context manager yielding a cursor and auto-committing."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"DB error: {e}")
        raise
    finally:
        cursor.close()


# Schema Setup

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS file_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    filename         TEXT    NOT NULL,
    event_type       TEXT    NOT NULL,
    source_path      TEXT,
    destination_path TEXT,
    timestamp        TEXT    NOT NULL,
    user             TEXT,
    process_name     TEXT,
    file_size        INTEGER DEFAULT 0,
    file_extension   TEXT,
    is_sensitive     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS integrity_checks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    filename      TEXT NOT NULL,
    filepath      TEXT NOT NULL,
    original_hash TEXT,
    current_hash  TEXT,
    status        TEXT NOT NULL,   -- MATCH | MISMATCH | NEW | DELETED
    timestamp     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    severity         TEXT NOT NULL,   -- CRITICAL | HIGH | MEDIUM | LOW
    alert_type       TEXT NOT NULL,
    filename         TEXT,
    source_path      TEXT,
    destination_path TEXT,
    description      TEXT,
    timestamp        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE | RESOLVED | INVESTIGATING
    user             TEXT,
    event_id         INTEGER
);

CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT UNIQUE NOT NULL,
    activity_count INTEGER DEFAULT 0,
    alert_count    INTEGER DEFAULT 0,
    last_activity  TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON file_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_filename   ON file_events(filename);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts(timestamp);
"""


def init_db():
    """Create all tables and indexes."""
    conn = get_connection()
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    logger.info("Database initialised at %s", config.DB_PATH)


# File events operations

def insert_file_event(filename: str, event_type: str, source_path: str = None,
                      destination_path: str = None, user: str = None,
                      process_name: str = None, file_size: int = 0,
                      file_extension: str = None, is_sensitive: bool = False) -> int:
    timestamp = datetime.now().isoformat(timespec="seconds")
    with get_db() as cur:
        cur.execute(
            """INSERT INTO file_events
               (filename, event_type, source_path, destination_path, timestamp,
                user, process_name, file_size, file_extension, is_sensitive)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (filename, event_type, source_path, destination_path, timestamp,
             user or config.SYSTEM_USER, process_name or "unknown",
             file_size, file_extension, int(is_sensitive))
        )
        _upsert_user(user or config.SYSTEM_USER, cur)
        return cur.lastrowid


def get_file_events(limit: int = 200, offset: int = 0, search: str = None,
                    event_type: str = None, user: str = None,
                    date_from: str = None, date_to: str = None) -> list:
    query = "SELECT * FROM file_events WHERE 1=1"
    params = []
    if search:
        query += " AND (filename LIKE ? OR source_path LIKE ? OR destination_path LIKE ?)"
        s = f"%{search}%"
        params += [s, s, s]
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if user:
        query += " AND user = ?"
        params.append(user)
    if date_from:
        query += " AND timestamp >= ?"
        params.append(date_from)
    if date_to:
        query += " AND timestamp <= ?"
        params.append(date_to)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    with get_db() as cur:
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


def count_file_events(minutes: int = None) -> int:
    with get_db() as cur:
        if minutes:
            since = (datetime.now() - timedelta(minutes=minutes)).isoformat()
            cur.execute("SELECT COUNT(*) FROM file_events WHERE timestamp >= ?", (since,))
        else:
            cur.execute("SELECT COUNT(*) FROM file_events")
        return cur.fetchone()[0]


def get_recent_events_by_file(filepath: str, minutes: int = 10) -> list:
    since = (datetime.now() - timedelta(minutes=minutes)).isoformat()
    with get_db() as cur:
        cur.execute(
            "SELECT * FROM file_events WHERE source_path=? AND timestamp>=? ORDER BY timestamp DESC",
            (filepath, since)
        )
        return [dict(r) for r in cur.fetchall()]


def count_events_window(minutes: int = 5) -> int:
    since = (datetime.now() - timedelta(minutes=minutes)).isoformat()
    with get_db() as cur:
        cur.execute("SELECT COUNT(*) FROM file_events WHERE timestamp >= ?", (since,))
        return cur.fetchone()[0]


# Integrity checks operations

def insert_integrity_check(filename: str, filepath: str, original_hash: str,
                            current_hash: str, status: str) -> int:
    timestamp = datetime.now().isoformat(timespec="seconds")
    with get_db() as cur:
        cur.execute(
            """INSERT INTO integrity_checks
               (filename, filepath, original_hash, current_hash, status, timestamp)
               VALUES (?,?,?,?,?,?)""",
            (filename, filepath, original_hash, current_hash, status, timestamp)
        )
        return cur.lastrowid


def get_integrity_baseline(filepath: str) -> dict | None:
    with get_db() as cur:
        cur.execute(
            "SELECT * FROM integrity_checks WHERE filepath=? AND status='NEW' ORDER BY id DESC LIMIT 1",
            (filepath,)
        )
        row = cur.fetchone()
        return dict(row) if row else None


def get_integrity_checks(limit: int = 200, status: str = None) -> list:
    query = "SELECT * FROM integrity_checks WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_db() as cur:
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


def count_integrity_violations() -> int:
    with get_db() as cur:
        cur.execute("SELECT COUNT(*) FROM integrity_checks WHERE status='MISMATCH'")
        return cur.fetchone()[0]


# Alerts operations

def insert_alert(severity: str, alert_type: str, filename: str = None,
                 source_path: str = None, destination_path: str = None,
                 description: str = None, user: str = None,
                 event_id: int = None) -> int:
    timestamp = datetime.now().isoformat(timespec="seconds")
    with get_db() as cur:
        cur.execute(
            """INSERT INTO alerts
               (severity, alert_type, filename, source_path, destination_path,
                description, timestamp, status, user, event_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (severity, alert_type, filename, source_path, destination_path,
             description, timestamp, "ACTIVE", user or config.SYSTEM_USER, event_id)
        )
        if user:
            _upsert_user_alert(user, cur)
        return cur.lastrowid


def get_alerts(limit: int = 200, offset: int = 0, severity: str = None,
               status: str = None, user: str = None, search: str = None,
               date_from: str = None, date_to: str = None) -> list:
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)
    if user:
        query += " AND user = ?"
        params.append(user)
    if search:
        query += " AND (filename LIKE ? OR description LIKE ? OR alert_type LIKE ?)"
        s = f"%{search}%"
        params += [s, s, s]
    if date_from:
        query += " AND timestamp >= ?"
        params.append(date_from)
    if date_to:
        query += " AND timestamp <= ?"
        params.append(date_to)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    with get_db() as cur:
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


def resolve_alert(alert_id: int) -> bool:
    with get_db() as cur:
        cur.execute(
            "UPDATE alerts SET status='RESOLVED' WHERE id=?", (alert_id,)
        )
        return cur.rowcount > 0


def update_alert_status(alert_id: int, status: str) -> bool:
    with get_db() as cur:
        cur.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
        return cur.rowcount > 0


def count_active_alerts() -> int:
    with get_db() as cur:
        cur.execute("SELECT COUNT(*) FROM alerts WHERE status='ACTIVE'")
        return cur.fetchone()[0]


def count_alerts_by_severity(severity: str) -> int:
    with get_db() as cur:
        cur.execute("SELECT COUNT(*) FROM alerts WHERE severity=?", (severity,))
        return cur.fetchone()[0]


def count_alerts_by_type(alert_type: str) -> int:
    with get_db() as cur:
        cur.execute("SELECT COUNT(*) FROM alerts WHERE alert_type=?", (alert_type,))
        return cur.fetchone()[0]


# User tracking operations

def _upsert_user(username: str, cur: sqlite3.Cursor):
    now = datetime.now().isoformat(timespec="seconds")
    cur.execute(
        """INSERT INTO users (username, activity_count, last_activity)
           VALUES (?, 1, ?)
           ON CONFLICT(username) DO UPDATE SET
               activity_count = activity_count + 1,
               last_activity  = excluded.last_activity""",
        (username, now)
    )


def _upsert_user_alert(username: str, cur: sqlite3.Cursor):
    now = datetime.now().isoformat(timespec="seconds")
    cur.execute(
        """INSERT INTO users (username, alert_count, last_activity)
           VALUES (?, 1, ?)
           ON CONFLICT(username) DO UPDATE SET
               alert_count   = alert_count + 1,
               last_activity = excluded.last_activity""",
        (username, now)
    )


def get_users(limit: int = 50) -> list:
    with get_db() as cur:
        cur.execute(
            "SELECT * FROM users ORDER BY activity_count DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


# Analytics and statistics queries

def get_folder_stats(folders: list) -> list:
    """Return statistics (event count, alert count, last activity) for specific folders."""
    stats = []
    with get_db() as cur:
        for folder in folders:
            # Normalise path for LIKE clause
            norm_folder = folder.rstrip("\\/") + "%"
            
            cur.execute("SELECT COUNT(*), MAX(timestamp) FROM file_events WHERE source_path LIKE ?", (norm_folder,))
            event_row = cur.fetchone()
            event_count = event_row[0] or 0
            last_event = event_row[1]
            
            cur.execute("SELECT COUNT(*), MAX(timestamp) FROM alerts WHERE source_path LIKE ?", (norm_folder,))
            alert_row = cur.fetchone()
            alert_count = alert_row[0] or 0
            last_alert = alert_row[1]
            
            last_activity = None
            if last_event and last_alert:
                last_activity = max(last_event, last_alert)
            else:
                last_activity = last_event or last_alert
                
            stats.append({
                "path": folder,
                "event_count": event_count,
                "alert_count": alert_count,
                "last_activity": last_activity
            })
    return stats

def get_alert_trends(days: int = 7) -> dict:
    """Return daily alert counts by severity for the past N days."""
    since = (datetime.now() - timedelta(days=days)).date().isoformat()
    with get_db() as cur:
        cur.execute(
            """SELECT DATE(timestamp) as day, severity, COUNT(*) as cnt
               FROM alerts WHERE timestamp >= ?
               GROUP BY day, severity ORDER BY day""",
            (since,)
        )
        rows = cur.fetchall()

    labels = []
    data = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    day_map = {}
    for row in rows:
        d = row["day"]
        if d not in day_map:
            day_map[d] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        day_map[d][row["severity"]] = row["cnt"]

    for i in range(days):
        d = (datetime.now() - timedelta(days=days - 1 - i)).date().isoformat()
        labels.append(d)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            data[sev].append(day_map.get(d, {}).get(sev, 0))

    return {"labels": labels, "datasets": data}


def get_top_sensitive_files(limit: int = 10) -> list:
    with get_db() as cur:
        cur.execute(
            """SELECT filename, COUNT(*) as access_count
               FROM file_events WHERE is_sensitive=1
               GROUP BY filename ORDER BY access_count DESC LIMIT ?""",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


def get_violation_breakdown() -> dict:
    with get_db() as cur:
        cur.execute(
            """SELECT alert_type, COUNT(*) as cnt
               FROM alerts GROUP BY alert_type ORDER BY cnt DESC"""
        )
        rows = cur.fetchall()
    return {r["alert_type"]: r["cnt"] for r in rows}


def get_hourly_timeline() -> dict:
    """Return hourly event counts for today."""
    today = datetime.now().date().isoformat()
    with get_db() as cur:
        cur.execute(
            """SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt
               FROM file_events WHERE DATE(timestamp)=?
               GROUP BY hour ORDER BY hour""",
            (today,)
        )
        rows = cur.fetchall()

    labels = [f"{h:02d}:00" for h in range(24)]
    counts = [0] * 24
    for row in rows:
        counts[int(row["hour"])] = row["cnt"]
    return {"labels": labels, "counts": counts}


def get_dashboard_stats() -> dict:
    with get_db() as cur:
        cur.execute("SELECT COUNT(*) FROM file_events")
        total_events = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM alerts WHERE status='ACTIVE'")
        active_alerts = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'")
        critical_alerts = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM integrity_checks WHERE status='MISMATCH'")
        integrity_violations = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM file_events WHERE is_sensitive=1")
        sensitive_transfers = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM alerts WHERE alert_type='USB Transfer'")
        usb_transfers = cur.fetchone()[0]

    return {
        "total_events": total_events,
        "active_alerts": active_alerts,
        "critical_alerts": critical_alerts,
        "integrity_violations": integrity_violations,
        "sensitive_transfers": sensitive_transfers,
        "usb_transfers": usb_transfers,
    }

# Database administration and backups

def export_alerts_csv() -> str:
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Severity", "Alert Type", "Filename", "Source Path", "Destination Path", "User", "Status", "Description"])
    
    with get_db() as cur:
        cur.execute("SELECT * FROM alerts ORDER BY id DESC")
        for row in cur.fetchall():
            writer.writerow([row["id"], row["timestamp"], row["severity"], row["alert_type"], row["filename"], row["source_path"], row["destination_path"], row["user"], row["status"], row["description"]])
    return output.getvalue()

def export_events_csv() -> str:
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Event Type", "Filename", "Source Path", "Destination Path", "User"])
    
    with get_db() as cur:
        cur.execute("SELECT * FROM file_events ORDER BY id DESC")
        for row in cur.fetchall():
            writer.writerow([row["id"], row["timestamp"], row["event_type"], row["filename"], row["source_path"], row["destination_path"], row["user"]])
    return output.getvalue()

def clear_dashboard_with_backup() -> tuple[bool, str]:
    import shutil
    import os
    from datetime import datetime
    
    try:
        # Create backup
        backup_name = f"securewatch_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        backup_path = os.path.join(os.path.dirname(config.DB_PATH), backup_name)
        
        # We need to copy the file. Ensure no active writes are happening if possible, 
        # but shutil.copy2 works fine for SQLite in most simple cases.
        shutil.copy2(config.DB_PATH, backup_path)
        
        with get_db() as cur:
            cur.execute("DELETE FROM file_events")
            cur.execute("DELETE FROM alerts")
            cur.execute("DELETE FROM integrity_checks")
            cur.execute("DELETE FROM users")
            
        return True, f"Dashboard cleared. Backup saved as {backup_name}."
    except Exception as e:
        return False, f"Failed to clear dashboard: {e}"

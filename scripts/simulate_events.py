# scripts/simulate_events.py
# Simulates database events and alerts for demonstration purposes.


import os
import sys
import time
import shutil
import random
import hashlib
import sqlite3
import getpass
from datetime import datetime, timedelta

# Ensure root on path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import config
from database import db

print("SecureWatch Event Simulation")

# Setup parameters
db.init_db()
USER = getpass.getuser()
SIM_DIR = os.path.join(ROOT, "sim_workspace")
USB_DIR = config.SIM_USB_PATH

for d in [SIM_DIR, USB_DIR]:
    os.makedirs(d, exist_ok=True)

# Create protected demo directories
for pdir in config.PROTECTED_DIRS:
    os.makedirs(pdir, exist_ok=True)

SENSITIVE_FILES = [
    ("salary.xlsx",          "HR Payroll data"),
    ("customer_data.csv",    "Customer PII records"),
    ("confidential.docx",    "Board meeting notes"),
    ("financial_report.pdf", "Q4 Financial statements"),
    ("budget.xlsx",          "Annual budget projections"),
    ("trade_secrets.docx",   "R&D trade secrets"),
    ("api_keys.txt",         "Production API keys"),
    ("database_backup.sql",  "Full database backup"),
    ("personnel_records.xlsx","Employee records"),
    ("medical_records.pdf",  "Patient medical records"),
]

NORMAL_FILES = [
    "meeting_notes.txt", "project_plan.docx", "readme.md",
    "logo.png", "presentation.pptx", "report_draft.docx",
    "data_analysis.py", "config.yaml", "invoice_123.pdf",
    "quarterly_review.txt",
]

USERS = [USER, "alice", "bob", "charlie", "dave"]
PROCESSES = ["explorer.exe", "WINWORD.EXE", "EXCEL.EXE", "chrome.exe",
             "OneDrive.exe", "cmd.exe", "powershell.exe"]

EVENT_TYPES = ["created", "modified", "deleted", "moved", "copied"]
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Helper functions
def make_fake_hash() -> str:
    return hashlib.sha256(os.urandom(32)).hexdigest()

def random_ts(days_back: int = 7) -> str:
    delta = timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    return (datetime.now() - delta).isoformat(timespec="seconds")

def insert_event(filename, event_type, src, dst=None, user=None,
                 process=None, size=None, ext=None, sensitive=False, ts=None):
    user    = user    or random.choice(USERS)
    process = process or random.choice(PROCESSES)
    size    = size    or random.randint(1024, 50 * 1024 * 1024)
    ext     = ext     or os.path.splitext(filename)[1]

    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO file_events
           (filename, event_type, source_path, destination_path, timestamp,
            user, process_name, file_size, file_extension, is_sensitive)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (filename, event_type, src, dst,
         ts or random_ts(), user, process, size, ext, int(sensitive))
    )
    eid = cur.lastrowid
    # upsert user
    now = datetime.now().isoformat(timespec="seconds")
    cur.execute(
        """INSERT INTO users (username, activity_count, last_activity)
           VALUES (?,1,?)
           ON CONFLICT(username) DO UPDATE SET
             activity_count=activity_count+1, last_activity=excluded.last_activity""",
        (user, now)
    )
    conn.commit()
    conn.close()
    return eid

def insert_alert(severity, alert_type, filename=None, src=None, dst=None,
                 desc=None, user=None, ts=None):
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO alerts
           (severity, alert_type, filename, source_path, destination_path,
            description, timestamp, status, user)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (severity, alert_type, filename, src, dst,
         desc or f"Simulated {alert_type} alert for {filename}",
         ts or random_ts(),
         random.choice(["ACTIVE", "ACTIVE", "ACTIVE", "INVESTIGATING", "RESOLVED"]),
         user or random.choice(USERS))
    )
    conn.commit()
    conn.close()

def insert_integrity(filename, filepath, orig_hash, curr_hash, status, ts=None):
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO integrity_checks
           (filename, filepath, original_hash, current_hash, status, timestamp)
           VALUES (?,?,?,?,?,?)""",
        (filename, filepath, orig_hash, curr_hash, status, ts or random_ts())
    )
    conn.commit()
    conn.close()

# Normal File Events
print("\n[1/6] Generating normal file events...")
for _ in range(80):
    fname = random.choice(NORMAL_FILES)
    etype = random.choice(EVENT_TYPES)
    pdir  = random.choice(config.MONITORED_DIRS)
    src   = os.path.join(pdir, fname)
    dst   = os.path.join(SIM_DIR, fname) if etype in ("moved","copied") else None
    insert_event(fname, etype, src, dst, sensitive=False)
    if _ % 20 == 0:
        print(f"   {_+1}/80 events written...")

print("   [OK] 80 normal events created")

# Sensitive File Events
print("\n[2/6] Generating sensitive file events...")
for fname, desc in SENSITIVE_FILES:
    pdir = random.choice(config.PROTECTED_DIRS)
    src  = os.path.join(pdir, fname)
    for _ in range(random.randint(3, 8)):
        etype = random.choice(["created","modified","modified","accessed"])
        insert_event(fname, etype, src, sensitive=True, size=random.randint(10*1024, 5*1024*1024))

print(f"   [OK] {len(SENSITIVE_FILES)} sensitive files x up to 8 events each")

# Security Alerts
print("\n[3/6] Generating security alerts...")

# CRITICAL -- USB Transfers
usb_user = random.choice(USERS)
for fname, _ in random.sample(SENSITIVE_FILES, 4):
    pdir = random.choice(config.PROTECTED_DIRS)
    insert_alert("CRITICAL", "USB Transfer", fname,
                 src=os.path.join(pdir, fname),
                 dst=os.path.join(USB_DIR, fname),
                 desc=(f"Sensitive file '{fname}' was copied to a removable USB drive. "
                       f"Source: {pdir} -> Destination: {USB_DIR}. User: {usb_user}. "
                       f"This may indicate data exfiltration."),
                 user=usb_user)

# CRITICAL -- Integrity Violations
for fname, _ in random.sample(SENSITIVE_FILES, 3):
    orig = make_fake_hash()
    curr = make_fake_hash()
    insert_alert("CRITICAL", "Integrity Violation", fname,
                 desc=(f"File integrity violation detected for '{fname}'. "
                       f"SHA-256 mismatch -- Original: {orig[:16]}... | "
                       f"Current: {curr[:16]}... The file may have been tampered with."))

# CRITICAL -- Sensitive File Deleted
insert_alert("CRITICAL", "Sensitive File Deleted", "financial_report.pdf",
             desc="Sensitive file 'financial_report.pdf' was DELETED. Immediate investigation required.")

# HIGH -- Bulk Transfer
insert_alert("HIGH", "Bulk Transfer",
             desc=f"Bulk file transfer: 134 files moved within 5 minutes by user '{random.choice(USERS)}'.",
             user=random.choice(USERS))

# HIGH -- Cloud Uploads
cloud_user = random.choice(USERS)
for fname in ["budget.xlsx", "customer_data.csv", "salary.xlsx"]:
    cloud_path = os.path.join(os.path.expanduser("~"), "OneDrive", fname)
    insert_alert("HIGH", "Cloud Upload", fname,
                 dst=cloud_path,
                 desc=f"Cloud storage upload detected: '{fname}' copied to OneDrive. User: {cloud_user}.",
                 user=cloud_user)

# HIGH -- Network Share
insert_alert("HIGH", "Network Share Transfer", "confidential.docx",
             dst=r"\\FileServer\SharedDocs\confidential.docx",
             desc="Network share transfer: 'confidential.docx' sent to \\\\FileServer\\SharedDocs. Verify authorisation.")

# MEDIUM -- Repeated Access
for fname, _ in random.sample(SENSITIVE_FILES, 3):
    insert_alert("MEDIUM", "Repeated Access", fname,
                 desc=f"Sensitive file '{fname}' accessed 6 times within 10 minutes. Possible data reconnaissance.",
                 user=random.choice(USERS))

# MEDIUM -- Large File
insert_alert("MEDIUM", "Large File Transfer", "database_backup.sql",
             desc="Large file transfer: 'database_backup.sql' (287.4 MB) moved. Threshold: 50 MB.",
             user=random.choice(USERS))

# LOW -- Informational
for i in range(8):
    fname = random.choice(NORMAL_FILES)
    insert_alert("LOW", "Unusual Destination", fname,
                 desc=f"File '{fname}' transferred to an unusual location. Routine review recommended.",
                 user=random.choice(USERS))

# USB Device Connected alert
insert_alert("HIGH", "USB Device Connected",
             src=USB_DIR,
             desc=f"Removable drive connected at '{USB_DIR}'. Monitor initiated for file activity.",
             user=usb_user)

print("   [OK] 25+ alerts across all severity levels created")

# Integrity Check Records
print("\n[4/6] Generating integrity check records...")

# Baselines (NEW)
for fname, _ in SENSITIVE_FILES:
    pdir = random.choice(config.PROTECTED_DIRS)
    h    = make_fake_hash()
    insert_integrity(fname, os.path.join(pdir, fname), h, h, "NEW", random_ts(14))

# Matches
for fname, _ in SENSITIVE_FILES[:6]:
    pdir = random.choice(config.PROTECTED_DIRS)
    h    = make_fake_hash()
    insert_integrity(fname, os.path.join(pdir, fname), h, h, "MATCH", random_ts(7))

# Violations (MISMATCH)
for fname, _ in SENSITIVE_FILES[:5]:
    pdir = random.choice(config.PROTECTED_DIRS)
    h1, h2 = make_fake_hash(), make_fake_hash()
    insert_integrity(fname, os.path.join(pdir, fname), h1, h2, "MISMATCH", random_ts(3))

# Deleted
insert_integrity("financial_report.pdf",
                 os.path.join(config.PROTECTED_DIRS[1], "financial_report.pdf"),
                 make_fake_hash(), None, "DELETED", random_ts(1))

print("   [OK] Integrity records: 10 NEW, 6 MATCH, 5 MISMATCH, 1 DELETED")

# Historical Trend Data
print("\n[5/6] Generating historical alert trends (7 days)...")
for day in range(7):
    ts_day = (datetime.now() - timedelta(days=6-day)).date()
    for severity in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        count = {
            "CRITICAL": random.randint(0, 5),
            "HIGH":     random.randint(1, 10),
            "MEDIUM":   random.randint(2, 15),
            "LOW":      random.randint(3, 20),
        }[severity]
        for _ in range(count):
            ts = datetime.combine(ts_day, datetime.min.time().replace(
                hour=random.randint(0,23),
                minute=random.randint(0,59)
            )).isoformat(timespec="seconds")
            fname = random.choice([f[0] for f in SENSITIVE_FILES])
            insert_alert(severity, random.choice([
                "USB Transfer","Integrity Violation","Bulk Transfer",
                "Cloud Upload","Repeated Access","Unusual Destination"
            ]), fname, ts=ts)

print("   [OK] 7-day historical data inserted")

# Hourly Timeline
print("\n[6/6] Generating today's hourly activity...")
today = datetime.now().date()
for hour in range(0, datetime.now().hour + 1):
    count = random.randint(0, 15) if 8 <= hour <= 18 else random.randint(0, 3)
    for _ in range(count):
        ts = datetime.combine(today, datetime.min.time().replace(
            hour=hour,
            minute=random.randint(0,59),
            second=random.randint(0,59)
        )).isoformat(timespec="seconds")
        fname = random.choice([f[0] for f in SENSITIVE_FILES] + NORMAL_FILES)
        is_sensitive = fname in [f[0] for f in SENSITIVE_FILES]
        pdir = random.choice(config.MONITORED_DIRS)
        insert_event(fname, random.choice(EVENT_TYPES),
                     os.path.join(pdir, fname),
                     sensitive=is_sensitive, ts=ts)

print("   [OK] Today's activity data inserted")

# Database Summary
conn = sqlite3.connect(config.DB_PATH)
cur  = conn.cursor()
cur.execute("SELECT COUNT(*) FROM file_events")
events = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM alerts")
alerts = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM integrity_checks")
checks = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM users")
users  = cur.fetchone()[0]
conn.close()

print("Simulation complete! Go to dashboard page.")

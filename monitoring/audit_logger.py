import logging
import os
from datetime import datetime

# Setup audit logger
audit_logger = logging.getLogger("securewatch.audit")
audit_logger.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter('[%(asctime)s] AUDIT | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# File Handler
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log_dir = os.path.join(base_dir, "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "audit.log")

file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(formatter)
audit_logger.addHandler(file_handler)

def log_audit_event(action: str, details: str, user: str = "SYSTEM"):
    """
    Log an administrative or configuration change.
    """
    audit_logger.info(f"User: {user} | Action: {action} | Details: {details}")

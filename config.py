# config.py
# System configuration.


import os
import getpass
import json
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

# Application settings
APP_NAME = "SecureWatch"
APP_VERSION = "1.0.0"
FLASK_HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.environ.get("FLASK_PORT", os.environ.get("PORT", 5000)))
FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1", "yes")
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24).hex() if os.environ.get("FLASK_DEBUG") != "True" else "securewatch-secret-key-change-in-production")

# Path settings
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "securewatch.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports", "output")
SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")

for _dir in [LOG_DIR, REPORT_DIR, SCREENSHOT_DIR,
             os.path.join(BASE_DIR, "database")]:
    os.makedirs(_dir, exist_ok=True)

# Monitored directories (falls back to home folder if preferred paths aren't writable)
def _resolve_dir(preferred: str) -> str:
    """Return preferred path if writable, otherwise fall back to user home."""
    try:
        os.makedirs(preferred, exist_ok=True)
        test_file = os.path.join(preferred, ".securewatch_probe")
        with open(test_file, "w") as f:
            f.write("probe")
        os.remove(test_file)
        return preferred
    except (OSError, PermissionError):
        fallback = os.path.join(os.path.expanduser("~"), os.path.basename(preferred))
        os.makedirs(fallback, exist_ok=True)
        return fallback

CUSTOM_FOLDERS_FILE = os.path.join(BASE_DIR, "database", "custom_folders.json")

def load_custom_folders() -> list:
    if os.path.exists(CUSTOM_FOLDERS_FILE):
        try:
            with open(CUSTOM_FOLDERS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_custom_folders(folders: list):
    with open(CUSTOM_FOLDERS_FILE, "w") as f:
        json.dump(folders, f, indent=2)

def is_system_folder(path: str) -> bool:
    """Basic check to prevent monitoring root or critical Windows folders."""
    path = os.path.abspath(path).lower()
    if path == "c:\\" or path == "c:":
        return True
    if path.startswith("c:\\windows") or path.startswith("c:\\program files"):
        return True
    return False

def add_custom_folder(path: str) -> tuple[bool, str]:
    path = os.path.abspath(path)
    if not os.path.exists(path) or not os.path.isdir(path):
        return False, "Directory does not exist."
    if is_system_folder(path):
        return False, "Cannot monitor critical system directories."
    
    folders = load_custom_folders()
    # Check if already in custom folders, or in default hardcoded ones
    if path in folders or path in MONITORED_DIRS:
        return False, "Directory is already being monitored."
    
    folders.append(path)
    save_custom_folders(folders)
    
    if path not in MONITORED_DIRS:
        MONITORED_DIRS.append(path)
    if path not in PROTECTED_DIRS:
        PROTECTED_DIRS.append(path)
        
    return True, "Directory added successfully."

def remove_custom_folder(path: str) -> tuple[bool, str]:
    folders = load_custom_folders()
    if path in folders:
        folders.remove(path)
        save_custom_folders(folders)
        
        if path in MONITORED_DIRS:
            MONITORED_DIRS.remove(path)
        if path in PROTECTED_DIRS:
            PROTECTED_DIRS.remove(path)
        return True, "Directory removed successfully."
    return False, "Directory not found in custom list."

MONITORED_DIRS = [
    _resolve_dir(r"C:\HR"),
    _resolve_dir(r"C:\Finance"),
    _resolve_dir(r"C:\CompanyData"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Documents"),
    os.path.join(os.path.expanduser("~"), "Downloads"),
]

# Append custom folders
for custom_dir in load_custom_folders():
    if custom_dir not in MONITORED_DIRS:
        MONITORED_DIRS.append(custom_dir)

# Deduplicate and only include directories that exist
MONITORED_DIRS = list(dict.fromkeys(
    d for d in MONITORED_DIRS if os.path.isdir(d)
))

# Protected / sensitive source directories — alerts fire when files LEAVE these
PROTECTED_DIRS = [
    _resolve_dir(r"C:\HR"),
    _resolve_dir(r"C:\Finance"),
    _resolve_dir(r"C:\CompanyData"),
]

# Also protect custom folders
for custom_dir in load_custom_folders():
    if custom_dir not in PROTECTED_DIRS:
        PROTECTED_DIRS.append(custom_dir)

# Custom Sensitive File Policy
CUSTOM_POLICY_FILE = os.path.join(BASE_DIR, "database", "custom_policy.json")

def load_custom_policy() -> list:
    if os.path.exists(CUSTOM_POLICY_FILE):
        try:
            with open(CUSTOM_POLICY_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_custom_policy(policies: list):
    with open(CUSTOM_POLICY_FILE, "w") as f:
        json.dump(policies, f, indent=2)

def add_custom_policy(value: str, policy_type: str, severity: str) -> tuple[bool, str]:
    policies = load_custom_policy()
    for p in policies:
        if p["value"].lower() == value.lower() and p["type"] == policy_type:
            return False, "Policy rule already exists."
    
    policies.append({
        "value": value,
        "type": policy_type,
        "severity": severity
    })
    save_custom_policy(policies)
    
    if policy_type == "filename":
        SENSITIVE_FILENAMES.add(value.lower())
    elif policy_type == "extension":
        if not value.startswith("."):
            value = "." + value
        SENSITIVE_EXTENSIONS.add(value.lower())
        
    return True, "Policy rule added successfully."

def remove_custom_policy(value: str, policy_type: str) -> tuple[bool, str]:
    policies = load_custom_policy()
    new_policies = [p for p in policies if not (p["value"].lower() == value.lower() and p["type"] == policy_type)]
    
    if len(new_policies) == len(policies):
        return False, "Policy rule not found."
        
    save_custom_policy(new_policies)
    
    if policy_type == "filename":
        if value.lower() in SENSITIVE_FILENAMES:
            SENSITIVE_FILENAMES.remove(value.lower())
    elif policy_type == "extension":
        v = value.lower() if value.startswith(".") else "." + value.lower()
        if v in SENSITIVE_EXTENSIONS:
            SENSITIVE_EXTENSIONS.remove(v)
            
    return True, "Policy rule removed successfully."

def export_policy() -> str:
    return json.dumps(load_custom_policy(), indent=2)

def import_policy(json_str: str) -> tuple[bool, str]:
    try:
        new_policies = json.loads(json_str)
        if not isinstance(new_policies, list):
            return False, "Invalid policy format."
            
        current = load_custom_policy()
        added = 0
        for p in new_policies:
            if "value" in p and "type" in p and "severity" in p:
                # Add if not exists
                if not any(cp["value"].lower() == p["value"].lower() and cp["type"] == p["type"] for cp in current):
                    current.append(p)
                    added += 1
                    
                    if p["type"] == "filename":
                        SENSITIVE_FILENAMES.add(p["value"].lower())
                    elif p["type"] == "extension":
                        v = p["value"].lower()
                        if not v.startswith("."): v = "." + v
                        SENSITIVE_EXTENSIONS.add(v)
                        
        save_custom_policy(current)
        return True, f"Imported {added} new policy rules."
    except Exception as e:
        return False, f"Failed to import: {e}"

# Sensitive File Policy
SENSITIVE_FILENAMES = {
    "salary.xlsx",
    "salaries.xlsx",
    "employee_data.xlsx",
    "customer_data.csv",
    "clients.csv",
    "confidential.docx",
    "financial_report.pdf",
    "budget.xlsx",
    "tax_return.pdf",
    "payroll.xlsx",
    "trade_secrets.docx",
    "intellectual_property.pdf",
    "merger_plan.pptx",
    "acquisition_data.xlsx",
    "personnel_records.xlsx",
    "medical_records.pdf",
    "passport_scan.pdf",
    "source_code.zip",
    "database_backup.sql",
    "api_keys.txt",
    "credentials.txt",
    "private_key.pem",
}

SENSITIVE_EXTENSIONS = {
    ".xlsx", ".xls",    # Spreadsheets
    ".csv",             # Data files
    ".docx", ".doc",    # Word documents
    ".pdf",             # PDFs
    ".pptx", ".ppt",    # Presentations
    ".sql", ".db",      # Databases
    ".pem", ".key",     # Keys/Certs
    ".bak", ".backup",  # Backups
    ".zip", ".tar", ".gz", ".7z",  # Archives (may contain sensitive data)
}

# Apply custom policies on startup
for p in load_custom_policy():
    if p["type"] == "filename":
        SENSITIVE_FILENAMES.add(p["value"].lower())
    elif p["type"] == "extension":
        v = p["value"].lower()
        if not v.startswith("."): v = "." + v
        SENSITIVE_EXTENSIONS.add(v)

def get_file_severity(filename: str) -> str | None:
    """Return the configured severity level for a file, or None if not custom."""
    filename = filename.lower()
    ext = os.path.splitext(filename)[1].lower()
    
    # Check custom policy overrides first
    for p in load_custom_policy():
        if p["type"] == "filename" and p["value"].lower() == filename:
            return p["severity"]
        if p["type"] == "extension":
            v = p["value"].lower()
            if not v.startswith("."): v = "." + v
            if v == ext:
                return p["severity"]
                
    return None

SENSITIVE_KEYWORDS = [
    "salary", "payroll", "finance", "confidential", "secret",
    "private", "password", "credential", "customer", "client",
    "personnel", "medical", "tax", "budget", "merger",
    "acquisition", "trade_secret", "intellectual", "classified",
]

# USB / Removable Drive Monitoring
USB_DRIVE_LETTERS = ["D:", "E:", "F:", "G:", "H:", "I:", "J:"]
USB_POLL_INTERVAL = 5  # seconds between USB scan cycles

# Network & Cloud Paths to Watch
NETWORK_SHARE_PATTERNS = [
    r"\\",            # Any UNC path
    r"//",
]

CLOUD_PATHS = [
    os.path.join(os.path.expanduser("~"), "OneDrive"),
    os.path.join(os.path.expanduser("~"), "Google Drive"),
    os.path.join(os.path.expanduser("~"), "Dropbox"),
    os.path.join(os.path.expanduser("~"), "Box"),
    # Common OneDrive for Business paths
    os.path.join(os.path.expanduser("~"), "SharePoint"),
]

# Simulation USB path (used by simulate_events.py)
SIM_USB_PATH = os.path.join(BASE_DIR, "simulated_usb")
os.makedirs(SIM_USB_PATH, exist_ok=True)

# Detection Thresholds
# Rule 1: Bulk Transfer
BULK_TRANSFER_THRESHOLD = 100       # files
BULK_TRANSFER_WINDOW_MINUTES = 5    # within N minutes

# Rule 3: Large File Transfer
LARGE_FILE_THRESHOLD_MB = 50        # MB

# Rule 5: Repeated Access
REPEATED_ACCESS_THRESHOLD = 5       # times
REPEATED_ACCESS_WINDOW_MINUTES = 10 # within N minutes

# Logging Settings
LOG_FILE = os.path.join(LOG_DIR, "securewatch.log")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_MAX_BYTES = 10 * 1024 * 1024   # 10 MB per file
LOG_BACKUP_COUNT = 5

# Dashboard Settings
DASHBOARD_REFRESH_INTERVAL = 30     # seconds
MAX_RECENT_EVENTS = 200             # events shown in live feed
MAX_RECENT_ALERTS = 500             # alerts returned by default

# Organisation Details
ORG_NAME = "SecureWatch Corp"
ORG_DEPARTMENT = "Security Operations Center (SOC)"
SYSTEM_USER = getpass.getuser()

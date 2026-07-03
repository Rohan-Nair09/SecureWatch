# reports/csv_report.py
# Exports database tables to CSV format.


import os
import sys
from datetime import datetime

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db


def generate_csv_reports() -> list[str]:
    # Export database tables to CSV files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    generated = []

    # Save events to CSV
    events = db.get_file_events(limit=10000)
    if events:
        df_events = pd.DataFrame(events)
        path = os.path.join(config.REPORT_DIR, f"file_events_{timestamp}.csv")
        df_events.to_csv(path, index=False)
        generated.append(path)

    # Save alerts to CSV
    alerts = db.get_alerts(limit=10000)
    if alerts:
        df_alerts = pd.DataFrame(alerts)
        path = os.path.join(config.REPORT_DIR, f"alerts_{timestamp}.csv")
        df_alerts.to_csv(path, index=False)
        generated.append(path)

    # Save integrity checks to CSV
    checks = db.get_integrity_checks(limit=10000)
    if checks:
        df_checks = pd.DataFrame(checks)
        path = os.path.join(config.REPORT_DIR, f"integrity_checks_{timestamp}.csv")
        df_checks.to_csv(path, index=False)
        generated.append(path)

    return generated

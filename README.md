# SecureWatch - File Transfer Monitoring & Data Loss Prevention System

SecureWatch is a Python-based security tool designed for monitoring file activities, detecting data leakage, and verifying file integrity in real-time. It runs a Flask-based web dashboard to visualize all security events and alerts.

## Features

- Real-time file system monitoring using watchdog (creation, modification, deletion, movement, copying).
- Automatic USB drive detection and background scanning for sensitive files.
- SHA-256 File Integrity Monitoring (FIM) to track baseline hash matches and mismatches.
- Simple detection rules:
  - Bulk transfers (many files modified in a short window).
  - Copying sensitive files to USB, cloud folders, or network shares.
  - Large file transfers (size threshold exceed).
  - Repeated file accesses.
- Dark theme dashboard displaying live feeds, hourly timelines, and event charts.
- Exportable CSV and PDF reports.

## Installation

### Prerequisites
- Python 3.10 or higher
- Windows 10 / 11

### Step-by-Step Setup

1. Clone or download the repository:
   ```bash
   cd SecureWatch
   ```

2. Set up a virtual environment (recommended):
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Start the Flask application:
   ```bash
   python app.py
   ```

The web dashboard will be available at `http://localhost:5000`.

### Database Simulation
To populate the database with some demo event logs and alerts, open a second terminal with the virtual environment activated and run:
```bash
python scripts/simulate_events.py
```

## Directory Structure
- `app.py`: Flask entry point.
- `config.py`: Application thresholds, monitored folders, and sensitive file patterns.
- `database/db.py`: SQLite WAL database queries and management.
- `monitoring/`: Core system monitoring modules (file system events, USB polling, rule engine).
- `integrity/hash_checker.py`: SHA-256 hash calculator and baseline checker.
- `alerts/alert_manager.py`: Alert creation and type definitions.
- `reports/`: Exporters for CSV and PDF reports.
- `static/` & `templates/`: Frontend interface resources.
- `scripts/simulate_events.py`: Database seeding script.

## Configuration
Monitored folders, sensitive filenames, keywords, and rule thresholds can be customized in `config.py`.

## License
MIT

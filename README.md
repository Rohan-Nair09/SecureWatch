# SecureWatch — File Transfer & Integrity Monitor

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-green?style=flat-square&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-lightgrey?style=flat-square&logo=sqlite&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5-purple?style=flat-square&logo=bootstrap&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

**A real-time host-based intrusion detection and data loss prevention dashboard.**

</div>

---

## 🛡️ Key Features

* **Real-time File Monitoring**: Uses `watchdog` to monitor creation, modification, deletion, and movement of files in monitored folders.
* **USB Drive Auditing**: Detects USB insertion, performs background scans for sensitive files, and logs file movements.
* **File Integrity Monitoring (FIM)**: Tracks file changes using SHA-256 baselines to highlight unauthorized modifications.
* **SOC-style Web Interface**: A premium dark-themed dashboard featuring real-time event feeds and statistics.
* **Compliance Reporting**: Generates downloadable PDF and CSV security audit reports.

---

## 🚨 Security Rules & Threat Levels

SecureWatch evaluates file activities against these pre-defined detection rules:

| Security Rule | Trigger Condition | Severity Level |
| :--- | :--- | :--- |
| **Bulk Transfer** | > 100 files modified within 5 minutes | 🔴 **HIGH** |
| **Data Exfiltration** | Sensitive file copied to USB, OneDrive, or Dropbox | 🔴 **CRITICAL** |
| **Large File Transfer** | Any file transfer exceeding 50 MB | 🟡 **MEDIUM** |
| **Unusual Destination** | Transfer to an unapproved directory | 🔵 **LOW** |
| **Repeated Access** | Same sensitive file modified > 5 times in 10 minutes | 🟡 **MEDIUM** |
| **Integrity Violation** | SHA-256 hash mismatch against baseline | 🔴 **CRITICAL** |

---

## 🚀 Setup & Installation

### Prerequisites
* Windows 10 / 11
* Python 3.10+

### Installation Steps

1. Clone this repository and navigate to the project directory:
   ```bash
   cd SecureWatch
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. Install required libraries:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the Flask application:
   ```bash
   python app.py
   ```

Open **`http://localhost:5000`** in your browser to view the dashboard.

### Load Demo Data
To populate the dashboard with 7 days of historical logs, alerts, and baseline events:
```bash
python scripts/simulate_events.py
```

---

## 📁 Repository Structure

```
SecureWatch/
├── app.py                  # Web application entry point
├── config.py               # Monitored directories, keywords, & thresholds
├── requirements.txt        # Third-party dependencies
│
├── monitoring/             # Watchdog FS & USB poll observers
├── integrity/              # SHA-256 FIM baseline generator
├── alerts/                 # Threat severity & alert router
├── dashboard/              # Flask routes and REST API
├── database/               # SQLite connection & query handlers
│
├── templates/              # Dashboard HTML pages
├── static/                 # Stylesheets, icons, and charts
└── scripts/                # Database simulation scripts
```

## 📝 License
Distributed under the MIT License.

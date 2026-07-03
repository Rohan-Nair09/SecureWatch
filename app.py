# app.py
# Main entry point for the Flask application.


import os
import sys
import logging
import logging.handlers
from datetime import datetime

from flask import Flask, redirect, url_for

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from database import db
from dashboard.dashboard import bp as dashboard_bp

# Logging Setup
def setup_logging():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    root = logging.getLogger()
    root.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)-25s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Rotating file handler
    fh = logging.handlers.RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
        encoding="utf-8"
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # Suppress noisy watchdog / werkzeug logs at DEBUG level
    logging.getLogger("watchdog").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


# Application Factory
def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.secret_key = config.SECRET_KEY

    # Register blueprints
    app.register_blueprint(dashboard_bp)

    # Root redirect
    @app.route("/")
    def root():
        return redirect(url_for("dashboard.index"))

    # Custom Jinja2 filters
    @app.template_filter("severity_badge")
    def severity_badge(sev: str) -> str:
        classes = {
            "CRITICAL": "badge-critical",
            "HIGH":     "badge-high",
            "MEDIUM":   "badge-medium",
            "LOW":      "badge-low",
        }
        return classes.get(sev, "badge-low")

    @app.template_filter("status_badge")
    def status_badge(status: str) -> str:
        classes = {
            "ACTIVE":         "badge-critical",
            "INVESTIGATING":  "badge-medium",
            "RESOLVED":       "badge-resolved",
        }
        return classes.get(status, "")

    @app.template_filter("fmt_size")
    def fmt_size(size: int) -> str:
        if not size:
            return "—"
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    @app.template_filter("fmt_ts")
    def fmt_ts(ts: str) -> str:
        if not ts:
            return "—"
        try:
            dt = datetime.fromisoformat(ts)
            return dt.strftime("%d %b %Y, %H:%M:%S")
        except Exception:
            return ts

    @app.context_processor
    def inject_globals():
        from monitoring import file_monitor, usb_monitor
        from database import db as _db
        _stats = _db.get_dashboard_stats()
        _monitor = {
            "file_monitor": file_monitor.is_running(),
            "usb_monitor":  usb_monitor.is_running(),
        }
        return {
            "app_name":    config.APP_NAME,
            "app_version": config.APP_VERSION,
            "now":         datetime.now(),
            "stats":       _stats,
            "monitor":     _monitor,
            "config":      config,
        }

    return app


# Main entry point
if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger("securewatch.app")
    logger.info("=" * 60)
    logger.info("  %s v%s -- Starting Up", config.APP_NAME, config.APP_VERSION)
    logger.info("=" * 60)

    # Initialise database
    db.init_db()
    logger.info("Database ready: %s", config.DB_PATH)

    # Start background monitors
    from monitoring import file_monitor, usb_monitor
    file_monitor.start_monitoring()
    usb_monitor.start_usb_monitor()

    # Create Flask app and run
    app = create_app()
    logger.info("Dashboard: http://%s:%d", config.FLASK_HOST, config.FLASK_PORT)
    logger.info("Press Ctrl+C to stop.")

    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False,  # Prevent double-starting monitors
    )

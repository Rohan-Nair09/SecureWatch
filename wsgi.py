# wsgi.py
# WSGI entry point for Waitress production server.

import os
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, setup_logging
import config
from database import db
from monitoring import file_monitor, usb_monitor

setup_logging()
logger = logging.getLogger("securewatch.wsgi")
logger.info("Starting Production WSGI for %s", config.APP_NAME)

# Initialize database
db.init_db()

# Start background monitors
file_monitor.start_monitoring()
usb_monitor.start_usb_monitor()

# Create Flask app
application = create_app()

if __name__ == "__main__":
    from waitress import serve
    logger.info("Starting Waitress server on %s:%d", config.FLASK_HOST, config.FLASK_PORT)
    serve(application, host=config.FLASK_HOST, port=config.FLASK_PORT)

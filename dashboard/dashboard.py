# dashboard/dashboard.py
# Blueprint for dashboard pages and API endpoints.


import os
import sys
import json
import logging
from datetime import datetime

from flask import (
    Blueprint, render_template, jsonify, request,
    redirect, url_for, flash, send_from_directory
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db
from alerts import alert_manager
from monitoring import file_monitor, usb_monitor
from monitoring.audit_logger import log_audit_event
from flask import Response

logger = logging.getLogger(__name__)

bp = Blueprint("dashboard", __name__)


# Dashboard views

@bp.route("/")
@bp.route("/dashboard")
def index():
    stats = db.get_dashboard_stats()
    monitor_status = {
        "file_monitor": file_monitor.is_running(),
        "usb_monitor":  usb_monitor.is_running(),
    }
    return render_template("dashboard.html", stats=stats, monitor=monitor_status,
                           app_name=config.APP_NAME, version=config.APP_VERSION)


@bp.route("/healthz")
def healthz():
    return jsonify({"status": "healthy"}), 200


@bp.route("/alerts-page")
def alerts_page():
    severity = request.args.get("severity", "")
    status   = request.args.get("status", "")
    user     = request.args.get("user", "")
    search   = request.args.get("search", "")
    page     = int(request.args.get("page", 1))
    per_page = 25

    alerts = db.get_alerts(
        limit=per_page,
        offset=(page - 1) * per_page,
        severity=severity or None,
        status=status or None,
        user=user or None,
        search=search or None,
    )
    users = db.get_users()
    stats = db.get_dashboard_stats()
    return render_template("alerts.html", alerts=alerts, users=users,
                           stats=stats, page=page, per_page=per_page,
                           severity=severity, status=status,
                           user=user, search=search,
                           app_name=config.APP_NAME)


@bp.route("/events-page")
def events_page():
    search     = request.args.get("search", "")
    event_type = request.args.get("event_type", "")
    user       = request.args.get("user", "")
    page       = int(request.args.get("page", 1))
    per_page   = 50

    events = db.get_file_events(
        limit=per_page,
        offset=(page - 1) * per_page,
        search=search or None,
        event_type=event_type or None,
        user=user or None,
    )
    stats = db.get_dashboard_stats()
    users = db.get_users()
    return render_template("events.html", events=events, stats=stats,
                           users=users, page=page, per_page=per_page,
                           search=search, event_type=event_type, user=user,
                           app_name=config.APP_NAME)


@bp.route("/integrity-page")
def integrity_page():
    status = request.args.get("status", "")
    checks = db.get_integrity_checks(limit=200, status=status or None)
    stats  = db.get_dashboard_stats()
    return render_template("integrity.html", checks=checks, stats=stats,
                           status_filter=status, app_name=config.APP_NAME)


@bp.route("/reports-page")
def reports_page():
    stats = db.get_dashboard_stats()
    # List previously generated reports
    report_files = []
    for fname in os.listdir(config.REPORT_DIR):
        fpath = os.path.join(config.REPORT_DIR, fname)
        report_files.append({
            "name": fname,
            "size": os.path.getsize(fpath),
            "created": datetime.fromtimestamp(os.path.getctime(fpath)).strftime("%Y-%m-%d %H:%M"),
        })
    report_files.sort(key=lambda x: x["created"], reverse=True)
    return render_template("reports.html", stats=stats, report_files=report_files,
                           app_name=config.APP_NAME)


@bp.route("/settings-page")
def settings_page():
    stats = db.get_dashboard_stats()
    monitor_status = {
        "file_monitor": file_monitor.is_running(),
        "usb_monitor":  usb_monitor.is_running(),
    }
    
    custom_folders = config.load_custom_folders()
    
    # Rebuild all preferred paths from config to check existence before filtering
    default_folders = [
        r"C:\HR", r"C:\Finance", r"C:\CompanyData",
        os.path.join(os.path.expanduser("~"), "Desktop"),
        os.path.join(os.path.expanduser("~"), "Documents"),
        os.path.join(os.path.expanduser("~"), "Downloads"),
    ]
    # resolve them
    default_resolved = []
    for d in default_folders:
        try:
            default_resolved.append(config._resolve_dir(d))
        except Exception:
            default_resolved.append(d)
            
    all_configured_folders = list(dict.fromkeys(default_resolved + custom_folders))
    
    folder_stats_map = {item["path"]: item for item in db.get_folder_stats(all_configured_folders)}
    
    display_folders = []
    for f in all_configured_folders:
        display_folders.append({
            "path": f,
            "exists": os.path.isdir(f),
            "is_custom": f in custom_folders,
            "stats": folder_stats_map.get(f, {"event_count": 0, "alert_count": 0, "last_activity": None})
        })
    
    return render_template("settings.html", stats=stats, monitor=monitor_status,
                           config=config, display_folders=display_folders, 
                           app_name=config.APP_NAME)


# Folder operations

@bp.route("/settings/add-folder", methods=["POST"])
def add_custom_folder():
    path = request.form.get("folder_path")
    if not path:
        flash("Folder path is required.", "danger")
        return redirect(url_for("dashboard.settings_page"))
        
    success, message = config.add_custom_folder(path)
    if success:
        log_audit_event("ADD_FOLDER", f"Added monitored folder: {path}", "Admin")
        flash(message, "success")
        if file_monitor.is_running():
            file_monitor.stop_monitoring()
            file_monitor.start_monitoring()
    else:
        flash(message, "danger")
        
    return redirect(url_for("dashboard.settings_page"))

@bp.route("/settings/remove-folder", methods=["POST"])
def remove_custom_folder():
    path = request.form.get("folder_path")
    if not path:
        flash("Folder path is required.", "danger")
        return redirect(url_for("dashboard.settings_page"))
        
    success, message = config.remove_custom_folder(path)
    if success:
        log_audit_event("REMOVE_FOLDER", f"Removed monitored folder: {path}", "Admin")
        flash(message, "success")
        if file_monitor.is_running():
            file_monitor.stop_monitoring()
            file_monitor.start_monitoring()
    else:
        flash(message, "danger")
        
    return redirect(url_for("dashboard.settings_page"))

# Alert actions

@bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
def resolve_alert(alert_id: int):
    success = alert_manager.resolve_alert(alert_id)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": success, "alert_id": alert_id})
    flash("Alert marked as resolved." if success else "Alert not found.", "success" if success else "danger")
    return redirect(url_for("dashboard.alerts_page"))


@bp.route("/alerts/<int:alert_id>/investigate", methods=["POST"])
def investigate_alert(alert_id: int):
    success = alert_manager.investigate_alert(alert_id)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": success, "alert_id": alert_id})
    flash("Alert marked as under investigation.", "info")
    return redirect(url_for("dashboard.alerts_page"))


# Monitor startup/shutdown

@bp.route("/monitor/start", methods=["POST"])
def start_monitor():
    file_monitor.start_monitoring()
    usb_monitor.start_usb_monitor()
    flash("Monitoring started successfully.", "success")
    return redirect(url_for("dashboard.settings_page"))


@bp.route("/monitor/stop", methods=["POST"])
def stop_monitor():
    file_monitor.stop_monitoring()
    usb_monitor.stop_usb_monitor()
    flash("Monitoring stopped.", "warning")
    return redirect(url_for("dashboard.settings_page"))


# REST API endpoints

@bp.route("/api/stats")
def api_stats():
    return jsonify(db.get_dashboard_stats())


@bp.route("/api/monitor-status")
def api_monitor_status():
    return jsonify({
        "file_monitor": file_monitor.is_running(),
        "usb_monitor":  usb_monitor.is_running(),
        "timestamp":    datetime.now().isoformat(),
    })


@bp.route("/api/alerts")
def api_alerts():
    limit    = min(int(request.args.get("limit", 50)), 500)
    offset   = int(request.args.get("offset", 0))
    severity = request.args.get("severity")
    status   = request.args.get("status")
    user     = request.args.get("user")
    search   = request.args.get("search")
    alerts   = db.get_alerts(limit=limit, offset=offset, severity=severity,
                             status=status, user=user, search=search)
    return jsonify({"alerts": alerts, "count": len(alerts)})


@bp.route("/api/events")
def api_events():
    limit  = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    events = db.get_file_events(limit=limit, offset=offset)
    return jsonify({"events": events, "count": len(events)})


@bp.route("/api/chart/trends")
def api_chart_trends():
    days = int(request.args.get("days", 7))
    return jsonify(db.get_alert_trends(days=days))


@bp.route("/api/chart/sensitive-files")
def api_chart_sensitive():
    return jsonify(db.get_top_sensitive_files(limit=10))


@bp.route("/api/chart/violations")
def api_chart_violations():
    return jsonify(db.get_violation_breakdown())


@bp.route("/api/chart/timeline")
def api_chart_timeline():
    return jsonify(db.get_hourly_timeline())


# Report generation and download

@bp.route("/reports/download/<filename>")
def download_report(filename):
    return send_from_directory(config.REPORT_DIR, filename, as_attachment=True)


@bp.route("/reports/generate/pdf", methods=["POST"])
def generate_pdf():
    try:
        from reports.pdf_report import generate_pdf_report
        filepath = generate_pdf_report()
        fname = os.path.basename(filepath)
        flash(f"PDF report generated: {fname}", "success")
    except Exception as e:
        logger.error("PDF generation error: %s", e)
        flash(f"PDF generation failed: {e}", "danger")
    return redirect(url_for("dashboard.reports_page"))


@bp.route("/reports/generate/csv", methods=["POST"])
def generate_csv():
    try:
        from reports.csv_report import generate_csv_reports
        files = generate_csv_reports()
        flash(f"CSV reports generated: {', '.join(os.path.basename(f) for f in files)}", "success")
    except Exception as e:
        logger.error("CSV generation error: %s", e)
        flash(f"CSV generation failed: {e}", "danger")
    return redirect(url_for("dashboard.reports_page"))

# Policy and database administration

@bp.route("/api/export-alerts-csv")
def api_export_alerts_csv():
    csv_str = db.export_alerts_csv()
    log_audit_event("EXPORT_ALERTS", "Exported alerts as CSV", "Admin")
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=alerts.csv"}
    )

@bp.route("/api/export-events-csv")
def api_export_events_csv():
    csv_str = db.export_events_csv()
    log_audit_event("EXPORT_EVENTS", "Exported file events as CSV", "Admin")
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=events.csv"}
    )

@bp.route("/api/clear-dashboard", methods=["POST"])
def clear_dashboard():
    success, message = db.clear_dashboard_with_backup()
    if success:
        log_audit_event("CLEAR_DASHBOARD", f"Dashboard data cleared. {message}", "Admin")
        flash(message, "success")
    else:
        log_audit_event("CLEAR_DASHBOARD_FAIL", f"Attempt failed: {message}", "Admin")
        flash(message, "danger")
    return redirect(url_for("dashboard.settings_page"))

@bp.route("/api/export-policy")
def export_policy():
    json_str = config.export_policy()
    log_audit_event("EXPORT_POLICY", "Exported custom sensitive file policy", "Admin")
    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-disposition": "attachment; filename=sensitive_policy.json"}
    )

@bp.route("/api/import-policy", methods=["POST"])
def import_policy():
    if "policy_file" not in request.files:
        flash("No file part", "danger")
        return redirect(url_for("dashboard.settings_page"))
    
    file = request.files["policy_file"]
    if file.filename == "":
        flash("No selected file", "danger")
        return redirect(url_for("dashboard.settings_page"))
        
    if file:
        json_str = file.read().decode("utf-8")
        success, message = config.import_policy(json_str)
        if success:
            log_audit_event("IMPORT_POLICY", message, "Admin")
            flash(message, "success")
        else:
            flash(message, "danger")
            
    return redirect(url_for("dashboard.settings_page"))

@bp.route("/settings/add-policy", methods=["POST"])
def add_custom_policy():
    val = request.form.get("policy_value")
    ptype = request.form.get("policy_type")
    sev = request.form.get("severity", "HIGH")
    
    if not val or not ptype:
        flash("Value and Type are required.", "danger")
        return redirect(url_for("dashboard.settings_page"))
        
    success, message = config.add_custom_policy(val, ptype, sev)
    if success:
        log_audit_event("ADD_POLICY", f"Added {ptype} policy: {val} ({sev})", "Admin")
        flash(message, "success")
    else:
        flash(message, "danger")
        
    return redirect(url_for("dashboard.settings_page"))

@bp.route("/settings/remove-policy", methods=["POST"])
def remove_custom_policy():
    val = request.form.get("policy_value")
    ptype = request.form.get("policy_type")
    
    if not val or not ptype:
        flash("Value and Type are required.", "danger")
        return redirect(url_for("dashboard.settings_page"))
        
    success, message = config.remove_custom_policy(val, ptype)
    if success:
        log_audit_event("REMOVE_POLICY", f"Removed {ptype} policy: {val}", "Admin")
        flash(message, "success")
    else:
        flash(message, "danger")
        
    return redirect(url_for("dashboard.settings_page"))

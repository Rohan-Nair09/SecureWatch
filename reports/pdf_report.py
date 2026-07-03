# reports/pdf_report.py
# Generates styled PDF reports using ReportLab.


import os
import sys
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db

# Color Palette
DARK_BG   = colors.HexColor("#0d1321")
ACCENT    = colors.HexColor("#00d4ff")
CRITICAL  = colors.HexColor("#ff4757")
HIGH      = colors.HexColor("#ff6b35")
MEDIUM    = colors.HexColor("#ffa502")
LOW       = colors.HexColor("#2ed573")
GREY_DARK = colors.HexColor("#1e2d40")
GREY_MID  = colors.HexColor("#2a3f55")
WHITE     = colors.white
TEXT      = colors.HexColor("#e2e8f0")

SEV_COLORS = {
    "CRITICAL": CRITICAL,
    "HIGH":     HIGH,
    "MEDIUM":   MEDIUM,
    "LOW":      LOW,
}


def _styles():
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=28, textColor=WHITE, alignment=TA_CENTER,
            fontName="Helvetica-Bold", spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontSize=13, textColor=ACCENT, alignment=TA_CENTER,
            fontName="Helvetica", spaceAfter=4,
        ),
        "section": ParagraphStyle(
            "SectionHeader",
            parent=base["Heading1"],
            fontSize=14, textColor=ACCENT, fontName="Helvetica-Bold",
            spaceBefore=18, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=9, textColor=TEXT, fontName="Helvetica",
            spaceAfter=4, leading=14,
        ),
        "small": ParagraphStyle(
            "Small",
            parent=base["Normal"],
            fontSize=8, textColor=TEXT, fontName="Helvetica",
        ),
        "label": ParagraphStyle(
            "Label",
            parent=base["Normal"],
            fontSize=10, textColor=WHITE, fontName="Helvetica-Bold",
        ),
        "stat_value": ParagraphStyle(
            "StatValue",
            parent=base["Normal"],
            fontSize=22, textColor=ACCENT, fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "stat_label": ParagraphStyle(
            "StatLabel",
            parent=base["Normal"],
            fontSize=8, textColor=TEXT, fontName="Helvetica",
            alignment=TA_CENTER,
        ),
    }
    return styles


def _stat_table(stats: dict, S: dict) -> Table:
    """Render the 6-metric overview as a coloured grid table."""
    labels = [
        ("Total Events",          str(stats["total_events"]),          ACCENT),
        ("Active Alerts",         str(stats["active_alerts"]),         HIGH),
        ("Critical Alerts",       str(stats["critical_alerts"]),       CRITICAL),
        ("Integrity Violations",  str(stats["integrity_violations"]),  MEDIUM),
        ("Sensitive Transfers",   str(stats["sensitive_transfers"]),   MEDIUM),
        ("USB Transfers",         str(stats["usb_transfers"]),         CRITICAL),
    ]
    cells = []
    col = []
    for i, (lbl, val, col_color) in enumerate(labels):
        cell = [
            Paragraph(val, ParagraphStyle("sv", fontSize=20, textColor=col_color,
                                          fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Spacer(1, 2),
            Paragraph(lbl, ParagraphStyle("sl", fontSize=8, textColor=TEXT,
                                          fontName="Helvetica", alignment=TA_CENTER)),
        ]
        col.append(cell)
        if (i + 1) % 3 == 0:
            cells.append(col)
            col = []
    if col:
        cells.append(col)

    flat = [[c for c in row] for row in cells]
    t = Table(flat, colWidths=[5.5 * cm, 5.5 * cm, 5.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), GREY_DARK),
        ("BOX",        (0, 0), (-1, -1), 1, GREY_MID),
        ("INNERGRID",  (0, 0), (-1, -1), 0.5, GREY_MID),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def _alert_table(alerts: list, S: dict) -> Table:
    header = ["ID", "Severity", "Type", "File", "Timestamp", "Status"]
    rows = [header]
    for a in alerts[:50]:
        rows.append([
            str(a.get("id", "")),
            a.get("severity", ""),
            a.get("alert_type", ""),
            (a.get("filename") or "N/A")[:30],
            (a.get("timestamp") or "")[:19],
            a.get("status", ""),
        ])

    col_widths = [1 * cm, 2.2 * cm, 4.5 * cm, 4 * cm, 4 * cm, 2.5 * cm]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  GREY_MID),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7),
        ("BACKGROUND",    (0, 1), (-1, -1), GREY_DARK),
        ("TEXTCOLOR",     (0, 1), (-1, -1), TEXT),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [GREY_DARK, GREY_MID]),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, GREY_MID),
        ("BOX",           (0, 0), (-1, -1), 0.5, ACCENT),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
    ])
    # Colour severity column
    for i, a in enumerate(alerts[:50], start=1):
        sev = a.get("severity", "LOW")
        style.add("TEXTCOLOR", (1, i), (1, i), SEV_COLORS.get(sev, WHITE))
        style.add("FONTNAME",  (1, i), (1, i), "Helvetica-Bold")
    t.setStyle(style)
    return t


def _events_table(events: list) -> Table:
    header = ["#", "Event", "Filename", "Source Path", "User", "Timestamp"]
    rows = [header]
    for e in events[:40]:
        rows.append([
            str(e.get("id", "")),
            e.get("event_type", ""),
            (e.get("filename") or "")[:25],
            (e.get("source_path") or "")[:35],
            e.get("user", ""),
            (e.get("timestamp") or "")[:19],
        ])
    col_widths = [0.8*cm, 2*cm, 3.5*cm, 5*cm, 2.5*cm, 4*cm]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  GREY_MID),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7),
        ("BACKGROUND",    (0, 1), (-1, -1), GREY_DARK),
        ("TEXTCOLOR",     (0, 1), (-1, -1), TEXT),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [GREY_DARK, GREY_MID]),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, GREY_MID),
        ("BOX",           (0, 0), (-1, -1), 0.5, ACCENT),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


class _DarkBackground:
    """Canvas callback to draw a dark background on every page."""
    def __call__(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(DARK_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        # Footer
        canvas.setFillColor(GREY_MID)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(2 * cm, 1 * cm,
                          f"{config.APP_NAME} — CONFIDENTIAL — Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        canvas.drawRightString(A4[0] - 2 * cm, 1 * cm, f"Page {doc.page}")
        canvas.restoreState()


def generate_pdf_report() -> str:
    """Generate a full PDF security report and return the file path."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"SecureWatch_Report_{timestamp}.pdf"
    out_path = os.path.join(config.REPORT_DIR, fname)

    S = _styles()
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2.5 * cm, bottomMargin=2 * cm,
    )

    story = []
    bg_cb = _DarkBackground()

    # Cover Page
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("SecureWatch", S["title"]))
    story.append(Paragraph("Secure File Transfer Monitoring System", S["subtitle"]))
    story.append(Paragraph("Security Incident Report", S["subtitle"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(f"Organisation: {config.ORG_NAME}", S["body"]))
    story.append(Paragraph(f"Department:   {config.ORG_DEPARTMENT}", S["body"]))
    story.append(Paragraph(f"Generated:    {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}", S["body"]))
    story.append(Paragraph(f"Generated By: {config.SYSTEM_USER}", S["body"]))
    story.append(Paragraph(f"Classification: CONFIDENTIAL", S["body"]))
    story.append(PageBreak())

    # Executive Summary
    stats = db.get_dashboard_stats()
    story.append(Paragraph("Executive Summary", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY_MID))
    story.append(Spacer(1, 0.3 * cm))
    story.append(_stat_table(stats, S))
    story.append(Spacer(1, 0.5 * cm))
    summary_text = (
        f"This report covers the security monitoring activity captured by {config.APP_NAME}. "
        f"A total of <b>{stats['total_events']}</b> file system events were recorded. "
        f"<b>{stats['active_alerts']}</b> alerts remain active, of which "
        f"<b>{stats['critical_alerts']}</b> are classified as CRITICAL severity. "
        f"<b>{stats['integrity_violations']}</b> file integrity violations were detected, "
        f"and <b>{stats['usb_transfers']}</b> USB transfer attempts were logged."
    )
    story.append(Paragraph(summary_text, S["body"]))

    # Alert Summary
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("Security Alerts", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY_MID))
    story.append(Spacer(1, 0.3 * cm))
    alerts = db.get_alerts(limit=50)
    if alerts:
        story.append(_alert_table(alerts, S))
    else:
        story.append(Paragraph("No alerts recorded.", S["body"]))

    # Integrity Violations
    story.append(PageBreak())
    story.append(Paragraph("File Integrity Violations", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY_MID))
    story.append(Spacer(1, 0.3 * cm))
    violations = db.get_integrity_checks(limit=30, status="MISMATCH")
    if violations:
        vrows = [["File", "Original Hash", "Current Hash", "Timestamp"]]
        for v in violations:
            vrows.append([
                v.get("filename", "")[:30],
                (v.get("original_hash") or "")[:16] + "...",
                (v.get("current_hash") or "N/A")[:16] + "...",
                (v.get("timestamp") or "")[:19],
            ])
        vt = Table(vrows, colWidths=[5*cm, 5*cm, 5*cm, 3.5*cm], repeatRows=1)
        vt.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  CRITICAL),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  WHITE),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7),
            ("BACKGROUND",  (0, 1), (-1, -1), GREY_DARK),
            ("TEXTCOLOR",   (0, 1), (-1, -1), TEXT),
            ("INNERGRID",   (0, 0), (-1, -1), 0.3, GREY_MID),
            ("BOX",         (0, 0), (-1, -1), 0.5, CRITICAL),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0,0), (-1, -1), 4),
        ]))
        story.append(vt)
    else:
        story.append(Paragraph("No integrity violations recorded.", S["body"]))

    # Audit Log
    story.append(PageBreak())
    story.append(Paragraph("Audit Log (Recent 40 Events)", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY_MID))
    story.append(Spacer(1, 0.3 * cm))
    events = db.get_file_events(limit=40)
    if events:
        story.append(_events_table(events))
    else:
        story.append(Paragraph("No file events recorded.", S["body"]))

    doc.build(story, onFirstPage=bg_cb, onLaterPages=bg_cb)
    return out_path

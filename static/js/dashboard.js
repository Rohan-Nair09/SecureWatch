// dashboard.js
// Handles auto-refresh, Chart.js init, live alert feed, and notifications.


"use strict";

// Chart.js defaults
Chart.defaults.color = "#8fa3bc";
Chart.defaults.borderColor = "#1c3050";
Chart.defaults.font.family = "Inter, sans-serif";
Chart.defaults.font.size = 11;

// Constants
const REFRESH_INTERVAL = 30_000; // ms
const ALERT_COLORS = {
  CRITICAL: "#ff3d5a",
  HIGH:     "#ff7b39",
  MEDIUM:   "#ffbe00",
  LOW:      "#2ecc71",
};
const ALERT_ICONS = {
  CRITICAL: "bi-exclamation-octagon-fill",
  HIGH:     "bi-exclamation-triangle-fill",
  MEDIUM:   "bi-info-circle-fill",
  LOW:      "bi-check-circle-fill",
};

// Module state variables
let charts = {};
let refreshTimer = null;
let lastAlertId  = 0;

// Dashboard entry point
function initDashboard() {
  loadTrends(7);
  loadViolations();
  loadTimeline();
  loadSensitiveFiles();
  loadLiveAlerts();
  startAutoRefresh();
}

// Manual refresh handler
function refreshDashboard() {
  const btn = document.getElementById("refresh-btn");
  if (btn) btn.classList.add("spinning");

  Promise.all([
    refreshStats(),
    loadTrends(document.getElementById("trend-days")?.value || 7),
    loadViolations(),
    loadTimeline(),
    loadSensitiveFiles(),
    loadLiveAlerts(),
  ]).finally(() => {
    if (btn) setTimeout(() => btn.classList.remove("spinning"), 800);
  });
}

// ================================================================
// STATS REFRESH
// ================================================================
async function refreshStats() {
  try {
    const res  = await fetch("/api/stats");
    const data = await res.json();

    document.querySelectorAll("[data-stat]").forEach(el => {
      const key = el.dataset.stat;
      if (data[key] !== undefined) {
        animateCounter(el, parseInt(el.textContent) || 0, data[key]);
      }
    });
  } catch (e) {
    console.warn("Stats refresh failed:", e);
  }
}

function animateCounter(el, from, to) {
  const duration = 600;
  const start    = performance.now();
  const diff     = to - from;

  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
    el.textContent = Math.round(from + diff * eased);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ================================================================
// CHART: Alert Trends (Line)
// ================================================================
async function loadTrends(days) {
  try {
    const res  = await fetch(`/api/chart/trends?days=${days}`);
    const data = await res.json();

    const ctx = document.getElementById("trendsChart");
    if (!ctx) return;

    const datasets = [
      {
        label: "Critical",
        data:  data.datasets.CRITICAL,
        borderColor: ALERT_COLORS.CRITICAL,
        backgroundColor: ALERT_COLORS.CRITICAL + "22",
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointHoverRadius: 6,
      },
      {
        label: "High",
        data:  data.datasets.HIGH,
        borderColor: ALERT_COLORS.HIGH,
        backgroundColor: ALERT_COLORS.HIGH + "22",
        fill: true,
        tension: 0.4,
        pointRadius: 4,
      },
      {
        label: "Medium",
        data:  data.datasets.MEDIUM,
        borderColor: ALERT_COLORS.MEDIUM,
        backgroundColor: ALERT_COLORS.MEDIUM + "22",
        fill: true,
        tension: 0.4,
        pointRadius: 4,
      },
      {
        label: "Low",
        data:  data.datasets.LOW,
        borderColor: ALERT_COLORS.LOW,
        backgroundColor: ALERT_COLORS.LOW + "22",
        fill: true,
        tension: 0.4,
        pointRadius: 4,
      },
    ];

    if (charts.trends) {
      charts.trends.data.labels    = data.labels;
      datasets.forEach((ds, i) => { charts.trends.data.datasets[i].data = ds.data; });
      charts.trends.update();
    } else {
      charts.trends = new Chart(ctx, {
        type: "line",
        data: { labels: data.labels, datasets },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          interaction: { intersect: false, mode: "index" },
          plugins: {
            legend: {
              position: "top",
              labels: { usePointStyle: true, pointStyle: "circle", padding: 16 }
            },
            tooltip: {
              backgroundColor: "#0d1a2d",
              borderColor: "#1c3050",
              borderWidth: 1,
              titleColor: "#e8f0fe",
              bodyColor: "#8fa3bc",
              padding: 10,
            },
          },
          scales: {
            x: {
              grid:   { color: "#1c305066" },
              ticks:  { color: "#566a7f", font: { size: 10 } },
            },
            y: {
              grid:   { color: "#1c305066" },
              ticks:  { color: "#566a7f", font: { size: 10 }, stepSize: 1 },
              beginAtZero: true,
            },
          },
        },
      });
    }
  } catch (e) {
    console.warn("Trends chart failed:", e);
  }
}

// ================================================================
// CHART: Violation Breakdown (Doughnut)
// ================================================================
async function loadViolations() {
  try {
    const res  = await fetch("/api/chart/violations");
    const data = await res.json();

    const ctx = document.getElementById("violationsChart");
    if (!ctx) return;

    const labels = Object.keys(data);
    const values = Object.values(data);
    const colors = [
      "#ff3d5a", "#ff7b39", "#ffbe00", "#2ecc71",
      "#00d4ff", "#a855f7", "#ec4899", "#06b6d4"
    ];

    if (charts.violations) {
      charts.violations.data.labels   = labels;
      charts.violations.data.datasets[0].data = values;
      charts.violations.update();
    } else {
      charts.violations = new Chart(ctx, {
        type: "doughnut",
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: colors.slice(0, labels.length),
            borderColor: "#0d1a2d",
            borderWidth: 3,
            hoverOffset: 6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: "65%",
          plugins: {
            legend: {
              position: "bottom",
              labels: {
                usePointStyle: true,
                pointStyle: "circle",
                padding: 12,
                font: { size: 10 },
                boxWidth: 10,
              },
            },
            tooltip: {
              backgroundColor: "#0d1a2d",
              borderColor: "#1c3050",
              borderWidth: 1,
              titleColor: "#e8f0fe",
              bodyColor: "#8fa3bc",
              padding: 10,
            },
          },
        },
      });
    }
  } catch (e) {
    console.warn("Violations chart failed:", e);
  }
}

// ================================================================
// CHART: Hourly Activity Timeline (Bar)
// ================================================================
async function loadTimeline() {
  try {
    const res  = await fetch("/api/chart/timeline");
    const data = await res.json();

    const ctx = document.getElementById("timelineChart");
    if (!ctx) return;

    const currentHour = new Date().getHours();
    const barColors   = data.counts.map((_, i) =>
      i === currentHour ? "#00d4ff" : "#00d4ff55"
    );

    if (charts.timeline) {
      charts.timeline.data.datasets[0].data = data.counts;
      charts.timeline.data.datasets[0].backgroundColor = barColors;
      charts.timeline.update();
    } else {
      charts.timeline = new Chart(ctx, {
        type: "bar",
        data: {
          labels: data.labels,
          datasets: [{
            label: "File Events",
            data:  data.counts,
            backgroundColor: barColors,
            borderRadius: 4,
            borderSkipped: false,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "#0d1a2d",
              borderColor: "#1c3050",
              borderWidth: 1,
              titleColor: "#e8f0fe",
              bodyColor: "#8fa3bc",
              padding: 8,
            },
          },
          scales: {
            x: {
              grid:  { display: false },
              ticks: { color: "#566a7f", font: { size: 9 }, maxRotation: 0 },
            },
            y: {
              grid:  { color: "#1c305066" },
              ticks: { color: "#566a7f", font: { size: 10 }, stepSize: 1 },
              beginAtZero: true,
            },
          },
        },
      });
    }
  } catch (e) {
    console.warn("Timeline chart failed:", e);
  }
}

// ================================================================
// CHART: Most Accessed Sensitive Files (Horizontal Bar)
// ================================================================
async function loadSensitiveFiles() {
  try {
    const res  = await fetch("/api/chart/sensitive-files");
    const data = await res.json();

    const ctx = document.getElementById("sensitiveChart");
    if (!ctx) return;

    const labels = data.map(d => d.filename);
    const counts = data.map(d => d.access_count);

    if (charts.sensitive) {
      charts.sensitive.data.labels = labels;
      charts.sensitive.data.datasets[0].data = counts;
      charts.sensitive.update();
    } else {
      charts.sensitive = new Chart(ctx, {
        type: "bar",
        data: {
          labels,
          datasets: [{
            label: "Access Count",
            data:  counts,
            backgroundColor: "rgba(255,190,0,0.7)",
            borderColor:     "#ffbe00",
            borderWidth:     1,
            borderRadius:    4,
          }],
        },
        options: {
          indexAxis: "y",
          responsive: true,
          maintainAspectRatio: true,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "#0d1a2d",
              borderColor: "#1c3050",
              borderWidth: 1,
              titleColor: "#e8f0fe",
              bodyColor: "#8fa3bc",
              padding: 8,
            },
          },
          scales: {
            x: {
              grid:  { color: "#1c305066" },
              ticks: { color: "#566a7f", font: { size: 10 }, stepSize: 1 },
              beginAtZero: true,
            },
            y: {
              grid:  { display: false },
              ticks: { color: "#8fa3bc", font: { size: 10 } },
            },
          },
        },
      });
    }
  } catch (e) {
    console.warn("Sensitive files chart failed:", e);
  }
}

// ================================================================
// LIVE ALERT FEED
// ================================================================
async function loadLiveAlerts() {
  const feed = document.getElementById("live-alert-feed");
  if (!feed) return;

  try {
    const res  = await fetch("/api/alerts?limit=20&status=ACTIVE");
    const data = await res.json();
    const alerts = data.alerts || [];

    if (alerts.length === 0) {
      feed.innerHTML = `
        <div class="empty-state py-4">
          <i class="bi bi-shield-check-fill text-success fs-3"></i>
          <p class="mt-2 text-muted small mb-0">No active alerts — system is secure.</p>
        </div>`;
      return;
    }

    // Check for new alerts (by ID)
    const newAlerts = lastAlertId > 0
      ? alerts.filter(a => a.id > lastAlertId)
      : [];

    if (newAlerts.length > 0) {
      newAlerts.forEach(a => {
        showToast(`${a.severity}: ${a.alert_type}`, a.severity.toLowerCase());
      });
    }

    if (alerts.length > 0) lastAlertId = Math.max(...alerts.map(a => a.id));

    feed.innerHTML = alerts.map(a => renderAlertItem(a)).join("");
  } catch (e) {
    console.warn("Alert feed failed:", e);
    feed.innerHTML = `<div class="loading-spinner text-danger">
      <i class="bi bi-exclamation-circle me-2"></i>Failed to load alerts
    </div>`;
  }
}

function renderAlertItem(a) {
  const sev   = a.severity || "LOW";
  const icon  = ALERT_ICONS[sev] || "bi-info-circle";
  const cls   = sev.toLowerCase();
  const desc  = a.description || "";
  const ts    = formatTimestamp(a.timestamp);
  const file  = a.filename ? `<span class="mono-text text-accent">${escHtml(a.filename)}</span>` : "";

  return `
    <div class="alert-item" id="feed-alert-${a.id}">
      <div class="alert-item-sev ai-${cls}">
        <i class="bi ${icon}"></i>
      </div>
      <div class="alert-item-body">
        <div class="alert-item-type" style="color:${ALERT_COLORS[sev] || '#fff'}">
          ${escHtml(a.alert_type)}
        </div>
        <div class="alert-item-desc">${escHtml(desc)}</div>
        <div class="alert-item-meta">
          ${file ? `<span>${file}</span>` : ""}
          <span><i class="bi bi-person me-1"></i>${escHtml(a.user || '—')}</span>
          <span><i class="bi bi-clock me-1"></i>${ts}</span>
        </div>
      </div>
      <div class="alert-item-status">
        <span class="sev-badge sev-${cls}">${sev}</span>
      </div>
    </div>`;
}

// ================================================================
// TOAST NOTIFICATIONS
// ================================================================
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const icons = {
    success: "bi-check-circle-fill",
    danger:  "bi-x-circle-fill",
    warning: "bi-exclamation-triangle-fill",
    info:    "bi-info-circle-fill",
    critical:"bi-exclamation-octagon-fill",
    high:    "bi-exclamation-triangle-fill",
    medium:  "bi-exclamation-circle-fill",
    low:     "bi-check-circle-fill",
  };
  const colors = {
    critical: "var(--critical)",
    high:     "var(--high)",
    medium:   "var(--medium)",
    low:      "var(--ok)",
    success:  "var(--ok)",
    danger:   "var(--critical)",
    info:     "var(--accent)",
    warning:  "var(--medium)",
  };
  const icon  = icons[type]  || "bi-info-circle-fill";
  const color = colors[type] || "var(--accent)";
  const cssType = ["success","danger","info","warning"].includes(type) ? type : "info";

  const el = document.createElement("div");
  el.className = `sw-toast toast-${cssType}`;
  el.innerHTML = `
    <i class="bi ${icon}" style="color:${color}"></i>
    <span>${escHtml(message)}</span>`;

  container.appendChild(el);
  setTimeout(() => {
    el.style.animation = "slideInRight 0.3s ease reverse";
    setTimeout(() => el.remove(), 300);
  }, 4000);
}

// ================================================================
// AUTO REFRESH
// ================================================================
function startAutoRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    refreshStats();
    loadLiveAlerts();
    loadTimeline();
  }, REFRESH_INTERVAL);
}

// ================================================================
// UTILITIES
// ================================================================
function formatTimestamp(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts.replace(" ", "T"));
    return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })
         + " · " + d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
  } catch {
    return ts;
  }
}

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

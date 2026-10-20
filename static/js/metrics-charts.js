(() => {
  "use strict";

  // Colors come from the same CSS custom properties the rest of the page already
  // uses, read at init time so charts match whichever theme (light/dark) is active
  // without duplicating the palette here.
  function token(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function data(id) {
    const el = document.getElementById(id);
    return el ? JSON.parse(el.textContent) : null;
  }

  function lineChart(canvasId, dataId, series) {
    const canvas = document.getElementById(canvasId);
    const rows = data(dataId);
    if (!canvas || !rows) return;
    new Chart(canvas, {
      type: "line",
      data: {
        labels: rows.map(row => row.label),
        datasets: series.map(({ key, label, color }) => ({
          label,
          data: rows.map(row => row[key]),
          borderColor: token(color),
          backgroundColor: token(color),
          tension: 0.25,
        })),
      },
      options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
    });
  }

  function barChart(canvasId, dataId, series) {
    const canvas = document.getElementById(canvasId);
    const rows = data(dataId);
    if (!canvas || !rows) return;
    new Chart(canvas, {
      type: "bar",
      data: {
        labels: rows.map(row => row.label),
        datasets: series.map(({ key, label, color }) => ({
          label,
          data: rows.map(row => row[key]),
          backgroundColor: token(color),
        })),
      },
      options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    lineChart("technique-chart", "technique-trend-data", [
      { key: "never", label: "Never hunted", color: "--neutral-fg" },
      { key: "clean", label: "Hunted, no finding", color: "--go-fg" },
      { key: "gap", label: "Gap identified", color: "--warn-fg" },
      { key: "detection", label: "Detection created", color: "--info-fg" },
    ]);

    lineChart("data-source-chart", "data-source-trend-data", [
      { key: "used", label: "Used", color: "--go-fg" },
      { key: "never", label: "Never used", color: "--neutral-fg" },
    ]);

    barChart("throughput-chart", "throughput-trend-data", [
      { key: "started", label: "Started", color: "--info-fg" },
      { key: "completed", label: "Completed", color: "--go-fg" },
    ]);

    lineChart("outcome-chart", "outcome-trend-data", [
      { key: "new_hunt_idea", label: "New hunt idea", color: "--neutral-fg" },
      { key: "analytics_detection", label: "Analytics/Detection", color: "--info-fg" },
      { key: "security_incident", label: "Security incident", color: "--stop-fg" },
      { key: "written_report", label: "Written report", color: "--go-fg" },
      { key: "visibility_gap", label: "Visibility gap", color: "--warn-fg" },
      { key: "security_control_issue", label: "Security control issue", color: "--accent" },
    ]);
  });
})();

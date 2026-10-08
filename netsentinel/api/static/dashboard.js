// Builds the two charts from the JSON data block. No inline script, so the CSP holds.
(function () {
  const el = document.getElementById("chart-data");
  if (!el || !window.Chart) return;
  const data = JSON.parse(el.textContent);
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const ink2 = css("--ink-2"), grid = css("--grid"), muted = css("--muted");
  Chart.defaults.font.family = 'system-ui, -apple-system, "Segoe UI", sans-serif';
  Chart.defaults.color = ink2;
  const axes = {
    x: { grid: { display: false }, ticks: { color: muted, maxTicksLimit: 8 }, border: { color: css("--axis") } },
    y: { beginAtZero: true, grid: { color: grid }, ticks: { color: muted, precision: 0 }, border: { display: false } },
  };

  const s = data.series;
  new Chart(document.getElementById("timeline"), {
    type: "line",
    data: {
      labels: s.map((r) => r.t),
      datasets: [
        { label: "Attack", data: s.map((r) => r.attack), borderColor: css("--series-2"), backgroundColor: css("--series-2"),
          borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, tension: 0 },
        { label: "Benign", data: s.map((r) => r.benign), borderColor: css("--series-1"), backgroundColor: css("--series-1"),
          borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, tension: 0 },
      ],
    },
    options: { maintainAspectRatio: false, interaction: { mode: "index", intersect: false }, scales: axes,
               plugins: { legend: { position: "top", align: "start", labels: { boxWidth: 12, boxHeight: 2 } } } },
  });

  const f = data.families;
  new Chart(document.getElementById("families"), {
    type: "bar",
    data: { labels: f.map((r) => r.family),
            datasets: [{ label: "Attack flows", data: f.map((r) => r.n), backgroundColor: css("--series-1"),
                         borderRadius: 4, borderSkipped: "start", maxBarThickness: 28 }] },
    options: { indexAxis: "y", maintainAspectRatio: false, scales: { x: axes.y, y: { ...axes.x, ticks: { color: ink2 } } },
               plugins: { legend: { display: false } } },
  });

  // Table views (accessible alternative to the charts), built with DOM APIs, never innerHTML.
  function table(target, headers, rows) {
    const t = document.createElement("table");
    const hr = t.createTHead().insertRow();
    headers.forEach((h, i) => { const th = document.createElement("th"); th.textContent = h; if (i) th.className = "num"; hr.appendChild(th); });
    const body = t.createTBody();
    rows.forEach((r) => { const tr = body.insertRow(); r.forEach((v, i) => { const td = tr.insertCell(); td.textContent = v; if (i) td.className = "num"; }); });
    document.getElementById(target).appendChild(t);
  }
  table("timeline-table", ["Time (UTC)", "Attack", "Benign"], s.filter((r) => r.attack || r.benign).map((r) => [r.t, r.attack, r.benign]));
  table("families-table", ["Family", "Attack flows"], f.map((r) => [r.family, r.n]));
})();

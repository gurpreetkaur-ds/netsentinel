// Charts for Overview, Threat Monitoring and Analytics, built from the page's JSON data block.
// Colours come from CSS tokens (validated categorical palette; reserved status colours for severity),
// every chart has a table view, and clicking a mark opens the matching filtered list.
(function () {
  "use strict";
  var dataEl = document.getElementById("chart-data");
  if (!dataEl || !window.Chart) return;
  var data = JSON.parse(dataEl.textContent);
  var meta = JSON.parse((document.getElementById("page-meta") || { textContent: "{}" }).textContent);
  var charts = [];
  var SEV = ["critical", "high", "medium", "low"];
  var SEV_VAR = { critical: "--critical", high: "--serious", medium: "--warning", low: "--low" };

  function css(v) { return getComputedStyle(document.documentElement).getPropertyValue(v).trim(); }
  function series(i) { return css("--series-" + ((i % 8) + 1)); }
  function go(url) { window.location.href = url; }

  function table(target, headers, rows) {
    var host = document.getElementById(target);
    if (!host) return;
    host.textContent = "";
    var t = document.createElement("table");
    var hr = t.createTHead().insertRow();
    headers.forEach(function (h, i) { var th = document.createElement("th"); th.textContent = h; if (i) th.className = "num"; hr.appendChild(th); });
    var body = t.createTBody();
    rows.forEach(function (r) { var tr = body.insertRow(); r.forEach(function (v, i) { var td = tr.insertCell(); td.textContent = v; if (i) td.className = "num"; }); });
    if (!rows.length) { var tr = body.insertRow(), td = tr.insertCell(); td.colSpan = headers.length; td.textContent = "No data in range."; }
    host.appendChild(t);
  }

  function base() {
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
    Chart.defaults.font.size = 12;
    Chart.defaults.color = css("--ink-2");
    Chart.defaults.borderColor = css("--grid");
    return {
      maintainAspectRatio: false, animation: { duration: 250 },
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { position: "top", align: "start", labels: { boxWidth: 10, boxHeight: 10, useBorderRadius: true, borderRadius: 3, color: css("--ink-2") } },
        tooltip: { backgroundColor: css("--surface-3"), titleColor: css("--ink"), bodyColor: css("--ink-2"), borderColor: css("--border-strong"),
                   borderWidth: 1, padding: 10, cornerRadius: 8, boxPadding: 4, usePointStyle: true }
      },
      scales: {
        x: { grid: { display: false }, ticks: { color: css("--muted"), maxTicksLimit: 8, maxRotation: 0 }, border: { color: css("--axis") } },
        y: { beginAtZero: true, grid: { color: css("--grid") }, ticks: { color: css("--muted"), precision: 0 }, border: { display: false } }
      },
      onHover: function (e, els) { e.native.target.style.cursor = els.length ? "pointer" : "default"; }
    };
  }

  function line(id, labels, sets, onClick) {
    var c = document.getElementById(id);
    if (!c) return;
    var o = base();
    o.onClick = function (e, els) { if (els.length && onClick) onClick(els[0].index); };
    charts.push(new Chart(c, { type: "line", data: { labels: labels, datasets: sets.map(function (s) {
      return { label: s.label, data: s.data, borderColor: s.color, backgroundColor: s.color, borderWidth: 2, pointRadius: 0,
               pointHoverRadius: 5, pointHoverBorderWidth: 2, pointHoverBorderColor: css("--surface"), tension: 0.25, fill: false };
    }) }, options: o }));
  }

  function stacked(id, labels, sets, onClick, horizontal) {
    var c = document.getElementById(id);
    if (!c) return;
    var o = base();
    o.indexAxis = horizontal ? "y" : "x";
    o.scales.x.stacked = o.scales.y.stacked = true;
    if (horizontal) { var t = o.scales.x; o.scales.x = o.scales.y; o.scales.y = t; o.scales.x.stacked = o.scales.y.stacked = true; }
    if (sets.length < 2) o.plugins.legend.display = false;
    o.interaction = { mode: sets.length > 1 ? "index" : "nearest", intersect: sets.length < 2, axis: horizontal ? "y" : "x" };
    o.onClick = function (e, els) { if (els.length && onClick) onClick(els[0].index, els[0].datasetIndex); };
    charts.push(new Chart(c, { type: "bar", data: { labels: labels, datasets: sets.map(function (s) {
      return { label: s.label, data: s.data, backgroundColor: s.color, borderColor: css("--surface"), borderWidth: sets.length > 1 ? 1 : 0,
               borderRadius: 4, borderSkipped: false, maxBarThickness: 28, categoryPercentage: 0.8, barPercentage: 0.9 };
    }) }, options: o }));
  }

  function pivot(rows, key, labelKey) {
    var labels = [], seen = {}, groups = {}, order = [];
    rows.forEach(function (r) {
      if (!(r[labelKey] in seen)) { seen[r[labelKey]] = labels.length; labels.push(r[labelKey]); }
      if (!(r[key] in groups)) { groups[r[key]] = []; order.push(r[key]); }
    });
    order.forEach(function (g) { groups[g] = labels.map(function () { return 0; }); });
    rows.forEach(function (r) { groups[r[key]][seen[r[labelKey]]] += r.n; });
    return { labels: labels, groups: groups, order: order };
  }

  function build() {
    charts.forEach(function (c) { c.destroy(); });
    charts = [];
    var range = meta.range || "30d";

    // Overview: activity + severity
    if (data.series && document.getElementById("chart-activity")) {
      var s = data.series, sets = [
        { label: "Attack (alerting)", data: s.map(function (r) { return r.attack; }), color: css("--critical") },
        { label: "Benign", data: s.map(function (r) { return r.benign; }), color: series(0) }];
      if (s.some(function (r) { return r.shadow_attack; }))
        sets.splice(1, 0, { label: "Attack (shadow, not alerted)", data: s.map(function (r) { return r.shadow_attack; }), color: series(3) });
      line("chart-activity", s.map(function (r) { return r.t; }), sets, function () { go("/dashboard/threats?range=" + range); });
      table("table-activity", ["Interval (UTC)", "Attack", "Shadow attack", "Benign"],
        s.filter(function (r) { return r.attack || r.benign || r.shadow_attack; }).map(function (r) { return [r.t, r.attack, r.shadow_attack, r.benign]; }));
    }
    if (data.severity && document.getElementById("chart-severity")) {
      var sv = data.severity;
      var c = document.getElementById("chart-severity"), o = base();
      o.indexAxis = "y"; o.plugins.legend.display = false;
      o.interaction = { mode: "nearest", intersect: true, axis: "y" };
      o.scales = { x: { beginAtZero: true, grid: { color: css("--grid") }, ticks: { color: css("--muted"), precision: 0 }, border: { display: false } },
                   y: { grid: { display: false }, ticks: { color: css("--ink-2") }, border: { color: css("--axis") } } };
      o.onClick = function (e, els) { if (els.length) go("/dashboard/tickets?severity=" + SEV[els[0].index] + "&status=active"); };
      charts.push(new Chart(c, { type: "bar", data: { labels: SEV.map(function (x) { return x.charAt(0).toUpperCase() + x.slice(1); }),
        datasets: [{ label: "Open tickets", data: SEV.map(function (x) { return sv[x]; }), backgroundColor: SEV.map(function (x) { return css(SEV_VAR[x]); }),
                     borderRadius: 4, borderSkipped: "start", maxBarThickness: 26 }] }, options: o }));
      table("table-severity", ["Severity", "Open tickets"], SEV.map(function (x) { return [x, sv[x]]; }));
    }

    // Threat monitoring
    if (data.series && document.getElementById("chart-alerts")) {
      stacked("chart-alerts", data.series.map(function (r) { return r.t; }),
        [{ label: "New alerts", data: data.series.map(function (r) { return r.alerts; }), color: css("--critical") }]);
      table("table-alerts", ["Interval (UTC)", "Alerts"], data.series.filter(function (r) { return r.alerts; }).map(function (r) { return [r.t, r.alerts]; }));
    }

    // Analytics
    if (data.by_family && document.getElementById("chart-family")) {
      var pf = pivot(data.by_family, "family", "day");
      // categorical slots in fixed order; families beyond 7 fold into "Other"
      var fams = pf.order.slice().sort(function (a, b) {
        return pf.groups[b].reduce(function (x, y) { return x + y; }, 0) - pf.groups[a].reduce(function (x, y) { return x + y; }, 0); });
      var keep = fams.slice(0, 7), other = fams.slice(7);
      var fsets = keep.map(function (f, i) { return { label: f, data: pf.groups[f], color: series(i) }; });
      if (other.length) fsets.push({ label: "Other", data: pf.labels.map(function (_, i) { return other.reduce(function (a, f) { return a + pf.groups[f][i]; }, 0); }), color: css("--muted") });
      stacked("chart-family", pf.labels, fsets, function (i, d) {
        var fam = fsets[d].label; go("/dashboard/threats?range=" + range + (fam !== "Other" ? "&family=" + encodeURIComponent(fam) : "")); });
      table("table-family", ["Day / family", "Alerts"], data.by_family.map(function (r) { return [r.day + " · " + r.family, r.n]; }));
    }
    if (data.by_sev && document.getElementById("chart-sev")) {
      var ps = pivot(data.by_sev, "severity", "day");
      var ssets = SEV.filter(function (x) { return ps.groups[x]; }).map(function (x) { return { label: x.charAt(0).toUpperCase() + x.slice(1), data: ps.groups[x], color: css(SEV_VAR[x]) }; });
      stacked("chart-sev", ps.labels, ssets, function (i, d) { go("/dashboard/tickets?severity=" + ssets[d].label.toLowerCase()); });
      table("table-sev", ["Day / severity", "Tickets"], data.by_sev.map(function (r) { return [r.day + " · " + r.severity, r.n]; }));
    }
    if (data.ai && document.getElementById("chart-ai")) {
      var statuses = ["accepted", "rejected", "dismissed", "proposed"], kinds = [];
      data.ai.forEach(function (r) { if (kinds.indexOf(r.kind) < 0) kinds.push(r.kind); });
      var colors = { accepted: css("--good"), rejected: css("--critical"), dismissed: css("--muted"), proposed: series(6) };
      stacked("chart-ai", kinds.map(function (k) { return k.replace(/_/g, " "); }), statuses.map(function (st) {
        return { label: st.charAt(0).toUpperCase() + st.slice(1), color: colors[st], data: kinds.map(function (k) {
          var m = data.ai.filter(function (r) { return r.kind === k && r.status === st; }); return m.length ? m[0].n : 0; }) };
      }), null, true);
      table("table-ai", ["Kind / outcome", "Count"], data.ai.map(function (r) { return [r.kind + " · " + r.status, r.n]; }));
    }
    if (data.closure && document.getElementById("chart-closure")) {
      var pc = pivot(data.closure, "closure_reason", "day");
      var reasons = pc.order;
      var rc = { false_positive: css("--critical"), remediated: css("--good"), duplicate: series(6), benign: series(0), risk_accepted: series(3), no_action_needed: series(2), other: css("--muted") };
      stacked("chart-closure", pc.labels, reasons.map(function (r) { return { label: r.replace(/_/g, " "), data: pc.groups[r], color: rc[r] || css("--muted") }; }),
        function () { go("/dashboard/tickets?status=closed"); });
      table("table-closure", ["Day / reason", "Closed"], data.closure.map(function (r) { return [r.day + " · " + (r.closure_reason || "–"), r.n]; }));
    }
  }
  build();
  document.addEventListener("ns:theme", build);
})();

// Network map: zones as columns, hosts as nodes, real aggregated flows as edges. Drawn with SVG DOM
// calls only. Selecting a node highlights its connections and shows its details.
(function () {
  "use strict";
  var svgEl = document.getElementById("netmap"), src = document.getElementById("net-data");
  if (!svgEl || !src || !window.NS) return;
  var NS_SVG = "http://www.w3.org/2000/svg", el = window.NS.el;
  var d = JSON.parse(src.textContent);
  // draw at the element's real size so text stays legible (no scaling)
  var W = Math.max(320, Math.round(svgEl.clientWidth || 1000)), H = Math.max(360, Math.round(svgEl.clientHeight || 560)), PAD = 16;
  svgEl.setAttribute("viewBox", "0 0 " + W + " " + H);

  function s(tag, attrs, parent) {
    var n = document.createElementNS(NS_SVG, tag);
    Object.keys(attrs).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (parent) parent.appendChild(n);
    return n;
  }

  // nodes
  var nodes = {}, assetsByIp = {};
  d.assets.forEach(function (a) { assetsByIp[a.ip] = a; });
  function node(ip) {
    if (!nodes[ip]) {
      var a = assetsByIp[ip];
      nodes[ip] = { ip: ip, asset: a || null, zone: d.zone_of[ip] || "unzoned", flowsOut: 0, flowsIn: 0, attacks: 0, ports: {}, peers: {},
                    risk: d.risk[ip] || null, sensor: ip === d.server_ip };
    }
    return nodes[ip];
  }
  d.assets.forEach(function (a) { node(a.ip); });
  if (d.server_ip) node(d.server_ip);
  d.edges.forEach(function (e) {
    var a = node(e.src), b = node(e.dst);
    a.flowsOut += e.flows; b.flowsIn += e.flows; a.attacks += e.attacks; b.attacks += e.attacks;
    a.peers[e.dst] = true; b.peers[e.src] = true;
    (e.ports || []).forEach(function (p) { b.ports[p] = true; });
  });

  // layout: one column per zone present
  var order = ["external", "dmz", "internal", "unzoned"];
  var labels = { external: "External", dmz: "DMZ", internal: "Internal", unzoned: "Unzoned" };
  var cols = order.filter(function (z) { return Object.keys(nodes).some(function (ip) { return nodes[ip].zone === z; }); });
  var colW = (W - PAD * 2) / Math.max(1, cols.length);
  var MAX_PER_COL = Math.max(6, Math.floor((H - 80) / 30));
  cols.forEach(function (z, ci) {
    var list = Object.keys(nodes).map(function (ip) { return nodes[ip]; }).filter(function (n) { return n.zone === z; })
      .sort(function (a, b) { return (b.attacks - a.attacks) || ((b.flowsIn + b.flowsOut) - (a.flowsIn + a.flowsOut)) || (b.asset ? 1 : 0) - (a.asset ? 1 : 0); });
    list.slice(MAX_PER_COL).forEach(function (n) { n.hidden = true; });
    list = list.slice(0, MAX_PER_COL);
    var gap = (H - PAD * 2 - 40) / Math.max(1, list.length);
    list.forEach(function (n, i) { n.x = PAD + colW * ci + colW / 2; n.y = PAD + 40 + gap * i + gap / 2; });
    s("rect", { class: "zone-bg", x: PAD + colW * ci + 8, y: PAD, width: colW - 16, height: H - PAD * 2, rx: 12 }, svgEl);
    var t = s("text", { class: "zone-label", x: PAD + colW * ci + 22, y: PAD + 22 }, svgEl);
    t.textContent = labels[z] + " · " + list.length + (list.length === MAX_PER_COL ? "+" : "");
  });

  // edges
  var maxFlows = Math.max.apply(null, [1].concat(d.edges.map(function (e) { return e.flows; })));
  var edgeEls = [];
  var gEdges = s("g", {}, svgEl);
  d.edges.forEach(function (e) {
    var a = nodes[e.src], b = nodes[e.dst];
    if (!a || !b || a.hidden || b.hidden || a.x === undefined || b.x === undefined) return;
    var mx = (a.x + b.x) / 2, bend = a.x === b.x ? 60 : 0;
    var p = s("path", { class: "edge" + (e.attacks ? " attack" : ""), d: "M" + a.x + "," + a.y + " C" + (mx + bend) + "," + a.y + " " + (mx + bend) + "," + b.y + " " + b.x + "," + b.y,
                       "stroke-width": (1 + 4 * Math.log(1 + e.flows) / Math.log(1 + maxFlows)).toFixed(2) }, gEdges);
    var title = s("title", {}, p);
    title.textContent = e.src + " → " + e.dst + ": " + e.flows + " flows, " + e.attacks + " flagged as attacks";
    edgeEls.push({ el: p, src: e.src, dst: e.dst });
  });

  // nodes
  var nodeEls = [];
  Object.keys(nodes).forEach(function (ip) {
    var n = nodes[ip];
    if (n.hidden || n.x === undefined) return;
    var risk = n.risk ? ["", "low", "medium", "high", "critical"][n.risk.sevrank] : "";
    var g = s("g", { class: "node " + (n.asset ? "asset" : "unknown") + (n.sensor ? " sensor" : "") + (risk ? " risk-" + risk : ""),
                     transform: "translate(" + n.x + "," + n.y + ")", tabindex: "0", role: "button",
                     "aria-label": (n.asset ? n.asset.name + " " : "Unknown host ") + ip + (risk ? ", open " + risk + " ticket" : "") }, svgEl);
    var r = n.asset ? 7 + (n.asset.criticality || 1) * 1.6 : 7;
    s("circle", { class: "ring", r: r }, g);
    if (n.attacks) s("circle", { r: 3, fill: getComputedStyle(document.documentElement).getPropertyValue("--critical") }, g);
    var label = s("text", { x: r + 6, y: 4 }, g);
    label.textContent = n.sensor ? "this server (sensor)" : n.asset ? n.asset.name : ip;
    nodeEls.push({ el: g, ip: ip });
    function select() { show(n); highlight(ip); }
    g.addEventListener("click", select);
    g.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(); } });
  });

  function highlight(ip) {
    edgeEls.forEach(function (e) { e.el.classList.toggle("dim", e.src !== ip && e.dst !== ip); });
    nodeEls.forEach(function (n) { n.el.classList.toggle("dim", n.ip !== ip && !nodes[ip].peers[n.ip]); });
  }

  var panel = document.getElementById("node-detail");
  function row(k, v) { return [el("dt", { text: k }), el("dd", { text: v })]; }
  function show(n) {
    panel.textContent = "";
    panel.appendChild(el("div", { cls: "card-head" }, [el("h2", { text: n.sensor ? "This server (live sensor)" : n.asset ? n.asset.name : "Unknown host" }),
      n.asset && n.asset.source.indexOf("demo:") === 0 ? el("span", { cls: "badge b-demo", text: "demo inventory" }) : null]));
    var dl = el("dl", { cls: "kv" });
    [].concat(row("Address", n.ip), row("Zone", n.zone),
      n.asset ? row("Role", n.asset.role || "–") : row("Inventory", "not in the asset inventory"),
      n.asset ? row("Criticality", n.asset.criticality + "/5") : [],
      row("Flows out / in", n.flowsOut.toLocaleString() + " / " + n.flowsIn.toLocaleString()),
      row("Attack flows", n.attacks.toLocaleString()),
      row("Ports reached", Object.keys(n.ports).slice(0, 12).join(", ") || "–"),
      row("Peers", Object.keys(n.peers).length + " hosts"),
      row("Open tickets", n.risk ? n.risk.open_tickets + " (highest " + ["", "low", "medium", "high", "critical"][n.risk.sevrank] + ")" : "none")
    ).forEach(function (x) { dl.appendChild(x); });
    panel.appendChild(dl);
    panel.appendChild(el("div", { cls: "row" }, [
      el("a", { cls: "btn sm", href: "/dashboard/threats?range=90d&ip=" + encodeURIComponent(n.ip), text: "Alerts" }),
      el("a", { cls: "btn sm", href: "/dashboard/tickets?ip=" + encodeURIComponent(n.ip), text: "Tickets" })]));
  }
})();

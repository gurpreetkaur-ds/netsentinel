// NetSentinel console shell: sidebar, theme, clock, global search, notifications, health, tabs,
// confirmation dialogs, copy buttons, uploads. DOM APIs only (never innerHTML with data), so text
// from tickets or logs can't become markup.
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var csrf = ($('meta[name="csrf-token"]') || {}).content || "";
  var store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } }
  };

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k];
      else if (k === "cls") n.className = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  function svg(name, cls) {
    var s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    s.setAttribute("class", "icon " + (cls || ""));
    s.setAttribute("aria-hidden", "true");
    var u = document.createElementNS("http://www.w3.org/2000/svg", "use");
    u.setAttribute("href", "#i-" + name);
    s.appendChild(u);
    return s;
  }
  function fmtUTC(d) { return d.toISOString().slice(0, 16).replace("T", " ") + " UTC"; }
  function ago(d) {
    var s = (Date.now() - d.getTime()) / 1000, f = s < 0 ? "in " : "", a = Math.abs(s), out;
    if (a < 60) out = Math.round(a) + "s"; else if (a < 3600) out = Math.round(a / 60) + " min";
    else if (a < 86400) out = Math.round(a / 3600) + " h"; else out = Math.round(a / 86400) + " d";
    return s < 0 ? f + out : out + " ago";
  }
  function api(path, opts) {
    opts = opts || {};
    var headers = opts.headers || {};
    if (opts.method === "POST") headers["X-CSRF-Token"] = csrf;
    if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
    return fetch(path, { method: opts.method || "GET", headers: headers, body: opts.body, credentials: "same-origin" })
      .then(function (r) {
        return r.text().then(function (t) {
          var data = null;
          try { data = t ? JSON.parse(t) : null; } catch (e) { data = null; }
          if (!r.ok) {
            var msg = (data && data.error && data.error.message) || ("Request failed (" + r.status + ")");
            var err = new Error(msg); err.status = r.status; throw err;
          }
          return data;
        });
      });
  }
  window.NS = { $: $, $$: $$, el: el, svg: svg, api: api, ago: ago, fmtUTC: fmtUTC, store: store, csrf: csrf };

  // ── sidebar ──────────────────────────────────────────────────────────────
  var shell = $("#shell");
  if (shell && store.get("ns-sidebar") === "collapsed") shell.classList.add("collapsed");
  var collapse = $("#collapse");
  if (collapse) collapse.addEventListener("click", function (e) {
    e.preventDefault();
    shell.classList.toggle("collapsed");
    store.set("ns-sidebar", shell.classList.contains("collapsed") ? "collapsed" : "open");
  });
  var menu = $("#menu");
  if (menu) menu.addEventListener("click", function () {
    var open = shell.classList.toggle("nav-open");
    menu.setAttribute("aria-expanded", open ? "true" : "false");
  });
  document.addEventListener("click", function (e) {
    if (shell && shell.classList.contains("nav-open") && !e.target.closest("#sidebar") && !e.target.closest("#menu")) {
      shell.classList.remove("nav-open"); if (menu) menu.setAttribute("aria-expanded", "false");
    }
  });

  // ── theme ────────────────────────────────────────────────────────────────
  var themeBtn = $("#theme-toggle");
  function paintThemeIcon() {
    if (!themeBtn) return;
    themeBtn.textContent = "";
    themeBtn.appendChild(svg(document.documentElement.getAttribute("data-theme") === "light" ? "moon" : "sun"));
  }
  paintThemeIcon();
  if (themeBtn) themeBtn.addEventListener("click", function () {
    var next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    store.set("ns-theme", next);
    paintThemeIcon();
    document.dispatchEvent(new CustomEvent("ns:theme"));
  });

  // ── clock & times ────────────────────────────────────────────────────────
  var cu = $("#clock-utc"), cl = $("#clock-local");
  function tick() {
    var d = new Date();
    if (cu) cu.textContent = d.toISOString().slice(11, 16) + " UTC";
    if (cl) {
      var tz = "";
      try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (e) { tz = ""; }
      cl.textContent = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + " " + (tz.split("/").pop() || "local").replace(/_/g, " ");
    }
  }
  tick(); setInterval(tick, 15000);
  function relTimes(root) {
    $$("time[datetime]", root).forEach(function (t) {
      var d = new Date(t.getAttribute("datetime"));
      if (isNaN(d)) return;
      t.title = fmtUTC(d) + " · " + d.toLocaleString() + " local";
      if (!t.dataset.abs) { t.dataset.abs = t.textContent; }
      t.textContent = ago(d);
    });
  }
  relTimes(document);
  setInterval(function () { relTimes(document); }, 60000);
  window.NS.relTimes = relTimes;

  // ── global search ────────────────────────────────────────────────────────
  var q = $("#global-search"), box = $("#search-results"), timer = null, active = -1;
  function closeSearch() { if (box) { box.hidden = true; q.setAttribute("aria-expanded", "false"); active = -1; } }
  function renderSearch(data, term) {
    box.textContent = "";
    var groups = [
      ["Tickets", data.tickets, function (r) { return { href: "/dashboard/tickets/" + encodeURIComponent(r.ticket_id), icon: "ticket", main: r.ticket_id + " · " + r.title, sub: r.status.replace(/_/g, " ") }; }],
      ["IP addresses", data.ips, function (r) { return { href: "/dashboard/threats?range=90d&ip=" + encodeURIComponent(r.ip), icon: "radar", main: r.ip, sub: r.n ? r.n + " alerts/tickets" : "search alerts" }; }],
      ["Hosts", data.hosts, function (r) { return { href: "/dashboard/tickets?q=" + encodeURIComponent(r.ip), icon: "server", main: r.name + " · " + r.ip, sub: (r.source || "").indexOf("demo:") === 0 ? "demo inventory" : r.role }; }],
      ["Alerts", data.alerts, function (r) { return { href: "/dashboard/threats?range=90d&ip=" + encodeURIComponent(r.src_ip || ""), icon: "zap", main: (r.family || "Unnamed") + " from " + (r.src_ip || "?"), sub: r.flow_count + " flows" }; }]
    ];
    var n = 0;
    groups.forEach(function (g) {
      if (!g[1] || !g[1].length) return;
      box.appendChild(el("div", { cls: "group", text: g[0] }));
      g[1].forEach(function (r) {
        var it = g[2](r);
        box.appendChild(el("a", { href: it.href, role: "option" }, [svg(it.icon, "sm"), el("span", { text: it.main }), el("span", { cls: "sub", text: it.sub || "" })]));
        n++;
      });
    });
    box.appendChild(el("a", { href: "/dashboard/tickets?q=" + encodeURIComponent(term), role: "option" }, [svg("search", "sm"), el("span", { text: "Search all tickets for “" + term + "”" })]));
    if (!n) box.insertBefore(el("div", { cls: "empty", text: "No direct matches." }), box.firstChild);
    box.hidden = false; q.setAttribute("aria-expanded", "true");
  }
  if (q && box) {
    q.addEventListener("input", function () {
      clearTimeout(timer);
      var term = q.value.trim();
      if (term.length < 2) { closeSearch(); return; }
      timer = setTimeout(function () {
        api("/dashboard/api/search?q=" + encodeURIComponent(term)).then(function (d) { renderSearch(d, term); })
          .catch(function (e) { box.textContent = ""; box.appendChild(el("div", { cls: "empty", text: e.message })); box.hidden = false; });
      }, 180);
    });
    q.addEventListener("keydown", function (e) {
      var items = $$("a", box);
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        active = Math.max(0, Math.min(items.length - 1, active + (e.key === "ArrowDown" ? 1 : -1)));
        items.forEach(function (a, i) { a.classList.toggle("active", i === active); });
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (items[active]) location.href = items[active].href;
        else if (q.value.trim()) location.href = "/dashboard/tickets?q=" + encodeURIComponent(q.value.trim());
      } else if (e.key === "Escape") { closeSearch(); q.blur(); }
    });
    document.addEventListener("click", function (e) { if (!e.target.closest(".search")) closeSearch(); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); q.focus(); }
    });
  }

  // ── notifications ────────────────────────────────────────────────────────
  var nb = $("#notif-btn"), np = $("#notif-panel"), nl = $("#notif-list"), dot = $("#notif-dot");
  var notifIcons = { overdue: "clock", critical: "alert", approval: "lock", ai: "sparkles", assigned: "user" };
  function loadNotifs() {
    if (!nl) return;
    api("/dashboard/api/notifications").then(function (d) {
      nl.textContent = "";
      var seen = Number(store.get("ns-notif-seen") || 0), newest = 0;
      if (!d.items.length) nl.appendChild(el("div", { cls: "empty small", text: "Nothing needs your attention." }));
      d.items.forEach(function (n) {
        var t = n.at ? new Date(n.at) : null;
        if (t && t.getTime() > newest) newest = t.getTime();
        nl.appendChild(el("a", { cls: "notif", href: n.href }, [
          el("span", { cls: "ico" }, [svg(notifIcons[n.kind] || "info", "sm")]),
          el("div", {}, [el("div", { cls: "t", text: n.title }), el("div", { cls: "s", text: n.text + (t ? " · " + ago(t) : "") })])
        ]));
      });
      if (dot) dot.hidden = !(newest > seen);
      nb.dataset.newest = String(newest);
    }).catch(function () { nl.textContent = ""; nl.appendChild(el("div", { cls: "empty small", text: "Notifications are unavailable right now." })); });
  }
  if (nb && np) {
    nb.addEventListener("click", function (e) {
      e.stopPropagation();
      np.hidden = !np.hidden;
      nb.setAttribute("aria-expanded", np.hidden ? "false" : "true");
      if (!np.hidden) { store.set("ns-notif-seen", nb.dataset.newest || String(Date.now())); if (dot) dot.hidden = true; }
    });
    document.addEventListener("click", function (e) { if (!e.target.closest("#notif-panel")) { np.hidden = true; nb.setAttribute("aria-expanded", "false"); } });
    loadNotifs(); setInterval(loadNotifs, 60000);
  }

  // ── health pill refresh ──────────────────────────────────────────────────
  var hp = $("#health-pill");
  if (hp) setInterval(function () {
    api("/dashboard/api/health").then(function (h) {
      var p = $(".pulse", hp), t = $(".txt", hp);
      if (p) p.className = "pulse " + h.state;
      if (t) t.textContent = h.label;
      hp.title = h.items.map(function (i) { return i.name + ": " + i.value; }).join("\n");
    }).catch(function () { /* keep last state */ });
  }, 30000);

  // ── tabs (progressive: without JS every section is visible) ──────────────
  var tabs = $$('[role="tab"][data-tab]');
  function showTab(name, focus) {
    if (!tabs.length) return;
    if (!$$('[role="tab"][data-tab="' + name + '"]').length) name = tabs[0].dataset.tab;
    tabs.forEach(function (t) { t.setAttribute("aria-selected", t.dataset.tab === name ? "true" : "false"); t.tabIndex = t.dataset.tab === name ? 0 : -1; });
    $$(".tab-panel").forEach(function (p) { p.hidden = p.id !== name; });
    if (focus) { var panel = document.getElementById(name); if (panel) panel.scrollIntoView({ block: "nearest" }); }
  }
  if (tabs.length) {
    tabs.forEach(function (t, i) {
      t.addEventListener("click", function (e) { e.preventDefault(); history.replaceState(null, "", "#" + t.dataset.tab); showTab(t.dataset.tab); });
      t.addEventListener("keydown", function (e) {
        if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
        var n = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
        n.focus(); n.click();
      });
    });
    $$('a[data-tab]:not([role="tab"])').forEach(function (a) {
      a.addEventListener("click", function (e) { e.preventDefault(); history.replaceState(null, "", "#" + a.dataset.tab); showTab(a.dataset.tab, true); });
    });
    showTab((location.hash || "#overview").slice(1));
    window.NS.showTab = showTab;
  }

  // ── confirmation dialogs for high-impact forms ───────────────────────────
  var dlg = $("#confirm-dialog");
  function confirmThen(title, text, okLabel, danger, go) {
    if (!dlg || typeof dlg.showModal !== "function") { if (window.confirm(text)) go(); return; }
    $("#confirm-title").textContent = title;
    $("#confirm-text").textContent = text;
    var ok = $("#confirm-ok"), cancel = $("#confirm-cancel");
    ok.textContent = okLabel || "Confirm";
    ok.className = "btn " + (danger ? "danger" : "primary");
    var done = function (yes) { dlg.close(); ok.onclick = cancel.onclick = null; if (yes) go(); };
    ok.onclick = function () { done(true); };
    cancel.onclick = function () { done(false); };
    dlg.showModal();
    cancel.focus();
  }
  window.NS.confirm = confirmThen;
  $$("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (f.dataset.confirmed) return;
      e.preventDefault();
      confirmThen("Please confirm", f.dataset.confirm, "Confirm", /close|escalate/i.test(f.dataset.confirm), function () {
        f.dataset.confirmed = "1"; f.requestSubmit ? f.requestSubmit() : f.submit();
      });
    });
  });
  // Response-action decisions: spell out the exact target and impact before approving or simulating.
  $$("form.decide-form").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      var b = e.submitter, verb = b && b.value;
      if (f.dataset.confirmed || !verb || verb === "complete" || verb === "reject") return;
      e.preventDefault();
      var what = f.dataset.action + " → " + f.dataset.target;
      var text = verb === "approve" ? "Approve “" + what + "”? " + (f.dataset.disruptive === "yes" ? "This action is disruptive. " : "") +
        "Approval is recorded under your name. NetSentinel will not carry it out on its own."
        : verb === "simulate" ? "Run a SIMULATION of “" + what + "”? Nothing will be changed on any system; the exact request is recorded."
        : "Cancel “" + what + "”? It can't be approved afterwards.";
      confirmThen(verb === "approve" ? "Approve response action" : verb === "simulate" ? "Simulate action" : "Cancel action", text,
        verb === "approve" ? "Approve" : verb === "simulate" ? "Run simulation" : "Cancel action", verb === "cancel", function () {
          f.dataset.confirmed = "1";
          var h = el("input", { type: "hidden", name: "decision", value: verb });
          f.appendChild(h);
          f.submit();
        });
    });
  });

  // ── copy buttons ─────────────────────────────────────────────────────────
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-copy]");
    if (!b) return;
    var code = b.parentElement.querySelector("code, pre");
    if (!code || !navigator.clipboard) return;
    navigator.clipboard.writeText(code.textContent).then(function () {
      var old = b.lastChild.textContent; b.lastChild.textContent = "Copied"; setTimeout(function () { b.lastChild.textContent = old; }, 1500);
    });
  });

  // ── bar widths (CSP forbids inline style attributes; CSSOM is allowed) ────
  $$("[data-pct]").forEach(function (f) { f.style.width = Math.max(2, Number(f.dataset.pct) || 0) + "%"; });

  // ── attachment upload ────────────────────────────────────────────────────
  var up = $("#upload");
  if (up) {
    var file = $("#upload-file"), btn = $("#upload-btn"), st = $("#upload-status");
    btn.addEventListener("click", function () {
      var f = file.files && file.files[0];
      if (!f) { st.textContent = "Choose a file first."; return; }
      if (f.size > 5 * 1024 * 1024) { st.textContent = "Files may be at most 5 MB."; return; }
      btn.disabled = true; st.textContent = "Uploading…";
      f.arrayBuffer().then(function (buf) {
        return api("/dashboard/api/tickets/" + encodeURIComponent(up.dataset.ticket) + "/attachments",
          { method: "POST", body: buf, headers: { "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent(f.name).replace(/%20/g, " ").replace(/%[0-9A-F]{2}/g, "_") } });
      }).then(function () { location.hash = "#evidence"; location.reload(); })
        .catch(function (e) { st.textContent = e.message; btn.disabled = false; });
    });
  }
})();

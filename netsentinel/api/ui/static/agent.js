// AI Security Agent client (ticket panel and agent page). Streams run progress over server-sent events
// and renders the structured result. Everything is inserted as text nodes: model output and ticket text
// can never become markup or script.
(function () {
  "use strict";
  var NS = window.NS;
  if (!NS) return;
  var el = NS.el, svg = NS.svg, api = NS.api;
  var meta = JSON.parse((document.getElementById("page-meta") || { textContent: "{}" }).textContent);
  var log = document.getElementById("agent-log");
  var form = document.getElementById("agent-form");
  var input = document.getElementById("agent-input");
  var picker = document.getElementById("agent-ticket");
  var state = { ticket: meta.ticket_id || null, conversation: meta.conversation_id || null, busy: false };
  var TOOL_LABELS = { get_ticket_details: "Reading the ticket", get_related_alerts: "Looking for related alerts",
    search_security_logs: "Searching flow logs", lookup_ip_reputation: "Checking IP reputation",
    get_asset_details: "Looking up the asset", get_detection_rule: "Reading the detection rule" };

  function scroll() { if (log) log.scrollTop = log.scrollHeight; }
  function badge(text, cls) { return el("span", { cls: "badge " + (cls || "b-outline"), text: text }); }
  function sevBadge(s) { return el("span", { cls: "badge sev-" + s, text: s.charAt(0).toUpperCase() + s.slice(1) }); }
  function section(label) { return el("div", { cls: "section-label", text: label }); }

  // ── recommendation decisions (shared by the panel and the AI tab) ─────────
  function decide(card, recId, decision) {
    var note = "";
    if (decision !== "accept" || card.dataset.kind === "severity_change" || card.dataset.kind === "escalation") {
      note = window.prompt(decision === "accept" ? "Reason (kept in the audit trail):" : "Optional note:", "") || "";
      if (decision === "accept" && !note.trim()) return;
    }
    NS.$$("button", card).forEach(function (b) { b.disabled = true; });
    api("/dashboard/api/ai/recommendations/" + recId, { method: "POST", json: { decision: decision, note: note } })
      .then(function (res) {
        card.classList.add("decided");
        NS.$$(".row", card).forEach(function (r) { if (r.querySelector("[data-decide]")) r.remove(); });
        var msg = res.status.charAt(0).toUpperCase() + res.status.slice(1);
        if (res.effect && res.effect.action_id) msg += ": proposed as a response action; an approver must approve it (Response tab).";
        if (res.effect && res.effect.comment_id) msg += ": posted as a comment.";
        if (res.effect && res.effect.severity) msg += ": severity changed to " + res.effect.severity + ".";
        if (res.effect && res.effect.escalated) msg += ": ticket escalated.";
        if (res.effect && res.effect.text !== undefined) {
          var target = document.getElementById("resolution-note");
          if (target) { target.value = res.effect.text; if (NS.showTab) NS.showTab("resolution", true); target.focus(); msg += ": copied into the resolution form for you to review."; }
        }
        card.appendChild(el("div", { cls: "tiny faint", text: msg }));
      })
      .catch(function (e) {
        NS.$$("button", card).forEach(function (b) { b.disabled = false; });
        card.appendChild(el("div", { cls: "tiny overdue", text: e.message }));
      });
  }
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-decide]");
    if (!b) return;
    var card = b.closest("[data-rec]");
    if (card) decide(card, card.dataset.rec, b.dataset.decide);
  });

  // ── rendering ────────────────────────────────────────────────────────────
  function userMsg(text) {
    var m = el("div", { cls: "msg user", text: text });
    log.appendChild(m); scroll();
  }
  function agentShell() {
    var steps = el("ul", { cls: "steps" });
    var status = el("li", {}, [el("span", { cls: "spinner", "aria-hidden": "true" }), el("span", { text: "Queued…" })]);
    steps.appendChild(status);
    var m = el("div", { cls: "msg agent-msg" }, [steps]);
    log.appendChild(m); scroll();
    return { root: m, steps: steps, status: status };
  }
  function setStatus(view, text, done, err) {
    view.status.textContent = "";
    view.status.appendChild(done ? svg(err ? "x" : "check", err ? "err" : "ok") : el("span", { cls: "spinner", "aria-hidden": "true" }));
    view.status.appendChild(el("span", { text: text }));
  }
  function addStep(view, ev) {
    var d = ev.data || {};
    if (ev.kind === "status") { setStatus(view, d.status === "running" ? "Investigating…" : "Queued…", false); return; }
    if (ev.kind === "tool_call") {
      var args = Object.keys(d.args || {}).map(function (k) { return k + "=" + d.args[k]; }).join(", ");
      var li = el("li", { "data-tool": d.tool }, [el("span", { cls: "spinner", "aria-hidden": "true" }),
        el("span", { text: (TOOL_LABELS[d.tool] || d.tool) + (args ? " (" + args + ")" : "") })]);
      view.steps.insertBefore(li, view.status); scroll(); return;
    }
    if (ev.kind === "tool_result") {
      var pending = NS.$$('li[data-tool="' + d.tool + '"]', view.steps).filter(function (x) { return !x.dataset.done; });
      var li2 = pending[0];
      if (li2) {
        li2.dataset.done = "1";
        li2.replaceChild(svg(d.ok ? "check" : "x", d.ok ? "ok" : "err"), li2.firstChild);
        if (!d.ok && d.error) li2.appendChild(el("span", { cls: "err", text: " · " + d.error }));
      }
      return;
    }
    if (ev.kind === "note") return;   // intermediate model text is not shown; the final answer is
  }

  function renderResult(view, run) {
    var r = run.result || {};
    setStatus(view, "Done · " + (run.tool_calls || 0) + " tool calls · " + (r.tools_used || []).length + " tools", true);
    var box = el("div", { cls: "stack" });
    if (run.guard_findings && run.guard_findings.length)
      box.appendChild(el("div", { cls: "banner warn small" }, [svg("alert"), el("span", { text: "Guard flagged " + run.guard_findings.length +
        " item(s): " + run.guard_findings.map(function (g) { return g.type.replace(/_/g, " ") + " (" + g.action + ")"; }).join("; ") })]));
    box.appendChild(el("div", { cls: "answer", text: r.answer || r.summary || "" }));
    var groups = [["confirmed", "Confirmed evidence"], ["hypothesis", "Hypotheses"], ["unknown", "Unknown"]];
    groups.forEach(function (g) {
      var items = (r.findings || []).filter(function (f) { return f.category === g[0]; });
      if (!items.length) return;
      box.appendChild(section(g[1]));
      items.forEach(function (f) {
        var refs = (f.evidence_refs || []).join(" · ");
        box.appendChild(el("div", { cls: "finding " + g[0] + (f.supported === false ? " unsupported" : "") }, [
          el("div", { cls: "row" }, [sevBadge(f.severity), badge(f.confidence + " confidence"), f.supported === false ? badge("unsupported: verify", "sev-medium") : null]),
          el("div", { text: f.statement }), refs ? el("div", { cls: "refs", text: refs }) : null]));
      });
    });
    if ((r.missing_evidence || []).length) {
      box.appendChild(section("Missing evidence"));
      box.appendChild(el("ul", { cls: "small" }, r.missing_evidence.map(function (x) { return el("li", { text: x }); })));
    }
    var recs = run.recommendations || [];
    if (recs.length) {
      box.appendChild(section("Recommended next steps"));
      recs.forEach(function (x) {
        var b = x.body || {};
        var card = el("div", { cls: "rec" + (x.status === "proposed" ? "" : " decided"), "data-rec": x.rec_id, "data-kind": x.kind }, [
          el("div", { cls: "rec-head" }, [badge("P" + x.priority), badge(x.kind.replace(/_/g, " "), "b-ai"), el("b", { text: x.title }),
            x.kind === "remediation" ? el("span", { cls: "mono small", text: (b.action_type || "") + " → " + (b.target || "") }) : null,
            x.kind === "severity_change" && b.severity ? sevBadge(b.severity) : null]),
          x.rationale ? el("div", { cls: "why", text: x.rationale }) : null]);
        if (b.command) {
          card.appendChild(el("div", { cls: "codeblock" }, [el("pre", {}, [el("code", { text: b.command.code })]),
            el("button", { cls: "btn sm copy", type: "button", "data-copy": "" }, [svg("copy", "sm"), el("span", { text: "Copy" })])]));
          card.appendChild(el("div", { cls: "tiny faint", text: b.command.language + " · for analyst review; NetSentinel never runs commands" }));
        }
        if (b.text) card.appendChild(el("div", { cls: "comment" }, [el("div", { cls: "text", text: b.text })]));
        if (x.status === "proposed" && meta.can_write && run.ticket_id) {
          var label = { comment_draft: "Post comment", resolution_draft: "Use draft", remediation: "Propose action", severity_change: "Apply", escalation: "Apply" }[x.kind] || "Accept";
          card.appendChild(el("div", { cls: "row" }, [el("button", { cls: "btn sm primary", type: "button", "data-decide": "accept", text: label }),
            el("button", { cls: "btn sm", type: "button", "data-decide": "reject", text: "Reject" }),
            el("button", { cls: "btn sm ghost", type: "button", "data-decide": "dismiss", text: "Dismiss" })]));
        } else if (x.status !== "proposed") {
          card.appendChild(el("div", { cls: "tiny faint", text: x.status }));
        }
        box.appendChild(card);
      });
    }
    var links = el("div", { cls: "row small" }, [
      el("a", { href: "/dashboard/reports/runs/" + run.run_id + ".md", text: "Export report" }),
      run.ticket_id && document.getElementById("ai") ? el("a", { href: "#ai", "data-reload": "1", text: "Open in the AI investigation tab" }) : null,
      run.ticket_id && !document.getElementById("ai") ? el("a", { href: "/dashboard/tickets/" + encodeURIComponent(run.ticket_id) + "#ai", text: "Open ticket" }) : null]);
    box.appendChild(links);
    view.root.appendChild(box);
    scroll();
  }
  document.addEventListener("click", function (e) {
    var a = e.target.closest("a[data-reload]");
    if (a) { e.preventDefault(); location.hash = "#ai"; location.reload(); }
  });

  function renderError(view, message) {
    setStatus(view, "Stopped", true, true);
    view.root.appendChild(el("div", { cls: "banner error small" }, [svg("alert"), el("span", { text: message })]));
    scroll();
  }

  function finish(view, runId) {
    return api("/dashboard/api/ai/runs/" + runId).then(function (run) {
      if (run.status === "completed") renderResult(view, run);
      else if (run.status === "failed") renderError(view, run.error || "The request failed.");
      return run;
    });
  }

  function follow(view, runId, after) {
    var done = false, last = after || 0;
    function poll() {
      if (done) return;
      api("/dashboard/api/ai/runs/" + runId).then(function (run) {
        (run.events || []).forEach(function (ev) { if (ev.id > last) { last = ev.id; addStep(view, ev); } });
        if (run.status === "completed" || run.status === "failed") { done = true; state.busy = false; finish(view, runId); }
        else setTimeout(poll, 2000);
      }).catch(function (e) { done = true; state.busy = false; renderError(view, e.message); });
    }
    if (!window.EventSource) { poll(); return; }
    var es = new EventSource("/dashboard/api/ai/runs/" + runId + "/stream?after=" + last);
    ["status", "tool_call", "tool_result", "note"].forEach(function (k) {
      es.addEventListener(k, function (m) { var ev = JSON.parse(m.data); last = ev.id; addStep(view, ev); });
    });
    es.addEventListener("final", function (m) { last = JSON.parse(m.data).id; done = true; es.close(); state.busy = false; finish(view, runId); });
    es.addEventListener("error", function (m) {
      if (m.data) { done = true; es.close(); state.busy = false; renderError(view, (JSON.parse(m.data).data || {}).message || "The request failed."); return; }
      es.close();
      if (!done) setTimeout(poll, 1000);   // stream dropped (proxy, timeout): fall back to polling
    });
  }

  function send(prompt) {
    if (state.busy || !prompt.trim()) return;
    state.busy = true;
    userMsg(prompt);
    var view = agentShell();
    var kind = /^investigate this ticket$/i.test(prompt.trim()) ? "investigate" : "question";
    if (!state.ticket && kind === "investigate") {
      state.busy = false; renderError(view, "Pick a ticket first, or ask about an IP address."); return;
    }
    api("/dashboard/api/ai/runs", { method: "POST", json: { prompt: prompt, ticket_id: state.ticket, kind: kind, conversation_id: state.conversation } })
      .then(function (res) { state.conversation = res.conversation_id; follow(view, res.run_id, 0); })
      .catch(function (e) { state.busy = false; renderError(view, e.message); });
  }

  function expand(p) {
    if (p === "Check this IP") {
      var ip = meta.source_ip;
      return ip ? "Check the reputation and history of " + ip + " and say what is known and unknown about it." : "Check this IP: ";
    }
    if (p === "Find related events") return "Find related events: other alerts and flows involving this ticket's addresses, and whether they change the picture.";
    if (p === "Explain this alert") return "Explain in plain language why this alert was triggered and how confident the detection is.";
    if (p === "Create a remediation plan") return "Create a prioritized remediation plan for this incident, with read-only investigation commands and any containment proposals the evidence supports.";
    if (p === "Draft a resolution note") return "Draft resolution notes for this ticket if the evidence supports resolving it; otherwise say what is still missing.";
    return p;
  }

  if (form && input) {
    form.addEventListener("submit", function (e) { e.preventDefault(); var v = input.value; input.value = ""; send(v); });
    input.addEventListener("keydown", function (e) { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event("submit")); } });
  }
  NS.$$("#agent-prompts [data-prompt]").forEach(function (b) {
    b.addEventListener("click", function () {
      var text = expand(b.dataset.prompt);
      if (/: $/.test(text)) { input.value = text; input.focus(); return; }
      send(text);
    });
  });
  var ask = document.getElementById("ask-ai");
  if (ask) ask.addEventListener("click", function () {
    var panel = document.getElementById("agent-panel");
    if (panel) panel.scrollIntoView({ behavior: "smooth", block: "start" });
    send("Investigate this ticket");
  });
  if (picker) picker.addEventListener("change", function () {
    state.ticket = picker.value || null; state.conversation = null;
    log.appendChild(el("div", { cls: "msg agent-msg" }, [el("div", { cls: "answer small", text: state.ticket ? "Now working on " + state.ticket + "." : "No ticket selected: questions about IP addresses work without one." })]));
    scroll();
  });

  // ── restore: the latest conversation on a ticket, or a run opened from the list ──
  function restore(runId) {
    api("/dashboard/api/ai/runs/" + runId + "?history=1").then(function (run) {
      if (run.ticket_id && picker) { picker.value = run.ticket_id; state.ticket = run.ticket_id; }
      state.conversation = run.conversation_id;
      (run.history || []).forEach(function (h) {
        if (h.run_id === run.run_id) return;
        userMsg(h.prompt);
        var v = agentShell();
        if (h.status === "completed") { setStatus(v, "Done", true); v.root.appendChild(el("div", { cls: "answer", text: h.answer || "" })); }
        else setStatus(v, h.status === "failed" ? "Failed: " + (h.error || "") : h.status, h.status !== "running" && h.status !== "queued", h.status === "failed");
      });
      userMsg(run.prompt);
      var view = agentShell();
      (run.events || []).forEach(function (ev) { addStep(view, ev); });
      if (run.status === "completed") renderResult(view, run);
      else if (run.status === "failed") renderError(view, run.error || "The request failed.");
      else { state.busy = true; follow(view, run.run_id, (run.events || []).reduce(function (a, e) { return Math.max(a, e.id); }, 0)); }
    }).catch(function () { /* nothing to restore */ });
  }
  if (meta.open_run) restore(meta.open_run);
  else if (meta.last_run) restore(meta.last_run);
})();

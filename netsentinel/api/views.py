"""Read-side queries for the SOC console. Every number shown comes from these, from real tables.

Data provenance is reported, not hidden: flows are attributed to their sender (replayed CICIDS-2017
lab traffic, the live sensor, other API clients) by the name of the API key that submitted them, and
inventory rows tagged 'demo:' are labelled as demo data.
"""

import json
from datetime import datetime, timedelta, timezone

from .. import tickets as tk

RANGES = {"24h": (timedelta(hours=24), "1 hour", "HH24:MI"), "7d": (timedelta(days=7), "6 hours", "Mon DD HH24h"),
          "30d": (timedelta(days=30), "1 day", "Mon DD"), "90d": (timedelta(days=90), "1 day", "Mon DD")}
AGENT_CONSUMERS = [("orchestrator", "detection.attack"), ("investigation", "investigation.requested"),
                   ("risk", "investigation.completed"), ("response", "risk.assessed"), ("ticket", "response.proposed")]
PROVENANCE_SQL = ("CASE WHEN k.name LIKE 'replay%%' THEN 'replay' WHEN k.name LIKE 'live sensor%%' THEN 'live_sensor' "
                  "WHEN k.name LIKE 'e2e%%' THEN 'test' ELSE 'api_client' END")
PROVENANCE_LABELS = {"replay": "Replayed CICIDS-2017 lab traffic", "live_sensor": "Live sensor (this server)",
                     "test": "End-to-end test traffic", "api_client": "Other API clients"}


def rows(conn, sql, params=()):
    return tk._rows(conn, sql, params)


def one(conn, sql, params=()):
    return conn.execute(sql, params).fetchone()


def safe_json(obj) -> str:
    """JSON for a <script type="application/json"> block: '<' escaped so nothing can close the tag."""
    return json.dumps(obj, default=str).replace("<", "\\u003c")


def json_ips(obj) -> list[str]:
    """Every IP address inside a JSON document (e.g. a ticket summary), validated."""
    import ipaddress
    from ..agents.investigation import IPV4
    out = set()
    for m in IPV4.findall(json.dumps(obj, default=str)):
        try:
            out.add(str(ipaddress.ip_address(m)))
        except ValueError:
            pass
    return sorted(out)


def rng(value: str | None) -> str:
    return value if value in RANGES else "30d"


# ── shared ─────────────────────────────────────────────────────────────────────────────────────
def nav_counts(conn) -> dict:
    r = one(conn, "SELECT (SELECT count(*) FROM tickets WHERE status NOT IN ('resolved', 'closed')), "
                  "(SELECT count(*) FROM response_actions WHERE status = 'proposed'), "
                  "(SELECT count(*) FROM tickets WHERE status NOT IN ('resolved', 'closed') AND sla_due_at < now())")
    return {"open": r[0], "approvals": r[1], "overdue": r[2]}


def health(conn) -> dict:
    now = datetime.now(timezone.utc)
    items = []

    def add(name, state, value, href=None):
        items.append({"name": name, "state": state, "value": value, "href": href})

    add("Database", "good", "connected")
    hb = {r["agent"]: r for r in rows(conn, "SELECT agent, status, at, detail FROM agent_heartbeats")}
    d = hb.get("detection")
    if d:
        age = (now - d["at"]).total_seconds()
        add("Detection agent", "good" if age < 120 and d["status"] == "ok" else "warning" if age < 900 else "critical",
            f"{d['status']}, heartbeat {int(age)} s ago")
    else:
        add("Detection agent", "critical", "no heartbeat")
    m = one(conn, "SELECT model_id FROM models WHERE status = 'active'")
    add("Detection model", "good" if m else "critical", m[0] if m else "none active: scoring paused")
    waiting = one(conn, "SELECT count(*) FROM flow_events WHERE status = 'received'")[0]
    backlog = 0
    for consumer, topic in AGENT_CONSUMERS:
        backlog += one(conn, "SELECT count(*) FROM bus_messages m WHERE m.topic = %s AND m.id > coalesce((SELECT last_id "
                             "FROM bus_offsets WHERE consumer = %s AND topic = %s), 0)", (topic, consumer, topic))[0]
    add("Pipeline backlog", "good" if waiting + backlog < 1000 else "warning",
        f"{waiting:,} flows waiting · {backlog:,} agent messages")
    s = one(conn, "SELECT max(f.received_at), bool_or(f.shadow) FROM flow_events f JOIN api_keys k USING (key_id) "
                  "WHERE k.name LIKE 'live sensor%%' AND f.received_at > now() - interval '7 days'")
    if s[0]:
        age = (now - s[0]).total_seconds()
        add("Live sensor", "good" if age < 600 else "warning",
            f"last flow {_age(age)} ago{' · shadow mode (no alerts)' if s[1] else ''}")
    else:
        add("Live sensor", "warning", "no flows in 7 days")
    a = hb.get("assistant")
    q = one(conn, "SELECT count(*) FILTER (WHERE status IN ('queued', 'running')), "
                  "count(*) FILTER (WHERE status = 'failed' AND created_at > now() - interval '1 hour') FROM ai_runs")
    if a:
        age = (now - a["at"]).total_seconds()
        add("AI Security Agent", "good" if age < 180 and not q[1] else "warning",
            f"worker {'online' if age < 180 else 'silent ' + _age(age)} · {q[0]} queued"
            + (f" · {q[1]} failed (1 h)" if q[1] else ""), "/dashboard/agent")
    else:
        add("AI Security Agent", "warning", "worker has not started yet", "/dashboard/agent")
    state = "critical" if any(i["state"] == "critical" for i in items) else (
        "warning" if any(i["state"] == "warning" for i in items) else "good")
    label = {"good": "All systems normal", "warning": "Degraded", "critical": "Attention needed"}[state]
    return {"state": state, "label": label, "items": items}


def _age(seconds: float) -> str:
    if seconds < 90:
        return f"{int(seconds)} s"
    if seconds < 5400:
        return f"{int(seconds // 60)} min"
    if seconds < 172800:
        return f"{seconds / 3600:.0f} h"
    return f"{seconds / 86400:.0f} d"


def provenance(conn, since) -> list[dict]:
    out = rows(conn, f"SELECT {PROVENANCE_SQL} AS origin, f.shadow, count(*) AS flows FROM flow_events f "
                     "JOIN api_keys k USING (key_id) WHERE f.received_at >= %s GROUP BY 1, 2 ORDER BY 3 DESC", (since,))
    for r in out:
        r["label"] = PROVENANCE_LABELS[r["origin"]] + (" · shadow mode" if r["shadow"] else "")
    return out


# ── overview ───────────────────────────────────────────────────────────────────────────────────
def overview(conn, range_key: str) -> dict:
    span, bucket, fmt = RANGES[range_key]
    since = datetime.now(timezone.utc) - span
    k = one(conn,
        "SELECT (SELECT count(*) FROM cases WHERE created_at >= %(s)s), "
        " (SELECT count(*) FROM detections d JOIN flow_events f USING (event_id) WHERE d.is_attack AND NOT f.shadow AND d.scored_at >= %(s)s), "
        " (SELECT count(*) FROM detections d JOIN flow_events f USING (event_id) WHERE d.is_attack AND f.shadow AND d.scored_at >= %(s)s), "
        " (SELECT count(*) FROM tickets WHERE status NOT IN ('resolved','closed') AND severity = 'critical'), "
        " (SELECT count(*) FROM tickets WHERE status NOT IN ('resolved','closed') AND severity = 'high'), "
        " (SELECT count(*) FROM tickets WHERE status NOT IN ('resolved','closed')), "
        " (SELECT count(*) FROM tickets WHERE status NOT IN ('resolved','closed') AND sla_due_at < now()), "
        " (SELECT count(*) FROM tickets WHERE status = 'awaiting_approval'), "
        " (SELECT extract(epoch FROM avg(acknowledged_at - created_at)) FROM tickets WHERE created_at >= %(s)s AND acknowledged_at IS NOT NULL), "
        " (SELECT count(*) FROM tickets WHERE created_at >= %(s)s AND acknowledged_at IS NOT NULL), "
        " (SELECT extract(epoch FROM avg(resolved_at - created_at)) FROM tickets WHERE created_at >= %(s)s AND resolved_at IS NOT NULL), "
        " (SELECT count(*) FROM tickets WHERE created_at >= %(s)s AND resolved_at IS NOT NULL), "
        " (SELECT count(*) FROM assets), (SELECT count(*) FROM assets WHERE source LIKE 'demo:%%'), "
        " (SELECT count(*) FROM network_zones), (SELECT count(*) FROM tickets WHERE created_at >= %(s)s)",
        {"s": since})
    kpi = dict(zip(("alerts", "attack_flows", "shadow_attack_flows", "critical", "high", "open", "overdue", "approval",
                    "mtta_s", "mtta_n", "mttr_s", "mttr_n", "assets", "demo_assets", "zones", "tickets_in_range"), k))
    series = rows(conn,
        f"SELECT to_char(b, '{fmt}') AS t, b AS at, "
        " count(d.event_id) FILTER (WHERE d.is_attack AND NOT f.shadow) AS attack, "
        " count(d.event_id) FILTER (WHERE d.is_attack AND f.shadow) AS shadow_attack, "
        " count(d.event_id) FILTER (WHERE NOT d.is_attack) AS benign "
        f"FROM generate_series(date_bin(%s::interval, %s::timestamptz, 'epoch'), now(), %s::interval) b "
        "LEFT JOIN detections d ON d.scored_at >= b AND d.scored_at < b + %s::interval "
        "LEFT JOIN flow_events f ON f.event_id = d.event_id GROUP BY b ORDER BY b", (bucket, since, bucket, bucket))
    severity = rows(conn, "SELECT severity, count(*) AS n FROM tickets WHERE status NOT IN ('resolved','closed') GROUP BY 1")
    sev = {s: 0 for s in ("critical", "high", "medium", "low")}
    sev.update({r["severity"]: r["n"] for r in severity})
    families = rows(conn, "SELECT coalesce(family, 'Unnamed') AS family, count(*) AS alerts, sum(flow_count) AS flows "
                          "FROM cases WHERE created_at >= %s GROUP BY 1 ORDER BY 2 DESC LIMIT 8", (since,))
    sources = rows(conn,
        "SELECT host(c.src_ip) AS ip, count(*) AS alerts, sum(c.flow_count) AS flows, max(c.last_seen) AS last_seen, "
        " array_agg(DISTINCT coalesce(c.family, 'Unnamed')) AS families, max(r.score) AS risk, "
        " (SELECT name FROM assets a WHERE c.src_ip <<= a.cidr ORDER BY masklen(a.cidr) DESC LIMIT 1) AS asset "
        "FROM cases c "
        "LEFT JOIN LATERAL (SELECT score FROM risk_assessments WHERE case_id = c.case_id ORDER BY created_at DESC LIMIT 1) r ON true "
        "WHERE c.created_at >= %s AND c.src_ip IS NOT NULL GROUP BY c.src_ip ORDER BY 2 DESC, 3 DESC LIMIT 8", (since,))
    incidents = rows(conn,
        "SELECT c.case_id::text, c.family, host(c.src_ip) AS src_ip, c.flow_count, c.last_seen, c.status, "
        " r.severity, r.score, t.ticket_id FROM cases c "
        "LEFT JOIN LATERAL (SELECT severity, score FROM risk_assessments WHERE case_id = c.case_id ORDER BY created_at DESC LIMIT 1) r ON true "
        "LEFT JOIN tickets t ON t.case_id = c.case_id ORDER BY c.last_seen DESC LIMIT 8")
    updates = rows(conn,
        "SELECT e.at, e.actor, e.event, e.detail, t.ticket_id, t.title, t.severity FROM ticket_events e "
        "JOIN tickets t USING (ticket_id) ORDER BY e.id DESC LIMIT 10")
    activity = recent_activity(conn, 10)
    return {"range": range_key, "since": since, "kpi": kpi, "severity": sev, "families": families, "sources": sources,
            "incidents": incidents, "updates": updates, "activity": activity, "prov": provenance(conn, since),
            "chart_data": safe_json({"series": series, "severity": sev, "families": families})}


def recent_activity(conn, limit: int = 10) -> list[dict]:
    return rows(conn,
        "SELECT * FROM ("
        " SELECT at, actor, action, object_type, object_id, detail, 'audit' AS src FROM audit_log "
        " UNION ALL SELECT finished_at, 'agent:assistant', 'ai.' || status, 'ai_run', coalesce(ticket_id, run_id::text), "
        "   jsonb_build_object('kind', kind, 'requested_by', requested_by, 'tool_calls', tool_calls), 'ai' "
        "   FROM ai_runs WHERE finished_at IS NOT NULL "
        " UNION ALL SELECT coalesce(decided_at, proposed_at), coalesce(decided_by, proposed_by), 'action.' || status, "
        "   'response_action', action_type || ' ' || target, '{}'::jsonb, 'action' FROM response_actions "
        "   WHERE decided_at IS NOT NULL) x ORDER BY at DESC NULLS LAST LIMIT %s", (limit,))


# ── threat monitoring ──────────────────────────────────────────────────────────────────────────
def threats(conn, *, range_key: str, family: str = "", severity: str = "", ip: str = "", has_ticket: str = "",
            page: int = 1) -> dict:
    span, bucket, fmt = RANGES[range_key]
    since = datetime.now(timezone.utc) - span
    where, p = ["c.last_seen >= %s"], [since]
    if family:
        where.append("coalesce(c.family, 'Unnamed') = %s")
        p.append(family)
    if severity:
        where.append("r.severity = %s")
        p.append(severity)
    if ip:
        ip = tk.clean_ip(ip, "IP")
        where.append("(c.src_ip = %s::inet OR EXISTS (SELECT 1 FROM case_events ce JOIN flow_events f USING (event_id) "
                     "WHERE ce.case_id = c.case_id AND f.dst_ip = %s::inet))")
        p += [ip, ip]
    if has_ticket == "no":
        where.append("t.ticket_id IS NULL")
    elif has_ticket == "yes":
        where.append("t.ticket_id IS NOT NULL")
    w = " AND ".join(where)
    base = ("FROM cases c LEFT JOIN LATERAL (SELECT severity, score FROM risk_assessments WHERE case_id = c.case_id "
            "ORDER BY created_at DESC LIMIT 1) r ON true LEFT JOIN tickets t ON t.case_id = c.case_id "
            f"WHERE {w}")
    total = one(conn, f"SELECT count(*) {base}", p)[0]
    size = 25
    page = max(1, page)
    alerts = rows(conn,
        "SELECT c.case_id::text, c.family, host(c.src_ip) AS src_ip, c.flow_count, c.first_seen, c.last_seen, c.status, "
        " round(c.max_p_attack::numeric, 4) AS max_p, r.severity, r.score, t.ticket_id, t.status AS ticket_status, "
        " (SELECT host(f.dst_ip) FROM case_events ce JOIN flow_events f USING (event_id) WHERE ce.case_id = c.case_id "
        "  AND f.dst_ip IS NOT NULL LIMIT 1) AS dst_ip, "
        " (SELECT count(*) FROM flow_events f JOIN case_events ce USING (event_id) JOIN api_keys k USING (key_id) "
        "  WHERE ce.case_id = c.case_id AND k.name LIKE 'replay%%') > 0 AS replayed "
        f"{base} ORDER BY c.last_seen DESC LIMIT %s OFFSET %s", (*p, size, (page - 1) * size))
    feed = rows(conn,
        f"SELECT d.scored_at, host(f.src_ip) AS src_ip, host(f.dst_ip) AS dst_ip, f.dst_port, d.family, d.attack_type, "
        f" round(d.p_attack::numeric, 4) AS p, f.shadow, {PROVENANCE_SQL} AS origin "
        "FROM detections d JOIN flow_events f USING (event_id) JOIN api_keys k USING (key_id) "
        "WHERE d.is_attack ORDER BY d.scored_at DESC LIMIT 25")
    families = [r[0] for r in conn.execute("SELECT DISTINCT coalesce(family, 'Unnamed') FROM cases ORDER BY 1")]
    series = rows(conn,
        f"SELECT to_char(b, '{fmt}') AS t, count(c.case_id) AS alerts "
        "FROM generate_series(date_bin(%s::interval, %s::timestamptz, 'epoch'), now(), %s::interval) b "
        "LEFT JOIN cases c ON c.created_at >= b AND c.created_at < b + %s::interval GROUP BY b ORDER BY b",
        (bucket, since, bucket, bucket))
    stats = one(conn, "SELECT count(*), count(*) FILTER (WHERE t.ticket_id IS NULL), count(DISTINCT c.src_ip) "
                      "FROM cases c LEFT JOIN tickets t ON t.case_id = c.case_id WHERE c.last_seen >= %s", (since,))
    return {"alerts": alerts, "total": total, "page": page, "pages": max(1, -(-total // size)), "feed": feed,
            "families": families, "range": range_key, "prov": provenance(conn, since),
            "stats": {"alerts": stats[0], "untriaged": stats[1], "sources": stats[2]},
            "chart_data": safe_json({"series": series}), "provenance_labels": PROVENANCE_LABELS}


# ── network map ────────────────────────────────────────────────────────────────────────────────
def network(conn, *, source: str, hours: int) -> dict:
    """Nodes: inventoried assets, zones, and the busiest real flow endpoints; edges: real aggregated flows.
    Nothing is invented: hosts without inventory are shown as 'unknown host' with their address."""
    from .. import site
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    origin = {"replay": "k.name LIKE 'replay%%'", "live": "k.name LIKE 'live sensor%%'"}.get(source, "true")
    edges = rows(conn,
        "SELECT host(f.src_ip) AS src, host(f.dst_ip) AS dst, count(*) AS flows, "
        " count(*) FILTER (WHERE d.is_attack) AS attacks, array_agg(DISTINCT f.dst_port) FILTER (WHERE f.dst_port IS NOT NULL) AS ports "
        "FROM flow_events f JOIN api_keys k USING (key_id) LEFT JOIN detections d USING (event_id) "
        f"WHERE f.received_at >= %s AND f.src_ip IS NOT NULL AND f.dst_ip IS NOT NULL AND {origin} "
        "GROUP BY 1, 2 ORDER BY count(*) FILTER (WHERE d.is_attack) DESC, 3 DESC LIMIT 60", (since,))
    for e in edges:
        e["ports"] = sorted(p for p in (e["ports"] or []) if p is not None)[:12]
    ips = sorted({e["src"] for e in edges} | {e["dst"] for e in edges})
    assets = rows(conn, "SELECT name, host(cidr) AS ip, masklen(cidr) AS bits, role, criticality, owner, source FROM assets "
                        "ORDER BY criticality DESC, name")
    zones = rows(conn, "SELECT cidr::text, zone, note, source FROM network_zones ORDER BY zone, cidr")
    risk = rows(conn,
        "SELECT ip, max(sevrank) AS sevrank, count(*) AS open_tickets FROM ("
        " SELECT host(source_ip) AS ip, array_position(ARRAY['low','medium','high','critical'], severity) AS sevrank FROM tickets "
        " WHERE status NOT IN ('resolved','closed') AND source_ip IS NOT NULL "
        " UNION ALL SELECT host(dest_ip), array_position(ARRAY['low','medium','high','critical'], severity) FROM tickets "
        " WHERE status NOT IN ('resolved','closed') AND dest_ip IS NOT NULL) x GROUP BY ip")
    zone_of = {}
    for ip in set(ips) | {a["ip"] for a in assets if a["bits"] in (32, 128)}:
        z = one(conn, "SELECT zone FROM network_zones WHERE %s::inet <<= cidr ORDER BY masklen(cidr) DESC LIMIT 1", (ip,))
        zone_of[ip] = z[0] if z else None
    s = site.load()
    return {"source": source, "hours": hours, "edges": edges, "assets": assets, "zones": zones,
            "data": safe_json({"edges": edges, "assets": [a for a in assets if a["bits"] in (32, 128)], "zones": zones,
                               "zone_of": zone_of, "risk": {r["ip"]: r for r in risk},
                               "server_ip": s.get("server_ip") if source == "live" else None}),
            "demo_inventory": any(a["source"].startswith("demo:") for a in assets) or any(
                z["source"].startswith("demo:") for z in zones)}


# ── analytics ──────────────────────────────────────────────────────────────────────────────────
def analytics(conn, range_key: str) -> dict:
    span, _, _ = RANGES[range_key]
    since = datetime.now(timezone.utc) - span
    day_fmt = "Mon DD"
    by_family = rows(conn,
        "SELECT to_char(date_trunc('day', created_at), %s) AS day, date_trunc('day', created_at) AS d, "
        " coalesce(family, 'Unnamed') AS family, count(*) AS n FROM cases WHERE created_at >= %s GROUP BY 1, 2, 3 ORDER BY 2",
        (day_fmt, since))
    by_sev = rows(conn,
        "SELECT to_char(date_trunc('day', created_at), %s) AS day, date_trunc('day', created_at) AS d, severity, count(*) AS n "
        "FROM tickets WHERE created_at >= %s GROUP BY 1, 2, 3 ORDER BY 2", (day_fmt, since))
    t = one(conn,
        "SELECT count(*), "
        " count(*) FILTER (WHERE acknowledged_at IS NOT NULL), extract(epoch FROM avg(acknowledged_at - created_at)), "
        " extract(epoch FROM percentile_cont(0.5) WITHIN GROUP (ORDER BY acknowledged_at - created_at)), "
        " count(*) FILTER (WHERE resolved_at IS NOT NULL), extract(epoch FROM avg(resolved_at - created_at)), "
        " extract(epoch FROM percentile_cont(0.5) WITHIN GROUP (ORDER BY resolved_at - created_at)), "
        " count(*) FILTER (WHERE reopen_count > 0), "
        " count(*) FILTER (WHERE resolved_at IS NOT NULL AND resolved_at <= sla_due_at), "
        " count(*) FILTER (WHERE (resolved_at IS NOT NULL AND resolved_at > sla_due_at) "
        "                  OR (resolved_at IS NULL AND sla_due_at < now())), "
        " count(*) FILTER (WHERE acknowledged_at IS NOT NULL AND acknowledged_at <= ack_due_at), "
        " count(*) FILTER (WHERE (acknowledged_at > ack_due_at) OR (acknowledged_at IS NULL AND ack_due_at < now())) "
        "FROM tickets WHERE created_at >= %s", (since,))
    keys = ("tickets", "acked", "mtta_s", "mtta_p50", "resolved", "mttr_s", "mttr_p50", "reopened", "sla_met", "sla_missed",
            "ack_met", "ack_missed")
    tm = dict(zip(keys, t))
    tm["sla_rate"] = (tm["sla_met"] / (tm["sla_met"] + tm["sla_missed"])) if (tm["sla_met"] + tm["sla_missed"]) else None
    tm["ack_rate"] = (tm["ack_met"] / (tm["ack_met"] + tm["ack_missed"])) if (tm["ack_met"] + tm["ack_missed"]) else None
    resolution_by_sev = rows(conn,
        "SELECT severity, count(*) AS n, extract(epoch FROM avg(resolved_at - created_at)) AS avg_s "
        "FROM tickets WHERE created_at >= %s AND resolved_at IS NOT NULL GROUP BY 1", (since,))
    ai = rows(conn, "SELECT kind, status, count(*) AS n FROM ai_recommendations WHERE created_at >= %s GROUP BY 1, 2",
              (since,))
    ai_runs = one(conn, "SELECT count(*), count(*) FILTER (WHERE status = 'completed'), count(*) FILTER (WHERE status = 'failed'), "
                        "avg(tool_calls) FILTER (WHERE status = 'completed'), "
                        "extract(epoch FROM avg(finished_at - started_at) FILTER (WHERE status = 'completed')) "
                        "FROM ai_runs WHERE created_at >= %s", (since,))
    closure = rows(conn,
        "SELECT to_char(date_trunc('day', resolved_at), %s) AS day, date_trunc('day', resolved_at) AS d, closure_reason, count(*) AS n "
        "FROM tickets WHERE status = 'closed' AND resolved_at >= %s GROUP BY 1, 2, 3 ORDER BY 2", (day_fmt, since))
    actions = rows(conn, "SELECT status, count(*) AS n FROM response_actions WHERE proposed_at >= %s GROUP BY 1", (since,))
    return {"range": range_key, "tm": tm, "resolution_by_sev": resolution_by_sev, "ai": ai,
            "ai_runs": dict(zip(("total", "completed", "failed", "avg_tools", "avg_s"), ai_runs)), "closure": closure,
            "actions": {r["status"]: r["n"] for r in actions},
            "chart_data": safe_json({"by_family": by_family, "by_sev": by_sev, "ai": ai, "closure": closure,
                                     "resolution_by_sev": resolution_by_sev})}


# ── global search & notifications ──────────────────────────────────────────────────────────────
def search(conn, q: str) -> dict:
    q = (q or "").strip()[:100]
    if len(q) < 2:
        return {"tickets": [], "alerts": [], "ips": [], "hosts": []}
    like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    try:
        ip = tk.clean_ip(q, "IP")
    except tk.TicketError:
        ip = None
    tickets = rows(conn, "SELECT ticket_id, title, severity, status FROM tickets WHERE ticket_id ILIKE %s OR title ILIKE %s "
                         "OR host(source_ip) LIKE %s OR host(dest_ip) LIKE %s ORDER BY updated_at DESC LIMIT 6",
                   (like, like, like, like))
    alerts = rows(conn, "SELECT case_id::text, family, host(src_ip) AS src_ip, flow_count, last_seen FROM cases "
                        "WHERE host(src_ip) LIKE %s OR family ILIKE %s OR case_id::text LIKE %s ORDER BY last_seen DESC LIMIT 5",
                  (like, like, like))
    ips = rows(conn, "SELECT ip, sum(n) AS n FROM (SELECT host(src_ip) AS ip, count(*) AS n FROM cases WHERE host(src_ip) LIKE %s "
                     "GROUP BY 1 UNION ALL SELECT host(source_ip), count(*) FROM tickets WHERE host(source_ip) LIKE %s GROUP BY 1) x "
                     "GROUP BY ip ORDER BY 2 DESC LIMIT 5", (like, like))
    if ip and not any(r["ip"] == ip for r in ips):
        ips.insert(0, {"ip": ip, "n": 0})
    hosts = rows(conn, "SELECT name, host(cidr) AS ip, role, source FROM assets WHERE name ILIKE %s OR role ILIKE %s "
                       "OR host(cidr) LIKE %s ORDER BY criticality DESC LIMIT 5", (like, like, like))
    return {"tickets": tickets, "alerts": alerts, "ips": ips, "hosts": hosts}


def notifications(conn, viewer: str) -> list[dict]:
    out = []
    for r in rows(conn, "SELECT ticket_id, title, sla_due_at FROM tickets WHERE status NOT IN ('resolved','closed') "
                        "AND sla_due_at < now() ORDER BY sla_due_at LIMIT 5"):
        out.append({"kind": "overdue", "at": r["sla_due_at"], "title": f"{r['ticket_id']} is past its SLA",
                    "text": r["title"], "href": f"/dashboard/tickets/{r['ticket_id']}"})
    for r in rows(conn, "SELECT ticket_id, title, created_at FROM tickets WHERE severity = 'critical' "
                        "AND status NOT IN ('resolved','closed') AND created_at > now() - interval '7 days' "
                        "ORDER BY created_at DESC LIMIT 5"):
        out.append({"kind": "critical", "at": r["created_at"], "title": f"Critical incident {r['ticket_id']}",
                    "text": r["title"], "href": f"/dashboard/tickets/{r['ticket_id']}"})
    n = one(conn, "SELECT count(*), max(proposed_at) FROM response_actions WHERE status = 'proposed'")
    if n[0]:
        out.append({"kind": "approval", "at": n[1], "title": f"{n[0]} response actions awaiting approval",
                    "text": "Review them in Tickets → Awaiting approval", "href": "/dashboard/tickets?quick=approval"})
    for r in rows(conn, "SELECT run_id::text, ticket_id, status, finished_at FROM ai_runs WHERE requested_by = %s "
                        "AND finished_at > now() - interval '24 hours' ORDER BY finished_at DESC LIMIT 5", (viewer,)):
        out.append({"kind": "ai", "at": r["finished_at"],
                    "title": f"AI investigation {'finished' if r['status'] == 'completed' else r['status']}",
                    "text": r["ticket_id"] or "General question",
                    "href": f"/dashboard/tickets/{r['ticket_id']}#ai" if r["ticket_id"] else f"/dashboard/agent?run={r['run_id']}"})
    for r in rows(conn, "SELECT e.ticket_id, e.at, e.actor FROM ticket_events e JOIN tickets t USING (ticket_id) "
                        "WHERE e.event = 'assigned' AND e.detail->>'to' = %s AND e.at > now() - interval '7 days' "
                        "ORDER BY e.id DESC LIMIT 5", (viewer,)):
        out.append({"kind": "assigned", "at": r["at"], "title": f"{r['ticket_id']} was assigned to you",
                    "text": f"by {r['actor']}", "href": f"/dashboard/tickets/{r['ticket_id']}"})
    m = one(conn, "SELECT count(*), max(at) FROM model_events WHERE event = 'check_failed' AND at > now() - interval '24 hours'")
    if m[0]:
        out.append({"kind": "critical", "at": m[1], "title": f"Model check failed {m[0]} times (24 h)",
                    "text": "Scoring may be paused", "href": "/dashboard/settings#model"})
    out.sort(key=lambda x: x["at"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return out[:15]

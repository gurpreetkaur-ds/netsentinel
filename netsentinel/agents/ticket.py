"""Ticket Agent: pipeline step 11 (TICKET TRACKING). One ticket per case.

response.proposed -> create/refresh the ticket (priority + SLA from severity, a labelled summary,
                     the proposed actions) and move the case to 'ticketed'
response.decided  -> timeline entry; status follows the human decisions

Tickets live in NetSentinel. Exporting to an external system (Jira, ServiceNow, …) can be added
through an adapter once one is chosen; its API is not assumed here.
"""

import json
import logging
import threading
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .. import bus as busmod
from .response import RESPONSE_DECIDED, RESPONSE_PROPOSED, _run_loop

log = logging.getLogger(__name__)



def _event(conn, ticket_id: str, actor: str, event: str, detail: dict) -> None:
    conn.execute("INSERT INTO ticket_events (ticket_id, actor, event, detail) VALUES (%s, %s, %s, %s)",
                 (ticket_id, actor, event, Jsonb(detail, dumps=_dumps)))


def _dumps(o):
    return json.dumps(o, default=str)


class TicketAgent:
    name = "ticket"

    def __init__(self, pool: ConnectionPool, bus: busmod.Bus | None = None):
        self.pool, self.bus = pool, bus or busmod.PostgresBus()
        self.stop_event = threading.Event()

    def _summary(self, conn, case_id, assessment_id) -> tuple[dict, dict]:
        c = conn.execute("SELECT host(src_ip), family, flow_count, first_seen, last_seen FROM cases WHERE case_id = %s",
                         (case_id,)).fetchone()
        r = conn.execute("SELECT score, severity, factors, requires_review, review_reasons, investigation_id "
                         "FROM risk_assessments WHERE assessment_id = %s", (assessment_id,)).fetchone()
        inv = conn.execute("SELECT telemetry, model_output, analysis, llm_status FROM investigations "
                           "WHERE investigation_id = %s", (r[5],)).fetchone()
        actions = conn.execute("SELECT action_id, action_type, target, disruptive, status FROM response_actions "
                               "WHERE assessment_id = %s ORDER BY proposed_at", (assessment_id,)).fetchall()
        telemetry, model_output, analysis, llm_status = inv
        summary = {
            "VERIFIED TELEMETRY": {"source_ip": c[0], "flows": c[2], "first_seen": c[3], "last_seen": c[4],
                                   "destinations": telemetry.get("destinations"),
                                   "top_ports": (telemetry.get("destination_ports") or {}).get("top", [])[:5]},
            "MODEL OUTPUT": {"family": model_output.get("case_family"), "attack_types": model_output.get("attack_types"),
                             "p_attack_mean": (model_output.get("p_attack") or {}).get("mean")},
            "LLM ANALYSIS": ({"status": llm_status, "summary": analysis.get("summary"),
                              "consistency": (analysis.get("model_assessment") or {}).get("consistency")}
                             if analysis else {"status": llm_status}),
            "RISK": {"score": r[0], "severity": r[1], "requires_review": r[3], "review_reasons": r[4],
                     "factors": [{k: f[k] for k in ("factor", "points", "provenance")} for f in r[2]]},
            "RECOMMENDATION": [{"action_id": str(a[0]), "action": a[1], "target": a[2], "disruptive": a[3],
                                "status": a[4]} for a in actions],
        }
        title = f"[{r[1].upper()}] {c[1] or 'Unnamed attack'} from {c[0] or 'unknown source'} ({c[2]} flows)"
        top = (telemetry.get("destinations") or {}).get("top") or []
        description = (f"{c[2]} flows classified as {c[1] or 'an unnamed attack family'} from {c[0] or 'an unknown source'} "
                       f"between {c[3]:%Y-%m-%d %H:%M:%S} and {c[4]:%H:%M:%S} UTC, to "
                       f"{(telemetry.get('destinations') or {}).get('distinct_ips', 0)} destination(s). "
                       f"Risk {r[0]}/100 ({r[1]}). Raised automatically by the detection pipeline.")
        return summary, {"title": title, "severity": r[1], "needs_review": r[3], "actions": len(actions),
                         "category": c[1] or "Unnamed", "source_ip": c[0], "dest_ip": top[0]["ip"] if top else None,
                         "description": description}

    def on_proposed(self, conn, payload: dict) -> str:
        case_id, assessment_id = payload["case_id"], payload["assessment_id"]
        summary, meta = self._summary(conn, case_id, assessment_id)
        status = "awaiting_approval" if meta["actions"] else "open"
        src, dst, category = meta["source_ip"], meta["dest_ip"], meta["category"]
        with conn.transaction():
            # A refresh never moves a ticket backwards: new proposals put an active ticket into
            # awaiting_approval, otherwise its status stays. Resolved/closed tickets keep theirs, and an
            # analyst's severity override (severity_locked) is kept.
            ticket_id, created, priority = conn.execute(
                "INSERT INTO tickets (case_id, title, severity, priority, status, needs_review, sla_due_at, ack_due_at, "
                " summary, category, source_ip, dest_ip, description) "
                "SELECT %s, %s, p.severity, p.priority, %s, %s, now() + make_interval(mins => p.resolve_minutes), "
                " now() + make_interval(mins => p.ack_minutes), %s, %s, %s, %s, %s FROM sla_policies p WHERE p.severity = %s "
                "ON CONFLICT (case_id) DO UPDATE SET title = EXCLUDED.title, needs_review = EXCLUDED.needs_review, "
                "summary = EXCLUDED.summary, "
                "severity = CASE WHEN tickets.severity_locked THEN tickets.severity ELSE EXCLUDED.severity END, "
                "priority = CASE WHEN tickets.severity_locked THEN tickets.priority ELSE EXCLUDED.priority END, "
                "status = CASE WHEN tickets.status IN ('resolved', 'closed') THEN tickets.status "
                "              WHEN EXCLUDED.status = 'awaiting_approval' THEN 'awaiting_approval' ELSE tickets.status END, "
                "updated_at = now() RETURNING ticket_id, (xmax = 0), priority",
                (case_id, meta["title"], status, meta["needs_review"], Jsonb(summary, dumps=_dumps), category, src, dst,
                 meta["description"], meta["severity"])).fetchone()
            _event(conn, ticket_id, f"agent:{self.name}", "created" if created else "refreshed",
                   {"priority": priority, "status": status, "proposed_actions": meta["actions"]})
            conn.execute("UPDATE cases SET status = 'ticketed', updated_at = now() WHERE case_id = %s "
                         "AND status = 'assessed'", (case_id,))
            conn.execute("INSERT INTO case_history (case_id, status, actor, detail) VALUES (%s, 'ticketed', %s, %s)",
                         (case_id, self.name, Jsonb({"ticket_id": ticket_id})))
        log.info("%s %s: %s", ticket_id, "created" if created else "refreshed", meta["title"])
        return ticket_id

    def on_decided(self, conn, payload: dict) -> None:
        if payload.get("ticket_id"):
            t = conn.execute("SELECT ticket_id, status, case_id FROM tickets WHERE ticket_id = %s",
                             (payload["ticket_id"],)).fetchone()
        else:
            t = conn.execute("SELECT ticket_id, status, case_id FROM tickets WHERE case_id = %s",
                             (payload["case_id"],)).fetchone()
        if not t:
            return
        pending = conn.execute("SELECT count(*) FROM response_actions WHERE (case_id = %s OR ticket_id = %s) "
                               "AND status = 'proposed'", (t[2], t[0])).fetchone()[0]
        with conn.transaction():
            _event(conn, t[0], payload["actor"], f"action_{payload['decision']}", {"action_id": payload["action_id"]})
            if t[1] == "awaiting_approval" and pending == 0:
                conn.execute("UPDATE tickets SET status = 'in_progress', updated_at = now() WHERE ticket_id = %s", (t[0],))
                _event(conn, t[0], f"agent:{self.name}", "status_changed", {"from": t[1], "to": "in_progress"})
            # keep the summary's action statuses current
            conn.execute(
                "UPDATE tickets SET updated_at = now(), summary = jsonb_set(summary, '{RECOMMENDATION}', "
                "(SELECT coalesce(jsonb_agg(jsonb_build_object('action_id', action_id::text, 'action', action_type, "
                "'target', target, 'disruptive', disruptive, 'status', status) ORDER BY proposed_at), '[]'::jsonb) "
                " FROM response_actions WHERE case_id = %s OR ticket_id = %s)) WHERE ticket_id = %s", (t[2], t[0], t[0]))

    def process(self, limit: int = 100) -> int:
        n = 0
        with self.pool.connection() as conn, conn.transaction():
            for topic, handler in ((RESPONSE_PROPOSED, self.on_proposed), (RESPONSE_DECIDED, self.on_decided)):
                msgs = self.bus.poll(conn, self.name, topic, limit)
                for m in msgs:
                    handler(conn, m.payload)
                if msgs:
                    self.bus.commit(conn, self.name, topic, msgs[-1].id)
                n += len(msgs)
        return n

    def run(self, idle_sleep: float = 2.0) -> None:
        _run_loop(self, idle_sleep)


def resolve(conn, ticket_id: str, *, actor: str, resolution: str, close: bool = False,
            closure_reason: str = "remediated") -> None:
    """Resolve, or close (resolving first if needed). Kept for the CLI; see netsentinel.tickets."""
    from .. import tickets
    t = conn.execute("SELECT status FROM tickets WHERE ticket_id = %s", (ticket_id,)).fetchone()
    if not t or t[0] == "closed":
        raise ValueError(f"{ticket_id} not found or already closed")
    if close:
        tickets.transition(conn, ticket_id, "closed", actor=actor, note=resolution, closure_reason=closure_reason)
    else:
        tickets.transition(conn, ticket_id, "resolved", actor=actor, note=resolution)


def assign(conn, ticket_id: str, *, actor: str, assignee: str) -> None:
    from .. import tickets
    tickets.assign(conn, ticket_id, assignee, actor=actor, check_analyst=False)

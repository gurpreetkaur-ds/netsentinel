"""Response Agent: proposes containment from a fixed playbook. It never executes anything.

- Only actions in ACTIONS can be proposed. Each is reversible and has an expiry or an undo, and
  destructive operations (delete, wipe, re-image, kill) are not in the catalog at all.
- Low-severity cases get observation-only proposals. Disruptive containment needs medium or
  higher severity.
- Proposals are 'proposed' until a human decides (`netsentinel responses approve|reject`). The
  database refuses decisions recorded by an agent. After approval, a human performs the action
  with their own tools and marks it completed.
"""

import logging
import signal
import threading
from dataclasses import dataclass

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .. import bus as busmod
from .risk import RISK_ASSESSED

log = logging.getLogger(__name__)

RESPONSE_PROPOSED = "response.proposed"
RESPONSE_DECIDED = "response.decided"


@dataclass(frozen=True)
class ActionSpec:
    description: str
    disruptive: bool       # may interrupt legitimate traffic or users
    undo: str              # how a human reverses it


ACTIONS: dict[str, ActionSpec] = {
    "increase_monitoring": ActionSpec("Raise logging/capture on the target(s) for 24 h", False, "lower the logging level"),
    "collect_host_forensics": ActionSpec("Collect read-only forensic data (process list, connections, auth logs)", False,
                                         "nothing to undo (read-only)"),
    "review_target_logs": ActionSpec("Review service/application logs on the target(s) for the case window", False,
                                     "nothing to undo (read-only)"),
    "rate_limit_source": ActionSpec("Rate-limit the source's connections to the target service for 24 h", True,
                                    "remove the rate-limit rule (auto-expires)"),
    "temporary_block_source": ActionSpec("Block the source IP at the perimeter for 24 h", True,
                                         "remove the block rule (auto-expires)"),
    "block_outbound_destination": ActionSpec("Block outbound traffic from the internal network to the destination for 24 h",
                                             True, "remove the egress rule (auto-expires)"),
    "isolate_host_for_investigation": ActionSpec("Move the internal host to the quarantine VLAN for investigation", True,
                                                 "move the host back to its normal VLAN"),
    "enable_waf_virtual_patch": ActionSpec("Enable the WAF rule set for the targeted web application", True,
                                           "disable the WAF rule set"),
    "credential_review": ActionSpec("Review targeted accounts for successful logins; reset any exposed credentials", True,
                                    "users set new passwords (no data is lost)"),
}
DISRUPTIVE_MIN_SEVERITY = {"medium", "high", "critical"}


@dataclass(frozen=True)
class Proposal:
    action_type: str
    target: str
    rationale: str
    params: dict


def plan(*, family: str | None, severity: str, src_ip: str | None, src_zone: str | None,
         targets: list[dict], top_port: str | None) -> list[Proposal]:
    """Pure playbook: case facts in, proposals out."""
    internal = src_zone == "internal"
    tgt = ", ".join(t["ip"] for t in targets[:5]) or "unknown targets"
    port = f":{top_port}" if top_port else ""
    out: list[Proposal] = [
        Proposal("increase_monitoring", tgt, "Keep visibility while the case is open.", {"hours": 24}),
    ]
    if family in (None, "Exploit") or not src_ip:
        out.append(Proposal("collect_host_forensics", tgt, "The attack is not well characterised; gather facts first.", {}))
        return out

    src = src_ip
    if family in ("DoS", "DDoS"):
        out.append(Proposal("review_target_logs", tgt, "Confirm whether the service was degraded.", {}))
        out.append(Proposal("rate_limit_source", f"{src} -> {tgt}{port}", f"{family} traffic from {src}.", {"hours": 24}))
        if severity in ("high", "critical") and not internal:
            out.append(Proposal("temporary_block_source", src, f"Sustained {family} from an external source.", {"hours": 24}))
    elif family == "PortScan":
        if internal:
            out.append(Proposal("collect_host_forensics", src, "An internal host scanning others may be compromised.", {}))
            out.append(Proposal("isolate_host_for_investigation", src, "Stop the scan spreading while it is examined.", {}))
        else:
            out.append(Proposal("temporary_block_source", src, "External reconnaissance; blocking slows follow-up attacks.",
                                {"hours": 24}))
    elif family == "BruteForce":
        out.append(Proposal("credential_review", tgt, f"Password guessing against {tgt}{port}.", {"port": top_port}))
        out.append(Proposal("temporary_block_source", src, "Stop further guessing from this source.", {"hours": 24}))
    elif family == "WebAttack":
        out.append(Proposal("review_target_logs", tgt, "Check application logs for successful injection.", {}))
        out.append(Proposal("enable_waf_virtual_patch", f"{tgt}{port}", "Filter the attack pattern at the application edge.", {}))
        out.append(Proposal("temporary_block_source", src, "Source sent web attacks.", {"hours": 24}))
    elif family in ("Botnet", "Infiltration"):
        if internal:
            out.append(Proposal("collect_host_forensics", src, f"{family} activity from an internal host.", {}))
            out.append(Proposal("isolate_host_for_investigation", src, "Contain a likely compromised host.", {}))
            out.append(Proposal("block_outbound_destination", tgt, "Cut the host's suspected command channel.", {"hours": 24}))
        else:
            out.append(Proposal("temporary_block_source", src, f"{family} traffic from an external source.", {"hours": 24}))

    if severity not in DISRUPTIVE_MIN_SEVERITY:   # low severity: watch, don't touch
        out = [p for p in out if not ACTIONS[p.action_type].disruptive]
    return out


def cautions_for(p: Proposal, *, src_asset: tuple | None, target_assets: list[tuple]) -> list[str]:
    c = []
    spec = ACTIONS[p.action_type]
    if spec.disruptive and src_asset and p.target.startswith(src_asset[1]):
        c.append(f"{src_asset[1]} is inventoried as {src_asset[0]} (criticality {src_asset[2]}/5); "
                 "acting on it may interrupt legitimate service")
    if p.action_type in ("enable_waf_virtual_patch", "rate_limit_source") and any(a[2] >= 4 for a in target_assets):
        c.append("target is a high-criticality asset; test the rule for false positives first")
    if spec.disruptive:
        c.append(f"undo: {spec.undo}")
    return c


class ResponseAgent:
    name = "response"

    def __init__(self, pool: ConnectionPool, bus: busmod.Bus | None = None):
        self.pool, self.bus = pool, bus or busmod.PostgresBus()
        self.stop_event = threading.Event()

    def propose(self, conn, case_id, assessment_id) -> list[dict]:
        latest = conn.execute("SELECT assessment_id::text FROM risk_assessments WHERE case_id = %s "
                              "ORDER BY created_at DESC LIMIT 1", (case_id,)).fetchone()
        if latest and latest[0] != str(assessment_id):
            log.info("case %s: assessment %s superseded by %s; not proposing", case_id, assessment_id, latest[0])
            return []
        row = conn.execute(
            "SELECT c.family, host(c.src_ip), r.severity, i.telemetry FROM cases c "
            "JOIN risk_assessments r ON r.case_id = c.case_id AND r.assessment_id = %s "
            "JOIN investigations i ON i.investigation_id = r.investigation_id WHERE c.case_id = %s",
            (assessment_id, case_id)).fetchone()
        if not row:
            raise ValueError(f"assessment {assessment_id} for case {case_id} not found")
        family, src, severity, telemetry = row
        zone = conn.execute("SELECT zone FROM network_zones WHERE %s::inet <<= cidr ORDER BY masklen(cidr) DESC LIMIT 1",
                            (src,)).fetchone() if src else None
        targets = (telemetry.get("destinations") or {}).get("top") or []
        top_port = ((telemetry.get("destination_ports") or {}).get("top") or [{}])[0].get("port")
        src_asset = conn.execute("SELECT name, %s, criticality FROM assets WHERE %s::inet <<= cidr "
                                 "ORDER BY masklen(cidr) DESC LIMIT 1", (src, src)).fetchone() if src else None
        target_assets = conn.execute(
            "SELECT DISTINCT a.name, host(f.dst_ip), a.criticality FROM case_events ce JOIN flow_events f USING (event_id) "
            "JOIN assets a ON f.dst_ip <<= a.cidr WHERE ce.case_id = %s", (case_id,)).fetchall()

        proposals = plan(family=family, severity=severity, src_ip=src, src_zone=zone[0] if zone else None,
                         targets=targets, top_port=top_port)
        # a re-assessed case must not get the same action proposed twice
        existing = {(a, t) for a, t in conn.execute(
            "SELECT action_type, target FROM response_actions WHERE case_id = %s AND status IN ('proposed', 'approved')",
            (case_id,))}
        proposals = [p for p in proposals if (p.action_type, p.target) not in existing]
        created = []
        with conn.transaction():
            for p in proposals:
                spec = ACTIONS[p.action_type]
                cautions = cautions_for(p, src_asset=src_asset, target_assets=target_assets)
                aid = conn.execute(
                    "INSERT INTO response_actions (case_id, assessment_id, action_type, target, params, rationale, "
                    "disruptive, reversible, cautions) VALUES (%s, %s, %s, %s, %s, %s, %s, true, %s) RETURNING action_id",
                    (case_id, assessment_id, p.action_type, p.target, Jsonb(p.params), p.rationale, spec.disruptive,
                     Jsonb(cautions))).fetchone()[0]
                created.append({"action_id": str(aid), "action_type": p.action_type, "target": p.target,
                                "disruptive": spec.disruptive})
            self.bus.publish(conn, RESPONSE_PROPOSED, {"case_id": str(case_id), "assessment_id": str(assessment_id),
                                                       "actions": created}, producer=self.name)
        log.info("case %s: %d actions proposed (%d disruptive), awaiting human approval", case_id, len(created),
                 sum(a["disruptive"] for a in created))
        return created

    def process(self, limit: int = 100) -> int:
        with self.pool.connection() as conn, conn.transaction():
            msgs = self.bus.poll(conn, self.name, RISK_ASSESSED, limit)
            for m in msgs:
                self.propose(conn, m.payload["case_id"], m.payload["assessment_id"])
            if msgs:
                self.bus.commit(conn, self.name, RISK_ASSESSED, msgs[-1].id)
            return len(msgs)

    def run(self, idle_sleep: float = 2.0) -> None:
        _run_loop(self, idle_sleep)


def _run_loop(agent, idle_sleep: float) -> None:
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: agent.stop_event.set())
    log.info("%s agent started", agent.name)
    while not agent.stop_event.is_set():
        try:
            n = agent.process()
        except Exception:
            log.exception("%s cycle failed; retrying", agent.name)
            n = 0
        if n == 0:
            agent.stop_event.wait(idle_sleep)
    log.info("%s agent stopped", agent.name)


# ── human decisions (CLI only) ─────────────────────────────────────────────────────────────────
def decide(conn, action_id: str, *, approve: bool, actor: str, note: str, bus: busmod.Bus | None = None) -> dict:
    if actor.startswith("agent:"):
        raise PermissionError("agents cannot approve or reject response actions")
    bus = bus or busmod.PostgresBus()
    status = "approved" if approve else "rejected"
    with conn.transaction():
        row = conn.execute(
            "UPDATE response_actions SET status = %s, decided_by = %s, decided_at = now(), decision_note = %s "
            "WHERE action_id = %s AND status = 'proposed' RETURNING case_id, action_type, target",
            (status, actor, note, action_id)).fetchone()
        if not row:
            raise ValueError(f"action {action_id} is not awaiting a decision")
        bus.publish(conn, RESPONSE_DECIDED, {"case_id": str(row[0]), "action_id": action_id, "decision": status,
                                             "actor": actor}, producer="human")
    return {"case_id": row[0], "action_type": row[1], "target": row[2], "status": status}


def complete(conn, action_id: str, *, actor: str, note: str, bus: busmod.Bus | None = None) -> dict:
    if actor.startswith("agent:"):
        raise PermissionError("only a human can confirm an action was carried out")
    bus = bus or busmod.PostgresBus()
    with conn.transaction():
        row = conn.execute(
            "UPDATE response_actions SET status = 'completed', completed_by = %s, completed_at = now(), "
            "decision_note = coalesce(decision_note || ' | ', '') || %s "
            "WHERE action_id = %s AND status = 'approved' RETURNING case_id, action_type, target",
            (actor, note, action_id)).fetchone()
        if not row:
            raise ValueError(f"action {action_id} is not approved (or already completed)")
        bus.publish(conn, RESPONSE_DECIDED, {"case_id": str(row[0]), "action_id": action_id, "decision": "completed",
                                             "actor": actor}, producer="human")
    return {"case_id": row[0], "action_type": row[1], "target": row[2], "status": "completed"}

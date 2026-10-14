"""Safe remediation workflow: propose → human approval → (simulated) execution → human verification.

- Only action types in the Response Agent's allowlisted catalog (agents.response.ACTIONS) exist.
- Proposals can come from the Response Agent's playbook, an analyst, or the AI Security Agent; all of
  them start as 'proposed', and only a human holding 'actions:decide' can approve them.
- Execution re-checks everything on the server at the moment it runs: the action is approved, the
  ticket is still active, the target is still a valid, non-protected address, and the approver's key is
  still valid (the caller re-authenticates).
- No firewall, EDR or identity-provider integration is configured (EXECUTORS is empty), so every
  execution is a SIMULATION: it records exactly what would be sent and changes nothing. Its outcome is
  'simulated', never 'succeeded'.
"""

import ipaddress
import re

from psycopg.types.json import Jsonb

from . import tickets
from .agents.response import ACTIONS, RESPONSE_DECIDED, decide as _decide
from . import bus as busmod

# Live executors would be registered here as {action_type: callable(target, params) -> dict}.
# None are configured; see docs/soc-platform.md ("Remediation integrations").
EXECUTORS: dict = {}

# What a live integration would do, shown in simulations so the analyst sees the exact request.
SIMULATED_STEPS = {
    "increase_monitoring": "raise capture/log level on {target} for {hours} h",
    "collect_host_forensics": "collect process list, open connections and auth logs from {target} (read-only)",
    "review_target_logs": "pull service/application logs from {target} for the incident window",
    "rate_limit_source": "add a rate-limit rule for {target} (expires after {hours} h)",
    "temporary_block_source": "add a perimeter deny rule for source {target} (expires after {hours} h)",
    "block_outbound_destination": "add an egress deny rule to {target} (expires after {hours} h)",
    "isolate_host_for_investigation": "move {target} to the quarantine VLAN",
    "enable_waf_virtual_patch": "enable the WAF virtual-patch rule set for {target}",
    "credential_review": "open a credential review for accounts on {target}",
}
TARGET_TOKEN = re.compile(r"[0-9a-fA-F:.]+(?:/\d{1,3})?")


class RemediationError(ValueError):
    pass


def _addresses(target: str) -> list:
    out = []
    for tok in TARGET_TOKEN.findall(target):
        try:
            out.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue
    return out


def protected_reason(conn, target: str) -> str | None:
    """Targets that must never be acted on automatically: this server, loopback, the owner's addresses,
    and anything too broad (a /0 … /15)."""
    from . import site
    s = site.load()
    nets = _addresses(target)
    if not nets:
        return "the target contains no IP address"
    me = {s.get("server_ip")} | set(s.get("owner_ips") or [])
    for n in nets:
        if n.prefixlen < (16 if n.version == 4 else 48):
            return f"{n} is too broad"
        if n.is_loopback or n.is_unspecified or n.is_multicast:
            return f"{n} is not a host address"
        for ip in me:
            if ip and ipaddress.ip_address(ip) in n:
                return f"{n} includes this server or an owner address"
    return None


def propose(conn, ticket_id: str, action_type: str, target: str, *, rationale: str, proposed_by: str,
            params: dict | None = None, run_id=None, allowed_ips: set[str] | None = None) -> str:
    """A new proposal on a ticket. allowed_ips (for agent proposals): every address in the target must be one of
    these (the ticket's own evidence), so a proposal can't be steered at an arbitrary host."""
    if action_type not in ACTIONS:
        raise RemediationError(f"'{action_type}' is not in the allowlisted action catalog")
    target = (target or "").strip()[:200]
    if not target:
        raise RemediationError("a target is required")
    reason = protected_reason(conn, target)
    if reason:
        raise RemediationError(f"target refused: {reason}")
    if allowed_ips is not None:
        outside = [str(n) for n in _addresses(target)
                   if not any(ipaddress.ip_address(ip) in n for ip in allowed_ips if ip)
                   or n.num_addresses > 1]
        if outside:
            raise RemediationError(f"target {', '.join(outside)} is not an address in this ticket's evidence")
    params = {k: v for k, v in (params or {}).items() if k in ("hours", "port") and isinstance(v, (int, str))}
    if action_type in ("rate_limit_source", "temporary_block_source", "block_outbound_destination", "increase_monitoring"):
        params["hours"] = min(int(params.get("hours") or 24), 72)   # temporary by construction
    spec = ACTIONS[action_type]
    with conn.transaction():
        t = conn.execute("SELECT status, case_id FROM tickets WHERE ticket_id = %s FOR UPDATE", (ticket_id,)).fetchone()
        if not t:
            raise tickets.NotFound(f"{ticket_id} not found")
        if t[0] in ("resolved", "closed"):
            raise RemediationError("the ticket is no longer active")
        dup = conn.execute("SELECT 1 FROM response_actions WHERE (ticket_id = %s OR case_id = %s) AND action_type = %s "
                           "AND target = %s AND status IN ('proposed', 'approved')",
                           (ticket_id, t[1], action_type, target)).fetchone()
        if dup:
            raise RemediationError("the same action on the same target is already proposed or approved")
        cautions = [f"undo: {spec.undo}"] if spec.disruptive else []
        aid = conn.execute(
            "INSERT INTO response_actions (ticket_id, action_type, target, params, rationale, disruptive, reversible, "
            "cautions, proposed_by, run_id) VALUES (%s, %s, %s, %s, %s, %s, true, %s, %s, %s) RETURNING action_id::text",
            (ticket_id, action_type, target, Jsonb(params), rationale[:1000], spec.disruptive, Jsonb(cautions),
             proposed_by, run_id)).fetchone()[0]
        if t[0] != "awaiting_approval":
            conn.execute("UPDATE tickets SET status = 'awaiting_approval', updated_at = now() WHERE ticket_id = %s",
                         (ticket_id,))
            tickets.event(conn, ticket_id, proposed_by, "status_changed", {"from": t[0], "to": "awaiting_approval"})
        tickets.event(conn, ticket_id, proposed_by, "action_proposed",
                      {"action_id": aid, "action": action_type, "target": target})
        tickets.audit(conn, proposed_by, "action.propose", "response_action", aid,
                      detail={"ticket_id": ticket_id, "action": action_type, "target": target})
    return aid


def decide(conn, action_id: str, *, approve: bool, actor: str, note: str, client: str | None = None) -> dict:
    res = _decide(conn, action_id, approve=approve, actor=actor, note=note)
    with conn.transaction():
        tickets.audit(conn, actor, "action.approve" if approve else "action.reject", "response_action", action_id,
                      client=client, detail={"note": note, "target": res["target"], "action": res["action_type"]})
    return res


def cancel(conn, action_id: str, *, actor: str, note: str, client: str | None = None) -> dict:
    if actor.startswith("agent:"):
        raise PermissionError("agents cannot cancel actions")
    with conn.transaction():
        row = conn.execute(
            "UPDATE response_actions SET status = 'cancelled', decided_by = coalesce(decided_by, %s), "
            "decided_at = coalesce(decided_at, now()), decision_note = coalesce(decision_note || ' | ', '') || %s "
            "WHERE action_id = %s AND status IN ('proposed', 'approved') RETURNING case_id, ticket_id, action_type, target",
            (actor, f"cancelled: {note}", action_id)).fetchone()
        if not row:
            raise RemediationError("only proposed or approved actions can be cancelled")
        busmod.PostgresBus().publish(conn, RESPONSE_DECIDED, {"case_id": row[0] and str(row[0]), "ticket_id": row[1],
                                                              "action_id": action_id, "decision": "cancelled",
                                                              "actor": actor}, producer="human")
        tickets.audit(conn, actor, "action.cancel", "response_action", action_id, client=client, detail={"note": note})
    return {"case_id": row[0], "ticket_id": row[1], "action_type": row[2], "target": row[3], "status": "cancelled"}


def execute(conn, action_id: str, *, actor: str, client: str | None = None) -> dict:
    """Runs an approved action through its executor, or simulates it when none is configured."""
    if actor.startswith("agent:"):
        raise PermissionError("agents cannot execute actions")
    with conn.transaction():
        a = conn.execute(
            "SELECT a.action_type, a.target, a.params, a.status, a.decided_by, coalesce(a.ticket_id, t.ticket_id), "
            " t.status FROM response_actions a LEFT JOIN tickets t ON t.ticket_id = a.ticket_id OR t.case_id = a.case_id "
            "WHERE a.action_id = %s FOR UPDATE OF a", (action_id,)).fetchone()
        if not a:
            raise RemediationError("no such action")
        action_type, target, params, status, approved_by, ticket_id, ticket_status = a
        if status != "approved":
            raise RemediationError("only approved actions can be executed")
        if action_type not in ACTIONS:
            raise RemediationError("this action type is no longer in the catalog")
        if ticket_status in ("resolved", "closed"):
            raise RemediationError("the ticket is no longer active")
        reason = protected_reason(conn, target)
        if reason:
            raise RemediationError(f"target refused at execution time: {reason}")
        executor = EXECUTORS.get(action_type)
        step = SIMULATED_STEPS[action_type].format(target=target, hours=params.get("hours", 24))
        if executor is None:
            mode, outcome = "simulation", "simulated"
            result = {"simulated": True, "integration": None, "would_do": step,
                      "message": "SIMULATION: no integration is configured for this action, so nothing was changed. "
                                 "Carry it out with your own tools, then mark the action completed."}
        else:  # pragma: no cover  (no live executors exist yet)
            mode = "live"
            try:
                result = executor(target, params)
                outcome = "succeeded"
            except Exception as e:
                result, outcome = {"error": str(e)[:300]}, "failed"
        eid = conn.execute(
            "INSERT INTO action_executions (action_id, mode, outcome, requested_by, approved_by, target, params, result) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING execution_id::text",
            (action_id, mode, outcome, actor, approved_by, target, Jsonb(params), Jsonb(result))).fetchone()[0]
        if ticket_id:
            tickets.event(conn, ticket_id, actor, f"action_{outcome}",
                          {"action_id": action_id, "execution_id": eid, "mode": mode, "would_do": step})
        tickets.audit(conn, actor, f"action.execute.{mode}", "response_action", action_id, client=client,
                      detail={"execution_id": eid, "outcome": outcome, "target": target})
    return {"execution_id": eid, "mode": mode, "outcome": outcome, "result": result}


def verify(conn, execution_id: str, *, actor: str, ok: bool, note: str, client: str | None = None) -> None:
    if actor.startswith("agent:"):
        raise PermissionError("agents cannot verify actions")
    note = tickets.clean_text(note, "Verification note", 1000, required=True)
    with conn.transaction():
        row = conn.execute(
            "UPDATE action_executions SET verification = %s, verified_by = %s, verified_at = now(), verification_note = %s "
            "WHERE execution_id = %s AND verification = 'unverified' RETURNING action_id",
            ("verified" if ok else "failed", actor, note, execution_id)).fetchone()
        if not row:
            raise RemediationError("this execution is already verified")
        tickets.audit(conn, actor, "action.verify", "action_execution", execution_id, client=client,
                      detail={"ok": ok, "note": note})

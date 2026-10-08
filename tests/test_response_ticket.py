import re

import psycopg
import pytest

from netsentinel.agents import response, ticket
from netsentinel.agents.response import ACTIONS, ResponseAgent, plan
from netsentinel.agents.risk import RiskAgent
from netsentinel.agents.ticket import TicketAgent
from test_orchestration import FakeLLM, _good_output, _investigate, seeded  # noqa: F401  (fixture)

DESTRUCTIVE = re.compile(r"\b(delete|wipe|re-?image|kill|format|destroy|shut\s*down|power\s*off|drop\s+table)\b", re.I)
T = [{"ip": "192.168.10.50", "flows": 10}]


def test_catalog_contains_no_destructive_actions():
    for name, spec in ACTIONS.items():
        assert not DESTRUCTIVE.search(name + " " + spec.description), name
        assert spec.undo


@pytest.mark.parametrize("family", ["DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Infiltration", None])
@pytest.mark.parametrize("zone", ["internal", "external", None])
def test_low_severity_never_proposes_disruptive_actions(family, zone):
    for p in plan(family=family, severity="low", src_ip="10.0.0.5", src_zone=zone, targets=T, top_port="80"):
        assert not ACTIONS[p.action_type].disruptive


def test_playbook_depends_on_direction():
    internal = {p.action_type for p in plan(family="Botnet", severity="high", src_ip="192.168.10.9", src_zone="internal",
                                            targets=[{"ip": "205.174.165.73"}], top_port="8080")}
    external = {p.action_type for p in plan(family="Botnet", severity="high", src_ip="205.174.165.73",
                                            src_zone="external", targets=T, top_port="8080")}
    assert {"isolate_host_for_investigation", "block_outbound_destination", "collect_host_forensics"} <= internal
    assert "temporary_block_source" not in internal and "temporary_block_source" in external


def test_unknown_source_or_family_only_observes():
    for kw in ({"family": None, "src_ip": "1.2.3.4"}, {"family": "DoS", "src_ip": None}):
        acts = plan(severity="critical", src_zone=None, targets=T, top_port="80", **kw)
        assert all(not ACTIONS[p.action_type].disruptive for p in acts)


def _through_ticket(pool, seeded):
    case_id, _ = _investigate(pool, seeded, FakeLLM(_good_output(f"{seeded}.1")))
    for agent in (RiskAgent(pool), ResponseAgent(pool), TicketAgent(pool)):
        while agent.process():
            pass
    return case_id


def test_full_chain_and_human_only_decisions(pool, seeded):
    case_id = _through_ticket(pool, seeded)
    with pool.connection() as c:
        tid, status, prio, summary = c.execute("SELECT ticket_id, status, priority, summary FROM tickets WHERE case_id = %s",
                                               (case_id,)).fetchone()
        assert re.fullmatch(r"NS-\d{6}", tid)
        assert set(summary) == {"VERIFIED TELEMETRY", "MODEL OUTPUT", "LLM ANALYSIS", "RISK", "RECOMMENDATION"}
        assert c.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone() == ("ticketed",)
        actions = c.execute("SELECT action_id::text, disruptive FROM response_actions WHERE case_id = %s",
                            (case_id,)).fetchall()
        assert actions and status == "awaiting_approval"

        with pytest.raises(PermissionError):
            response.decide(c, actions[0][0], approve=True, actor="agent:response", note="x")
        with pytest.raises(psycopg.errors.CheckViolation):      # even bypassing the code, the DB refuses
            c.execute("UPDATE response_actions SET status = 'approved', decided_by = 'agent:x', decided_at = now() "
                      "WHERE action_id = %s", (actions[0][0],))
        with pytest.raises(psycopg.errors.RaiseException):
            c.execute("UPDATE response_actions SET target = '0.0.0.0/0' WHERE action_id = %s", (actions[0][0],))
        with pytest.raises(ValueError):                          # can't complete what wasn't approved
            response.complete(c, actions[0][0], actor="human:t", note="x")

        response.decide(c, actions[0][0], approve=True, actor="human:analyst", note="confirmed scan")
        for aid, _ in actions[1:]:
            response.decide(c, aid, approve=False, actor="human:analyst", note="not needed")
        with pytest.raises(ValueError):
            response.decide(c, actions[0][0], approve=False, actor="human:analyst", note="changed mind")
        response.complete(c, actions[0][0], actor="human:analyst", note="done in firewall UI")
    TicketAgent(pool).process()
    with pool.connection() as c:
        assert c.execute("SELECT status FROM tickets WHERE ticket_id = %s", (tid,)).fetchone() == ("in_progress",)
        events = [e[0] for e in c.execute("SELECT event FROM ticket_events WHERE ticket_id = %s ORDER BY id", (tid,))]
        assert events[0] == "created" and "action_approved" in events and "action_completed" in events
        ticket.resolve(c, tid, actor="human:analyst", resolution="scan blocked", close=True)
        assert c.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone() == ("closed",)
        with pytest.raises(ValueError):
            ticket.resolve(c, tid, actor="human:analyst", resolution="again", close=True)


def test_superseded_assessment_gets_no_proposals(pool, seeded):
    case_id, _ = _investigate(pool, seeded, FakeLLM(_good_output(f"{seeded}.1")))
    with pool.connection() as c:
        inv = c.execute("SELECT investigation_id FROM investigations WHERE case_id = %s", (case_id,)).fetchone()[0]
        risk = RiskAgent(pool)
        old = risk.assess(c, case_id, inv)["assessment_id"]
        new = risk.assess(c, case_id, inv)["assessment_id"]
        agent = ResponseAgent(pool)
        assert agent.propose(c, case_id, old) == []
        assert agent.propose(c, case_id, new)

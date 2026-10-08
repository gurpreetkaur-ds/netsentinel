import random
import uuid

import pytest
from psycopg.types.json import Jsonb

from netsentinel import bus as busmod
from netsentinel import llm
from netsentinel.agents.investigation import InvestigationAgent, guard
from netsentinel.agents.orchestrator import INVESTIGATION_REQUESTED, Orchestrator
from netsentinel.ml import schema


def _net():
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}"


@pytest.fixture
def seeded(pool):
    """Detections published as the Detection Agent would, for fresh, unique source IPs."""
    net = _net()
    plan = [(f"{net}.1", "PortScan", 5), (f"{net}.2", "DoS", 3), (f"{net}.1", "DoS", 2)]
    with pool.connection() as c, c.transaction():
        c.execute("INSERT INTO models (model_id, artifact_path, sha256, schema_version, features, registered_by) "
                  "VALUES ('fake-model', 'artifacts/none', %s, 'x', '{}', 'pytest') ON CONFLICT DO NOTHING", ("0" * 64,))
        key_id = c.execute("SELECT key_id FROM api_keys LIMIT 1").fetchone()
        if not key_id:
            c.execute("INSERT INTO api_keys (key_id, name, key_sha256, scopes, created_by) "
                      "VALUES ('aaaaaaaaaaaa', 'k', %s, '{ingest:write}', 'pytest')", (b"\0" * 32,))
            key_id = ("aaaaaaaaaaaa",)
        flow = {f: 1.0 for f in schema.FEATURES}
        for src, family, n in plan:
            for port in range(n):
                eid = c.execute(
                    "INSERT INTO flow_events (batch_id, key_id, source, flow, status, src_ip, dst_ip, src_port, dst_port, protocol) "
                    "VALUES (gen_random_uuid(), %s, 'cicflowmeter', %s, 'scored', %s, %s, 40000, %s, 6) RETURNING event_id",
                    (key_id[0], Jsonb(flow), src, f"{net}.99", 20 + port)).fetchone()[0]
                c.execute("INSERT INTO detections (event_id, model_id, p_attack, threshold, is_attack, family, "
                          "family_confidence, missing_features) VALUES (%s, 'fake-model', 0.99, 0.5, true, %s, 0.9, 0)",
                          (eid, family))
                busmod.PostgresBus().publish(c, busmod.DETECTION_ATTACK, {"event_id": str(eid)}, producer="pytest")
    return net


def _cases(pool, net):
    with pool.connection() as c:
        return {r[0]: (r[1], r[2]) for r in c.execute(
            "SELECT correlation_key, flow_count, status FROM cases WHERE correlation_key LIKE %s", (f"{net}.%",))}


def test_orchestrator_correlates_by_source_and_family_idempotently(pool, seeded):
    orch = Orchestrator(pool)
    while orch.correlate():
        pass
    net = seeded
    assert _cases(pool, net) == {f"{net}.1|PortScan": (5, "open"), f"{net}.2|DoS": (3, "open"), f"{net}.1|DoS": (2, "open")}
    with pool.connection() as c:                       # replay the whole topic: at-least-once delivery
        c.execute("UPDATE bus_offsets SET last_id = 0 WHERE consumer = 'orchestrator'")
    while orch.correlate():
        pass
    assert _cases(pool, net)[f"{net}.1|PortScan"] == (5, "open")


def test_dispatch_waits_for_quiet_period(pool, seeded):
    orch = Orchestrator(pool)
    while orch.correlate():
        pass
    assert not any(k.startswith(seeded) for k in _dispatched_keys(pool, orch.dispatch()))
    with pool.connection() as c:
        c.execute("UPDATE cases SET updated_at = now() - interval '1 minute' WHERE correlation_key LIKE %s", (f"{seeded}.%",))
    keys = _dispatched_keys(pool, orch.dispatch())
    assert {f"{seeded}.1|PortScan", f"{seeded}.2|DoS", f"{seeded}.1|DoS"} <= keys
    assert all(v[1] == "investigating" for v in _cases(pool, seeded).values())


def _dispatched_keys(pool, case_ids):
    with pool.connection() as c:
        return {r[0] for r in c.execute("SELECT correlation_key FROM cases WHERE case_id = ANY(%s)", (case_ids,))}


class FakeLLM:
    def __init__(self, output=None, error=None):
        self.output, self.error, self.calls = output, error, []

    def complete(self, *, system, prompt, schema):
        self.calls.append(prompt)
        if self.error:
            raise self.error
        return llm.LLMResult(dict(self.output), "fake-claude", 5)


def _good_output(src):
    return {
        "summary": f"Source {src} probed 5 ports on one host.",
        "model_assessment": {"consistency": "consistent", "reasoning": "Many short flows to distinct ports."},
        "observations": [{"statement": "5 distinct destination ports", "evidence_refs": ["telemetry.destination_ports"]},
                         {"statement": "made-up", "evidence_refs": ["telemetry.nonexistent"]}],
        "hypotheses": [{"hypothesis": "Reconnaissance", "likelihood": "high"}],
        "recommended_next_steps": ["Check which ports answered.", "Block the source at the firewall."],
        "data_gaps": ["No payload data."], "confidence": "medium",
    }


def _investigate(pool, seeded, fake):
    orch = Orchestrator(pool)
    while orch.correlate():
        pass
    with pool.connection() as c:
        c.execute("UPDATE cases SET updated_at = now() - interval '1 minute' WHERE correlation_key LIKE %s", (f"{seeded}.%",))
        orch.dispatch()
        case_id = c.execute("SELECT case_id FROM cases WHERE correlation_key = %s", (f"{seeded}.1|PortScan",)).fetchone()[0]
    return case_id, InvestigationAgent(pool, llm=fake).investigate(case_id)


def test_investigation_labels_sections_and_guards_output(pool, seeded):
    fake = FakeLLM(_good_output(f"{seeded}.1"))
    case_id, res = _investigate(pool, seeded, fake)
    assert res["llm_status"] == "ok"
    assert {f["type"] for f in res["findings"]} == {"unknown_evidence_ref", "response_action_removed"}
    assert "<evidence>" in fake.calls[0] and f"{seeded}.1" in fake.calls[0]
    with pool.connection() as c:
        tel, mo, an, rec, status = c.execute(
            "SELECT telemetry, model_output, analysis, recommendations, llm_status FROM investigations WHERE case_id = %s",
            (case_id,)).fetchone()
        case_status = c.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()[0]
        det = c.execute("SELECT count(*) FROM detections d JOIN case_events USING (event_id) "
                        "WHERE case_id = %s AND is_attack AND family = 'PortScan'", (case_id,)).fetchone()[0]
    assert tel["destination_ports"]["distinct"] == 5 and tel["case"]["source_ip"] == f"{seeded}.1"
    assert mo["families"] == {"PortScan": 5}
    assert rec["next_steps"] == ["Check which ports answered."]          # containment step stripped
    assert an["observations"][1]["unsupported"] is True
    assert case_status == "investigated" and det == 5                    # LLM changed nothing upstream


def test_fabricated_ip_rejects_analysis(pool, seeded):
    out = _good_output("203.0.113.77")                                   # not in the evidence
    case_id, res = _investigate(pool, seeded, FakeLLM(out))
    assert res["llm_status"] == "guard_rejected"
    assert any(f["type"] == "fabricated_ip" and f["value"] == "203.0.113.77" for f in res["findings"])


def test_llm_unavailable_falls_back_to_rule_based_steps(pool, seeded):
    case_id, res = _investigate(pool, seeded, FakeLLM(error=llm.LLMUnavailable("down")))
    assert res["llm_status"] == "unavailable"
    with pool.connection() as c:
        an, rec = c.execute("SELECT analysis, recommendations FROM investigations WHERE case_id = %s", (case_id,)).fetchone()
    assert an is None and rec["source"] == "rule-based fallback" and rec["next_steps"]


def test_guard_unit():
    tel = {"case": {"source_ip": "192.168.10.50"}, "destination_ports": {"distinct": 3}}
    out = {"summary": "192.168.10.50 and 10.9.9.9", "observations": [], "recommended_next_steps": ["Isolate the host"]}
    cleaned, findings, rejected = guard(out, tel, {})
    assert rejected and cleaned["recommended_next_steps"] == []
    assert {f["type"] for f in findings} == {"fabricated_ip", "response_action_removed"}


def test_llm_refuses_static_api_keys(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
    with pytest.raises(llm.LLMUnavailable, match="static API keys"):
        llm.ClaudeClient().complete(system="s", prompt="p", schema={"type": "object"})


def test_llm_subprocess_env_is_minimal(monkeypatch):
    monkeypatch.setenv("NETSENTINEL_DB_NAME", "secret-ish")
    monkeypatch.setenv("WALL_SOCKET", "/run/wall-netsentinel/proxy.sock")
    env = llm._env()
    assert "NETSENTINEL_DB_NAME" not in env and "WALL_SOCKET" not in env and "PATH" in env


class FlakyLLM(FakeLLM):
    def complete(self, *, system, prompt, schema):
        self.calls.append(prompt)
        if len(self.calls) == 1:
            raise llm.LLMUnavailable("Claude runtime error: ResultError")
        return llm.LLMResult(dict(self.output), "fake-claude", 5)


def test_transient_llm_error_is_retried_once(pool, seeded):
    fake = FlakyLLM(_good_output(f"{seeded}.1"))
    _, res = _investigate(pool, seeded, fake)
    assert res["llm_status"] == "ok" and len(fake.calls) == 2


@pytest.mark.parametrize("step,removed", [
    ("Verify why the connection terminated via RST immediately after SYN by checking firewall logs.", False),
    ("Check whether the source was blocked by the perimeter firewall.", False),
    ("Isolate the host from the network.", True),
    ("Block 172.16.0.1 at the edge.", True),
    ("Terminate the suspicious process.", True),
])
def test_guard_distinguishes_containment_from_investigation(step, removed):
    _, findings, _ = guard({"observations": [], "recommended_next_steps": [step]}, {"x": "172.16.0.1"}, {})
    assert any(f["type"] == "response_action_removed" for f in findings) is removed


@pytest.mark.parametrize("text,rejected", [
    ("scanning neighbours on the 192.168.10.0/24 subnet", False),   # contains evidence host
    ("traffic from 192.168.10.8", False),
    ("the whole 10.0.0.0/8 range", True),                            # too broad / unrelated
    ("0.0.0.0/0", True),
    ("the 172.20.0.0/16 network", True),                             # no evidence host inside
    ("bare network address 192.168.10.0", True),                     # bare IP must match exactly
    ("C2 at 203.0.113.9", True),
])
def test_guard_cidr_grounding(text, rejected):
    tel = {"case": {"source_ip": "192.168.10.8"}, "destinations": {"top": [{"ip": "192.168.10.15"}]}}
    _, _, rej = guard({"summary": text, "observations": [], "recommended_next_steps": []}, tel, {})
    assert rej is rejected


def test_long_attack_stays_one_case_after_dispatch(pool, seeded):
    orch = Orchestrator(pool)
    while orch.correlate():
        pass
    with pool.connection() as c:
        c.execute("UPDATE cases SET updated_at = now() - interval '1 minute' WHERE correlation_key LIKE %s", (f"{seeded}.%",))
    orch.dispatch()                                    # cases now 'investigating'
    # more flows from the same source+family arrive: they must join the dispatched case
    with pool.connection() as c, c.transaction():
        eid = c.execute("SELECT ce.event_id FROM case_events ce JOIN cases cs USING (case_id) WHERE cs.correlation_key = %s "
                        "LIMIT 1", (f"{seeded}.1|PortScan",)).fetchone()[0]
        flow = c.execute("SELECT key_id, flow, src_ip, dst_ip FROM flow_events WHERE event_id = %s", (eid,)).fetchone()
        new = c.execute("INSERT INTO flow_events (batch_id, key_id, source, flow, status, src_ip, dst_ip, dst_port, protocol) "
                        "VALUES (gen_random_uuid(), %s, 'cicflowmeter', %s, 'scored', %s, %s, 9999, 6) RETURNING event_id",
                        (flow[0], Jsonb(flow[1]), flow[2], flow[3])).fetchone()[0]
        c.execute("INSERT INTO detections (event_id, model_id, p_attack, threshold, is_attack, family, family_confidence, "
                  "missing_features) VALUES (%s, 'fake-model', 0.99, 0.5, true, 'PortScan', 0.9, 0)", (new,))
        busmod.PostgresBus().publish(c, busmod.DETECTION_ATTACK, {"event_id": str(new)}, producer="pytest")
    while orch.correlate():
        pass
    assert _cases(pool, seeded)[f"{seeded}.1|PortScan"] == (6, "investigating")


class SlowLLM(FakeLLM):
    def complete(self, *, system, prompt, schema):
        import threading, time
        self.calls.append(threading.current_thread().name)
        time.sleep(0.3)
        return llm.LLMResult(dict(self.output), "fake-claude", 300)


def test_investigations_run_in_parallel_and_skip_finished(pool, seeded):
    import time
    orch = Orchestrator(pool)
    while orch.correlate():
        pass
    with pool.connection() as c:
        c.execute("UPDATE cases SET updated_at = now() - interval '1 minute' WHERE correlation_key LIKE %s", (f"{seeded}.%",))
    orch.dispatch()
    fake = SlowLLM(_good_output(f"{seeded}.1"))
    agent = InvestigationAgent(pool, llm=fake, workers=3)
    t = time.monotonic()
    while agent.process():
        pass
    with pool.connection() as c:
        statuses = {r[0] for r in c.execute("SELECT status FROM cases WHERE correlation_key LIKE %s", (f"{seeded}.%",))}
    assert statuses == {"investigated"}
    assert len(set(fake.calls)) > 1                    # more than one worker thread was used
    with pool.connection() as c:                       # redelivery: nothing is investigated twice
        c.execute("UPDATE bus_offsets SET last_id = 0 WHERE consumer = 'investigation'")
    n_before = len(fake.calls)
    while agent.process():
        pass
    assert len(fake.calls) == n_before


def test_unavailable_investigation_is_retried_later_and_capped(pool, seeded):
    case_id, res = _investigate(pool, seeded, FakeLLM(error=llm.LLMUnavailable("session limit")))
    assert res["llm_status"] == "unavailable"
    orch = Orchestrator(pool)
    assert case_id not in orch.dispatch()                         # too soon
    with pool.connection() as c:
        c.execute("ALTER TABLE investigations DISABLE TRIGGER investigations_append_only")
        c.execute("UPDATE investigations SET created_at = now() - interval '20 minutes' WHERE case_id = %s", (case_id,))
        c.execute("ALTER TABLE investigations ENABLE TRIGGER investigations_append_only")
    assert case_id in orch.dispatch()                             # retried
    res2 = InvestigationAgent(pool, llm=FakeLLM(_good_output(f"{seeded}.1"))).investigate(case_id)
    assert res2["llm_status"] == "ok"


def test_reassessment_does_not_duplicate_proposals(pool, seeded):
    from netsentinel.agents.response import ResponseAgent
    from netsentinel.agents.risk import RiskAgent
    case_id, _ = _investigate(pool, seeded, FakeLLM(_good_output(f"{seeded}.1")))
    with pool.connection() as c:
        inv = c.execute("SELECT investigation_id FROM investigations WHERE case_id = %s", (case_id,)).fetchone()[0]
        first = RiskAgent(pool).assess(c, case_id, inv)["assessment_id"]
        n1 = len(ResponseAgent(pool).propose(c, case_id, first))
        second = RiskAgent(pool).assess(c, case_id, inv)["assessment_id"]
        assert n1 > 0 and ResponseAgent(pool).propose(c, case_id, second) == []

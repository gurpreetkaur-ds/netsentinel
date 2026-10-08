import copy
import inspect

import pytest

from netsentinel import bus as busmod
from netsentinel.agents.risk import RISK_ASSESSED, RiskAgent, review_reasons, score_case, severity_for
from test_orchestration import FakeLLM, _good_output, _investigate, seeded  # noqa: F401  (fixture)

TEL = {"case": {"flows": 208}, "destinations": {"distinct_ips": 1},
       "source_activity_around_case": {"distinct_destination_ports": 108, "window_margin_seconds": 300},
       "flow_statistics": {"share_flows_without_response": 0.1}}
MO = {"case_family": "DoS", "p_attack": {"mean": 0.9999}}


def test_score_is_explained_and_deterministic():
    s1, f1 = score_case(telemetry=TEL, model_output=MO, max_criticality=4, hit_assets=["lab-web01 (4/5)"],
                        source_zone="external")
    s2, _ = score_case(telemetry=copy.deepcopy(TEL), model_output=dict(MO), max_criticality=4,
                       hit_assets=["lab-web01 (4/5)"], source_zone="external")
    assert s1 == s2 == sum(f["points"] for f in f1)
    by = {f["factor"]: f for f in f1}
    assert by["attack_family"]["points"] == 20 and by["attack_family"]["provenance"] == "MODEL OUTPUT"
    assert by["scale"]["points"] == 12 and by["scale"]["provenance"] == "VERIFIED TELEMETRY"
    assert by["asset_criticality"]["points"] == 15 and by["asset_criticality"]["provenance"] == "ASSET INVENTORY"
    assert by["internal_source"]["points"] == 0          # external DoS source
    assert s1 == 67 and severity_for(s1) == "high"


def test_context_moves_the_score_in_the_expected_direction():
    def s(**kw):
        args = dict(telemetry=TEL, model_output={"case_family": "Botnet", "p_attack": {"mean": 0.99}},
                    max_criticality=2, hit_assets=["ws"], source_zone="external")
        args.update(kw)
        return score_case(**args)[0]
    assert s(source_zone="internal") == s() + 10                 # internal host acting like a bot
    assert s(max_criticality=5) > s(max_criticality=2)
    assert s(max_criticality=None) == s(max_criticality=2)       # unknown asset is not "safe"
    assert s(model_output={"case_family": None, "p_attack": {"mean": 0.99}}) >= \
           s(model_output={"case_family": "PortScan", "p_attack": {"mean": 0.99}})
    assert score_case(telemetry={}, model_output={}, max_criticality=None, hit_assets=[], source_zone=None)[0] >= 0


@pytest.mark.parametrize("score,band", [(100, "critical"), (80, "critical"), (79, "high"), (60, "high"),
                                        (59, "medium"), (40, "medium"), (39, "low"), (0, "low")])
def test_severity_bands(score, band):
    assert severity_for(score) == band


def test_llm_opinion_only_triggers_review_never_score():
    disputing = {"llm_status": "ok", "analysis": {"model_assessment": {"consistency": "inconsistent"}}}
    agreeing = {"llm_status": "ok", "analysis": {"model_assessment": {"consistency": "consistent"}}}
    assert review_reasons(severity="medium", investigation=agreeing, model_output=MO) == []
    assert any("disputes" in r for r in review_reasons(severity="medium", investigation=disputing, model_output=MO))
    assert any("guard" in r for r in review_reasons(severity="low", investigation={"llm_status": "guard_rejected"},
                                                     model_output=MO))
    assert review_reasons(severity="critical", investigation=agreeing, model_output=MO)
    # score_case cannot see the LLM at all: its inputs are model output, telemetry and inventory only
    assert set(inspect.signature(score_case).parameters) == {
        "telemetry", "model_output", "max_criticality", "hit_assets", "source_zone"}


def test_risk_agent_end_to_end(pool, seeded):
    net = seeded
    with pool.connection() as c:
        c.execute("INSERT INTO assets (cidr, name, criticality) VALUES (%s, 'test-dc', 5) ON CONFLICT DO NOTHING",
                  (f"{net}.99/32",))
        c.execute("INSERT INTO network_zones (cidr, zone) VALUES (%s, 'internal') ON CONFLICT DO NOTHING", (f"{net}.0/24",))
    case_id, res = _investigate(pool, seeded, FakeLLM(_good_output(f"{net}.1")))
    agent = RiskAgent(pool)
    while agent.process():
        pass
    with pool.connection() as c:
        score, severity, factors, review, status = c.execute(
            "SELECT r.score, r.severity, r.factors, r.requires_review, c.status FROM risk_assessments r "
            "JOIN cases c USING (case_id) WHERE r.case_id = %s", (case_id,)).fetchone()
        msgs = busmod.PostgresBus().poll(c, "t-risk-reader", RISK_ASSESSED, 10_000)
    by = {f["factor"]: f["points"] for f in factors}
    assert by["asset_criticality"] == 20 and by["internal_source"] == 10     # internal scanner hitting the DC
    assert status == "assessed" and severity == severity_for(score)
    assert any(m.payload["case_id"] == str(case_id) and m.payload["score"] == score for m in msgs)


def test_latest_assessment_is_unambiguous_within_one_transaction(pool, seeded):
    case_id, _ = _investigate(pool, seeded, FakeLLM(_good_output(f"{seeded}.1")))
    with pool.connection() as c, c.transaction():
        inv = c.execute("SELECT investigation_id FROM investigations WHERE case_id = %s", (case_id,)).fetchone()[0]
        first = RiskAgent(pool).assess(c, case_id, inv)["assessment_id"]
        second = RiskAgent(pool).assess(c, case_id, inv)["assessment_id"]
        latest = c.execute("SELECT assessment_id FROM risk_assessments WHERE case_id = %s ORDER BY created_at DESC LIMIT 1",
                           (case_id,)).fetchone()[0]
    assert latest == second != first

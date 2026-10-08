"""Risk Assessment Agent: a deterministic, explainable 0-100 score per case.

Inputs, by provenance:
  MODEL OUTPUT        - attack family, model confidence
  VERIFIED TELEMETRY  - scale, breadth, whether targets answered, source zone
  ASSET INVENTORY     - criticality of the hosts that were hit (operator-maintained)
  LLM ANALYSIS        - never scored. A disagreement with the model or a guard rejection only
                        sets `requires_review`, so a human looks; it cannot raise or lower the score.

Same inputs, same score: every factor records its points, its reason and its provenance.
"""

import logging
import math
import signal
import threading

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .. import bus as busmod
from .investigation import INVESTIGATION_COMPLETED

log = logging.getLogger(__name__)

RISK_ASSESSED = "risk.assessed"
RULES_VERSION = "risk-rules-v1"

FAMILY_SEVERITY = {  # impact if the attack succeeds, before context
    "Infiltration": 35, "Botnet": 35, "Exploit": 35, "WebAttack": 30, "BruteForce": 25,
    "DDoS": 25, "DoS": 20, "PortScan": 10,
}
UNKNOWN_FAMILY_SEVERITY = 25        # an attack the model can't name is not a reason to relax
CRITICALITY_POINTS = {5: 20, 4: 15, 3: 10, 2: 5, 1: 0}
UNKNOWN_ASSET_POINTS = 5            # hosts missing from the inventory are a risk in themselves
COMPROMISE_FAMILIES = {"Botnet", "Infiltration", "PortScan", "BruteForce"}
SEVERITY_BANDS = ((80, "critical"), (60, "high"), (40, "medium"), (0, "low"))


def severity_for(score: int) -> str:
    return next(name for floor, name in SEVERITY_BANDS if score >= floor)


def score_case(*, telemetry: dict, model_output: dict, max_criticality: int | None, hit_assets: list[str],
               source_zone: str | None) -> tuple[int, list[dict]]:
    factors = []

    def add(name, points, reason, provenance):
        factors.append({"factor": name, "points": points, "reason": reason, "provenance": provenance})

    family = model_output.get("case_family")
    base = FAMILY_SEVERITY.get(family, UNKNOWN_FAMILY_SEVERITY)
    add("attack_family", base, f"family {family or 'unnamed'} base severity", "MODEL OUTPUT")

    p = (model_output.get("p_attack") or {}).get("mean") or 0
    conf = 10 if p >= 0.99 else 5 if p >= 0.9 else 0
    add("model_confidence", conf, f"mean p_attack {p:.4f}", "MODEL OUTPUT")

    flows = (telemetry.get("case") or {}).get("flows") or 0
    scale = min(15, round(5 * math.log10(flows))) if flows > 1 else 0
    add("scale", scale, f"{flows} attack flows in the case", "VERIFIED TELEMETRY")

    targets = (telemetry.get("destinations") or {}).get("distinct_ips") or 0
    breadth = 10 if targets >= 10 else 5 if targets >= 3 else 0
    add("target_breadth", breadth, f"{targets} distinct destination hosts", "VERIFIED TELEMETRY")

    activity = telemetry.get("source_activity_around_case") or {}
    ports = activity.get("distinct_destination_ports") or 0
    add("source_port_fanout", 5 if ports >= 100 else 0,
        f"source contacted {ports} distinct ports within ±{activity.get('window_margin_seconds', 0)}s", "VERIFIED TELEMETRY")

    stats = telemetry.get("flow_statistics") or {}
    no_resp = stats.get("share_flows_without_response")
    answered = no_resp is not None and no_resp < 0.5
    add("targets_responded", 5 if answered else 0,
        "most flows got a response from the target" if answered else "most flows got no response, or unknown",
        "VERIFIED TELEMETRY")

    if max_criticality is None:
        add("asset_criticality", UNKNOWN_ASSET_POINTS, "targets not in the asset inventory", "ASSET INVENTORY")
    else:
        add("asset_criticality", CRITICALITY_POINTS[max_criticality],
            f"highest criticality hit: {max_criticality}/5 ({', '.join(hit_assets[:3])})", "ASSET INVENTORY")

    internal_src = source_zone == "internal"
    add("internal_source", 10 if internal_src and family in COMPROMISE_FAMILIES else 0,
        f"source zone: {source_zone or 'unknown'}"
        + ("; an internal host behaving this way may be compromised" if internal_src and family in COMPROMISE_FAMILIES else ""),
        "ASSET INVENTORY")

    score = max(0, min(100, sum(f["points"] for f in factors)))
    return score, factors


def review_reasons(*, severity: str, investigation: dict, model_output: dict) -> list[str]:
    reasons = []
    if severity == "critical":
        reasons.append("critical severity always gets a human review")
    status = investigation.get("llm_status")
    if status == "guard_rejected":
        reasons.append("LLM analysis was rejected by the guard (possible fabricated facts)")
    elif status in ("unavailable", "invalid_output"):
        reasons.append(f"no LLM analysis available ({status})")
    consistency = ((investigation.get("analysis") or {}).get("model_assessment") or {}).get("consistency")
    if consistency == "inconsistent":
        reasons.append("LLM analysis disputes the model's verdict; the score is unchanged, a human should decide")
    if not model_output.get("case_family"):
        reasons.append("the model could not name the attack family")
    return reasons


class RiskAgent:
    name = "risk"

    def __init__(self, pool: ConnectionPool, bus: busmod.Bus | None = None):
        self.pool, self.bus = pool, bus or busmod.PostgresBus()
        self.stop_event = threading.Event()

    def assess(self, conn, case_id, investigation_id) -> dict:
        inv = conn.execute("SELECT telemetry, model_output, analysis, llm_status FROM investigations "
                           "WHERE investigation_id = %s AND case_id = %s", (investigation_id, case_id)).fetchone()
        if not inv:
            raise ValueError(f"investigation {investigation_id} for case {case_id} not found")
        telemetry, model_output, analysis, llm_status = inv
        assets = conn.execute(
            "SELECT DISTINCT ON (f.dst_ip) a.criticality, a.name FROM case_events ce JOIN flow_events f USING (event_id) "
            "JOIN assets a ON f.dst_ip <<= a.cidr WHERE ce.case_id = %s ORDER BY f.dst_ip, masklen(a.cidr) DESC",
            (case_id,)).fetchall()
        assets.sort(key=lambda r: -r[0])
        zone = conn.execute(
            "SELECT z.zone FROM cases c JOIN network_zones z ON c.src_ip <<= z.cidr WHERE c.case_id = %s "
            "ORDER BY masklen(z.cidr) DESC LIMIT 1", (case_id,)).fetchone()
        score, factors = score_case(telemetry=telemetry, model_output=model_output,
                                    max_criticality=assets[0][0] if assets else None,
                                    hit_assets=[f"{n} ({c}/5)" for c, n in assets], source_zone=zone[0] if zone else None)
        severity = severity_for(score)
        reasons = review_reasons(severity=severity, investigation={"analysis": analysis, "llm_status": llm_status},
                                 model_output=model_output)
        with conn.transaction():
            aid = conn.execute(
                "INSERT INTO risk_assessments (case_id, investigation_id, score, severity, factors, requires_review, "
                "review_reasons, rules_version) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING assessment_id",
                (case_id, investigation_id, score, severity, Jsonb(factors), bool(reasons), Jsonb(reasons),
                 RULES_VERSION)).fetchone()[0]
            conn.execute("UPDATE cases SET status = 'assessed', updated_at = now() "
                         "WHERE case_id = %s AND status = 'investigated'", (case_id,))
            conn.execute("INSERT INTO case_history (case_id, status, actor, detail) VALUES (%s, 'assessed', %s, %s)",
                         (case_id, self.name, Jsonb({"assessment_id": str(aid), "score": score, "severity": severity})))
            self.bus.publish(conn, RISK_ASSESSED, {"case_id": str(case_id), "assessment_id": str(aid), "score": score,
                                                   "severity": severity, "requires_review": bool(reasons)},
                             producer=self.name)
        log.info("case %s: risk %d (%s)%s", case_id, score, severity, " - review required" if reasons else "")
        return {"assessment_id": aid, "score": score, "severity": severity, "factors": factors, "review_reasons": reasons}

    def process(self, limit: int = 100) -> int:
        with self.pool.connection() as conn, conn.transaction():
            msgs = self.bus.poll(conn, self.name, INVESTIGATION_COMPLETED, limit)
            for m in msgs:
                self.assess(conn, m.payload["case_id"], m.payload["investigation_id"])
            if msgs:
                self.bus.commit(conn, self.name, INVESTIGATION_COMPLETED, msgs[-1].id)
            return len(msgs)

    def run(self, idle_sleep: float = 2.0) -> None:
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: self.stop_event.set())
        log.info("risk agent started")
        while not self.stop_event.is_set():
            try:
                n = self.process()
            except Exception:
                log.exception("risk cycle failed; retrying")
                n = 0
            if n == 0:
                self.stop_event.wait(idle_sleep)
        log.info("risk agent stopped")

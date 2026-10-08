"""End-to-end validation of the live pipeline (steps 1-12) against explicit invariants.

    netsentinel e2e [--flows 400] [--seed N] [--timeout 1800]

Uses an ephemeral ingest key (created and revoked by the replay tool) plus a few deliberately
malformed flows, waits until every case created by this run is ticketed, then checks each step.
Writes artifacts/e2e/<run>.json and exits non-zero if any invariant fails.
"""

import getpass
import json
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx

from . import db, replay
from .ml.data import ROOT
from .security import api_keys

TERMINAL = ("ticketed", "closed")


def _malformed(base_url: str, pool) -> tuple[str, dict]:
    key = api_keys.generate()
    with pool.connection() as c:
        api_keys.register(c, key_id=api_keys.parse_key_id(key), sha256_hex=api_keys.digest(key).hex(),
                          name="e2e malformed (ephemeral)", scopes=["ingest:write"], created_by=getpass.getuser(),
                          expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    flows = [{"event_id": "bad-1", "features": {"Protocol": "tcp"}},
             {"event_id": "bad-2", "features": {"Dst Port": 70000, "Protocol": 6}},
             {"event_id": "bad-3", "features": {"Flow Duration": 5}}]
    try:
        r = httpx.post(f"{base_url}/v1/flows", json={"source": "cicflowmeter", "flows": flows},
                       headers={"Authorization": f"Bearer {key}"}, timeout=30)
        r.raise_for_status()
        # negative auth checks against the live API
        checks = {
            "no_key_401": httpx.get(f"{base_url}/v1/whoami", timeout=10).status_code == 401,
            "wrong_scope_403": httpx.get(f"{base_url}/v1/flows/{uuid.uuid4()}",
                                         headers={"Authorization": f"Bearer {key}"}, timeout=10).status_code == 403,
        }
    finally:
        with pool.connection() as c:
            api_keys.revoke(c, api_keys.parse_key_id(key), reason="e2e done", actor=getpass.getuser())
    return api_keys.parse_key_id(key), checks


def run(*, base_url: str, flows: int, seed: int, timeout: float) -> dict:
    started = datetime.now(timezone.utc)
    pool = db.make_pool(max_size=2)
    try:
        rep = replay.run(base_url=base_url, limit=flows, seed=seed, batch_size=250, rate=0, timeout=300, pool=pool)
        bad_key, auth_checks = _malformed(base_url, pool)
        keys = [rep["key_id"], bad_key]

        # Wait stage by stage; "nothing pending" only counts once the earlier stages have finished,
        # otherwise an empty result (no cases yet) would look like success.
        deadline = time.monotonic() + timeout
        with pool.connection() as c:
            while True:
                unprocessed = c.execute("SELECT count(*) FROM flow_events WHERE key_id = ANY(%s) AND status = 'received'",
                                        (keys,)).fetchone()[0]
                uncorrelated = c.execute(
                    "SELECT count(*) FROM detections d JOIN flow_events f USING (event_id) "
                    "LEFT JOIN case_events ce USING (event_id) WHERE f.key_id = ANY(%s) AND d.is_attack AND ce.case_id IS NULL",
                    (keys,)).fetchone()[0]
                cases = c.execute(
                    "SELECT DISTINCT ce.case_id, cs.status FROM flow_events f JOIN case_events ce USING (event_id) "
                    "JOIN cases cs ON cs.case_id = ce.case_id WHERE f.key_id = ANY(%s)", (keys,)).fetchall()
                pending = [cid for cid, st in cases if st not in TERMINAL]
                if (unprocessed == 0 and uncorrelated == 0 and cases and not pending) or time.monotonic() > deadline:
                    break
                time.sleep(10)
            case_ids = [cid for cid, _ in cases]
            q = lambda sql, p=(): c.execute(sql, p).fetchall()
            flow_status = dict(q("SELECT status, count(*) FROM flow_events WHERE key_id = ANY(%s) GROUP BY 1", (keys,)))
            rejects = dict(q("SELECT client_event_id, reject_reason FROM flow_events WHERE key_id = %s", (bad_key,)))
            unassigned = q("SELECT count(*) FROM detections d JOIN flow_events f USING (event_id) "
                           "LEFT JOIN case_events ce USING (event_id) WHERE f.key_id = %s AND d.is_attack AND ce.case_id IS NULL",
                           (rep["key_id"],))[0][0]
            inv = q("SELECT DISTINCT ON (case_id) case_id, llm_status, llm_model, jsonb_array_length(guard_findings), duration_ms "
                    "FROM investigations WHERE case_id = ANY(%s) ORDER BY case_id, created_at DESC", (case_ids,))
            risk = q("SELECT DISTINCT ON (case_id) case_id, score, severity, requires_review FROM risk_assessments "
                     "WHERE case_id = ANY(%s) ORDER BY case_id, created_at DESC", (case_ids,))
            acts = q("SELECT count(*), count(*) FILTER (WHERE NOT reversible), count(*) FILTER (WHERE decided_by IS NOT NULL), "
                     "count(*) FILTER (WHERE disruptive) FROM response_actions WHERE case_id = ANY(%s)", (case_ids,))[0]
            tickets = q("SELECT t.ticket_id, t.priority, t.status, (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(t.summary) k), "
                        "extract(epoch FROM t.created_at - cs.created_at) FROM tickets t JOIN cases cs USING (case_id) "
                        "WHERE t.case_id = ANY(%s)", (case_ids,))
            lat = q("SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM d.scored_at - f.received_at)), "
                    "percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM d.scored_at - f.received_at)) "
                    "FROM detections d JOIN flow_events f USING (event_id) WHERE f.key_id = %s", (rep["key_id"],))[0]
    finally:
        pool.close()

    journal = subprocess.run(["journalctl", "-u", "netsentinel-*", "--since", started.strftime("%Y-%m-%d %H:%M:%S UTC"),
                              "--no-pager", "-o", "cat"], capture_output=True, text=True).stdout
    errors = [l for l in journal.splitlines() if any(w in l for w in ("Traceback", " ERROR ", "Permission denied",
                                                                       "Operation not permitted"))]
    det = rep["detection"]
    llm = {}
    for _, status, *_ in inv:
        llm[status] = llm.get(status, 0) + 1
    sections = {"VERIFIED TELEMETRY", "MODEL OUTPUT", "LLM ANALYSIS", "RISK", "RECOMMENDATION"}
    checks = {
        "1_ingest_all_accepted": rep["send"]["accepted"] == flows,
        "2_malformed_rejected_with_reason": len(rejects) == 3 and all(rejects.values()),
        "2_auth_no_key_401": auth_checks["no_key_401"],
        "2_auth_wrong_scope_403": auth_checks["wrong_scope_403"],
        "6_all_valid_flows_scored": flow_status.get("scored") == flows and flow_status.get("received", 0) == 0,
        "6_attack_recall_ge_0.99": (det["attack_recall"] or 0) >= 0.99,
        "6_false_positive_rate_le_0.005": (det["false_positive_rate"] or 0) <= 0.005,
        "7_every_attack_in_a_case": unassigned == 0,
        "8_every_case_investigated": len(inv) == len(case_ids) > 0,
        "8_llm_ran_under_sandbox": llm.get("ok", 0) > 0,
        "8_no_guard_rejections": llm.get("guard_rejected", 0) == 0,
        "9_every_case_risk_scored": len(risk) == len(case_ids) > 0,
        "10_actions_proposed": acts[0] > 0,
        "10_actions_reversible": acts[1] == 0,
        "10_no_action_decided_by_machine": acts[2] == 0,
        "7_cases_created": len(case_ids) > 0,
        "11_every_case_ticketed": len(tickets) == len(case_ids) > 0 and not pending,
        "11_tickets_have_all_sections": bool(tickets) and all(set(t[3]) == sections for t in tickets),
        "ops_no_errors_in_service_logs": not errors,
    }
    report = {
        "run_started": started.isoformat(), "replay_run": rep["run_id"], "flows": flows, "seed": seed,
        "checks": checks, "passed": all(checks.values()),
        "detection": {k: det[k] for k in ("confusion_matrix", "attack_recall", "false_positive_rate", "latency_seconds")},
        "detection_latency_p50_p95_s": [round(float(x or 0), 3) for x in lat],
        "malformed_reject_reasons": rejects,
        "cases": len(case_ids), "still_pending": len(pending),
        "investigations": llm, "claude_ms": sorted(int(r[4] or 0) for r in inv),
        "risk": sorted(({"score": r[1], "severity": r[2], "review": r[3]} for r in risk), key=lambda r: -r["score"]),
        "response_actions": {"total": acts[0], "disruptive": acts[3], "irreversible": acts[1], "machine_decided": acts[2]},
        "tickets": [{"ticket": t[0], "priority": t[1], "status": t[2], "case_to_ticket_s": round(float(t[4]), 1)} for t in tickets],
        "log_errors": errors[:20],
    }
    out = ROOT / "artifacts" / "e2e"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{rep['run_id']}.json").write_text(json.dumps(report, indent=2, default=str))
    return report

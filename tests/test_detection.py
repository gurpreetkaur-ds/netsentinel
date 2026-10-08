import hashlib
import math
import shutil
import uuid

import numpy as np
import pandas as pd
import psycopg
import pytest
from fastapi.testclient import TestClient

from netsentinel import bus as busmod
from netsentinel import registry
from netsentinel.agents.detection import DetectionAgent
from netsentinel.api.app import create_app
from netsentinel.ml import data, schema
from netsentinel.pipeline.features import extract
from netsentinel.security import api_keys

V1 = "artifacts/v1/detector.joblib"
needs_model = pytest.mark.skipif(not (data.ROOT / V1).exists(), reason="train v1 first")


# ── steps 2-4 ──────────────────────────────────────────────────────────────────────────────────
def full_flow(value=1.0):
    return {f: value for f in schema.FEATURES}


def test_extract_full_flow_in_schema_order():
    x = extract({**full_flow(), "Dst Port": 443})
    assert x.reject_reason is None and x.missing == 0
    assert x.vector[schema.FEATURES.index("Dst Port")] == 443


def test_extract_accepts_original_cicflowmeter_names_and_ignores_labels():
    flow = full_flow()
    flow["Destination Port"] = flow.pop("Dst Port")
    flow["Label"] = "BENIGN"
    flow["Attempted Category"] = 3
    x = extract(flow)
    assert x.reject_reason is None and x.ignored_fields == 2
    assert x.vector[schema.FEATURES.index("Dst Port")] == 1.0


@pytest.mark.parametrize("patch,reason", [
    ({"Protocol": "tcp"}, "non_numeric_feature:Protocol"),
    ({"Protocol": True}, "non_numeric_feature:Protocol"),
    ({"Dst Port": 70000}, "out_of_range:Dst Port"),
    ({"dst_port": 80}, "ambiguous_feature:Dst Port"),
])
def test_extract_rejections(patch, reason):
    assert extract({**full_flow(), **patch}).reject_reason == reason


def test_extract_missing_and_non_finite():
    flow = full_flow()
    flow["Flow Bytes/s"] = None
    flow["Flow Packets/s"] = math.inf
    x = extract(flow)
    assert x.reject_reason is None and x.missing == 2
    sparse = {f: 1.0 for f in schema.FEATURES[:10]}
    assert extract(sparse).reject_reason.startswith("too_many_missing_features")


# ── step 7 bus ─────────────────────────────────────────────────────────────────────────────────
def test_bus_offsets_and_uncommitted_messages(pool):
    bus, consumer = busmod.PostgresBus(), "c-" + uuid.uuid4().hex[:8]
    topic = "test." + "".join(chr(97 + int(c, 16)) for c in uuid.uuid4().hex[:10])
    with pool.connection() as a, pool.connection() as b:
        with a.transaction():
            first = bus.publish(a, topic, {"n": 1}, producer="t")
        with b.transaction():                       # publisher still in flight ...
            bus.publish(b, topic, {"n": 2}, producer="t")
            assert [m.payload["n"] for m in bus.poll(a, consumer, topic)] == [1]   # ... is not visible yet
        msgs = bus.poll(a, consumer, topic)
        assert [m.payload["n"] for m in msgs] == [1, 2]
        bus.commit(a, consumer, topic, first)
        assert [m.payload["n"] for m in bus.poll(a, consumer, topic)] == [2]


# ── step 5 registry / model check ──────────────────────────────────────────────────────────────
@needs_model
def test_registry_lifecycle_requires_human_approval(conn):
    mid = "t-" + uuid.uuid4().hex[:8]
    registry.register(conn, mid, V1, actor="pytest")
    with pytest.raises(ValueError):
        registry.activate(conn, mid, actor="pytest")
    registry.approve(conn, mid, actor="human")
    registry.activate(conn, mid, actor="human")
    assert registry.check_and_load(conn, actor="pytest").model_id == mid
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("UPDATE models SET sha256 = %s WHERE model_id = %s", ("0" * 64, mid))
    assert conn.execute("SELECT count(*) FROM models WHERE status = 'active'").fetchone()[0] == 1


def test_registry_refuses_paths_outside_artifacts(conn):
    for path in ("../../etc/passwd", "/etc/passwd", "netsentinel/cli.py"):
        with pytest.raises(registry.ModelCheckFailed):
            registry.register(conn, "t-" + uuid.uuid4().hex[:8], path, actor="pytest")


@needs_model
def test_model_check_detects_tampering(conn):
    tmp_dir = data.ROOT / "artifacts" / ("test-" + uuid.uuid4().hex[:8])
    tmp_dir.mkdir()
    try:
        copy = tmp_dir / "detector.joblib"
        shutil.copy(data.ROOT / V1, copy)
        mid = "t-" + uuid.uuid4().hex[:8]
        registry.register(conn, mid, str(copy.relative_to(data.ROOT)), actor="pytest")
        registry.approve(conn, mid, actor="human")
        registry.activate(conn, mid, actor="human")
        with copy.open("ab") as f:
            f.write(b"tampered")
        with pytest.raises(registry.ModelCheckFailed, match="hash does not match"):
            registry.check_and_load(conn, actor="pytest")
        n = conn.execute("SELECT count(*) FROM model_events WHERE model_id = %s AND event = 'check_failed'",
                         (mid,)).fetchone()[0]
        assert n == 1
    finally:
        shutil.rmtree(tmp_dir)


# ── steps 2-7 end to end ───────────────────────────────────────────────────────────────────────
def real_flows(n_each=20):
    df = pd.read_parquet(data.CACHE / "wednesday.parquet")
    picks = pd.concat([df[df["Label"] == "BENIGN"].sample(n_each, random_state=1),
                       df[df["Label"] == "DoS Hulk"].sample(n_each, random_state=1)])
    flows = []
    for _, row in picks.iterrows():
        feats = {f: (float(row[f]) if np.isfinite(float(row[f])) else None) for f in schema.FEATURES}
        feats["Label"] = "BENIGN"  # a lying label must not matter
        flows.append({"event_id": f"t-{uuid.uuid4().hex[:12]}", "features": feats, "_truth": row["Label"]})
    return flows


@needs_model
def test_detection_agent_end_to_end(pool):
    key = api_keys.generate()
    with pool.connection() as c:
        api_keys.register(c, key_id=api_keys.parse_key_id(key), sha256_hex=hashlib.sha256(key.encode()).hexdigest(),
                          name="e2e", scopes=["ingest:write", "events:read"], created_by="pytest")
        mid = "e2e-" + uuid.uuid4().hex[:8]
        registry.register(c, mid, V1, actor="pytest")
        registry.approve(c, mid, actor="human")
        registry.activate(c, mid, actor="human")
        c.execute("UPDATE flow_events SET status = 'rejected', reject_reason = 'test isolation' WHERE status = 'received'")

    flows = real_flows()
    truth = {f["event_id"]: f.pop("_truth") for f in flows}
    bad = {"event_id": "t-bad-" + uuid.uuid4().hex[:6], "features": {"Protocol": "udp"}}
    with TestClient(create_app(pool=pool)) as client:
        r = client.post("/v1/flows", json={"source": "cicflowmeter", "flows": flows + [bad]},
                        headers={"Authorization": f"Bearer {key}"})
        assert r.status_code == 202
        ids = {e["client_event_id"]: e["event_id"] for e in r.json()["events"]}

    agent = DetectionAgent(pool, batch_size=1000)
    stats = agent.process_batch()
    assert stats == {"scored": 40, "rejected": 1, "attacks": stats["attacks"], "blocked": False}

    with pool.connection() as c:
        rows = dict(c.execute("SELECT f.client_event_id, d.is_attack FROM detections d JOIN flow_events f USING (event_id) "
                              "WHERE f.event_id = ANY(%s)", ([uuid.UUID(i) for i in ids.values()],)).fetchall())
        correct = sum(rows[e] == (truth[e] != "BENIGN") for e in truth)
        assert correct >= 38, f"only {correct}/40 correct"
        assert c.execute("SELECT status, reject_reason FROM flow_events WHERE event_id = %s",
                         (uuid.UUID(ids[bad["event_id"]]),)).fetchone() == ("rejected", "non_numeric_feature:Protocol")
        msgs = busmod.PostgresBus().poll(c, "e2e-" + uuid.uuid4().hex[:6], busmod.DETECTION_ATTACK, limit=10_000)
        ours = [m for m in msgs if m.payload["event_id"] in {ids[e] for e in truth}]
        assert len(ours) == stats["attacks"]
        assert all(m.payload["provenance"] == "MODEL OUTPUT" and m.payload["model_id"] == mid for m in ours)
        with pytest.raises(psycopg.errors.RaiseException):
            c.execute("UPDATE detections SET is_attack = false WHERE model_id = %s", (mid,))
        hb = c.execute("SELECT status FROM agent_heartbeats WHERE agent = 'detection'").fetchone()
        assert hb == ("ok",)


@needs_model
def test_agent_fails_closed_without_valid_model(pool):
    with pool.connection() as c:
        c.execute("UPDATE models SET status = 'retired' WHERE status = 'active'")
        c.execute("INSERT INTO flow_events (batch_id, key_id, source, flow) "
                  "SELECT gen_random_uuid(), key_id, 'cicflowmeter', '{}'::jsonb FROM api_keys LIMIT 1")
    stats = DetectionAgent(pool).process_batch()
    assert stats["blocked"] and stats["scored"] == 0
    with pool.connection() as c:
        assert c.execute("SELECT count(*) FROM flow_events WHERE status = 'received'").fetchone()[0] >= 1
        assert c.execute("SELECT status FROM agent_heartbeats WHERE agent = 'detection'").fetchone() == ("degraded",)


@needs_model
def test_rollback_reactivates_a_previously_active_model(conn):
    a, b = "rb-a-" + uuid.uuid4().hex[:6], "rb-b-" + uuid.uuid4().hex[:6]
    for m in (a, b):
        registry.register(conn, m, V1, actor="pytest")
        registry.approve(conn, m, actor="human")
    registry.activate(conn, a, actor="human")
    registry.activate(conn, b, actor="human")          # a is now retired
    registry.activate(conn, a, actor="human")          # rollback
    assert conn.execute("SELECT model_id FROM models WHERE status = 'active'").fetchone()[0] == a
    c = "rb-c-" + uuid.uuid4().hex[:6]
    registry.register(conn, c, V1, actor="pytest")
    with pytest.raises(ValueError):                    # a never-approved candidate still can't go live
        registry.activate(conn, c, actor="human")


@needs_model
def test_shadow_flows_are_scored_but_never_alerted(pool):
    key = api_keys.generate()
    with pool.connection() as c:
        api_keys.register(c, key_id=api_keys.parse_key_id(key), sha256_hex=hashlib.sha256(key.encode()).hexdigest(),
                          name="shadow", scopes=["ingest:write"], created_by="pytest")
        mid = "sh-" + uuid.uuid4().hex[:8]
        registry.register(c, mid, V1, actor="pytest")
        registry.approve(c, mid, actor="human")
        registry.activate(c, mid, actor="human")
    flows = real_flows(10)
    for f in flows:
        f.pop("_truth")
    with TestClient(create_app(pool=pool)) as client:
        assert client.post("/v1/flows", json={"source": "cicflowmeter", "mode": "shadow", "flows": flows},
                           headers={"Authorization": f"Bearer {key}"}).status_code == 202
    DetectionAgent(pool, batch_size=1000).process_batch()
    with pool.connection() as c:
        kid = api_keys.parse_key_id(key)
        scored, attacks = c.execute("SELECT count(*), count(*) FILTER (WHERE d.is_attack) FROM detections d "
                                    "JOIN flow_events f USING (event_id) WHERE f.key_id = %s", (kid,)).fetchone()
        ids = [str(r[0]) for r in c.execute("SELECT event_id FROM flow_events WHERE key_id = %s", (kid,))]
        msgs = busmod.PostgresBus().poll(c, "shadow-check-" + uuid.uuid4().hex[:6], busmod.DETECTION_ATTACK, 100_000)
    assert scored == 20 and attacks >= 9                     # half are DoS Hulk: detected ...
    assert not [m for m in msgs if m.payload["event_id"] in ids]   # ... but never published as alerts

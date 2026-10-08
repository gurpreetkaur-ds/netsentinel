import hashlib
import logging
import uuid

import pytest
from fastapi.testclient import TestClient

from netsentinel.api.app import create_app
from netsentinel.security import api_keys


def _key(pool, scopes=("ingest:write", "events:read")):
    key = api_keys.generate()
    with pool.connection() as c:
        api_keys.register(c, key_id=api_keys.parse_key_id(key), sha256_hex=hashlib.sha256(key.encode()).hexdigest(),
                          name="api-test", scopes=scopes, created_by="pytest")
    return key


@pytest.fixture
def client(pool):
    with TestClient(create_app(pool=pool)) as c:
        yield c


def H(key):
    return {"Authorization": f"Bearer {key}"}


FLOW = {"Dst Port": 80, "Protocol": 6, "Flow Duration": 1234, "Flow Bytes/s": None, "Label": "BENIGN"}


def test_health_is_public(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert r.headers["cache-control"] == "no-store" and "x-request-id" in r.headers


def test_whoami_requires_key_and_never_echoes_it(client, pool):
    assert client.get("/v1/whoami").status_code == 401
    assert client.get("/v1/whoami", headers=H("nsk_bad")).status_code == 401
    key = _key(pool)
    for headers in (H(key), {"X-API-Key": key}):
        r = client.get("/v1/whoami", headers=headers)
        assert r.status_code == 200 and r.json()["key_id"] == api_keys.parse_key_id(key)
        assert key.split("_", 2)[2] not in r.text


def test_ingest_and_idempotency(client, pool):
    key = _key(pool)
    body = {"source": "cicflowmeter", "flows": [{"event_id": "a1", "features": FLOW}, {"features": FLOW}]}
    r = client.post("/v1/flows", json=body, headers=H(key))
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 2 and r.json()["duplicates"] == 0
    r2 = client.post("/v1/flows", json={"source": "cicflowmeter", "flows": [{"event_id": "a1", "features": FLOW}]},
                     headers=H(key))
    assert r2.json()["accepted"] == 0 and r2.json()["duplicates"] == 1

    eid = next(e["event_id"] for e in r.json()["events"] if e["client_event_id"] == "a1")
    got = client.get(f"/v1/flows/{eid}", headers=H(key))
    assert got.status_code == 200 and got.json()["flow"] == FLOW and got.json()["status"] == "received"


def test_scopes_and_tenant_isolation(client, pool):
    reader = _key(pool, scopes=("events:read",))
    writer = _key(pool, scopes=("ingest:write",))
    body = {"source": "cicflowmeter", "flows": [{"features": FLOW}]}
    assert client.post("/v1/flows", json=body, headers=H(reader)).status_code == 403
    eid = client.post("/v1/flows", json=body, headers=H(writer)).json()["events"][0]["event_id"]
    assert client.get(f"/v1/flows/{eid}", headers=H(writer)).status_code == 403
    # another key can't see it, and can't tell it exists
    assert client.get(f"/v1/flows/{eid}", headers=H(_key(pool))).status_code == 404
    assert client.get(f"/v1/flows/{uuid.uuid4()}", headers=H(_key(pool))).status_code == 404


@pytest.mark.parametrize("body", [
    {"source": "pcap", "flows": [{"features": FLOW}]},
    {"source": "cicflowmeter", "flows": []},
    {"source": "cicflowmeter", "flows": [{"features": FLOW, "extra": 1}]},
    {"source": "cicflowmeter", "flows": [{"features": {"x": {"nested": 1}}}]},
    {"source": "cicflowmeter", "flows": [{"event_id": "bad id!", "features": FLOW}]},
    {"source": "cicflowmeter", "flows": [{"features": {f"f{i}": 1 for i in range(201)}}]},
])
def test_invalid_batches_rejected(client, pool, body):
    r = client.post("/v1/flows", json=body, headers=H(_key(pool)))
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_request"


def test_non_finite_numbers_rejected(client, pool):
    raw = '{"source":"cicflowmeter","flows":[{"features":{"Flow Bytes/s": Infinity}}]}'
    r = client.post("/v1/flows", content=raw, headers={**H(_key(pool)), "Content-Type": "application/json"})
    assert r.status_code == 422


def test_batch_and_body_limits(client, pool, monkeypatch):
    monkeypatch.setenv("NETSENTINEL_MAX_BATCH", "3")
    monkeypatch.setenv("NETSENTINEL_MAX_BODY_BYTES", "2000")
    key = _key(pool)
    with TestClient(create_app(pool=pool)) as c:
        many = {"source": "cicflowmeter", "flows": [{"features": {"a": 1}}] * 4}
        assert c.post("/v1/flows", json=many, headers=H(key)).status_code == 413
        big = {"source": "cicflowmeter", "flows": [{"features": {"s": "x" * 250, **{f"key_{i}": i for i in range(190)}}}]}
        assert c.post("/v1/flows", json=big, headers=H(key)).status_code == 413


def test_failed_auth_lockout(client):
    for _ in range(20):
        assert client.get("/v1/whoami", headers=H("nsk_nope")).status_code == 401
    r = client.get("/v1/whoami", headers=H("nsk_nope"))
    assert r.status_code == 429 and r.headers["retry-after"] == "300"


def test_key_never_logged(client, pool, caplog):
    key = _key(pool)
    kid = api_keys.parse_key_id(key)
    with caplog.at_level(logging.DEBUG):
        client.get("/v1/whoami", headers=H(key))
        client.get("/v1/whoami", headers=H(f"nsk_{kid}_" + "B" * 43))
    assert key.split("_", 2)[2] not in caplog.text and "B" * 43 not in caplog.text

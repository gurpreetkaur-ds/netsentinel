import threading
import uuid

import pytest
from fastapi.testclient import TestClient

from netsentinel import registry, replay
from netsentinel.agents.detection import DetectionAgent
from netsentinel.api.app import create_app
from netsentinel.ml import data

pytestmark = pytest.mark.skipif(not (data.ROOT / "artifacts/v1/detector.joblib").exists(), reason="train v1 first")


def test_replay_end_to_end(pool):
    with pool.connection() as c:
        mid = "replay-" + uuid.uuid4().hex[:8]
        registry.register(c, mid, "artifacts/v1/detector.joblib", actor="pytest")
        registry.approve(c, mid, actor="human")
        registry.activate(c, mid, actor="human")
    agent = DetectionAgent(pool, batch_size=200)
    worker = threading.Thread(target=agent.run, kwargs={"idle_sleep": 0.2}, daemon=True)
    worker.start()
    try:
        result = replay.run(base_url="http://test", limit=600, seed=1, batch_size=250, rate=0, timeout=60,
                            client=TestClient(create_app(pool=pool)), pool=pool)
    finally:
        agent.stop_event.set()
        worker.join(10)
    det = result["detection"]
    assert result["send"]["accepted"] == 600 and det["pending_after_timeout"] == 0
    assert det["status"] == {"scored": 600}
    assert det["attack_recall"] >= 0.99 and det["false_positive_rate"] <= 0.01
    with pool.connection() as c:   # the ephemeral key was revoked
        assert c.execute("SELECT revoked_at IS NOT NULL FROM api_keys WHERE key_id = %s",
                         (result["key_id"],)).fetchone() == (True,)
    assert (data.ROOT / "artifacts" / "replay" / f"{result['run_id']}.json").exists()

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from netsentinel.agents.detection import window_features
from netsentinel.api.app import create_app
from netsentinel.ml import data, schema, windows
from netsentinel.security import api_keys

SLICE = data.ROOT / "data/interim/distrinet/friday.parquet"


@pytest.mark.skipif(not SLICE.exists(), reason="distrinet data not prepared")
def test_live_window_features_equal_training_features(pool):
    df = pd.read_parquet(SLICE)
    t0 = pd.Timestamp("2017-07-07 16:56:00")   # Friday port-scan period (timestamps are UTC)
    df = df[(df["Timestamp"] >= t0) & (df["Timestamp"] < t0 + pd.Timedelta(minutes=2))]
    scanner = df.loc[df["Label"] == "Portscan", "Src IP"].mode()[0]
    # the scanner's flows plus other sources' flows, so windows must also keep sources apart
    df = pd.concat([df[df["Src IP"] == scanner].sort_values("Timestamp").head(600),
                    df[df["Src IP"] != scanner].head(200)]).reset_index(drop=True)
    expected = windows.from_frame(df)

    key = api_keys.generate()
    with pool.connection() as c:
        api_keys.register(c, key_id=api_keys.parse_key_id(key), sha256_hex=hashlib.sha256(key.encode()).hexdigest(),
                          name="parity", scopes=["ingest:write"], created_by="pytest")
    run = api_keys.parse_key_id(key)
    flows = []
    for i, r in df.iterrows():
        flows.append({"event_id": f"par-{run}-{i}", "observed_at": r["Timestamp"].tz_localize("UTC").isoformat(),
                      "context": {"src_ip": r["Src IP"], "dst_ip": r["Dst IP"], "src_port": int(r["Src Port"]),
                                  "dst_port": int(r["Dst Port"]), "protocol": int(r["Protocol"])},
                      "features": {f: (float(r[f]) if np.isfinite(float(r[f])) else None) for f in schema.FEATURES}})
    with TestClient(create_app(pool=pool)) as client:
        for s in range(0, len(flows), 400):
            assert client.post("/v1/flows", json={"source": "cicflowmeter", "flows": flows[s:s + 400]},
                               headers={"Authorization": f"Bearer {key}"}).status_code == 202
    with pool.connection() as c:
        ids = dict(c.execute("SELECT client_event_id, event_id FROM flow_events WHERE key_id = %s", (run,)).fetchall())
        got = window_features(c, [ids[f"par-{run}-{i}"] for i in range(len(df))])
    assert np.isfinite(got).all()
    np.testing.assert_allclose(got, expected, rtol=1e-5, atol=1e-5)
    assert got[:, windows.WINDOW_FEATURES.index("src_win_flows")].max() > 50   # a busy source really is exercised

"""Replay tool: streams held-out CICIDS-2017 flows through the real API, then measures what the
pipeline detected against ground truth that never left this process.

The run uses an ephemeral API key (ingest:write, 1-day expiry) that exists only in memory and is
revoked when the run ends. Nothing secret is stored.
"""

import getpass
import ipaddress
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from . import db
from .ml import data, schema, taxonomy, train_v1
from .ml import windows as windows_mod
from .security import api_keys

log = logging.getLogger(__name__)


def e1_test_sample(limit: int, seed: int) -> pd.DataFrame:
    """Rows from v1's held-out E1 test split (never seen in training), sampled keeping the class mix."""
    D = train_v1.prepare()
    idx = np.arange(len(D["X"]))
    _, te = train_test_split(idx, test_size=0.2, stratify=D["label"], random_state=train_v1.SEED)
    rng = np.random.default_rng(seed)
    pick = rng.choice(te, size=min(limit, len(te)), replace=False)
    out = pd.DataFrame(D["X"][pick], columns=schema.FEATURES)
    out["_label"], out["_family"] = D["label"][pick], D["family"][pick]
    for i, col in enumerate(("_src_ip", "_dst_ip", "_src_port", "_dst_port", "_protocol")):
        out[col] = D["context"][pick, i]
    return out


def _flows(df: pd.DataFrame, run_id: str) -> tuple[list[dict], dict]:
    flows, truth = [], {}
    feats = df[list(schema.FEATURES)].to_numpy()
    for i, row in enumerate(feats):
        eid = f"replay-{run_id}-{i:07d}"
        flows.append({"event_id": eid,
                      "context": {"src_ip": str(ipaddress.IPv4Address(int(df["_src_ip"].iat[i]))),
                                  "dst_ip": str(ipaddress.IPv4Address(int(df["_dst_ip"].iat[i]))),
                                  "src_port": int(df["_src_port"].iat[i]), "dst_port": int(df["_dst_port"].iat[i]),
                                  "protocol": int(df["_protocol"].iat[i])},
                      "features": {f: (None if np.isnan(v) else float(v)) for f, v in zip(schema.FEATURES, row)}})
        truth[eid] = (df["_label"].iat[i], df["_family"].iat[i])
    return flows, truth


def time_slice(day: str, start_utc: str, minutes: float, warmup_s: float = 60,
               not_before: pd.Timestamp | None = None) -> tuple[list[dict], dict]:
    """Every flow of a real capture interval (corrected CICIDS-2017, full timestamps), in the order the
    flows ended, i.e. the order a live sensor would deliver them. Times are shifted so the slice ends
    now, keeping their spacing; per-source windows then mean what they meant in training.

    The `warmup_s` before the interval is sent too, so every measured flow's 60 s window is already full
    (as on a continuously running sensor); warm-up flows are not in the returned ground truth.
    `not_before` (UTC) moves the slice later if needed, so it never overlaps flows already stored:
    overlapping replays would share per-source windows, which real traffic never does."""
    df = pd.read_parquet(data.ROOT / "data/interim/distrinet" / f"{day}.parquet")
    t0 = pd.Timestamp(f"{df['Timestamp'].iloc[0].date()} {start_utc}")
    df = df[(df["Timestamp"] >= t0 - pd.Timedelta(seconds=warmup_s))
            & (df["Timestamp"] < t0 + pd.Timedelta(minutes=minutes))].copy()
    df["_end"] = df["Timestamp"] + pd.to_timedelta(df["Flow Duration"].fillna(0), unit="us")
    df = df.sort_values("_end").reset_index(drop=True)
    shift = pd.Timestamp.now(tz="UTC").tz_localize(None) - df["_end"].max()
    if not_before is not None and df["Timestamp"].min() + shift < not_before:
        shift = not_before - df["Timestamp"].min()
    run_id = uuid.uuid4().hex[:8]
    observed = (df["Timestamp"] + shift).dt.tz_localize("UTC")
    feats = df[list(schema.FEATURES)].to_numpy(dtype=np.float64)
    flows, truth = [], {}
    for i in range(len(df)):
        eid = f"slice-{run_id}-{i:07d}"
        flows.append({"event_id": eid, "observed_at": observed.iat[i].isoformat(),
                      "context": {"src_ip": df["Src IP"].iat[i], "dst_ip": df["Dst IP"].iat[i],
                                  "src_port": int(df["Src Port"].iat[i]), "dst_port": int(df["Dst Port"].iat[i]),
                                  "protocol": int(df["Protocol"].iat[i])},
                      "features": {f: (float(v) if np.isfinite(v) else None) for f, v in zip(schema.FEATURES, feats[i])}})
        if df["Timestamp"].iat[i] >= t0:            # warm-up flows are sent but not measured
            label = df["Label"].iat[i]
            truth[eid] = (label, taxonomy.lookup(label).family)
    return flows, truth


def _ephemeral_key(conn) -> str:
    key = api_keys.generate()
    api_keys.register(conn, key_id=api_keys.parse_key_id(key), sha256_hex=api_keys.digest(key).hex(),
                      name="replay (ephemeral)", scopes=["ingest:write"], created_by=getpass.getuser(),
                      expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    return key


def send(client: httpx.Client, key: str, flows: list[dict], *, batch_size: int, rate: float) -> dict:
    sent = accepted = 0
    started = time.monotonic()
    for start in range(0, len(flows), batch_size):
        batch = flows[start:start + batch_size]
        r = client.post("/v1/flows", json={"source": "cicflowmeter", "flows": batch},
                        headers={"Authorization": f"Bearer {key}"})
        if r.status_code != 202:
            raise RuntimeError(f"API returned {r.status_code}: {r.json().get('error', {}).get('code')}")
        sent += len(batch)
        accepted += r.json()["accepted"]
        if rate > 0:  # pace to `rate` flows/second
            ahead = sent / rate - (time.monotonic() - started)
            if ahead > 0:
                time.sleep(ahead)
    return {"sent": sent, "accepted": accepted, "seconds": round(time.monotonic() - started, 2)}


def wait_and_measure(pool, key_id: str, truth: dict, *, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    with pool.connection() as conn:
        while True:
            pending = conn.execute("SELECT count(*) FROM flow_events WHERE key_id = %s AND status = 'received'",
                                   (key_id,)).fetchone()[0]
            if pending == 0 or time.monotonic() > deadline:
                break
            time.sleep(1)
        rows = conn.execute(
            "SELECT f.client_event_id, f.status, f.reject_reason, d.is_attack, d.family, d.attack_type, "
            "extract(epoch FROM d.scored_at - f.received_at) "
            "FROM flow_events f LEFT JOIN detections d USING (event_id) WHERE f.key_id = %s", (key_id,)).fetchall()
    df = pd.DataFrame(rows, columns=["eid", "status", "reject_reason", "is_attack", "family", "attack_type", "latency"])
    df = df[df["eid"].isin(truth.keys())]          # measure only flows with ground truth (not warm-up)
    df["label"] = df["eid"].map(lambda e: truth[e][0])
    df["true_family"] = df["eid"].map(lambda e: truth[e][1])
    scored = df[df["status"] == "scored"]
    y, p = (scored["label"] != "BENIGN").to_numpy(), scored["is_attack"].astype(bool).to_numpy()
    caught = scored[y & p]
    named = caught[caught["family"].notna()]
    lat = scored["latency"].astype(float)
    return {
        "flows": len(df), "pending_after_timeout": int(pending),
        "status": df["status"].value_counts().to_dict(),
        "reject_reasons": df["reject_reason"].dropna().value_counts().to_dict(),
        "confusion_matrix": {"tn": int((~y & ~p).sum()), "fp": int((~y & p).sum()),
                             "fn": int((y & ~p).sum()), "tp": int((y & p).sum())},
        "attack_recall": float(p[y].mean()) if y.any() else None,
        "false_positive_rate": float(p[~y].mean()) if (~y).any() else None,
        "family_coverage": float(len(named) / len(caught)) if len(caught) else None,
        "family_accuracy_when_named": float((named["family"] == named["true_family"]).mean()) if len(named) else None,
        "missed_by_label": scored[y & ~p]["label"].value_counts().to_dict(),
        "latency_seconds": {"p50": float(lat.quantile(0.5)), "p95": float(lat.quantile(0.95)), "max": float(lat.max())}
        if len(lat) else None,
    }


def run(*, base_url: str, limit: int, seed: int, batch_size: int, rate: float, timeout: float,
        client: httpx.Client | None = None, pool=None, slice_spec: tuple[str, str, float] | None = None) -> dict:
    run_id = uuid.uuid4().hex[:8]
    own_pool = pool is None
    pool = pool or db.make_pool(max_size=2)
    try:
        if slice_spec:
            with pool.connection() as conn:
                latest = conn.execute("SELECT max(ended_at) FROM flow_events").fetchone()[0]
            gap = pd.Timedelta(seconds=windows_mod.WINDOW_SECONDS * 2)
            flows, truth = time_slice(*slice_spec, not_before=(pd.Timestamp(latest).tz_convert(None) + gap) if latest else None)
            sample = {"slice": {"day": slice_spec[0], "start_utc": slice_spec[1], "minutes": slice_spec[2]}}
        else:
            df = e1_test_sample(limit, seed)
            flows, truth = _flows(df, run_id)
            sample = {"limit": limit, "seed": seed}
        sample["labels"] = pd.Series([t[0] for t in truth.values()]).value_counts().to_dict()
        with pool.connection() as conn:
            key = _ephemeral_key(conn)
        key_id = api_keys.parse_key_id(key)
        try:
            with (client or httpx.Client(base_url=base_url, timeout=60)) as c:
                sent = send(c, key, flows, batch_size=batch_size, rate=rate)
        finally:
            with pool.connection() as conn:
                api_keys.revoke(conn, key_id, reason="replay finished", actor=getpass.getuser())
            del key
        log.info("sent %s; waiting for the Detection Agent", sent)
        result = {"run_id": run_id, "key_id": key_id, "sample": sample, "send": sent,
                  "detection": wait_and_measure(pool, key_id, truth, timeout=timeout)}
    finally:
        if own_pool:
            pool.close()
    out = data.ROOT / "artifacts" / "replay"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{run_id}.json").write_text(json.dumps(result, indent=2, default=str))
    return result

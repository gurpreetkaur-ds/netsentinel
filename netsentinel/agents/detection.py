"""Detection Agent: pipeline steps 2-7 for ingested flows.

received flow -> VALIDATE/NORMALIZE/EXTRACT -> MODEL CHECK -> INFERENCE -> detections row
             -> EVENT PUBLISH (detection.attack) for the orchestrator / Investigation Agent.

Several agents can run side by side: work is claimed with FOR UPDATE SKIP LOCKED, and each batch
(status changes, detections and published events) commits atomically. If the model check fails,
nothing is scored and flows wait in 'received'. The agent fails closed, never with a stale or
unverified model.
"""

import logging
import math
import signal
import socket
import threading

import numpy as np
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .. import bus as busmod
from .. import registry
from ..ml import schema, windows
from ..pipeline.features import extract

log = logging.getLogger(__name__)


def _num(x):
    return None if x is None or (isinstance(x, float) and math.isnan(x)) else float(x)


def window_features(conn, event_ids: list) -> np.ndarray:
    """Per-source 60 s window features for these (already ingested) flows, computed from the flows each
    source had *ended* within the window, exactly as in training (netsentinel/ml/windows.py).
    Rows without a source IP or end time get NaN, which the model treats as missing."""
    out = np.full((len(event_ids), len(windows.WINDOW_FEATURES)), np.nan, dtype=np.float32)
    rows = conn.execute(
        "WITH w AS (SELECT src_ip, min(ended_at) AS lo, max(ended_at) AS hi FROM flow_events "
        "           WHERE event_id = ANY(%s) AND src_ip IS NOT NULL AND ended_at IS NOT NULL GROUP BY src_ip) "
        "SELECT f.event_id, host(f.src_ip), host(f.dst_ip), f.dst_port, extract(epoch FROM f.ended_at), f.flow "
        "FROM flow_events f JOIN w ON f.src_ip = w.src_ip "
        " AND f.ended_at > w.lo - make_interval(secs => %s) AND f.ended_at <= w.hi "
        "WHERE f.status <> 'rejected'",
        (event_ids, windows.WINDOW_SECONDS)).fetchall()
    if not rows:
        return out
    ids = [r[0] for r in rows]
    vecs = [extract(r[5]).vector for r in rows]
    col = lambda name: np.array([v[schema.FEATURES.index(name)] if v is not None else np.nan for v in vecs])
    W = windows.compute(np.array([r[1] for r in rows], dtype=object), np.array([r[2] or "" for r in rows], dtype=object),
                        np.array([r[3] if r[3] is not None else -1 for r in rows]), np.array([float(r[4]) for r in rows]),
                        col("Total Bwd packets"), col("RST Flag Count"))
    pos = {eid: i for i, eid in enumerate(ids)}
    for i, eid in enumerate(event_ids):
        if eid in pos:
            out[i] = W[pos[eid]]
    return out


class DetectionAgent:
    name = "detection"

    def __init__(self, pool: ConnectionPool, bus: busmod.Bus | None = None, *, batch_size: int = 500):
        self.pool, self.bus, self.batch_size = pool, bus or busmod.PostgresBus(), batch_size
        self.model: registry.LoadedModel | None = None
        self.actor = f"agent:{self.name}@{socket.gethostname()}"
        self._last_check_error: str | None = None
        self.stop_event = threading.Event()

    def _heartbeat(self, conn, status: str, detail: dict) -> None:
        conn.execute("INSERT INTO agent_heartbeats (agent, status, detail) VALUES (%s, %s, %s) "
                     "ON CONFLICT (agent) DO UPDATE SET status = EXCLUDED.status, detail = EXCLUDED.detail, at = now()",
                     (self.name, status, Jsonb(detail)))

    def process_batch(self) -> dict:
        with self.pool.connection() as conn:
            try:
                self.model = registry.check_and_load(conn, actor=self.actor, current=self.model)
                self._last_check_error = None
            except registry.ModelCheckFailed as e:
                self.model = None
                if str(e) != self._last_check_error:  # publish once per distinct failure, not every poll
                    log.error("MODEL CHECK FAILED, scoring paused: %s", e)
                    with conn.transaction():
                        self.bus.publish(conn, busmod.MODEL_CHECK_FAILED, {"reason": str(e)}, producer=self.name)
                    self._last_check_error = str(e)
                self._heartbeat(conn, "degraded", {"model_check": str(e)})
                return {"blocked": True, "scored": 0, "rejected": 0, "attacks": 0}

            det, model_id = self.model.detector, self.model.model_id
            with conn.transaction():
                rows = conn.execute(
                    "SELECT event_id, flow FROM flow_events WHERE status = 'received' "
                    "ORDER BY received_at LIMIT %s FOR UPDATE SKIP LOCKED", (self.batch_size,)).fetchall()
                shadow = {r[0] for r in conn.execute(
                    "SELECT event_id FROM flow_events WHERE event_id = ANY(%s) AND shadow", ([r[0] for r in rows],))}
                valid_ids, vectors, missing, rejected = [], [], [], []
                for event_id, flow in rows:
                    x = extract(flow)
                    if x.reject_reason:
                        rejected.append((x.reject_reason, event_id))
                    else:
                        valid_ids.append(event_id); vectors.append(x.vector); missing.append(x.missing)
                if rejected:
                    conn.cursor().executemany(
                        "UPDATE flow_events SET status = 'rejected', reject_reason = %s WHERE event_id = %s", rejected)
                attacks = 0
                if valid_ids:
                    X = np.vstack(vectors)
                    if len(det.features) > len(schema.FEATURES):      # model trained with window features
                        X = np.hstack([X, window_features(conn, valid_ids)])
                    out = det.predict(X)
                    records = []
                    for eid, miss, r in zip(valid_ids, missing, out.itertuples(index=False)):
                        thr = float(r.threshold)   # per row: a v2 model may use its fallback detector
                        records.append((eid, model_id, float(r.p_attack), thr, bool(r.is_attack), r.family,
                                        _num(r.family_confidence), r.attack_type, _num(r.type_confidence), miss))
                    conn.cursor().executemany(
                        "INSERT INTO detections (event_id, model_id, p_attack, threshold, is_attack, family, "
                        "family_confidence, attack_type, type_confidence, missing_features) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", records)
                    conn.execute("UPDATE flow_events SET status = 'scored' WHERE event_id = ANY(%s)", (valid_ids,))
                    for rec in records:
                        if rec[4] and rec[0] not in shadow:      # shadow flows are scored, never alerted
                            attacks += 1
                            self.bus.publish(conn, busmod.DETECTION_ATTACK, {
                                "provenance": "MODEL OUTPUT", "event_id": str(rec[0]), "model_id": model_id,
                                "p_attack": rec[2], "threshold": rec[3], "family": rec[5], "family_confidence": rec[6],
                                "attack_type": rec[7], "type_confidence": rec[8], "missing_features": rec[9],
                            }, producer=self.name)
                stats = {"scored": len(valid_ids), "rejected": len(rejected), "attacks": attacks, "blocked": False}
                self._heartbeat(conn, "ok", {"model_id": model_id, "last_batch": stats})
        if rows:
            log.info("batch: %s", stats)
        return stats

    def run(self, idle_sleep: float = 1.0) -> None:
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: self.stop_event.set())
        log.info("detection agent started")
        while not self.stop_event.is_set():
            try:
                s = self.process_batch()
                busy = s["scored"] + s["rejected"] == self.batch_size
            except Exception:
                log.exception("batch failed; retrying")
                busy = False
            if not busy:
                # back off while the model check is failing; it is re-checked on every wake-up
                self.stop_event.wait(idle_sleep if self.model is not None else 10.0)
        with self.pool.connection() as conn:
            self._heartbeat(conn, "stopped", {})
        log.info("detection agent stopped")

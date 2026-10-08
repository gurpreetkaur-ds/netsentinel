"""Model registry and pipeline step 5 (MODEL CHECK).

A model file is a pickle, and unpickling runs code. So a model is only ever loaded after its bytes
hash to the SHA-256 recorded at registration, and only if it lives under artifacts/, is the single
active model, and was approved by a human. Lifecycle: candidate -> approved -> active -> retired.
"""

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

import joblib
import psycopg
from psycopg.types.json import Jsonb

from .ml import schema, windows
from .ml.data import ROOT

log = logging.getLogger(__name__)
ARTIFACTS = (ROOT / "artifacts").resolve()


# Feature schemas this service can compute; a model must declare one of them, with exactly its features.
KNOWN_SCHEMAS = {schema.SCHEMA_VERSION: schema.FEATURES,
                 "cicflowmeter-v2-window60": schema.FEATURES + windows.WINDOW_FEATURES}


class ModelCheckFailed(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_path(artifact_path: str) -> Path:
    p = (ROOT / artifact_path).resolve()
    if not p.is_relative_to(ARTIFACTS) or not p.is_file():
        raise ModelCheckFailed(f"model artifact must be an existing file under {ARTIFACTS}")
    return p


def _event(conn, model_id: str, event: str, actor: str, detail: dict | None = None) -> None:
    conn.execute("INSERT INTO model_events (model_id, event, actor, detail) VALUES (%s, %s, %s, %s)",
                 (model_id, event, actor, Jsonb(detail or {})))


def register(conn: psycopg.Connection, model_id: str, artifact_path: str, *, actor: str) -> dict:
    """Records a candidate. It loads the file once, as the operator who trained it, to read its metadata."""
    path = _safe_path(artifact_path)
    digest = _sha256(path)
    det = joblib.load(path)
    meta = dict(getattr(det, "metadata", {}))
    rel = str(path.relative_to(ROOT))
    with conn.transaction():
        conn.execute(
            "INSERT INTO models (model_id, artifact_path, sha256, schema_version, features, metrics, registered_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (model_id, rel, digest, det.schema_version, list(det.features),
             Jsonb({k: meta.get(k) for k in ("version", "trained_at", "sklearn", "data", "thresholds", "target_fpr")}),
             actor))
        _event(conn, model_id, "registered", actor, {"sha256": digest, "path": rel})
    return {"model_id": model_id, "sha256": digest, "schema_version": det.schema_version}


def approve(conn, model_id: str, *, actor: str) -> None:
    with conn.transaction():
        cur = conn.execute("UPDATE models SET status = 'approved', approved_by = %s, approved_at = now() "
                           "WHERE model_id = %s AND status = 'candidate'", (actor, model_id))
        if cur.rowcount != 1:
            raise ValueError(f"model {model_id!r} is not a candidate")
        _event(conn, model_id, "approved", actor)


def reject(conn, model_id: str, *, actor: str) -> None:
    with conn.transaction():
        cur = conn.execute("UPDATE models SET status = 'rejected' WHERE model_id = %s AND status = 'candidate'",
                           (model_id,))
        if cur.rowcount != 1:
            raise ValueError(f"model {model_id!r} is not a candidate")
        _event(conn, model_id, "rejected", actor)


def activate(conn, model_id: str, *, actor: str) -> None:
    """Swaps the active model atomically; the previous one is retired."""
    with conn.transaction():
        row = conn.execute("SELECT status FROM models WHERE model_id = %s AND approved_by IS NOT NULL FOR UPDATE",
                           (model_id,)).fetchone()
        # 'retired' models were approved and active before: re-activating one is the rollback path.
        if not row or row[0] not in ("approved", "retired"):
            raise ValueError(f"model {model_id!r} must be approved (or a previously active model) to activate")
        prev = conn.execute("UPDATE models SET status = 'retired' WHERE status = 'active' RETURNING model_id").fetchone()
        if prev:
            _event(conn, prev[0], "retired", actor, {"replaced_by": model_id})
        conn.execute("UPDATE models SET status = 'active', activated_at = now() WHERE model_id = %s", (model_id,))
        _event(conn, model_id, "activated", actor, {"replaced": prev[0] if prev else None})


def list_models(conn) -> list[dict]:
    cur = conn.execute("SELECT model_id, status, sha256, schema_version, registered_by, registered_at, "
                       "approved_by, approved_at, activated_at, metrics FROM models ORDER BY registered_at")
    cols = [c.name for c in cur.description]
    return [dict(zip(cols, r)) for r in cur]


@dataclass
class LoadedModel:
    model_id: str
    sha256: str
    detector: object


def check_and_load(conn: psycopg.Connection, *, actor: str, current: LoadedModel | None = None) -> LoadedModel:
    """MODEL CHECK. Returns the active model (reusing `current` if it is still the active one),
    or raises ModelCheckFailed. Failures are audit-logged on the model."""
    row = conn.execute("SELECT model_id, artifact_path, sha256, schema_version, features, approved_by "
                       "FROM models WHERE status = 'active'").fetchone()
    if not row:
        raise ModelCheckFailed("no active model: register, approve and activate one")
    model_id, artifact_path, digest, schema_version, features, approved_by = row
    if current and current.model_id == model_id and current.sha256 == digest:
        return current

    def fail(reason: str):
        with conn.transaction():
            _event(conn, model_id, "check_failed", actor, {"reason": reason})
        raise ModelCheckFailed(f"model {model_id}: {reason}")

    if not approved_by:
        fail("active model has no recorded approver")
    if KNOWN_SCHEMAS.get(schema_version) != tuple(features):
        fail(f"feature schema mismatch (model {schema_version}; service knows {sorted(KNOWN_SCHEMAS)})")
    try:
        path = _safe_path(artifact_path)
    except ModelCheckFailed as e:
        fail(str(e))
    if _sha256(path) != digest:
        fail("artifact hash does not match the registry: file changed since approval")
    det = joblib.load(path)  # safe to unpickle only now: bytes are the approved ones
    if tuple(det.features) != tuple(features):
        fail("loaded model's feature list differs from its registration")
    log.info("model check passed: %s (sha256 %s…)", model_id, digest[:12])
    return LoadedModel(model_id, digest, det)

"""API key format, digests and the key store.

Key format:  nsk_<key_id: 12 hex>_<secret: 43 base64url chars = 256 random bits>

The server stores only SHA-256(full key). A plain (unsalted, unpeppered) digest is sufficient
because the secret is 256 bits of CSPRNG output, which rules out brute force and precomputation.
It also lets a client compute the digest on their own machine, so the plaintext key never has to
touch the server to be registered.
"""

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime

import psycopg
from psycopg.types.json import Jsonb

SCOPES = frozenset({"ingest:write", "events:read", "actions:decide"})
KEY_RE = re.compile(r"^nsk_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$")
KEY_ID_RE = re.compile(r"^[0-9a-f]{12}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_DUMMY_DIGEST = hashlib.sha256(b"netsentinel-timing-equaliser").digest()


class InvalidKey(Exception):
    """Deliberately carries no detail about why; callers return one generic 401."""


def generate() -> str:
    """Only for tests and server-side service keys. User keys are generated on the client."""
    key_id = secrets.token_hex(6)
    secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    return f"nsk_{key_id}_{secret}"


def digest(key: str) -> bytes:
    return hashlib.sha256(key.encode()).digest()


def parse_key_id(key: str) -> str:
    m = KEY_RE.match(key)
    if not m:
        raise InvalidKey()
    return m.group(1)


@dataclass(frozen=True)
class ApiKey:
    key_id: str
    name: str
    scopes: tuple[str, ...]
    expires_at: datetime | None


def _validate_scopes(scopes) -> list[str]:
    scopes = sorted(set(scopes))
    if not scopes or not set(scopes) <= SCOPES:
        raise ValueError(f"scopes must be a non-empty subset of {sorted(SCOPES)}")
    return scopes


def register(conn: psycopg.Connection, *, key_id: str, sha256_hex: str, name: str,
             scopes, created_by: str, expires_at: datetime | None = None) -> None:
    if not KEY_ID_RE.match(key_id):
        raise ValueError("key_id must be 12 lowercase hex characters")
    sha256_hex = sha256_hex.strip().lower()
    if not DIGEST_RE.match(sha256_hex):
        raise ValueError("sha256 must be 64 hex characters")
    scopes = _validate_scopes(scopes)
    with conn.transaction():
        conn.execute(
            "INSERT INTO api_keys (key_id, name, key_sha256, scopes, created_by, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (key_id, name, bytes.fromhex(sha256_hex), scopes, created_by, expires_at))
        conn.execute("INSERT INTO api_key_events (key_id, event, actor, detail) VALUES (%s, 'registered', %s, %s)",
                     (key_id, created_by, Jsonb({"name": name, "scopes": scopes})))


def grant(conn: psycopg.Connection, key_id: str, scope: str, *, actor: str) -> bool:
    if scope not in SCOPES:
        raise ValueError(f"unknown scope {scope!r}")
    with conn.transaction():
        cur = conn.execute("UPDATE api_keys SET scopes = array_append(scopes, %s) WHERE key_id = %s "
                           "AND revoked_at IS NULL AND NOT (%s = ANY(scopes))", (scope, key_id, scope))
        if cur.rowcount != 1:
            return False
        conn.execute("INSERT INTO api_key_events (key_id, event, actor, detail) VALUES (%s, 'scope_granted', %s, %s)",
                     (key_id, actor, Jsonb({"scope": scope})))
    return True


def revoke(conn: psycopg.Connection, key_id: str, *, reason: str, actor: str) -> bool:
    with conn.transaction():
        cur = conn.execute("UPDATE api_keys SET revoked_at = now(), revoked_reason = %s "
                           "WHERE key_id = %s AND revoked_at IS NULL", (reason, key_id))
        if cur.rowcount != 1:
            return False
        conn.execute("INSERT INTO api_key_events (key_id, event, actor, detail) VALUES (%s, 'revoked', %s, %s)",
                     (key_id, actor, Jsonb({"reason": reason})))
    return True


def list_keys(conn: psycopg.Connection) -> list[dict]:
    cur = conn.execute(
        "SELECT key_id, name, scopes, created_at, created_by, expires_at, last_used_at, revoked_at, revoked_reason "
        "FROM api_keys ORDER BY created_at")
    cols = [c.name for c in cur.description]
    return [dict(zip(cols, row)) for row in cur]


def authenticate(conn: psycopg.Connection, presented: str, *, client: str) -> ApiKey:
    """Returns the key's record, or raises InvalidKey (unknown, wrong, revoked or expired)."""
    try:
        key_id = parse_key_id(presented)
    except InvalidKey:
        hmac.compare_digest(_DUMMY_DIGEST, digest(presented[:200]))
        raise
    row = conn.execute(
        "SELECT name, key_sha256, scopes, expires_at, revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) "
        "FROM api_keys WHERE key_id = %s", (key_id,)).fetchone()
    stored = bytes(row[1]) if row else _DUMMY_DIGEST
    matches = hmac.compare_digest(stored, digest(presented))
    if not row:
        raise InvalidKey()
    if not matches:
        # Someone knows a real key_id but not its secret: worth an audit entry. The failure is
        # recorded in its own transaction so it persists even though the request is rejected.
        with conn.transaction():
            conn.execute("INSERT INTO api_key_events (key_id, event, actor, detail) VALUES (%s, 'auth_failed', %s, %s)",
                         (key_id, client, Jsonb({"reason": "digest_mismatch"})))
        raise InvalidKey()
    if not row[4]:
        raise InvalidKey()
    with conn.transaction():
        conn.execute("UPDATE api_keys SET last_used_at = now() WHERE key_id = %s "
                     "AND (last_used_at IS NULL OR last_used_at < now() - interval '60 seconds')", (key_id,))
    return ApiKey(key_id, row[0], tuple(row[2]), row[3])

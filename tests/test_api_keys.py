import hashlib
import secrets

import psycopg
import pytest

from netsentinel.security import api_keys


def _new(conn, scopes=("ingest:write",), name="test"):
    key = api_keys.generate()
    api_keys.register(conn, key_id=api_keys.parse_key_id(key), sha256_hex=hashlib.sha256(key.encode()).hexdigest(),
                      name=name, scopes=scopes, created_by="pytest")
    return key


def test_generated_key_format_and_entropy():
    k = api_keys.generate()
    assert api_keys.KEY_RE.match(k)
    assert len({api_keys.generate() for _ in range(1000)}) == 1000


def test_powershell_compatible_digest_matches():
    # The Windows script computes lowercase hex SHA-256 of the UTF-8 key; the server must agree.
    k = api_keys.generate()
    assert api_keys.digest(k).hex() == hashlib.sha256(k.encode("utf-8")).hexdigest()


def test_only_digest_is_stored(conn):
    key = _new(conn)
    kid = api_keys.parse_key_id(key)
    secret = key.split("_", 2)[2]
    row = conn.execute("SELECT row_to_json(k)::text FROM api_keys k WHERE key_id = %s", (kid,)).fetchone()[0]
    events = conn.execute("SELECT string_agg(detail::text, '') FROM api_key_events WHERE key_id = %s", (kid,)).fetchone()[0]
    assert secret not in row and key not in row and secret not in events


def test_authenticate_accepts_valid_and_rejects_others(conn):
    key = _new(conn)
    assert api_keys.authenticate(conn, key, client="t").scopes == ("ingest:write",)
    kid = api_keys.parse_key_id(key)
    wrong = f"nsk_{kid}_" + "A" * 43
    for bad in ["", "garbage", key + "x", wrong, api_keys.generate()]:
        with pytest.raises(api_keys.InvalidKey):
            api_keys.authenticate(conn, bad, client="t")
    fails = conn.execute("SELECT count(*) FROM api_key_events WHERE key_id = %s AND event = 'auth_failed'",
                         (kid,)).fetchone()[0]
    assert fails == 1  # the wrong secret for a real key_id is audited


def test_revoked_and_expired_keys_rejected(conn):
    key = _new(conn)
    kid = api_keys.parse_key_id(key)
    assert api_keys.revoke(conn, kid, reason="test", actor="pytest")
    with pytest.raises(api_keys.InvalidKey):
        api_keys.authenticate(conn, key, client="t")
    assert not api_keys.revoke(conn, kid, reason="again", actor="pytest")

    key2 = _new(conn)
    # created_at is immutable, so expire the key just after its creation time.
    conn.execute("UPDATE api_keys SET expires_at = created_at + interval '1 microsecond' WHERE key_id = %s",
                 (api_keys.parse_key_id(key2),))
    with pytest.raises(api_keys.InvalidKey):
        api_keys.authenticate(conn, key2, client="t")


def test_database_guards(conn):
    key = _new(conn)
    kid = api_keys.parse_key_id(key)
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("UPDATE api_keys SET key_sha256 = %s WHERE key_id = %s", (secrets.token_bytes(32), kid))
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("DELETE FROM api_keys WHERE key_id = %s", (kid,))
    api_keys.revoke(conn, kid, reason="t", actor="pytest")
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("UPDATE api_keys SET revoked_at = NULL, revoked_reason = NULL WHERE key_id = %s", (kid,))
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("DELETE FROM api_key_events WHERE key_id = %s", (kid,))


def test_register_validation(conn):
    good = hashlib.sha256(b"x").hexdigest()
    for kwargs in [dict(key_id="XYZ", sha256_hex=good, scopes=["ingest:write"]),
                   dict(key_id="0123456789ab", sha256_hex="abc", scopes=["ingest:write"]),
                   dict(key_id="0123456789ab", sha256_hex=good, scopes=["admin"]),
                   dict(key_id="0123456789ab", sha256_hex=good, scopes=[])]:
        with pytest.raises(ValueError):
            api_keys.register(conn, name="n", created_by="pytest", **kwargs)


def test_public_has_no_table_privileges(conn):
    n = conn.execute("SELECT count(*) FROM information_schema.role_table_grants "
                     "WHERE grantee = 'PUBLIC' AND table_schema = 'public'").fetchone()[0]
    assert n == 0

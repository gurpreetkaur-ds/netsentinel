"""Applies netsentinel/migrations/*.sql in order, each once, each in its own transaction."""

from importlib import resources

import psycopg


def pending(conn: psycopg.Connection) -> list[str]:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations "
                 "(version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
    conn.execute("REVOKE ALL ON schema_migrations FROM PUBLIC")
    conn.commit()
    done = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    files = sorted(f.name for f in resources.files("netsentinel.migrations").iterdir() if f.name.endswith(".sql"))
    return [f for f in files if f.removesuffix(".sql") not in done]


def apply(conn: psycopg.Connection) -> list[str]:
    applied = []
    for name in pending(conn):
        sql = resources.files("netsentinel.migrations").joinpath(name).read_text()
        with conn.transaction():
            conn.execute(sql)
            conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (name.removesuffix(".sql"),))
        applied.append(name)
    return applied

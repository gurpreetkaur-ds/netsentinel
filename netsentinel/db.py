"""PostgreSQL access. Every new connection asks the Wall for the current rotating password."""

import psycopg
from psycopg_pool import ConnectionPool

from . import config, wall


class WallConnection(psycopg.Connection):
    @classmethod
    def connect(cls, conninfo: str = "", **kwargs):
        creds = wall.db_credentials()
        kwargs.update(user=creds.username, password=creds.password)
        return super().connect(conninfo, **kwargs)


def _conn_kwargs() -> dict:
    s = config.load()
    # autocommit: every write is inside an explicit conn.transaction(), so audit records written
    # before a request is rejected are never rolled back with it.
    return {"host": s.db_host, "port": s.db_port, "dbname": s.db_name,
            "application_name": "netsentinel", "autocommit": True}


def connect() -> psycopg.Connection:
    return WallConnection.connect(**_conn_kwargs())


def make_pool(min_size: int = 1, max_size: int = 10) -> ConnectionPool:
    return ConnectionPool(
        kwargs=_conn_kwargs(), connection_class=WallConnection,
        min_size=min_size, max_size=max_size, open=True, name="netsentinel",
    )

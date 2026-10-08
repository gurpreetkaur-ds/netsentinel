"""Integration tests run against the netsentinel_test database through the real Security Wall.

Run with:  sg wall-netsentinel-clients -c '.venv/bin/pytest'
"""

import os

os.environ["NETSENTINEL_DB_NAME"] = "netsentinel_test"

import pytest  # noqa: E402

from netsentinel import db, migrate  # noqa: E402


@pytest.fixture(scope="session")
def pool():
    with db.connect() as conn:
        # Fresh schema per run: this database belongs to tests only.
        conn.execute("DROP SCHEMA public CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        migrate.apply(conn)
    p = db.make_pool(max_size=4)
    yield p
    p.close()


@pytest.fixture
def conn(pool):
    with pool.connection() as c:
        yield c

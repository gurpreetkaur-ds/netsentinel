"""Event bus (pipeline step 7). Postgres-backed now; agents depend only on the Bus interface, so
it can move to Kafka/Redis Streams later without touching agent code.

Delivery is at-least-once: a consumer commits its offset in the same transaction as the work
the messages caused, so a crash replays messages rather than losing them.
"""

from dataclasses import dataclass
from typing import Protocol

import psycopg
from psycopg.types.json import Jsonb

DETECTION_ATTACK = "detection.attack"
DETECTION_REJECTED = "detection.rejected"
MODEL_CHECK_FAILED = "model.check_failed"


@dataclass(frozen=True)
class Message:
    id: int
    topic: str
    payload: dict
    producer: str


class Bus(Protocol):
    def publish(self, conn: psycopg.Connection, topic: str, payload: dict, *, producer: str) -> int: ...
    def poll(self, conn: psycopg.Connection, consumer: str, topic: str, limit: int = 100) -> list[Message]: ...
    def commit(self, conn: psycopg.Connection, consumer: str, topic: str, last_id: int) -> None: ...


class PostgresBus:
    def publish(self, conn, topic, payload, *, producer):
        row = conn.execute("INSERT INTO bus_messages (topic, payload, producer) VALUES (%s, %s, %s) RETURNING id",
                           (topic, Jsonb(payload), producer)).fetchone()
        conn.execute("SELECT pg_notify('netsentinel_bus', %s)", (topic,))
        return row[0]

    def poll(self, conn, consumer, topic, limit=100):
        conn.execute("INSERT INTO bus_offsets (consumer, topic) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                     (consumer, topic))
        rows = conn.execute(
            "SELECT m.id, m.topic, m.payload, m.producer FROM bus_messages m "
            "JOIN bus_offsets o ON o.consumer = %s AND o.topic = m.topic "
            "WHERE m.topic = %s AND m.id > o.last_id AND m.txid < pg_snapshot_xmin(pg_current_snapshot()) "
            "ORDER BY m.id LIMIT %s",
            (consumer, topic, limit)).fetchall()
        return [Message(*r) for r in rows]

    def commit(self, conn, consumer, topic, last_id):
        conn.execute("UPDATE bus_offsets SET last_id = greatest(last_id, %s), updated_at = now() "
                     "WHERE consumer = %s AND topic = %s", (last_id, consumer, topic))

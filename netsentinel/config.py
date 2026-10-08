"""Runtime settings. Only non-secret values come from the environment; secrets come from the Wall."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    wall_socket: str
    db_host: str
    db_port: int
    db_name: str
    max_batch: int
    max_body_bytes: int


def load() -> Settings:
    env = os.environ.get
    return Settings(
        wall_socket=env("WALL_SOCKET", "/run/wall-netsentinel/proxy.sock"),
        db_host=env("NETSENTINEL_DB_HOST", "localhost"),
        db_port=int(env("NETSENTINEL_DB_PORT", "5432")),
        db_name=env("NETSENTINEL_DB_NAME", "netsentinel"),
        max_batch=int(env("NETSENTINEL_MAX_BATCH", "1000")),
        max_body_bytes=int(env("NETSENTINEL_MAX_BODY_BYTES", str(8 * 1024 * 1024))),
    )

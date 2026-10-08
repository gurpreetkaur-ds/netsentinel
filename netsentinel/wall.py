"""Client for the Security Wall.

The app talks only to its project proxy over a Unix socket that the OS restricts to the
wall-netsentinel-clients group; the proxy holds the short-lived wall token. Secret values are kept
in memory only and never written to the environment, disk or logs.
"""

import http.client
import json
import logging
import socket
from dataclasses import dataclass

from . import config

log = logging.getLogger(__name__)
PROJECT = "netsentinel"


class WallUnavailable(RuntimeError):
    pass


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 5.0):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def _get(path: str) -> dict:
    sock_path = config.load().wall_socket
    conn = _UnixConnection(sock_path)
    try:
        conn.request("GET", f"/v1/{path}")
        res = conn.getresponse()
        body = res.read()
    except OSError as e:
        log.error("cannot reach the Security Wall proxy at %s (%s)", sock_path, type(e).__name__)
        raise WallUnavailable("Security Wall proxy unreachable") from None
    finally:
        conn.close()
    if res.status != 200:
        # Log the path and status only, never the body.
        log.error("wall GET %s failed with HTTP %s", path, res.status)
        raise WallUnavailable(f"Security Wall returned HTTP {res.status}")
    return json.loads(body)


@dataclass(frozen=True)
class DbCredentials:
    username: str
    password: str

    def __repr__(self) -> str:  # never render the password
        return f"DbCredentials(username={self.username!r}, password=***)"


def db_credentials() -> DbCredentials:
    """Current DB credential, fetched fresh per new connection so rotations apply immediately."""
    data = _get(f"database/static-creds/{PROJECT}-db")["data"]
    return DbCredentials(data["username"], data["password"])

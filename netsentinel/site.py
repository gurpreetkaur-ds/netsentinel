"""Site-specific settings (domain, server address, the owner's IPs, capture interface).

They live in config/site.json, which is not committed; config/site.example.json shows the format.
Override the location with NETSENTINEL_SITE.
"""

import json
import os
from functools import lru_cache
from pathlib import Path

from .ml.data import ROOT

DEFAULTS = {"domain": None, "server_ip": None, "owner_ips": [], "interface": "eth0"}


@lru_cache(maxsize=1)
def load() -> dict:
    path = Path(os.environ.get("NETSENTINEL_SITE", ROOT / "config" / "site.json"))
    try:
        return {**DEFAULTS, **json.loads(path.read_text())}
    except FileNotFoundError:
        return dict(DEFAULTS)

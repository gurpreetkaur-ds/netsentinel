"""ASGI entry point: uvicorn netsentinel.api.main:app"""

import logging

from .app import create_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
app = create_app()


def dashboard_app():
    """uvicorn factory for the public, dashboard-only listener."""
    return create_app(dashboard_only=True)

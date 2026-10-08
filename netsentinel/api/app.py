"""NetSentinel internal API (pipeline step 1: INGEST).

Clients authenticate with an API key whose SHA-256 digest was registered by an operator.
Keys are never logged; errors never say why a key was rejected.
"""

import logging
import math
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .. import config, db
from . import dashboard
from ..pipeline.features import flow_duration_us
from ..security import api_keys

log = logging.getLogger("netsentinel.api")

FeatureValue = float | int | str | bool | None


class FlowContext(BaseModel):
    """Who talked to whom: VERIFIED TELEMETRY for correlation and investigation, never a model input."""
    model_config = ConfigDict(extra="forbid")
    src_ip: IPv4Address | IPv6Address | None = None
    dst_ip: IPv4Address | IPv6Address | None = None
    src_port: int | None = Field(None, ge=0, le=65535)
    dst_port: int | None = Field(None, ge=0, le=65535)
    protocol: int | None = Field(None, ge=0, le=255)


class FlowIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str | None = Field(None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$",
                                 description="Client-side id; resubmitting it is idempotent.")
    observed_at: datetime | None = None
    context: FlowContext | None = None
    features: dict[Annotated[str, Field(min_length=1, max_length=64)], FeatureValue] = Field(max_length=200)

    @field_validator("features")
    @classmethod
    def finite_numbers(cls, v: dict) -> dict:
        for k, x in v.items():
            if isinstance(x, float) and not math.isfinite(x):
                raise ValueError(f"feature {k!r} is not finite; send null for missing or infinite values")
            if isinstance(x, str) and len(x) > 256:
                raise ValueError(f"feature {k!r} is longer than 256 characters")
        return v


class FlowBatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["cicflowmeter", "zeek", "netflow"]
    mode: Literal["live", "shadow"] = Field("live", description="shadow: score and store, but raise no alerts")
    flows: list[FlowIn] = Field(min_length=1)


def _ended_at(flow: "FlowIn") -> datetime | None:
    """observed_at (flow start) + Flow Duration (µs), when both are known."""
    if flow.observed_at is None:
        return None
    duration = flow_duration_us(flow.features)
    return flow.observed_at + timedelta(microseconds=duration) if duration is not None else None


class AuthFailureLimiter:
    """Blocks a client address after too many failed authentications in a sliding window."""

    def __init__(self, limit: int = 20, window_s: float = 300.0):
        self.limit, self.window = limit, window_s
        self.fails: dict[str, deque] = defaultdict(deque)

    def _trim(self, client: str, now: float) -> deque:
        q = self.fails[client]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, client: str) -> bool:
        return len(self._trim(client, time.monotonic())) >= self.limit

    def record(self, client: str) -> None:
        self._trim(client, time.monotonic()).append(time.monotonic())


def _error(status: int, code: str, message: str, request: Request, headers: dict | None = None) -> JSONResponse:
    rid = getattr(request.state, "request_id", None)
    return JSONResponse({"error": {"code": code, "message": message, "request_id": rid}}, status, headers=headers)


def create_app(pool: ConnectionPool | None = None, *, dashboard_only: bool = False) -> FastAPI:
    settings = config.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pool = pool or db.make_pool()
        try:
            yield
        finally:
            if pool is None:
                app.state.pool.close()

    app = FastAPI(title="NetSentinel API", version="1", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url="/v1/openapi.json")
    app.state.limiter = AuthFailureLimiter()
    app.include_router(dashboard.build_router())

    @app.middleware("http")
    async def envelope(request: Request, call_next):
        request.state.request_id = str(uuid.uuid4())
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > settings.max_body_bytes):
            return _error(413, "payload_too_large", f"Request body exceeds {settings.max_body_bytes} bytes.", request)
        if request.method == "POST" and length is None:
            return _error(411, "length_required", "Content-Length is required.", request)
        response = await call_next(request)
        response.headers["X-Request-Id"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.url.scheme == "https":  # served over TLS: tell browsers never to use plain HTTP here
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        code, message = exc.detail if isinstance(exc.detail, tuple) else ("error", str(exc.detail))
        if request.url.path.startswith("/dashboard") and "text/html" in request.headers.get("accept", ""):
            return dashboard.error_page(request, exc.status_code, message)
        return _error(exc.status_code, code, message, request, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Echo locations and messages only, never the submitted values.
        details = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()][:50]
        body = {"error": {"code": "invalid_request", "message": "Request validation failed.",
                          "request_id": request.state.request_id, "details": details}}
        return JSONResponse(body, 422)

    def authenticated(request: Request) -> api_keys.ApiKey:
        client = request.client.host if request.client else "unknown"
        if app.state.limiter.blocked(client):
            raise HTTPException(429, ("too_many_failures", "Too many failed authentications. Try again later."),
                                {"Retry-After": "300"})
        auth = request.headers.get("authorization", "")
        presented = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-api-key", "")
        try:
            if not presented:
                raise api_keys.InvalidKey()
            with app.state.pool.connection() as conn:
                return api_keys.authenticate(conn, presented, client=client)
        except api_keys.InvalidKey:
            app.state.limiter.record(client)
            log.warning("rejected api key from %s", client)
            raise HTTPException(401, ("unauthorized", "Missing or invalid API key."),
                                {"WWW-Authenticate": "Bearer"}) from None

    def require(scope: str):
        def check(key: api_keys.ApiKey = Depends(authenticated)) -> api_keys.ApiKey:
            if scope not in key.scopes:
                raise HTTPException(403, ("forbidden", f"This key lacks the '{scope}' scope."))
            return key
        return check

    @app.get("/healthz")
    def healthz():
        try:
            with app.state.pool.connection(timeout=3) as conn:
                conn.execute("SELECT 1")
        except Exception:
            log.exception("health check failed")
            return JSONResponse({"status": "degraded"}, 503)
        return {"status": "ok"}

    @app.get("/v1/whoami")
    def whoami(key: api_keys.ApiKey = Depends(authenticated)):
        return {"key_id": key.key_id, "name": key.name, "scopes": list(key.scopes),
                "expires_at": key.expires_at}

    @app.post("/v1/flows", status_code=202)
    def ingest(batch: FlowBatchIn, key: api_keys.ApiKey = Depends(require("ingest:write"))):
        if len(batch.flows) > settings.max_batch:
            raise HTTPException(413, ("batch_too_large", f"At most {settings.max_batch} flows per request."))
        batch_id = uuid.uuid4()
        with app.state.pool.connection() as conn, conn.transaction():
            ctx = [f.context or FlowContext() for f in batch.flows]
            rows = conn.execute(
                "INSERT INTO flow_events (batch_id, key_id, source, shadow, client_event_id, observed_at, ended_at, flow, "
                "src_ip, dst_ip, src_port, dst_port, protocol) "
                "SELECT %s, %s, %s, %s, e, o, en, f, si, di, sp, dp, pr FROM unnest(%s::text[], %s::timestamptz[], "
                "%s::timestamptz[], %s::jsonb[], %s::inet[], %s::inet[], %s::int[], %s::int[], %s::smallint[]) "
                "AS t(e, o, en, f, si, di, sp, dp, pr) "
                "ON CONFLICT (key_id, client_event_id) DO NOTHING RETURNING event_id, client_event_id",
                (batch_id, key.key_id, batch.source, batch.mode == "shadow",
                 [f.event_id for f in batch.flows], [f.observed_at for f in batch.flows],
                 [_ended_at(f) for f in batch.flows], [Jsonb(f.features) for f in batch.flows],
                 [c.src_ip and str(c.src_ip) for c in ctx], [c.dst_ip and str(c.dst_ip) for c in ctx],
                 [c.src_port for c in ctx], [c.dst_port for c in ctx], [c.protocol for c in ctx])).fetchall()
        return {"batch_id": batch_id, "received": len(batch.flows), "accepted": len(rows),
                "duplicates": len(batch.flows) - len(rows),
                "events": [{"event_id": r[0], "client_event_id": r[1]} for r in rows]}

    @app.get("/v1/flows/{event_id}")
    def get_flow(event_id: uuid.UUID, key: api_keys.ApiKey = Depends(require("events:read"))):
        with app.state.pool.connection() as conn:
            row = conn.execute(
                "SELECT event_id, batch_id, source, client_event_id, observed_at, status, received_at, flow, "
                "host(src_ip), host(dst_ip), src_port, dst_port, protocol "
                "FROM flow_events WHERE event_id = %s AND key_id = %s", (event_id, key.key_id)).fetchone()
        if not row:  # other keys' events are indistinguishable from missing ones
            raise HTTPException(404, ("not_found", "No such event."))
        cols = ("event_id", "batch_id", "source", "client_event_id", "observed_at", "status", "received_at", "flow")
        out = dict(zip(cols, row[:8]))
        out["context"] = dict(zip(("src_ip", "dst_ip", "src_port", "dst_port", "protocol"), row[8:]))
        return out

    if dashboard_only:
        # Public listener: only the dashboard (and a health check). The /v1 ingestion API and its
        # OpenAPI schema do not exist on this app at all.
        app.router.routes = [r for r in app.router.routes if not getattr(r, "path", "").startswith("/v1")]
        app.openapi_url = None

        @app.get("/", include_in_schema=False)
        def root():
            return RedirectResponse("/dashboard", status_code=303)

    return app

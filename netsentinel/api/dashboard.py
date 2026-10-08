"""Pipeline step 12 (DASHBOARD): a read-only SOC view served by the API process.

Sign-in uses an API key with the `events:read` scope, typed into a password field and checked
like any API call. The browser then holds only a signed session cookie (HttpOnly, SameSite=Strict,
8 h). The signing secret is random per process and never stored, so a restart signs everyone out.
Every request re-checks that the key is still active: revoking the key ends its sessions at once.

Read-only on purpose: approving response actions stays on the CLI, where the human's identity is
the operator's own login.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from ..agents import response as response_agent
from ..agents import ticket as ticket_agent
from ..security import api_keys

HERE = Path(__file__).parent
COOKIE = "ns_session"
SESSION_SECONDS = 8 * 3600
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
AGENT_CONSUMERS = [("orchestrator", "detection.attack"), ("investigation", "investigation.requested"),
                   ("risk", "investigation.completed"), ("response", "risk.assessed"), ("ticket", "response.proposed")]

templates = Jinja2Templates(directory=str(HERE / "templates"))  # autoescape is on for .html


class _Sessions:
    def __init__(self):
        self.secret = secrets.token_bytes(32)

    def issue(self, key_id: str) -> str:
        body = base64.urlsafe_b64encode(json.dumps({"k": key_id, "exp": int(time.time()) + SESSION_SECONDS}).encode())
        sig = base64.urlsafe_b64encode(hmac.new(self.secret, body, hashlib.sha256).digest())
        return f"{body.decode()}.{sig.decode()}"

    def csrf(self, token: str) -> str:
        """Per-session form token: forms are only accepted with the token of the session that rendered them."""
        return hmac.new(self.secret, b"csrf:" + token.encode(), hashlib.sha256).hexdigest()[:32]

    def verify(self, token: str | None) -> str | None:
        if not token or token.count(".") != 1:
            return None
        body, sig = token.encode().split(b".")
        good = base64.urlsafe_b64encode(hmac.new(self.secret, body, hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good):
            return None
        try:
            data = json.loads(base64.urlsafe_b64decode(body))
        except ValueError:
            return None
        return data["k"] if data.get("exp", 0) > time.time() else None


def _secure_headers(resp: Response) -> Response:
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Frame-Options"] = "DENY"
    # same-origin (not no-referrer): browsers then send a real Origin on our own form posts,
    # which the CSRF check needs; other sites still get no referrer.
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


def _page(request: Request, name: str, ctx: dict, status: int = 200) -> Response:
    return _secure_headers(templates.TemplateResponse(request, name, ctx, status_code=status))


def error_page(request: Request, status: int, message: str) -> Response:
    titles = {401: "Not signed in", 403: "Not allowed", 404: "Not found", 409: "Already decided", 429: "Slow down"}
    return _page(request, "error.html", {"title": titles.get(status, "Something went wrong"), "message": message,
                                         "viewer": None}, status)


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    return origin is None or origin.split("://", 1)[-1] == request.headers.get("host")


def build_router() -> APIRouter:
    router = APIRouter(prefix="/dashboard", include_in_schema=False)
    sessions = _Sessions()

    def viewer(request: Request) -> dict | None:
        key_id = sessions.verify(request.cookies.get(COOKIE))
        if not key_id:
            return None
        with request.app.state.pool.connection() as conn:
            row = conn.execute("SELECT name, scopes FROM api_keys WHERE key_id = %s AND revoked_at IS NULL "
                               "AND (expires_at IS NULL OR expires_at > now()) AND 'events:read' = ANY(scopes)",
                               (key_id,)).fetchone()
        return {"key_id": key_id, "name": row[0], "scopes": row[1]} if row else None

    async def step_up(request: Request, who: dict) -> dict:
        """For state-changing forms: same origin, this session's form token, and the API key typed again,
        which must be the signed-in key and hold 'actions:decide'. Returns the form fields."""
        if not _same_origin(request):
            raise HTTPException(403, ("forbidden", "Cross-origin request refused."))
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode(errors="replace")).items()}
        if not hmac.compare_digest(form.get("csrf", ""), sessions.csrf(request.cookies.get(COOKIE, ""))):
            raise HTTPException(403, ("forbidden", "This form has expired. Reload the page and try again."))
        client = request.client.host if request.client else "unknown"
        limiter = request.app.state.limiter
        if limiter.blocked(client):
            raise HTTPException(429, ("too_many_failures", "Too many failed attempts. Try again in 5 minutes."))
        try:
            with request.app.state.pool.connection() as conn:
                key = api_keys.authenticate(conn, form.get("api_key", "").strip(), client=client)
            if key.key_id != who["key_id"] or "actions:decide" not in key.scopes:
                raise api_keys.InvalidKey()
        except api_keys.InvalidKey:
            limiter.record(client)
            raise HTTPException(403, ("forbidden", "Confirmation failed: re-enter the key you signed in with "
                                                   "(it needs the 'actions:decide' permission).")) from None
        if not form.get("note", "").strip():
            raise HTTPException(422, ("invalid_request", "A note is required: it is kept in the audit trail."))
        return form

    @router.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return _page(request, "login.html", {"error": None})

    @router.post("/login")
    async def login(request: Request):
        if not _same_origin(request):
            raise HTTPException(403, ("forbidden", "Cross-origin sign-in refused."))
        client = request.client.host if request.client else "unknown"
        limiter = request.app.state.limiter
        if limiter.blocked(client):
            return _page(request, "login.html", {"error": "Too many failed attempts. Try again in 5 minutes."}, 429)
        form = parse_qs((await request.body()).decode(errors="replace"))
        presented = (form.get("api_key") or [""])[0].strip()
        try:
            with request.app.state.pool.connection() as conn:
                key = api_keys.authenticate(conn, presented, client=client)
            if "events:read" not in key.scopes:
                raise api_keys.InvalidKey()
        except api_keys.InvalidKey:
            limiter.record(client)
            return _page(request, "login.html", {"error": "That key was not accepted."}, 401)
        resp = RedirectResponse("/dashboard", status_code=303)
        resp.set_cookie(COOKIE, sessions.issue(key.key_id), max_age=SESSION_SECONDS, httponly=True, samesite="strict",
                        secure=request.url.scheme == "https", path="/dashboard")
        return resp

    @router.post("/logout")
    def logout(request: Request):
        if not _same_origin(request):
            raise HTTPException(403, ("forbidden", "Cross-origin request refused."))
        resp = RedirectResponse("/dashboard/login", status_code=303)
        resp.delete_cookie(COOKIE, path="/dashboard")
        return resp

    @router.get("", response_class=HTMLResponse)
    def index(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        with request.app.state.pool.connection() as conn:
            ctx = overview(conn)
        ctx["viewer"] = who["name"]
        return _page(request, "index.html", ctx)

    @router.get("/tickets/{ticket_id}", response_class=HTMLResponse)
    def ticket_page(request: Request, ticket_id: str):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        with request.app.state.pool.connection() as conn:
            ctx = ticket_detail(conn, ticket_id)
        if ctx is None:
            raise HTTPException(404, ("not_found", "No such ticket."))
        ctx["viewer"] = who["name"]
        ctx["can_decide"] = "actions:decide" in who["scopes"]
        ctx["csrf"] = sessions.csrf(request.cookies.get(COOKIE, ""))
        return _page(request, "ticket.html", ctx)

    @router.post("/actions/{action_id}")
    async def decide_action(request: Request, action_id: str):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        form = await step_up(request, who)
        actor = f"human:{who['name']}@dashboard"
        verb = form.get("decision")
        try:
            with request.app.state.pool.connection() as conn:
                if verb == "complete":
                    res = response_agent.complete(conn, action_id, actor=actor, note=form["note"].strip())
                elif verb in ("approve", "reject"):
                    res = response_agent.decide(conn, action_id, approve=verb == "approve", actor=actor,
                                                note=form["note"].strip())
                else:
                    raise HTTPException(422, ("invalid_request", "Unknown decision."))
                tid = conn.execute("SELECT ticket_id FROM tickets WHERE case_id = %s", (res["case_id"],)).fetchone()
        except ValueError as e:
            raise HTTPException(409, ("conflict", str(e))) from None
        return RedirectResponse(f"/dashboard/tickets/{tid[0]}" if tid else "/dashboard", status_code=303)

    @router.post("/tickets/{ticket_id}/close")
    async def close_ticket(request: Request, ticket_id: str):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        form = await step_up(request, who)
        try:
            with request.app.state.pool.connection() as conn:
                ticket_agent.resolve(conn, ticket_id, actor=f"human:{who['name']}@dashboard",
                                     resolution=form["note"].strip(), close=True)
        except ValueError as e:
            raise HTTPException(409, ("conflict", str(e))) from None
        return RedirectResponse(f"/dashboard/tickets/{ticket_id}", status_code=303)

    @router.get("/files/{name}")
    def files(request: Request, name: str):
        """The project presentation, for signed-in users only."""
        allowed = {"NetSentinel.pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                   "NetSentinel.pdf": "application/pdf"}
        if not viewer(request):
            return RedirectResponse("/dashboard/login", status_code=303)
        path = HERE.parents[1] / "presentation" / name
        if name not in allowed or not path.is_file():
            raise HTTPException(404, ("not_found", "Not found."))
        return Response(path.read_bytes(), media_type=allowed[name],
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @router.get("/static/{name}")
    def static(name: str):
        allowed = {"chart.umd.min.js": "text/javascript", "dashboard.js": "text/javascript", "dashboard.css": "text/css"}
        if name not in allowed:
            raise HTTPException(404, ("not_found", "Not found."))
        return Response((HERE / "static" / name).read_bytes(), media_type=allowed[name])

    return router


# ── queries ────────────────────────────────────────────────────────────────────────────────────
def _rows(conn, sql: str, params=()) -> list[dict]:
    cur = conn.execute(sql, params)
    cols = [c.name for c in cur.description]
    return [dict(zip(cols, r)) for r in cur]


def overview(conn) -> dict:
    one = lambda sql, p=(): conn.execute(sql, p).fetchone()
    kpi = one("SELECT (SELECT count(*) FROM flow_events WHERE received_at > now() - interval '24 hours'),"
              " (SELECT count(*) FROM detections WHERE is_attack AND scored_at > now() - interval '24 hours'),"
              " (SELECT count(*) FROM flow_events WHERE status = 'rejected' AND received_at > now() - interval '24 hours'),"
              " (SELECT count(*) FROM flow_events WHERE status = 'received'),"
              " (SELECT count(*) FROM tickets WHERE status NOT IN ('resolved', 'closed')),"
              " (SELECT count(*) FROM tickets WHERE status NOT IN ('resolved', 'closed') AND sla_due_at < now()),"
              " (SELECT count(*) FROM tickets WHERE status NOT IN ('resolved', 'closed') AND needs_review),"
              " (SELECT count(*) FROM response_actions WHERE status = 'proposed')")
    keys = ("flows_24h", "attacks_24h", "rejected_24h", "waiting_flows", "open_tickets", "overdue", "needs_review",
            "pending_actions")
    model = one("SELECT model_id, left(sha256, 12), approved_by, activated_at FROM models WHERE status = 'active'")
    check_failed = one("SELECT count(*) FROM model_events WHERE event = 'check_failed' AND at > now() - interval '24 hours'")[0]
    hb = one("SELECT status, at FROM agent_heartbeats WHERE agent = 'detection'")
    backlog = []
    for consumer, topic in AGENT_CONSUMERS:
        n = one("SELECT count(*) FROM bus_messages m WHERE m.topic = %s AND m.id > "
                "coalesce((SELECT last_id FROM bus_offsets WHERE consumer = %s AND topic = %s), 0)",
                (topic, consumer, topic))[0]
        backlog.append({"agent": consumer, "topic": topic, "waiting": n})
    series = _rows(conn,
        "SELECT to_char(b, 'HH24:MI') AS t, "
        " count(d.event_id) FILTER (WHERE d.is_attack) AS attack, count(d.event_id) FILTER (WHERE NOT d.is_attack) AS benign "
        "FROM generate_series(date_bin('15 minutes', now() - interval '24 hours', 'epoch'), now(), interval '15 minutes') b "
        "LEFT JOIN detections d ON d.scored_at >= b AND d.scored_at < b + interval '15 minutes' GROUP BY b ORDER BY b")
    families = _rows(conn, "SELECT coalesce(family, 'Unnamed') AS family, count(*) AS n FROM detections "
                           "WHERE is_attack AND scored_at > now() - interval '24 hours' GROUP BY 1 ORDER BY 2 DESC")
    tickets = _rows(conn,
        "SELECT t.ticket_id, t.priority, t.status, t.needs_review, t.title, t.sla_due_at, t.assignee, "
        " t.sla_due_at < now() AS overdue, r.score, "
        " (SELECT count(*) FROM response_actions a WHERE a.case_id = t.case_id AND a.status = 'proposed') AS pending "
        "FROM tickets t LEFT JOIN LATERAL (SELECT score FROM risk_assessments WHERE case_id = t.case_id "
        " ORDER BY created_at DESC LIMIT 1) r ON true "
        "WHERE t.status NOT IN ('resolved', 'closed') ORDER BY t.priority, r.score DESC NULLS LAST, t.sla_due_at LIMIT 100")
    actions = _rows(conn,
        "SELECT a.action_id, a.action_type, a.target, a.disruptive, a.cautions, t.ticket_id, t.priority "
        "FROM response_actions a JOIN tickets t USING (case_id) WHERE a.status = 'proposed' "
        "ORDER BY t.priority, a.disruptive DESC, a.proposed_at LIMIT 100")
    return {"kpi": dict(zip(keys, kpi)), "model": model, "model_check_failures_24h": check_failed, "heartbeat": hb,
            "backlog": backlog, "tickets": tickets, "actions": actions,
            # "<" escaped so no value can ever close the <script> data block
            "chart_data": json.dumps({"series": series, "families": families}).replace("<", "\\u003c")}


def ticket_detail(conn, ticket_id: str) -> dict | None:
    t = _rows(conn, "SELECT * FROM tickets WHERE ticket_id = %s", (ticket_id,))
    if not t:
        return None
    t = t[0]
    inv = _rows(conn, "SELECT analysis, recommendations, llm_status, llm_model, guard_findings, telemetry, model_output "
                      "FROM investigations WHERE case_id = %s ORDER BY created_at DESC LIMIT 1", (t["case_id"],))
    risk = _rows(conn, "SELECT score, severity, factors, requires_review, review_reasons, rules_version "
                       "FROM risk_assessments WHERE case_id = %s ORDER BY created_at DESC LIMIT 1", (t["case_id"],))
    actions = _rows(conn, "SELECT action_id, action_type, target, rationale, disruptive, cautions, status, decided_by, "
                          "decision_note, completed_by FROM response_actions WHERE case_id = %s ORDER BY proposed_at",
                    (t["case_id"],))
    timeline = _rows(conn, "SELECT at, actor, event, detail FROM ticket_events WHERE ticket_id = %s ORDER BY id", (ticket_id,))
    return {"t": t, "inv": inv[0] if inv else None, "risk": risk[0] if risk else None, "actions": actions,
            "timeline": timeline, "json": lambda o: json.dumps(o, indent=2, default=str)}

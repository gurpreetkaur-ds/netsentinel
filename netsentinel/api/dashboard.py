"""SOC console (pipeline step 12): dashboard, threat monitoring, tickets, AI Security Agent, network map,
analytics, reports and settings, served by the API process under /dashboard.

Authentication: sign-in with an API key holding `events:read`. The browser then holds only a signed
session cookie (HttpOnly, SameSite=Strict, 8 h); the signing secret is random per process and never
stored, so a restart signs everyone out. Every request re-checks that the key is still active.

Authorization is server side on every route (security/rbac.py): viewer (read), analyst
(`tickets:write`: ticket work and AI requests) and approver (`actions:decide`). State-changing requests
need the same origin plus this session's CSRF token (form field or X-CSRF-Token header). Decisions
on response actions additionally ask for the API key again (step-up).
"""

import asyncio
import base64
import csv
import hashlib
import hmac
import io
import json
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from .. import assistant, remediation, tickets as tk
from ..agents import response as response_agent
from ..security import api_keys, rbac
from . import views

HERE = Path(__file__).parent
COOKIE = "ns_session"
SESSION_SECONDS = 8 * 3600
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
STATIC = {"chart.umd.min.js": "text/javascript", "dashboard.css": "text/css",
          "app.js": "text/javascript", "charts.js": "text/javascript", "agent.js": "text/javascript",
          "network.js": "text/javascript", "theme.js": "text/javascript"}
OK_MESSAGES = {"created": "Ticket created.", "updated": "Ticket updated.", "status": "Status changed.",
               "assigned": "Assignment updated.", "severity": "Severity changed.", "escalated": "Ticket escalated.",
               "comment": "Comment added.", "proposed": "Response action proposed. An approver must approve it.",
               "decided": "Decision recorded.", "simulated": "Simulation recorded. Nothing was changed on any system.",
               "verified": "Verification recorded.", "cancelled": "Action cancelled."}
EVENT_LABELS = {"created": "created the ticket", "refreshed": "refreshed the ticket from new evidence",
                "assigned": "changed the assignee", "status_changed": "changed the status", "resolved": "resolved the ticket",
                "closed": "closed the ticket", "reopened": "reopened the ticket", "severity_changed": "changed the severity",
                "escalated": "escalated the ticket", "updated": "edited the ticket", "attachment_added": "attached a file",
                "action_proposed": "proposed a response action", "action_approved": "approved a response action",
                "action_rejected": "rejected a response action", "action_completed": "confirmed an action was carried out",
                "action_cancelled": "cancelled a response action", "action_simulated": "ran a SIMULATED execution",
                "ai_requested": "asked the AI Security Agent", "ai_completed": "finished an AI investigation",
                "ai_failed": "AI request failed", "ai_question": "asked the AI agent", "ai_investigate": "requested an AI investigation",
                "recommendation_accepted": "accepted an AI recommendation",
                "recommendation_rejected": "rejected an AI recommendation",
                "recommendation_dismissed": "dismissed an AI recommendation"}

templates = Jinja2Templates(directory=str(HERE / "ui" / "templates"))  # autoescape is on for .html


def _dt(v, fmt="%Y-%m-%d %H:%M"):
    if not v:
        return "–"
    if isinstance(v, str):
        try:
            v = datetime.fromisoformat(v)
        except ValueError:
            return v
    return v.astimezone(timezone.utc).strftime(fmt) + " UTC"


def _dur(seconds):
    if seconds is None:
        return "–"
    s = float(seconds)
    if s < 60:
        return f"{s:.0f}s"
    if s < 3600:
        return f"{s / 60:.0f}m"
    if s < 86400:
        return f"{int(s // 3600)}h {int(s % 3600 // 60)}m"
    return f"{s / 86400:.1f}d"


templates.env.filters["dt"] = _dt
templates.env.filters["dur"] = _dur
templates.env.filters["iso"] = lambda v: v.isoformat() if hasattr(v, "isoformat") else (v or "")
templates.env.filters["tojson_pretty"] = lambda o: json.dumps(o, indent=2, default=str)
templates.env.filters["label"] = lambda s: tk.STATUS_LABELS.get(s, (s or "").replace("_", " ").capitalize())
templates.env.globals.update(STATUS_LABELS=tk.STATUS_LABELS, CLOSURE_REASONS=tk.CLOSURE_REASONS, SEVERITIES=tk.SEVERITIES,
                             CATEGORIES=tk.CATEGORIES, EVENT_LABELS=EVENT_LABELS, ACTIONS=response_agent.ACTIONS,
                             QUICK=tk.QUICK)


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
        data = self.payload(token)
        return data["k"] if data else None

    def payload(self, token: str | None) -> dict | None:
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
        return data if data.get("exp", 0) > time.time() else None


def _secure_headers(resp: Response) -> Response:
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Frame-Options"] = "DENY"
    # same-origin (not no-referrer): browsers then send a real Origin on our own form posts,
    # which the CSRF check needs; other sites still get no referrer.
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return resp


def _page(request: Request, name: str, ctx: dict, status: int = 200) -> Response:
    return _secure_headers(templates.TemplateResponse(request, name, ctx, status_code=status))


def error_page(request: Request, status: int, message: str) -> Response:
    titles = {401: "Not signed in", 403: "Not allowed", 404: "Not found", 409: "That didn't work", 422: "Check the form",
              429: "Slow down"}
    return _page(request, "error.html", {"title": titles.get(status, "Something went wrong"), "message": message,
                                         "viewer": None, "status": status}, status)


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    return origin is None or origin.split("://", 1)[-1] == request.headers.get("host")


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _initials(name: str) -> str:
    parts = [p for p in name.replace("-", " ").replace("_", " ").split() if p[:1].isalnum()]
    return "".join(p[0] for p in parts[:2]).upper() or "?"


def _date(v: str | None):
    if not v:
        return None
    try:
        d = datetime.fromisoformat(v.strip())
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
    except ValueError:
        raise tk.TicketError("Dates must look like 2026-10-14 or 2026-10-14T18:30.") from None


def _int(v, default=1) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def build_router() -> APIRouter:
    router = APIRouter(prefix="/dashboard", include_in_schema=False)
    sessions = _Sessions()

    # ── identity & guards ──────────────────────────────────────────────────────────────────────
    def viewer(request: Request) -> dict | None:
        token = request.cookies.get(COOKIE)
        data = sessions.payload(token)
        if not data:
            return None
        with request.app.state.pool.connection() as conn:
            row = conn.execute("SELECT name, scopes FROM api_keys WHERE key_id = %s AND revoked_at IS NULL "
                               "AND (expires_at IS NULL OR expires_at > now()) AND 'events:read' = ANY(scopes)",
                               (data["k"],)).fetchone()
        if not row:
            return None
        return {"key_id": data["k"], "name": row[0], "scopes": row[1], "role": rbac.role(row[1]),
                "can_write": rbac.can(row[1], "write"), "can_decide": rbac.can(row[1], "decide"),
                "initials": _initials(row[0]), "actor": f"human:{row[0]}@dashboard", "expires": data["exp"]}

    def need(who: dict, permission: str) -> None:
        if not rbac.can(who["scopes"], permission):
            what = {"write": "edit tickets (it needs the 'tickets:write' permission)",
                    "decide": "decide on response actions (it needs the 'actions:decide' permission)"}[permission]
            raise HTTPException(403, ("forbidden", f"Your key can't {what}."))

    def api_viewer(request: Request, permission: str = "read") -> dict:
        who = viewer(request)
        if not who:
            raise HTTPException(401, ("unauthorized", "Your session has ended. Sign in again."))
        need(who, permission)
        if request.method == "POST":
            if not _same_origin(request):
                raise HTTPException(403, ("forbidden", "Cross-origin request refused."))
            if not hmac.compare_digest(request.headers.get("x-csrf-token", ""),
                                       sessions.csrf(request.cookies.get(COOKIE, ""))):
                raise HTTPException(403, ("forbidden", "This page has expired. Reload it and try again."))
        return who

    async def read_form(request: Request) -> dict:
        """Same-origin + CSRF check for HTML forms. Returns {field: [values]}."""
        if not _same_origin(request):
            raise HTTPException(403, ("forbidden", "Cross-origin request refused."))
        form = parse_qs((await request.body()).decode(errors="replace"), keep_blank_values=True)
        if not hmac.compare_digest((form.get("csrf") or [""])[0], sessions.csrf(request.cookies.get(COOKIE, ""))):
            raise HTTPException(403, ("forbidden", "This form has expired. Reload the page and try again."))
        return form

    def f1(form: dict, key: str, default: str = "") -> str:
        return (form.get(key) or [default])[0]

    async def step_up(request: Request, who: dict) -> dict:
        """For response-action decisions: same origin, this session's form token, and the API key typed again,
        which must be the signed-in key and hold 'actions:decide'. Returns the form fields (first values)."""
        form = {k: v[0] for k, v in (await read_form(request)).items()}
        client = _client(request)
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

    def base_ctx(request: Request, conn, who: dict, active: str, **kw) -> dict:
        ctx = {"viewer": who["name"], "who": who, "active": active, "csrf": sessions.csrf(request.cookies.get(COOKIE, "")),
               "counts": views.nav_counts(conn), "health": views.health(conn), "now": datetime.now(timezone.utc),
               "ok": OK_MESSAGES.get(request.query_params.get("ok", "")), "error": None}
        ctx.update(kw)
        return ctx

    def signed_in(request: Request):
        who = viewer(request)
        if not who:
            raise _Redirect("/dashboard/login")
        return who

    # ── sign-in ────────────────────────────────────────────────────────────────────────────────
    @router.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return _page(request, "login.html", {"error": None})

    @router.post("/login")
    async def login(request: Request):
        if not _same_origin(request):
            raise HTTPException(403, ("forbidden", "Cross-origin sign-in refused."))
        client = _client(request)
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
                with conn.transaction():
                    tk.audit(conn, f"human:{key.name}@dashboard", "session.sign_in", "api_key", key.key_id, client=client)
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

    # ── pages ──────────────────────────────────────────────────────────────────────────────────
    @router.get("", response_class=HTMLResponse)
    def index(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        r = views.rng(request.query_params.get("range"))
        with request.app.state.pool.connection() as conn:
            ctx = base_ctx(request, conn, who, "overview", **views.overview(conn, r))
        return _page(request, "index.html", ctx)

    @router.get("/threats", response_class=HTMLResponse)
    def threats(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        q = request.query_params
        filt = {"family": q.get("family", "")[:40], "severity": q.get("severity", "") if q.get("severity") in tk.SEVERITIES else "",
                "ip": q.get("ip", "")[:45], "has_ticket": q.get("has_ticket", "")}
        with request.app.state.pool.connection() as conn:
            try:
                data = views.threats(conn, range_key=views.rng(q.get("range")), page=_int(q.get("page")), **filt)
            except tk.TicketError as e:
                filt["ip"] = ""
                data = views.threats(conn, range_key=views.rng(q.get("range")), **filt)
                data["error_msg"] = str(e)
            ctx = base_ctx(request, conn, who, "threats", filt=filt, **data)
        ctx["error"] = data.get("error_msg")
        return _page(request, "threats.html", ctx)

    def _filters(q) -> tk.Filters:
        return tk.Filters(q=q.get("q", "")[:100], severity=q.getlist("severity"), status=_status_filter(q.getlist("status")),
                          category=q.get("category", "") if q.get("category") in tk.CATEGORIES else "",
                          assignee=q.get("assignee", "")[:100], sla=q.get("sla", ""), since=_date(q.get("since")),
                          until=_date(q.get("until")), quick=q.get("quick", "") if q.get("quick") in tk.QUICK else "",
                          sort=q.get("sort", "updated"), order=q.get("order", "desc"), page=_int(q.get("page")),
                          page_size=_int(q.get("size"), 25), source_ip=q.get("ip", "")[:45])

    def _status_filter(values: list[str]) -> list[str]:
        out = []
        for v in values:
            out += list(tk.ACTIVE) if v == "active" else [v] if v in tk.STATUSES else []
        return out

    @router.get("/tickets", response_class=HTMLResponse)
    def ticket_list(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        q = request.query_params
        error = None
        try:
            f = _filters(q)
        except tk.TicketError as e:
            f, error = tk.Filters(), str(e)
        with request.app.state.pool.connection() as conn:
            try:
                rows, total = tk.search(conn, f, viewer=who["name"])
            except tk.TicketError as e:
                f.source_ip, error = "", str(e)
                rows, total = tk.search(conn, f, viewer=who["name"])
            ctx = base_ctx(request, conn, who, "tickets", rows=rows, total=total, f=f, analysts=tk.analysts(conn),
                           pages=max(1, -(-total // f.page_size)), raw=q, status_values=q.getlist("status"))
        ctx["error"] = error

        def link(**changes):
            params = [(k, v) for k, v in q.multi_items() if k not in changes and k != "page"]
            for k, v in changes.items():
                if v not in (None, ""):
                    params += [(k, x) for x in v] if isinstance(v, list) else [(k, v)]
            return "/dashboard/tickets" + ("?" + urlencode(params) if params else "")
        ctx["link"] = link
        return _page(request, "tickets.html", ctx)

    @router.get("/tickets/new", response_class=HTMLResponse)
    def ticket_new(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        need(who, "write")
        case_id = request.query_params.get("case_id")
        with request.app.state.pool.connection() as conn:
            prefill, case = {}, None
            if case_id:
                try:
                    uuid.UUID(case_id)
                except ValueError:
                    raise HTTPException(404, ("not_found", "No such alert.")) from None
                case = views.rows(conn, "SELECT c.case_id::text, c.family, host(c.src_ip) AS src_ip, c.flow_count, c.first_seen, "
                                        "c.last_seen, r.severity, r.score, (SELECT host(f.dst_ip) FROM case_events ce JOIN "
                                        "flow_events f USING (event_id) WHERE ce.case_id = c.case_id AND f.dst_ip IS NOT NULL "
                                        "LIMIT 1) AS dst_ip, t.ticket_id FROM cases c LEFT JOIN LATERAL (SELECT severity, score "
                                        "FROM risk_assessments WHERE case_id = c.case_id ORDER BY created_at DESC LIMIT 1) r ON true "
                                        "LEFT JOIN tickets t ON t.case_id = c.case_id WHERE c.case_id = %s", (case_id,))
                if not case:
                    raise HTTPException(404, ("not_found", "No such alert."))
                case = case[0]
                if case["ticket_id"]:
                    return RedirectResponse(f"/dashboard/tickets/{case['ticket_id']}", status_code=303)
                prefill = {"title": f"{case['family'] or 'Unnamed'} activity from {case['src_ip'] or 'unknown source'}",
                           "severity": case["severity"] or "medium", "category": case["family"] or "Unnamed",
                           "source_ip": case["src_ip"] or "", "dest_ip": case["dst_ip"] or "",
                           "description": f"Created from alert {case['case_id']}: {case['flow_count']} flows between "
                                          f"{_dt(case['first_seen'])} and {_dt(case['last_seen'])}."}
            ctx = base_ctx(request, conn, who, "tickets", form=prefill, case=case, analysts=tk.analysts(conn),
                           duplicates=[])
        return _page(request, "ticket_new.html", ctx)

    @router.post("/tickets")
    async def ticket_create(request: Request):
        who = signed_in(request)
        need(who, "write")
        form = await read_form(request)
        fields = {k: f1(form, k) for k in ("title", "description", "severity", "category", "source_ip", "dest_ip",
                                           "affected_asset", "evidence_notes", "tags", "assignee", "due_at", "case_id")}
        case_id = fields.pop("case_id") or None
        confirm = f1(form, "confirm_duplicate") == "yes"
        with request.app.state.pool.connection() as conn:
            try:
                if case_id:
                    uuid.UUID(case_id)
                new = tk.NewTicket(title=fields["title"], severity=fields["severity"], category=fields["category"],
                                   description=fields["description"], source_ip=fields["source_ip"], dest_ip=fields["dest_ip"],
                                   affected_asset=fields["affected_asset"], evidence_notes=fields["evidence_notes"],
                                   tags=fields["tags"], assignee=None if fields["assignee"] in ("", "__none__") else
                                   (who["name"] if fields["assignee"] == "__me__" else fields["assignee"]),
                                   due_at=_date(fields["due_at"]))
                tk.validate_new(conn, new)
                dups = tk.find_duplicates(conn, source_ip=new.source_ip, category=new.category, case_id=case_id)
                if dups and not confirm:
                    ctx = base_ctx(request, conn, who, "tickets", form=fields | {"case_id": case_id}, case=None,
                                   analysts=tk.analysts(conn), duplicates=dups)
                    return _page(request, "ticket_new.html", ctx, 409)
                tid = tk.create(conn, new, actor=who["actor"], client=_client(request),
                                origin="alert" if case_id else "manual", case_id=case_id)
            except (tk.TicketError, ValueError) as e:
                ctx = base_ctx(request, conn, who, "tickets", form=fields | {"case_id": case_id}, case=None,
                               analysts=tk.analysts(conn), duplicates=[])
                ctx["error"] = str(e)
                return _page(request, "ticket_new.html", ctx, 422)
        return RedirectResponse(f"/dashboard/tickets/{tid}?ok=created", status_code=303)

    def render_ticket(request: Request, who: dict, ticket_id: str, *, error: str | None = None, status: int = 200):
        with request.app.state.pool.connection() as conn:
            d = tk.detail(conn, ticket_id)
            if d is None:
                raise HTTPException(404, ("not_found", "No such ticket."))
            recs = views.rows(conn, "SELECT rec_id::text, run_id::text, kind, title, body, rationale, confidence, evidence_refs, "
                                    "priority, status, decided_by, decided_at, decision_note, created_at FROM ai_recommendations "
                                    "WHERE ticket_id = %s ORDER BY status = 'proposed' DESC, priority, created_at DESC LIMIT 60",
                              (ticket_id,))
            latest = views.rows(conn, "SELECT run_id::text, conversation_id::text, result, guard_findings, model, status, "
                                      "finished_at, tool_calls FROM ai_runs WHERE ticket_id = %s AND status = 'completed' "
                                      "AND kind = 'investigate' ORDER BY finished_at DESC LIMIT 1", (ticket_id,))
            if not latest:
                latest = views.rows(conn, "SELECT run_id::text, conversation_id::text, result, guard_findings, model, status, "
                                          "finished_at, tool_calls FROM ai_runs WHERE ticket_id = %s AND status = 'completed' "
                                          "ORDER BY finished_at DESC LIMIT 1", (ticket_id,))
            ctx = base_ctx(request, conn, who, "tickets", **d, recs=recs, latest=latest[0] if latest else None,
                           analysts=tk.analysts(conn), executors=remediation.EXECUTORS,
                           sim_steps=remediation.SIMULATED_STEPS)
        ctx["error"] = error
        return _page(request, "ticket.html", ctx, status)

    @router.get("/tickets/{ticket_id}", response_class=HTMLResponse)
    def ticket_page(request: Request, ticket_id: str):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        return render_ticket(request, who, ticket_id)

    async def ticket_op(request: Request, ticket_id: str, op, ok: str, permission: str = "write"):
        who = signed_in(request)
        need(who, permission)
        form = await read_form(request)
        try:
            with request.app.state.pool.connection() as conn:
                op(conn, who, form)
        except tk.NotFound:
            raise HTTPException(404, ("not_found", "No such ticket.")) from None
        except (tk.TicketError, remediation.RemediationError, ValueError) as e:
            return render_ticket(request, who, ticket_id, error=str(e), status=409)
        anchor = f1(form, "return", "")
        anchor = anchor if anchor in ("ai", "collab", "resolution", "evidence", "timeline", "response") else ""
        return RedirectResponse(f"/dashboard/tickets/{ticket_id}?ok={ok}" + (f"#{anchor}" if anchor else ""), status_code=303)

    @router.post("/tickets/{ticket_id}/status")
    async def ticket_status(request: Request, ticket_id: str):
        def op(conn, who, form):
            tk.transition(conn, ticket_id, f1(form, "to"), actor=who["actor"], note=f1(form, "note"),
                          closure_reason=f1(form, "closure_reason") or None, duplicate_of=f1(form, "duplicate_of") or None,
                          client=_client(request))
        return await ticket_op(request, ticket_id, op, "status")

    @router.post("/tickets/{ticket_id}/assign")
    async def ticket_assign(request: Request, ticket_id: str):
        def op(conn, who, form):
            a = f1(form, "assignee")
            tk.assign(conn, ticket_id, who["name"] if a == "__me__" else (None if a == "__none__" else a),
                      actor=who["actor"], client=_client(request))
        return await ticket_op(request, ticket_id, op, "assigned")

    @router.post("/tickets/{ticket_id}/severity")
    async def ticket_severity(request: Request, ticket_id: str):
        def op(conn, who, form):
            tk.set_severity(conn, ticket_id, f1(form, "severity"), actor=who["actor"], note=f1(form, "note"),
                            client=_client(request))
        return await ticket_op(request, ticket_id, op, "severity")

    @router.post("/tickets/{ticket_id}/escalate")
    async def ticket_escalate(request: Request, ticket_id: str):
        def op(conn, who, form):
            tk.escalate(conn, ticket_id, actor=who["actor"], note=f1(form, "note"), client=_client(request))
        return await ticket_op(request, ticket_id, op, "escalated")

    @router.post("/tickets/{ticket_id}/edit")
    async def ticket_edit(request: Request, ticket_id: str):
        def op(conn, who, form):
            fields = {k: f1(form, k) for k in tk.EDITABLE if k in form}
            if "sla_due_at" in fields:
                fields["sla_due_at"] = _date(fields["sla_due_at"])
            tk.update_fields(conn, ticket_id, fields, actor=who["actor"], client=_client(request))
        return await ticket_op(request, ticket_id, op, "updated")

    @router.post("/tickets/{ticket_id}/comments")
    async def ticket_comment(request: Request, ticket_id: str):
        def op(conn, who, form):
            parent = f1(form, "parent_id")
            tk.add_comment(conn, ticket_id, f1(form, "body"), actor=who["actor"], kind=f1(form, "kind", "comment"),
                           parent_id=_int(parent, None) if parent else None, client=_client(request))
        return await ticket_op(request, ticket_id, op, "comment")

    @router.post("/tickets/{ticket_id}/actions")
    async def ticket_propose(request: Request, ticket_id: str):
        def op(conn, who, form):
            remediation.propose(conn, ticket_id, f1(form, "action_type"), f1(form, "target"),
                                rationale=tk.clean_text(f1(form, "rationale"), "Rationale", 1000, required=True),
                                proposed_by=who["actor"], params={"hours": _int(f1(form, "hours"), 24)})
        return await ticket_op(request, ticket_id, op, "proposed")

    @router.post("/tickets/{ticket_id}/close")
    async def close_ticket(request: Request, ticket_id: str):
        """Close with step-up confirmation (kept from the first dashboard version)."""
        who = signed_in(request)
        form = await step_up(request, who)
        try:
            with request.app.state.pool.connection() as conn:
                tk.transition(conn, ticket_id, "closed", actor=who["actor"], note=form["note"].strip(),
                              closure_reason=form.get("closure_reason") or "remediated", client=_client(request))
        except tk.NotFound:
            raise HTTPException(404, ("not_found", "No such ticket.")) from None
        except tk.TicketError as e:
            raise HTTPException(409, ("conflict", str(e))) from None
        return RedirectResponse(f"/dashboard/tickets/{ticket_id}", status_code=303)

    @router.post("/actions/{action_id}")
    async def decide_action(request: Request, action_id: str):
        who = signed_in(request)
        try:
            uuid.UUID(action_id)
        except ValueError:
            raise HTTPException(404, ("not_found", "No such action.")) from None
        form = await step_up(request, who)
        verb, note, client = form.get("decision"), form["note"].strip()[:500], _client(request)
        ok = "decided"
        try:
            with request.app.state.pool.connection() as conn:
                if verb == "complete":
                    response_agent.complete(conn, action_id, actor=who["actor"], note=note)
                    with conn.transaction():
                        tk.audit(conn, who["actor"], "action.complete", "response_action", action_id, client=client,
                                 detail={"note": note})
                elif verb in ("approve", "reject"):
                    remediation.decide(conn, action_id, approve=verb == "approve", actor=who["actor"], note=note,
                                             client=client)
                elif verb == "simulate":
                    remediation.execute(conn, action_id, actor=who["actor"], client=client)
                    ok = "simulated"
                elif verb == "cancel":
                    remediation.cancel(conn, action_id, actor=who["actor"], note=note, client=client)
                    ok = "cancelled"
                else:
                    raise HTTPException(422, ("invalid_request", "Unknown decision."))
                tid = conn.execute("SELECT coalesce(a.ticket_id, t.ticket_id) FROM response_actions a LEFT JOIN tickets t "
                                   "ON t.case_id = a.case_id WHERE a.action_id = %s", (action_id,)).fetchone()
        except (ValueError, remediation.RemediationError) as e:
            raise HTTPException(409, ("conflict", str(e))) from None
        return RedirectResponse(f"/dashboard/tickets/{tid[0]}?ok={ok}#response" if tid and tid[0] else "/dashboard",
                                status_code=303)

    @router.post("/executions/{execution_id}/verify")
    async def verify_execution(request: Request, execution_id: str):
        who = signed_in(request)
        need(who, "decide")
        form = await read_form(request)
        try:
            uuid.UUID(execution_id)
            with request.app.state.pool.connection() as conn:
                remediation.verify(conn, execution_id, actor=who["actor"], ok=f1(form, "result") == "verified",
                                   note=f1(form, "note"), client=_client(request))
                tid = conn.execute("SELECT coalesce(a.ticket_id, t.ticket_id) FROM action_executions e JOIN response_actions a "
                                   "USING (action_id) LEFT JOIN tickets t ON t.case_id = a.case_id WHERE e.execution_id = %s",
                                   (execution_id,)).fetchone()
        except (ValueError, remediation.RemediationError, tk.TicketError) as e:
            raise HTTPException(409, ("conflict", str(e))) from None
        return RedirectResponse(f"/dashboard/tickets/{tid[0]}?ok=verified#response", status_code=303)

    @router.get("/tickets/{ticket_id}/attachments/{attachment_id}")
    def attachment(request: Request, ticket_id: str, attachment_id: str):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        try:
            uuid.UUID(attachment_id)
        except ValueError:
            raise HTTPException(404, ("not_found", "Not found.")) from None
        with request.app.state.pool.connection() as conn:
            row = conn.execute("SELECT filename, data FROM ticket_attachments WHERE attachment_id = %s AND ticket_id = %s",
                               (attachment_id, ticket_id)).fetchone()
            if row:
                with conn.transaction():
                    tk.audit(conn, who["actor"], "attachment.download", "ticket", ticket_id, client=_client(request),
                             detail={"attachment_id": attachment_id})
        if not row:
            raise HTTPException(404, ("not_found", "Not found."))
        # always a download, never rendered: evidence files are untrusted content
        return Response(bytes(row[1]), media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{row[0]}"',
                                 "Content-Security-Policy": "default-src 'none'; sandbox"})

    @router.post("/api/tickets/{ticket_id}/attachments")
    async def attachment_upload(request: Request, ticket_id: str):
        who = api_viewer(request, "write")
        data = await request.body()
        name = request.headers.get("x-filename", "")
        try:
            name = bytes(name, "latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
        try:
            with request.app.state.pool.connection() as conn:
                aid = tk.add_attachment(conn, ticket_id, name, data, actor=who["actor"], client=_client(request))
        except tk.NotFound:
            raise HTTPException(404, ("not_found", "No such ticket.")) from None
        except tk.TicketError as e:
            raise HTTPException(422, ("invalid_attachment", str(e))) from None
        return {"attachment_id": aid}

    @router.get("/agent", response_class=HTMLResponse)
    def agent_page(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        sel = request.query_params.get("ticket", "")[:20]
        with request.app.state.pool.connection() as conn:
            recent = views.rows(conn, "SELECT ticket_id, title, severity, status, ai_status FROM tickets "
                                      "ORDER BY (status NOT IN ('resolved','closed')) DESC, updated_at DESC LIMIT 40")
            if sel and not any(r["ticket_id"] == sel for r in recent):
                extra = views.rows(conn, "SELECT ticket_id, title, severity, status, ai_status FROM tickets WHERE ticket_id = %s",
                                   (sel,))
                recent = extra + recent
            runs = views.rows(conn,
                "SELECT r.run_id::text, r.ticket_id, r.kind, r.prompt, r.status, r.requested_by, r.created_at, r.finished_at, "
                " r.tool_calls, r.model, jsonb_array_length(coalesce(r.result->'findings', '[]')) AS findings, "
                " (SELECT count(*) FROM ai_recommendations x WHERE x.run_id = r.run_id) AS recs "
                "FROM ai_runs r WHERE r.ticket_id IS NOT NULL OR r.requested_by = %s ORDER BY r.created_at DESC LIMIT 25",
                (who["actor"],))
            stats = views.one(conn, "SELECT count(*), count(*) FILTER (WHERE status = 'completed'), "
                                    "count(*) FILTER (WHERE status = 'failed'), "
                                    "(SELECT count(*) FROM ai_recommendations WHERE status = 'accepted'), "
                                    "(SELECT count(*) FROM ai_recommendations WHERE status IN ('rejected', 'dismissed')) "
                                    "FROM ai_runs WHERE created_at > now() - interval '30 days'")
            ctx = base_ctx(request, conn, who, "agent", recent=recent, runs=runs, selected=sel,
                           stats=dict(zip(("runs", "completed", "failed", "accepted", "rejected"), stats)),
                           tools=assistant.TOOLS, max_tool_calls=assistant.MAX_TOOL_CALLS,
                           open_run=request.query_params.get("run", ""))
        return _page(request, "agent.html", ctx)

    @router.get("/network", response_class=HTMLResponse)
    def network_page(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        source = request.query_params.get("source", "replay")
        source = source if source in ("replay", "live", "all") else "replay"
        hours = {"24h": 24, "7d": 168, "30d": 720, "90d": 2160}.get(request.query_params.get("range", "30d"), 720)
        with request.app.state.pool.connection() as conn:
            ctx = base_ctx(request, conn, who, "network", **views.network(conn, source=source, hours=hours),
                           range=request.query_params.get("range", "30d") if request.query_params.get("range") in
                           ("24h", "7d", "30d", "90d") else "30d")
        return _page(request, "network.html", ctx)

    @router.get("/analytics", response_class=HTMLResponse)
    def analytics_page(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        with request.app.state.pool.connection() as conn:
            ctx = base_ctx(request, conn, who, "analytics", **views.analytics(conn, views.rng(request.query_params.get("range"))))
        return _page(request, "analytics.html", ctx)

    @router.get("/reports", response_class=HTMLResponse)
    def reports_page(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        with request.app.state.pool.connection() as conn:
            runs = views.rows(conn, "SELECT r.run_id::text, r.ticket_id, r.kind, r.prompt, r.finished_at, r.requested_by, "
                                    "t.title FROM ai_runs r LEFT JOIN tickets t USING (ticket_id) WHERE r.status = 'completed' "
                                    "AND (r.ticket_id IS NOT NULL OR r.requested_by = %s) ORDER BY r.finished_at DESC LIMIT 30",
                              (who["actor"],))
            recent = views.rows(conn, "SELECT ticket_id, title, severity, status, updated_at FROM tickets "
                                      "ORDER BY updated_at DESC LIMIT 30")
            ctx = base_ctx(request, conn, who, "reports", runs=runs, recent=recent)
        return _page(request, "reports.html", ctx)

    @router.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        import os
        from .. import llm
        with request.app.state.pool.connection() as conn:
            sla = views.rows(conn, "SELECT * FROM sla_policies ORDER BY ack_minutes")
            model = views.rows(conn, "SELECT model_id, left(sha256, 12) AS sha, approved_by, activated_at, metrics "
                                     "FROM models WHERE status = 'active'")
            audit = views.rows(conn, "SELECT at, actor, action, object_type, object_id, client FROM audit_log "
                                     "ORDER BY id DESC LIMIT 50") if who["can_decide"] else []
            people = views.rows(conn, "SELECT name, scopes, last_used_at FROM api_keys WHERE revoked_at IS NULL AND "
                                      "(expires_at IS NULL OR expires_at > now()) AND 'events:read' = ANY(scopes) "
                                      "AND name NOT LIKE '%%(ephemeral)%%' ORDER BY name")
            for p in people:
                p["role"] = rbac.role(p["scopes"])
            ctx = base_ctx(request, conn, who, "settings", sla=sla, model=model[0] if model else None, audit=audit,
                           people=people, ai_model=os.environ.get("NETSENTINEL_CLAUDE_MODEL", llm.DEFAULT_MODEL),
                           tools=assistant.TOOLS, executors=remediation.EXECUTORS, actions=response_agent.ACTIONS,
                           session_expires=datetime.fromtimestamp(who["expires"], timezone.utc))
        return _page(request, "settings.html", ctx)

    # ── reports & exports ──────────────────────────────────────────────────────────────────────
    def _download(text: str, name: str, media: str) -> Response:
        return Response(text.encode(), media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @router.get("/reports/tickets/{ticket_id}.md")
    def ticket_report(request: Request, ticket_id: str):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        from . import reports
        with request.app.state.pool.connection() as conn:
            text = reports.ticket_markdown(conn, ticket_id, generated_by=who["name"])
            if text is None:
                raise HTTPException(404, ("not_found", "No such ticket."))
            with conn.transaction():
                tk.audit(conn, who["actor"], "report.export", "ticket", ticket_id, client=_client(request))
        return _download(text, f"{ticket_id}-incident-report.md", "text/markdown; charset=utf-8")

    @router.get("/reports/runs/{run_id}.md")
    def run_report(request: Request, run_id: str):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        from . import reports
        try:
            uuid.UUID(run_id)
        except ValueError:
            raise HTTPException(404, ("not_found", "Not found.")) from None
        with request.app.state.pool.connection() as conn:
            text = reports.run_markdown(conn, run_id, viewer_actor=who["actor"])
        if text is None:
            raise HTTPException(404, ("not_found", "Not found."))
        return _download(text, f"ai-investigation-{run_id[:8]}.md", "text/markdown; charset=utf-8")

    @router.get("/reports/tickets.csv")
    def tickets_csv(request: Request):
        who = viewer(request)
        if not who:
            return RedirectResponse("/dashboard/login", status_code=303)
        try:
            f = _filters(request.query_params)
        except tk.TicketError as e:
            raise HTTPException(422, ("invalid_request", str(e))) from None
        f.page, f.page_size = 1, 100
        out = io.StringIO()
        w = csv.writer(out)
        cols = ["ticket_id", "title", "severity", "priority", "status", "category", "source_ip", "dest_ip", "affected_asset",
                "assignee", "origin", "created_at", "updated_at", "sla_due_at", "overdue", "acknowledged_at", "resolved_at",
                "escalated", "ai_status"]
        w.writerow(cols)
        with request.app.state.pool.connection() as conn:
            n = 0
            while n < 5000:
                rows, total = tk.search(conn, f, viewer=who["name"])
                for r in rows:
                    w.writerow([_csv_safe(r[c]) for c in cols])
                n += len(rows)
                if not rows or n >= total:
                    break
                f.page += 1
            with conn.transaction():
                tk.audit(conn, who["actor"], "report.export_csv", "tickets", "*", client=_client(request), detail={"rows": n})
        return _download(out.getvalue(), "netsentinel-tickets.csv", "text/csv; charset=utf-8")

    # ── JSON API for the console ───────────────────────────────────────────────────────────────
    @router.get("/api/search")
    def api_search(request: Request):
        api_viewer(request)
        with request.app.state.pool.connection() as conn:
            return JSONResponse(json.loads(json.dumps(views.search(conn, request.query_params.get("q", "")), default=str)))

    @router.get("/api/notifications")
    def api_notifications(request: Request):
        who = api_viewer(request)
        with request.app.state.pool.connection() as conn:
            items = views.notifications(conn, who["name"])
        return JSONResponse(json.loads(json.dumps({"items": items}, default=str)))

    @router.get("/api/health")
    def api_health(request: Request):
        api_viewer(request)
        with request.app.state.pool.connection() as conn:
            return JSONResponse(json.loads(json.dumps(views.health(conn), default=str)))

    @router.post("/api/ai/runs")
    async def api_ai_start(request: Request):
        who = api_viewer(request, "write")
        try:
            body = json.loads(await request.body() or b"{}")
        except ValueError:
            raise HTTPException(422, ("invalid_request", "Body must be JSON.")) from None
        if not isinstance(body, dict):
            raise HTTPException(422, ("invalid_request", "Body must be a JSON object."))
        ticket_id = body.get("ticket_id") or None
        conv = body.get("conversation_id") or None
        if conv:
            try:
                uuid.UUID(str(conv))
            except ValueError:
                conv = None
        try:
            with request.app.state.pool.connection() as conn:
                res = assistant.enqueue(conn, requested_by=who["actor"], prompt=str(body.get("prompt", "")),
                                        ticket_id=str(ticket_id) if ticket_id else None,
                                        kind="investigate" if body.get("kind") == "investigate" else "question",
                                        conversation_id=conv, client=_client(request))
        except assistant.RateLimited as e:
            raise HTTPException(429, ("rate_limited", str(e))) from None
        except tk.NotFound as e:
            raise HTTPException(404, ("not_found", str(e))) from None
        except tk.TicketError as e:
            raise HTTPException(422, ("invalid_request", str(e))) from None
        return JSONResponse(res, 202)

    def _run_visible(conn, run_id: str, who: dict) -> dict | None:
        try:
            uuid.UUID(run_id)
        except ValueError:
            return None
        r = views.rows(conn, "SELECT run_id::text, conversation_id::text, ticket_id, requested_by, kind, prompt, status, result, "
                             "guard_findings, error, model, tool_calls, created_at, started_at, finished_at FROM ai_runs "
                             "WHERE run_id = %s", (run_id,))
        if not r or (r[0]["ticket_id"] is None and r[0]["requested_by"] != who["actor"]):
            return None
        return r[0]

    @router.get("/api/ai/runs/{run_id}")
    def api_ai_run(request: Request, run_id: str):
        who = api_viewer(request)
        with request.app.state.pool.connection() as conn:
            run = _run_visible(conn, run_id, who)
            if not run:
                raise HTTPException(404, ("not_found", "No such AI run."))
            run["recommendations"] = views.rows(conn,
                "SELECT rec_id::text, kind, title, body, rationale, confidence, evidence_refs, priority, status, decided_by, "
                "decision_note FROM ai_recommendations WHERE run_id = %s ORDER BY priority, created_at", (run_id,))
            run["events"] = views.rows(conn, "SELECT id, at, kind, data FROM ai_run_events WHERE run_id = %s ORDER BY id",
                                       (run_id,))
            if request.query_params.get("history") == "1":
                run["history"] = views.rows(conn,
                    "SELECT run_id::text, prompt, status, result->>'answer' AS answer, error, created_at FROM ai_runs "
                    "WHERE conversation_id = %s AND created_at <= %s ORDER BY created_at",
                    (run["conversation_id"], run["created_at"]))
        return JSONResponse(json.loads(json.dumps(run, default=str)))

    @router.get("/api/ai/runs/{run_id}/stream")
    async def api_ai_stream(request: Request, run_id: str):
        """Server-sent events: progress of one run, read from ai_run_events. Ends at 'final' or 'error'."""
        who = await run_in_threadpool(api_viewer, request)
        pool = request.app.state.pool

        def visible():
            with pool.connection() as conn:
                return _run_visible(conn, run_id, who)
        if not await run_in_threadpool(visible):
            raise HTTPException(404, ("not_found", "No such AI run."))
        after = _int(request.headers.get("last-event-id") or request.query_params.get("after"), 0)

        def fetch(last):
            with pool.connection() as conn:
                return views.rows(conn, "SELECT id, at, kind, data FROM ai_run_events WHERE run_id = %s AND id > %s "
                                        "ORDER BY id LIMIT 100", (run_id, last))

        async def gen():
            last, started = after, time.monotonic()
            yield "retry: 3000\n\n"
            while time.monotonic() - started < 300:
                if await request.is_disconnected():
                    return
                done = False
                for e in await run_in_threadpool(fetch, last):
                    last = e["id"]
                    yield f"id: {e['id']}\nevent: {e['kind']}\ndata: {json.dumps(e, default=str)}\n\n"
                    done = done or e["kind"] in ("final", "error")
                if done:
                    return
                yield ": keep-alive\n\n"
                await asyncio.sleep(0.8)
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @router.post("/api/ai/recommendations/{rec_id}")
    async def api_ai_decide(request: Request, rec_id: str):
        who = api_viewer(request, "write")
        try:
            uuid.UUID(rec_id)
            body = json.loads(await request.body() or b"{}")
        except ValueError:
            raise HTTPException(422, ("invalid_request", "Bad request.")) from None
        decision = body.get("decision")
        if decision not in ("accept", "reject", "dismiss"):
            raise HTTPException(422, ("invalid_request", "decision must be accept, reject or dismiss"))
        try:
            with request.app.state.pool.connection() as conn:
                result = _apply_recommendation(conn, rec_id, decision, who, str(body.get("note", ""))[:500], _client(request))
        except tk.NotFound as e:
            raise HTTPException(404, ("not_found", str(e))) from None
        except (tk.TicketError, remediation.RemediationError) as e:
            raise HTTPException(409, ("conflict", str(e))) from None
        return JSONResponse(json.loads(json.dumps(result, default=str)))

    # ── static & files ─────────────────────────────────────────────────────────────────────────
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
        if name not in STATIC or not (HERE / "ui" / "static" / name).is_file():
            raise HTTPException(404, ("not_found", "Not found."))
        return Response((HERE / "ui" / "static" / name).read_bytes(), media_type=STATIC[name],
                        headers={"Cache-Control": "private, max-age=300"})

    return router


class _Redirect(HTTPException):
    def __init__(self, location: str):
        super().__init__(303, ("redirect", "Sign in again."), {"Location": location})


def _csv_safe(v):
    """Neutralise spreadsheet formula injection in exported text."""
    if v is None:
        return ""
    s = v.isoformat() if hasattr(v, "isoformat") else ",".join(v) if isinstance(v, list) else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _apply_recommendation(conn, rec_id: str, decision: str, who: dict, note: str, client: str) -> dict:
    """A human decides on an AI recommendation. Accepting applies it through the same server-side checks as
    doing it by hand; nothing the agent proposes bypasses permissions or validation."""
    rec = views.rows(conn, "SELECT rec_id::text, run_id::text, ticket_id, kind, title, body, status FROM ai_recommendations "
                           "WHERE rec_id = %s", (rec_id,))
    if not rec:
        raise tk.NotFound("No such recommendation.")
    rec = rec[0]
    if rec["status"] != "proposed":
        raise tk.TicketError("This recommendation was already decided.")
    tid, body, effect = rec["ticket_id"], rec["body"], None
    if decision == "accept":
        if not tid:
            raise tk.TicketError("Only recommendations about a ticket can be applied.")
        kind = rec["kind"]
        if kind == "comment_draft":
            effect = {"comment_id": tk.add_comment(conn, tid, body.get("text", ""), actor=who["actor"], ai_drafted=True,
                                                   client=client)}
        elif kind == "severity_change":
            tk.set_severity(conn, tid, body.get("severity"), actor=who["actor"],
                            note=note or f"Accepted AI recommendation: {rec['title']}", client=client)
            effect = {"severity": body.get("severity")}
        elif kind == "escalation":
            tk.escalate(conn, tid, actor=who["actor"], note=note or f"Accepted AI recommendation: {rec['title']}", client=client)
            effect = {"escalated": True}
        elif kind == "remediation":
            # becomes a response-action PROPOSAL; an approver must still approve it
            row = conn.execute("SELECT host(source_ip), host(dest_ip), summary FROM tickets WHERE ticket_id = %s",
                               (tid,)).fetchone()
            allowed = {ip for ip in row[:2] if ip} | set(views.json_ips(row[2]))
            effect = {"action_id": remediation.propose(
                conn, tid, body.get("action_type", ""), body.get("target", ""), proposed_by="agent:assistant",
                rationale=f"AI recommendation accepted by {who['name']}: {rec['title']}", run_id=rec["run_id"],
                allowed_ips=allowed)}
        elif kind == "resolution_draft":
            effect = {"text": body.get("text", "")}
    status = {"accept": "accepted", "reject": "rejected", "dismiss": "dismissed"}[decision]
    with conn.transaction():
        n = conn.execute("UPDATE ai_recommendations SET status = %s, decided_by = %s, decided_at = now(), decision_note = %s "
                         "WHERE rec_id = %s AND status = 'proposed'", (status, who["actor"], note or None, rec_id)).rowcount
        if n != 1:
            raise tk.TicketError("This recommendation was already decided.")
        if tid:
            tk.event(conn, tid, who["actor"], f"recommendation_{status}", {"rec_id": rec_id, "kind": rec["kind"],
                                                                          "title": rec["title"][:200]})
        tk.audit(conn, who["actor"], f"ai.recommendation.{status}", "ai_recommendation", rec_id, client=client,
                 detail={"kind": rec["kind"], "effect": effect})
    return {"status": status, "effect": effect}

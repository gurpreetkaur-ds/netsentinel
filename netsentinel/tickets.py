"""Ticket service: the one place tickets are created and changed (dashboard, CLI and agents).

Every change runs in one transaction with its timeline entry (ticket_events) and, for human actions,
an audit_log row. The database enforces the lifecycle (tickets_guard); the checks here exist to give
clear errors before the database would refuse.
"""

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from psycopg.types.json import Jsonb

SEVERITIES = ("low", "medium", "high", "critical")
ACTIVE = ("open", "acknowledged", "investigating", "in_progress", "awaiting_approval")
STATUSES = ACTIVE + ("resolved", "closed")
CATEGORIES = ("PortScan", "DoS", "DDoS", "BruteForce", "WebAttack", "Botnet", "Infiltration", "Exploit", "Malware",
              "Phishing", "Data exfiltration", "Policy violation", "Unnamed", "Other")
CLOSURE_REASONS = {"remediated": "Remediated", "false_positive": "False positive", "duplicate": "Duplicate",
                   "benign": "Benign (expected activity)", "risk_accepted": "Risk accepted",
                   "no_action_needed": "No action needed", "other": "Other"}
STATUS_LABELS = {"open": "Open", "acknowledged": "Acknowledged", "investigating": "Investigating",
                 "in_progress": "In progress", "awaiting_approval": "Awaiting approval", "resolved": "Resolved",
                 "closed": "Closed"}
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9:._-]{0,39}$")
ATTACHMENT_TYPES = {  # extension -> (served type, how to check the content)
    ".txt": ("text/plain", "text"), ".log": ("text/plain", "text"), ".csv": ("text/csv", "text"),
    ".json": ("application/json", "json"), ".md": ("text/markdown", "text"), ".xml": ("application/xml", "text"),
    ".yaml": ("text/yaml", "text"), ".yml": ("text/yaml", "text"),
    ".pcap": ("application/vnd.tcpdump.pcap", "pcap"), ".pcapng": ("application/vnd.tcpdump.pcap", "pcapng"),
    ".png": ("image/png", "png"), ".jpg": ("image/jpeg", "jpeg"), ".jpeg": ("image/jpeg", "jpeg"),
    ".pdf": ("application/pdf", "pdf"),
}
MAGIC = {"png": (b"\x89PNG\r\n\x1a\n",), "jpeg": (b"\xff\xd8\xff",), "pdf": (b"%PDF-",),
         "pcap": (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"),
         "pcapng": (b"\x0a\x0d\x0d\x0a",)}
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
MAX_ATTACHMENTS_PER_TICKET = 25


class TicketError(ValueError):
    """A request that conflicts with the ticket's state or fails validation (shown to the user)."""


class NotFound(TicketError):
    pass


def _dumps(o):
    return json.dumps(o, default=str)


def event(conn, ticket_id: str, actor: str, name: str, detail: dict) -> None:
    conn.execute("INSERT INTO ticket_events (ticket_id, actor, event, detail) VALUES (%s, %s, %s, %s)",
                 (ticket_id, actor, name, Jsonb(detail, dumps=_dumps)))


def audit(conn, actor: str, action: str, object_type: str, object_id: str, *, client: str | None = None,
          detail: dict | None = None) -> None:
    conn.execute("INSERT INTO audit_log (actor, action, object_type, object_id, client, detail) "
                 "VALUES (%s, %s, %s, %s, %s, %s)",
                 (actor, action, object_type, str(object_id), client, Jsonb(detail or {}, dumps=_dumps)))


def _locked(conn, ticket_id: str) -> dict:
    cur = conn.execute("SELECT * FROM tickets WHERE ticket_id = %s FOR UPDATE", (ticket_id,))
    row = cur.fetchone()
    if not row:
        raise NotFound(f"{ticket_id} not found")
    return dict(zip([c.name for c in cur.description], row))


# ── validation ─────────────────────────────────────────────────────────────────────────────────
def clean_text(value, field: str, max_len: int, *, required: bool = False) -> str:
    v = (value or "").replace("\r\n", "\n").strip()
    v = "".join(ch for ch in v if ch == "\n" or ch == "\t" or ord(ch) >= 32)   # no control characters
    if required and not v:
        raise TicketError(f"{field} is required.")
    if len(v) > max_len:
        raise TicketError(f"{field} must be at most {max_len} characters.")
    return v


def clean_ip(value, field: str) -> str | None:
    v = (value or "").strip()
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise TicketError(f"{field} must be an IPv4 or IPv6 address.") from None


def clean_tags(value) -> list[str]:
    raw = value if isinstance(value, list) else (value or "").split(",")
    tags = sorted({t.strip().lower() for t in raw if t and t.strip()})
    bad = [t for t in tags if not TAG_RE.match(t)]
    if bad:
        raise TicketError("Tags may use lowercase letters, digits and : . _ - (max 40 characters each).")
    if len(tags) > 20:
        raise TicketError("At most 20 tags.")
    return tags


def _choice(value, allowed, field: str) -> str:
    if value not in allowed:
        raise TicketError(f"{field} must be one of: {', '.join(allowed)}.")
    return value


def analysts(conn) -> list[str]:
    """People who can own tickets: active, non-ephemeral keys that may edit tickets."""
    return [r[0] for r in conn.execute(
        "SELECT DISTINCT name FROM api_keys WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) "
        "AND 'events:read' = ANY(scopes) AND scopes && ARRAY['tickets:write', 'actions:decide'] "
        "AND name NOT LIKE '%%(ephemeral)%%' ORDER BY name")]


# ── create ─────────────────────────────────────────────────────────────────────────────────────
@dataclass
class NewTicket:
    title: str
    severity: str
    category: str
    description: str = ""
    source_ip: str | None = None
    dest_ip: str | None = None
    affected_asset: str | None = None
    evidence_notes: str = ""
    tags: list | str | None = None
    assignee: str | None = None
    due_at: datetime | None = None


def validate_new(conn, t: NewTicket) -> NewTicket:
    t.title = clean_text(t.title, "Title", 300, required=True)
    t.description = clean_text(t.description, "Description", 5000)
    t.evidence_notes = clean_text(t.evidence_notes, "Evidence", 10000)
    t.affected_asset = clean_text(t.affected_asset, "Affected asset", 200) or None
    t.severity = _choice(t.severity, SEVERITIES, "Severity")
    t.category = _choice(t.category, CATEGORIES, "Category")
    t.source_ip = clean_ip(t.source_ip, "Source IP")
    t.dest_ip = clean_ip(t.dest_ip, "Destination IP")
    t.tags = clean_tags(t.tags)
    if t.assignee and t.assignee not in analysts(conn):
        raise TicketError("The assignee must be an analyst with ticket permissions.")
    if t.due_at and t.due_at <= datetime.now(timezone.utc):
        raise TicketError("The due date must be in the future.")
    return t


def find_duplicates(conn, *, source_ip: str | None, category: str | None, case_id=None,
                    exclude: str | None = None) -> list[dict]:
    """Active tickets that probably describe the same incident: same alert, or same source + category
    within 14 days."""
    if not source_ip and not case_id:
        return []
    return _rows(conn,
        "SELECT ticket_id, title, status, severity, created_at FROM tickets "
        "WHERE status NOT IN ('resolved', 'closed') AND ticket_id IS DISTINCT FROM %s AND ("
        " (%s::uuid IS NOT NULL AND case_id = %s::uuid) OR "
        " (%s::inet IS NOT NULL AND source_ip = %s::inet AND category = %s AND created_at > now() - interval '14 days')) "
        "ORDER BY created_at DESC LIMIT 5",
        (exclude, case_id, case_id, source_ip, source_ip, category))


def create(conn, t: NewTicket, *, actor: str, client: str | None = None, origin: str = "manual",
           case_id=None, duplicate_of: str | None = None) -> str:
    t = validate_new(conn, t)
    with conn.transaction():
        summary = {"MANUAL": {"created_by": actor}}
        if case_id is not None:
            case = conn.execute("SELECT host(src_ip), family, flow_count, first_seen, last_seen FROM cases "
                                "WHERE case_id = %s FOR UPDATE", (case_id,)).fetchone()
            if not case:
                raise NotFound("No such alert.")
            existing = conn.execute("SELECT ticket_id FROM tickets WHERE case_id = %s", (case_id,)).fetchone()
            if existing:
                raise TicketError(f"This alert already has ticket {existing[0]}.")
            summary = {"VERIFIED TELEMETRY": {"source_ip": case[0], "flows": case[2], "first_seen": case[3],
                                              "last_seen": case[4]},
                       "MODEL OUTPUT": {"family": case[1]}, "MANUAL": {"created_by": actor}}
        tid = conn.execute(
            "INSERT INTO tickets (case_id, title, description, severity, priority, status, sla_due_at, ack_due_at, "
            " summary, origin, created_by, category, source_ip, dest_ip, affected_asset, evidence_notes, tags, "
            " assignee, duplicate_of) "
            "SELECT %s, %s, %s, p.severity, p.priority, 'open', coalesce(%s, now() + make_interval(mins => p.resolve_minutes)), "
            " now() + make_interval(mins => p.ack_minutes), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s "
            "FROM sla_policies p WHERE p.severity = %s RETURNING ticket_id",
            (case_id, t.title, t.description, t.due_at, Jsonb(summary, dumps=_dumps), origin, actor, t.category,
             t.source_ip, t.dest_ip, t.affected_asset, t.evidence_notes, t.tags, t.assignee, duplicate_of,
             t.severity)).fetchone()[0]
        event(conn, tid, actor, "created", {"origin": origin, "severity": t.severity, "category": t.category,
                                            "case_id": case_id, "duplicate_of": duplicate_of})
        if t.assignee:
            event(conn, tid, actor, "assigned", {"from": None, "to": t.assignee})
        if case_id is not None:
            conn.execute("INSERT INTO case_history (case_id, status, actor, detail) "
                         "SELECT case_id, status, %s, %s FROM cases WHERE case_id = %s",
                         (actor, Jsonb({"ticket_id": tid, "note": "ticket created from alert"}), case_id))
        audit(conn, actor, "ticket.create", "ticket", tid, client=client,
              detail={"origin": origin, "severity": t.severity, "case_id": case_id})
    return tid


# ── changes ────────────────────────────────────────────────────────────────────────────────────
def allowed_transitions(status: str) -> list[str]:
    """Mirrors ticket_transition_ok() in migration 0010."""
    if status in ACTIVE:
        out = (["acknowledged"] if status == "open" else []) + ["investigating", "in_progress", "awaiting_approval",
                                                                "resolved", "closed"]
        return [s for s in out if s != status]
    if status == "resolved":
        return ["investigating", "closed"]
    return []


def transition(conn, ticket_id: str, to: str, *, actor: str, note: str = "", client: str | None = None,
               closure_reason: str | None = None, duplicate_of: str | None = None) -> dict:
    to = _choice(to, STATUSES, "Status")
    note = clean_text(note, "Note", 2000)
    with conn.transaction():
        t = _locked(conn, ticket_id)
        frm = t["status"]
        if to not in allowed_transitions(frm):
            raise TicketError(f"A ticket that is {STATUS_LABELS[frm].lower()} cannot move to "
                              f"{STATUS_LABELS[to].lower()}.")
        sets, params = ["status = %s", "updated_at = now()"], [to]
        if to == "resolved":
            if not note:
                raise TicketError("Resolution notes are required to resolve a ticket.")
            sets += ["resolved_at = now()", "resolution = %s"]
            params.append(note)
        elif to == "closed":
            reason = _choice(closure_reason, tuple(CLOSURE_REASONS), "Closure reason")
            if reason == "duplicate":
                if not duplicate_of or not conn.execute("SELECT 1 FROM tickets WHERE ticket_id = %s AND ticket_id <> %s",
                                                        (duplicate_of, ticket_id)).fetchone():
                    raise TicketError("Name the ticket this one duplicates.")
                sets.append("duplicate_of = %s")
                params.append(duplicate_of)
            if frm != "resolved" and not note:
                raise TicketError("Explain why the ticket is closed without being resolved.")
            sets += ["closure_reason = %s", "resolved_at = coalesce(resolved_at, now())",
                     "resolution = coalesce(nullif(%s, ''), resolution)"]
            params += [reason, note]
        elif frm == "resolved":   # reopen
            if not note:
                raise TicketError("A reason is required to reopen a ticket.")
            sets += ["resolved_at = NULL"]
        conn.execute(f"UPDATE tickets SET {', '.join(sets)} WHERE ticket_id = %s", (*params, ticket_id))
        name = {"resolved": "resolved", "closed": "closed"}.get(to, "reopened" if frm == "resolved" else "status_changed")
        detail = {"from": frm, "to": to}
        if note:
            detail["note"] = note
        if to == "closed":
            detail["closure_reason"] = closure_reason
        event(conn, ticket_id, actor, name, detail)
        if to == "closed" and t["case_id"]:
            conn.execute("UPDATE cases SET status = 'closed', updated_at = now() WHERE case_id = %s", (t["case_id"],))
            conn.execute("INSERT INTO case_history (case_id, status, actor, detail) VALUES (%s, 'closed', %s, %s)",
                         (t["case_id"], actor, Jsonb({"ticket_id": ticket_id})))
        audit(conn, actor, f"ticket.{name}", "ticket", ticket_id, client=client, detail=detail)
    return detail


def assign(conn, ticket_id: str, assignee: str | None, *, actor: str, client: str | None = None,
           check_analyst: bool = True) -> None:
    assignee = (assignee or "").strip() or None
    if assignee and check_analyst and assignee not in analysts(conn):
        raise TicketError("The assignee must be an analyst with ticket permissions.")
    with conn.transaction():
        t = _locked(conn, ticket_id)
        if t["status"] == "closed":
            raise TicketError("Closed tickets cannot be reassigned.")
        if t["assignee"] == assignee:
            return
        conn.execute("UPDATE tickets SET assignee = %s, updated_at = now() WHERE ticket_id = %s", (assignee, ticket_id))
        event(conn, ticket_id, actor, "assigned", {"from": t["assignee"], "to": assignee})
        audit(conn, actor, "ticket.assign", "ticket", ticket_id, client=client,
              detail={"from": t["assignee"], "to": assignee})


def set_severity(conn, ticket_id: str, severity: str, *, actor: str, note: str, client: str | None = None) -> None:
    severity = _choice(severity, SEVERITIES, "Severity")
    note = clean_text(note, "Reason", 2000, required=True)
    with conn.transaction():
        t = _locked(conn, ticket_id)
        if t["status"] == "closed":
            raise TicketError("Closed tickets cannot change severity.")
        if t["severity"] == severity:
            raise TicketError(f"The ticket is already {severity}.")
        # SLA deadlines follow the new policy, measured from when the ticket was opened
        conn.execute(
            "UPDATE tickets t SET severity = p.severity, priority = p.priority, severity_locked = true, updated_at = now(), "
            "sla_due_at = t.created_at + make_interval(mins => p.resolve_minutes), "
            "ack_due_at = t.created_at + make_interval(mins => p.ack_minutes) "
            "FROM sla_policies p WHERE p.severity = %s AND t.ticket_id = %s", (severity, ticket_id))
        detail = {"from": t["severity"], "to": severity, "note": note}
        event(conn, ticket_id, actor, "severity_changed", detail)
        audit(conn, actor, "ticket.severity", "ticket", ticket_id, client=client, detail=detail)


def escalate(conn, ticket_id: str, *, actor: str, note: str, client: str | None = None) -> None:
    note = clean_text(note, "Reason", 2000, required=True)
    with conn.transaction():
        t = _locked(conn, ticket_id)
        if t["status"] in ("resolved", "closed"):
            raise TicketError("Only active tickets can be escalated.")
        if t["escalated"]:
            raise TicketError("The ticket is already escalated.")
        conn.execute("UPDATE tickets SET escalated = true, updated_at = now() WHERE ticket_id = %s", (ticket_id,))
        event(conn, ticket_id, actor, "escalated", {"note": note})
        audit(conn, actor, "ticket.escalate", "ticket", ticket_id, client=client, detail={"note": note})


EDITABLE = ("title", "description", "category", "source_ip", "dest_ip", "affected_asset", "evidence_notes", "tags",
            "sla_due_at")


def update_fields(conn, ticket_id: str, fields: dict, *, actor: str, client: str | None = None) -> list[str]:
    clean = {}
    for k, v in fields.items():
        if k not in EDITABLE:
            raise TicketError(f"{k} cannot be edited.")
        clean[k] = {"title": lambda: clean_text(v, "Title", 300, required=True),
                    "description": lambda: clean_text(v, "Description", 5000),
                    "category": lambda: _choice(v, CATEGORIES, "Category"),
                    "source_ip": lambda: clean_ip(v, "Source IP"),
                    "dest_ip": lambda: clean_ip(v, "Destination IP"),
                    "affected_asset": lambda: clean_text(v, "Affected asset", 200) or None,
                    "evidence_notes": lambda: clean_text(v, "Evidence", 10000),
                    "tags": lambda: clean_tags(v),
                    "sla_due_at": lambda: v}[k]()
    with conn.transaction():
        t = _locked(conn, ticket_id)
        if t["status"] == "closed":
            raise TicketError("Closed tickets cannot be edited.")
        if "sla_due_at" in clean and (not isinstance(clean["sla_due_at"], datetime)
                                      or clean["sla_due_at"] <= datetime.now(timezone.utc)):
            raise TicketError("The due date must be a future date and time.")
        changed = {k: v for k, v in clean.items() if (str(t[k]) if t[k] is not None else None) != (
            str(v) if v is not None else None) and not (k == "tags" and sorted(t[k]) == v)}
        if not changed:
            return []
        conn.execute(f"UPDATE tickets SET {', '.join(f'{k} = %s' for k in changed)}, updated_at = now() "
                     "WHERE ticket_id = %s", (*changed.values(), ticket_id))
        detail = {"fields": sorted(changed)}
        if "sla_due_at" in changed:
            detail["due"] = {"from": t["sla_due_at"], "to": changed["sla_due_at"]}
        event(conn, ticket_id, actor, "updated", detail)
        audit(conn, actor, "ticket.update", "ticket", ticket_id, client=client, detail=detail)
    return sorted(changed)


def add_comment(conn, ticket_id: str, body: str, *, actor: str, kind: str = "comment", parent_id: int | None = None,
                ai_drafted: bool = False, client: str | None = None) -> int:
    body = clean_text(body, "Comment", 5000, required=True)
    kind = _choice(kind, ("comment", "internal_note"), "Comment type")
    with conn.transaction():
        t = _locked(conn, ticket_id)
        if t["status"] == "closed":
            raise TicketError("Closed tickets do not accept comments.")
        if parent_id is not None and not conn.execute(
                "SELECT 1 FROM ticket_comments WHERE comment_id = %s AND ticket_id = %s", (parent_id, ticket_id)).fetchone():
            raise TicketError("The comment you replied to is not on this ticket.")
        cid = conn.execute("INSERT INTO ticket_comments (ticket_id, parent_id, author, kind, body, ai_drafted) "
                           "VALUES (%s, %s, %s, %s, %s, %s) RETURNING comment_id",
                           (ticket_id, parent_id, actor, kind, body, ai_drafted)).fetchone()[0]
        conn.execute("UPDATE tickets SET updated_at = now() WHERE ticket_id = %s", (ticket_id,))
        audit(conn, actor, "ticket.comment", "ticket", ticket_id, client=client,
              detail={"comment_id": cid, "kind": kind, "ai_drafted": ai_drafted})
    return cid


def check_attachment(filename: str, data: bytes) -> tuple[str, str]:
    """Returns (safe filename, content type) or raises TicketError. Content must match the extension."""
    name = re.sub(r"[^A-Za-z0-9._ ()-]", "_", (filename or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]).strip(" .")[:120]
    ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    if not name or ext not in ATTACHMENT_TYPES:
        raise TicketError("Allowed file types: " + ", ".join(sorted(ATTACHMENT_TYPES)) + ".")
    if not data:
        raise TicketError("The file is empty.")
    if len(data) > MAX_ATTACHMENT_BYTES:
        raise TicketError("Files may be at most 5 MB.")
    ctype, check = ATTACHMENT_TYPES[ext]
    if check in MAGIC:
        if not data.startswith(MAGIC[check]):
            raise TicketError(f"The file's content does not match its {ext} extension.")
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise TicketError(f"{ext} files must be UTF-8 text.") from None
        if "\x00" in text:
            raise TicketError(f"{ext} files must be text.")
        if check == "json":
            try:
                json.loads(text)
            except ValueError:
                raise TicketError("The .json file is not valid JSON.") from None
    return name, ctype


def add_attachment(conn, ticket_id: str, filename: str, data: bytes, *, actor: str, client: str | None = None) -> str:
    name, ctype = check_attachment(filename, data)
    digest = hashlib.sha256(data).hexdigest()
    with conn.transaction():
        t = _locked(conn, ticket_id)
        if t["status"] == "closed":
            raise TicketError("Closed tickets do not accept attachments.")
        n = conn.execute("SELECT count(*) FROM ticket_attachments WHERE ticket_id = %s", (ticket_id,)).fetchone()[0]
        if n >= MAX_ATTACHMENTS_PER_TICKET:
            raise TicketError(f"A ticket can hold at most {MAX_ATTACHMENTS_PER_TICKET} attachments.")
        aid = conn.execute("INSERT INTO ticket_attachments (ticket_id, filename, content_type, size_bytes, sha256, data, "
                           "uploaded_by) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING attachment_id::text",
                           (ticket_id, name, ctype, len(data), digest, data, actor)).fetchone()[0]
        conn.execute("UPDATE tickets SET updated_at = now() WHERE ticket_id = %s", (ticket_id,))
        event(conn, ticket_id, actor, "attachment_added", {"attachment_id": aid, "filename": name, "sha256": digest,
                                                           "size_bytes": len(data)})
        audit(conn, actor, "ticket.attach", "ticket", ticket_id, client=client,
              detail={"attachment_id": aid, "filename": name, "sha256": digest})
    return aid


# ── queries ────────────────────────────────────────────────────────────────────────────────────
def _rows(conn, sql: str, params=()) -> list[dict]:
    cur = conn.execute(sql, params)
    cols = [c.name for c in cur.description]
    return [dict(zip(cols, r)) for r in cur]


SORTS = {"id": "t.ticket_id", "title": "t.title", "severity": "array_position(ARRAY['critical','high','medium','low'], t.severity)",
         "category": "t.category", "status": "array_position(ARRAY['open','acknowledged','investigating','awaiting_approval',"
         "'in_progress','resolved','closed'], t.status)", "assignee": "t.assignee", "created": "t.created_at",
         "updated": "t.updated_at", "due": "t.sla_due_at", "source": "t.source_ip"}
QUICK = {"mine": "My tickets", "critical": "Critical incidents", "unassigned": "Unassigned", "approval": "Awaiting approval",
         "overdue": "Overdue", "resolved": "Recently resolved", "escalated": "Escalated"}


@dataclass
class Filters:
    q: str = ""
    severity: list | None = None
    status: list | None = None
    category: str = ""
    assignee: str = ""
    sla: str = ""            # overdue | due_soon | ok
    since: datetime | None = None
    until: datetime | None = None
    quick: str = ""
    sort: str = "updated"
    order: str = "desc"
    page: int = 1
    page_size: int = 25
    source_ip: str = ""


def search(conn, f: Filters, *, viewer: str | None = None) -> tuple[list[dict], int]:
    where, p = [], []
    if f.q:
        like = "%" + f.q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(t.ticket_id ILIKE %s OR t.title ILIKE %s OR t.description ILIKE %s OR host(t.source_ip) LIKE %s "
                     "OR host(t.dest_ip) LIKE %s OR t.affected_asset ILIKE %s OR %s = ANY(t.tags))")
        p += [like, like, like, like, like, like, f.q.lower()]
    if f.severity:
        where.append("t.severity = ANY(%s)")
        p.append([s for s in f.severity if s in SEVERITIES])
    if f.status:
        where.append("t.status = ANY(%s)")
        p.append([s for s in f.status if s in STATUSES])
    if f.category:
        where.append("t.category = %s")
        p.append(f.category)
    if f.assignee == "__none__":
        where.append("t.assignee IS NULL")
    elif f.assignee:
        where.append("t.assignee = %s")
        p.append(f.assignee)
    if f.source_ip:
        ip = clean_ip(f.source_ip, "IP")
        where.append("(t.source_ip = %s::inet OR t.dest_ip = %s::inet)")
        p += [ip, ip]
    open_ = "t.status NOT IN ('resolved', 'closed')"
    if f.sla == "overdue":
        where.append(f"{open_} AND t.sla_due_at < now()")
    elif f.sla == "due_soon":
        where.append(f"{open_} AND t.sla_due_at BETWEEN now() AND now() + interval '4 hours'")
    elif f.sla == "ok":
        where.append(f"({open_} AND t.sla_due_at >= now() OR t.resolved_at <= t.sla_due_at)")
    if f.since:
        where.append("t.created_at >= %s")
        p.append(f.since)
    if f.until:
        where.append("t.created_at < %s")
        p.append(f.until)
    quick = {"mine": ("t.assignee = %s", [viewer]), "critical": (f"t.severity = 'critical' AND {open_}", []),
             "unassigned": (f"t.assignee IS NULL AND {open_}", []), "approval": ("t.status = 'awaiting_approval'", []),
             "overdue": (f"{open_} AND t.sla_due_at < now()", []),
             "resolved": ("t.status IN ('resolved', 'closed') AND t.resolved_at > now() - interval '7 days'", []),
             "escalated": (f"t.escalated AND {open_}", [])}.get(f.quick)
    if quick:
        where.append(quick[0])
        p += quick[1]
    sql_where = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT count(*) FROM tickets t {sql_where}", p).fetchone()[0]
    order = SORTS.get(f.sort, SORTS["updated"]) + (" ASC" if f.order == "asc" else " DESC") + " NULLS LAST"
    size = max(1, min(int(f.page_size), 100))
    page = max(1, int(f.page))
    rows = _rows(conn,
        "SELECT t.ticket_id, t.title, left(t.description, 160) AS description, t.severity, t.priority, t.category, "
        " host(t.source_ip) AS source_ip, host(t.dest_ip) AS dest_ip, t.affected_asset, t.assignee, t.status, t.origin, "
        " t.created_at, t.updated_at, t.sla_due_at, t.ack_due_at, t.acknowledged_at, t.resolved_at, t.escalated, "
        " t.needs_review, t.ai_status, t.tags, "
        f" ({open_} AND t.sla_due_at < now()) AS overdue, "
        " (SELECT count(*) FROM response_actions a WHERE (a.case_id = t.case_id OR a.ticket_id = t.ticket_id) "
        "  AND a.status = 'proposed') AS pending "
        f"FROM tickets t {sql_where} ORDER BY {order}, t.ticket_id DESC LIMIT %s OFFSET %s",
        (*p, size, (page - 1) * size))
    return rows, total


def detail(conn, ticket_id: str) -> dict | None:
    t = _rows(conn, "SELECT *, host(source_ip) AS source_ip, host(dest_ip) AS dest_ip, "
                    "(status NOT IN ('resolved', 'closed') AND sla_due_at < now()) AS overdue, "
                    "(status = 'open' AND ack_due_at < now()) AS ack_overdue FROM tickets WHERE ticket_id = %s",
              (ticket_id,))
    if not t:
        return None
    t = t[0]
    cid = t["case_id"]
    inv = _rows(conn, "SELECT analysis, recommendations, llm_status, llm_model, guard_findings, telemetry, model_output, "
                      "created_at FROM investigations WHERE case_id = %s ORDER BY created_at DESC LIMIT 1", (cid,)) if cid else []
    risk = _rows(conn, "SELECT score, severity, factors, requires_review, review_reasons, rules_version "
                       "FROM risk_assessments WHERE case_id = %s ORDER BY created_at DESC LIMIT 1", (cid,)) if cid else []
    case = _rows(conn, "SELECT case_id, host(src_ip) AS src_ip, family, status, first_seen, last_seen, flow_count, "
                       "max_p_attack FROM cases WHERE case_id = %s", (cid,)) if cid else []
    actions = _rows(conn,
        "SELECT a.action_id, a.action_type, a.target, a.params, a.rationale, a.disruptive, a.reversible, a.cautions, "
        " a.status, a.proposed_by, a.proposed_at, a.decided_by, a.decided_at, a.decision_note, a.completed_by, "
        " a.completed_at, a.run_id FROM response_actions a WHERE a.case_id = %s OR a.ticket_id = %s ORDER BY a.proposed_at",
        (cid, ticket_id))
    executions = _rows(conn, "SELECT e.* FROM action_executions e JOIN response_actions a USING (action_id) "
                             "WHERE a.case_id = %s OR a.ticket_id = %s ORDER BY e.started_at", (cid, ticket_id))
    comments = _rows(conn, "SELECT comment_id, parent_id, author, kind, body, ai_drafted, created_at FROM ticket_comments "
                           "WHERE ticket_id = %s ORDER BY comment_id", (ticket_id,))
    attachments = _rows(conn, "SELECT attachment_id::text, filename, content_type, size_bytes, sha256, uploaded_by, "
                              "created_at FROM ticket_attachments WHERE ticket_id = %s ORDER BY created_at", (ticket_id,))
    events = _rows(conn, "SELECT at, actor, event, detail FROM ticket_events WHERE ticket_id = %s ORDER BY id", (ticket_id,))
    runs = _rows(conn, "SELECT run_id::text, conversation_id::text, kind, prompt, status, requested_by, created_at, "
                       "finished_at, tool_calls, error FROM ai_runs WHERE ticket_id = %s ORDER BY created_at", (ticket_id,))
    related = _rows(conn,
        "SELECT c.case_id::text, c.family, host(c.src_ip) AS src_ip, c.flow_count, c.first_seen, c.last_seen, c.status, "
        " tk.ticket_id FROM cases c LEFT JOIN tickets tk ON tk.case_id = c.case_id "
        "WHERE c.case_id IS DISTINCT FROM %s AND (c.src_ip = %s::inet OR c.src_ip = %s::inet) "
        "ORDER BY c.last_seen DESC LIMIT 10", (cid, t["source_ip"], t["dest_ip"])) if (t["source_ip"] or t["dest_ip"]) else []
    assets = _rows(conn,
        "SELECT name, host(cidr) AS ip, cidr::text, role, criticality, owner, source FROM assets "
        "WHERE %s::inet <<= cidr OR %s::inet <<= cidr ORDER BY criticality DESC LIMIT 5",
        (t["source_ip"], t["dest_ip"])) if (t["source_ip"] or t["dest_ip"]) else []
    history = [e for e in events if e["event"] == "assigned"]
    timeline = sorted(
        [{"at": e["at"], "actor": e["actor"], "kind": "event", "event": e["event"], "detail": e["detail"]} for e in events]
        + [{"at": c["created_at"], "actor": c["author"], "kind": "comment", "event": c["kind"],
            "detail": {"body": c["body"][:280], "ai_drafted": c["ai_drafted"]}} for c in comments]
        + [{"at": r["created_at"], "actor": r["requested_by"], "kind": "ai", "event": f"ai_{r['kind']}",
            "detail": {"prompt": r["prompt"][:200], "status": r["status"]}} for r in runs]
        + [{"at": a["proposed_at"], "actor": a["proposed_by"], "kind": "action", "event": "action_proposed",
            "detail": {"action": a["action_type"], "target": a["target"]}} for a in actions]
        + [{"at": x["started_at"], "actor": x["requested_by"], "kind": "execution", "event": f"action_{x['outcome']}",
            "detail": {"mode": x["mode"], "target": x["target"]}} for x in executions],
        key=lambda e: e["at"])
    return {"t": t, "inv": inv[0] if inv else None, "risk": risk[0] if risk else None, "case": case[0] if case else None,
            "actions": actions, "executions": executions, "comments": comments, "attachments": attachments,
            "timeline": timeline, "assignment_history": history, "runs": runs, "related": related, "assets": assets,
            "transitions": allowed_transitions(t["status"])}

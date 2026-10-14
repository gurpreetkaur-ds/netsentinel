"""Markdown exports: an incident report per ticket and an AI investigation report per run.

Sections keep their provenance labels (VERIFIED TELEMETRY, MODEL OUTPUT, ANALYST, AI AGENT) so a reader
can tell recorded facts from opinions. Untrusted free text is quoted, never interpreted.
"""

import json
from datetime import datetime, timezone

from .. import tickets as tk
from . import views


def _t(v) -> str:
    if not v:
        return "–"
    return v.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if hasattr(v, "astimezone") else str(v)


def _quote(text: str) -> str:
    return "\n".join("> " + line for line in (text or "").splitlines()) or "> (empty)"


def _md(text) -> str:
    """Neutralise markdown/HTML control characters in untrusted single-line values."""
    s = str(text if text is not None else "–")
    for ch in ("\\", "`", "*", "_", "[", "]", "<", ">", "|", "#"):
        s = s.replace(ch, "\\" + ch)
    return s.replace("\n", " ")


def _run_section(run: dict, recs: list[dict]) -> list[str]:
    r = run["result"] or {}
    out = [f"*Run {run['run_id']} · {run['kind']} · requested by {_md(run['requested_by'])} · {_t(run['finished_at'])} · "
           f"model {_md(run['model'])} · {run['tool_calls']} tool calls · tools: {', '.join(r.get('tools_used', [])) or 'none'}*",
           "", "**Question**", "", _quote(run["prompt"]), "", "**Summary**", "", r.get("summary", "–"), "",
           "**Why the alert fired**", "", r.get("why_triggered", "–"), ""]
    for cat, title in (("confirmed", "Confirmed evidence"), ("hypothesis", "Hypotheses (inferred)"),
                       ("unknown", "Unknown / open questions")):
        items = [f for f in r.get("findings", []) if f["category"] == cat]
        if items:
            out += [f"**{title}**", ""]
            for f in items:
                flag = "" if f.get("supported", True) else " ⚠ *unsupported by the evidence: verify*"
                refs = ", ".join(f"`{x}`" for x in f["evidence_refs"]) or "no reference"
                out.append(f"- [{f['severity']}, {f['confidence']} confidence] {f['statement']}{flag}  \n  evidence: {refs}")
            out.append("")
    aff = r.get("affected") or {}
    if any(aff.values()):
        out += ["**Affected**", ""] + [f"- {k}: {', '.join(v)}" for k, v in aff.items() if v] + [""]
    if r.get("alternative_explanations"):
        out += ["**Alternative explanations**", ""] + [f"- {x}" for x in r["alternative_explanations"]] + [""]
    if r.get("missing_evidence"):
        out += ["**Missing evidence**", ""] + [f"- {x}" for x in r["missing_evidence"]] + [""]
    if recs:
        out += ["**Recommendations** (proposals; nothing was executed by the agent)", ""]
        for x in recs:
            extra = ""
            b = x["body"] or {}
            if x["kind"] == "remediation":
                extra = f" — `{b.get('action_type')}` on `{b.get('target')}`"
            elif x["kind"] == "severity_change":
                extra = f" — to **{b.get('severity')}**"
            out.append(f"- P{x['priority']} [{x['kind']}, {x['confidence']}] {x['title']}{extra} — *status: {x['status']}"
                       + (f" by {_md(x['decided_by'])}" if x["decided_by"] else "") + "*")
            if x["rationale"]:
                out.append(f"  - why: {x['rationale']}")
            if b.get("command"):
                out += ["", f"  ```{b['command'].get('language', 'text')}", "  " + b["command"]["code"].replace("\n", "\n  "),
                        "  ```", "  *For analyst review. NetSentinel does not run commands.*"]
        out.append("")
    if run["guard_findings"]:
        out += ["**Guard findings** (checks applied to the agent's answer)", ""]
        out += [f"- {g.get('type')}: {g.get('action')} ({_md(json.dumps(g.get('value'))[:120])})" for g in run["guard_findings"]]
        out.append("")
    return out


def ticket_markdown(conn, ticket_id: str, *, generated_by: str) -> str | None:
    d = tk.detail(conn, ticket_id)
    if not d:
        return None
    t = d["t"]
    out = [f"# Incident report: {t['ticket_id']}", "",
           f"*Generated {_t(datetime.now(timezone.utc))} by {_md(generated_by)} from NetSentinel. Times are UTC.*", "",
           "## Overview", "",
           "| Field | Value |", "|---|---|",
           f"| Title | {_md(t['title'])} |", f"| Severity / priority | {t['severity']} / {t['priority']} |",
           f"| Status | {tk.STATUS_LABELS[t['status']]} |", f"| Category | {_md(t['category'])} |",
           f"| Source IP | {_md(t['source_ip'])} |", f"| Destination IP | {_md(t['dest_ip'])} |",
           f"| Affected asset | {_md(t['affected_asset'])} |", f"| Assignee | {_md(t['assignee'])} |",
           f"| Origin | {t['origin']} (created by {_md(t['created_by'])}) |", f"| Created | {_t(t['created_at'])} |",
           f"| Acknowledged | {_t(t['acknowledged_at'])} |", f"| SLA due | {_t(t['sla_due_at'])}"
           + (" **(overdue)**" if t["overdue"] else "") + " |",
           f"| Resolved | {_t(t['resolved_at'])} |", f"| Escalated | {'yes' if t['escalated'] else 'no'} |",
           f"| Tags | {_md(', '.join(t['tags']) or '–')} |", ""]
    out += ["## Description (analyst/agent text)", "", _quote(t["description"]), ""]
    if t["evidence_notes"]:
        out += ["## Evidence notes (analyst text)", "", _quote(t["evidence_notes"]), ""]
    if d["case"]:
        c = d["case"]
        out += ["## Alert (VERIFIED TELEMETRY + MODEL OUTPUT)", "",
                f"- Alert {c['case_id']}: {c['family'] or 'unnamed family'} from {c['src_ip']}, {c['flow_count']} flows, "
                f"{_t(c['first_seen'])} → {_t(c['last_seen'])}, max p_attack {c['max_p_attack']:.4f}", ""]
    if d["risk"]:
        r = d["risk"]
        out += [f"## Risk assessment (RULES {r['rules_version']})", "", f"Score **{r['score']}/100** ({r['severity']}).", "",
                "| Factor | Points | Reason | Provenance |", "|---|---|---|---|"]
        out += [f"| {_md(f['factor'])} | {f['points']} | {_md(f['reason'])} | {f['provenance']} |" for f in r["factors"]]
        out.append("")
    if d["inv"] and d["inv"]["analysis"]:
        a = d["inv"]["analysis"]
        out += [f"## Pipeline investigation (LLM ANALYSIS, status {d['inv']['llm_status']})", "", a.get("summary", ""), ""]
    if d["attachments"]:
        out += ["## Attachments", "", "| File | Size | SHA-256 | Uploaded by |", "|---|---|---|---|"]
        out += [f"| {_md(a['filename'])} | {a['size_bytes']:,} B | `{a['sha256']}` | {_md(a['uploaded_by'])} |"
                for a in d["attachments"]]
        out.append("")
    runs = views.rows(conn, "SELECT run_id::text, kind, prompt, requested_by, finished_at, model, tool_calls, result, "
                            "guard_findings FROM ai_runs WHERE ticket_id = %s AND status = 'completed' "
                            "ORDER BY finished_at DESC LIMIT 1", (ticket_id,))
    if runs:
        recs = views.rows(conn, "SELECT kind, title, body, rationale, confidence, priority, status, decided_by "
                                "FROM ai_recommendations WHERE run_id = %s ORDER BY priority", (runs[0]["run_id"],))
        out += ["## Latest AI Security Agent investigation (AI AGENT: opinion, verify before acting)", ""]
        out += _run_section(runs[0], recs)
    if d["actions"]:
        out += ["## Response actions", "", "| Action | Target | Proposed by | Status | Decided by | Note |",
                "|---|---|---|---|---|---|"]
        out += [f"| {a['action_type']} | `{a['target']}` | {_md(a['proposed_by'])} | {a['status']} | {_md(a['decided_by'])} "
                f"| {_md(a['decision_note'])} |" for a in d["actions"]]
        out.append("")
    if d["executions"]:
        out += ["## Executions", ""]
        out += [f"- {_t(x['started_at'])} · **{x['mode'].upper()}** · outcome {x['outcome']} · target `{x['target']}` · "
                f"requested by {_md(x['requested_by'])} · verification {x['verification']}"
                + (" — *simulation: nothing was changed on any system*" if x["mode"] == "simulation" else "")
                for x in d["executions"]]
        out.append("")
    if t["status"] in ("resolved", "closed"):
        out += ["## Resolution", "", f"Closure reason: {tk.CLOSURE_REASONS.get(t['closure_reason'], '–')}", "",
                _quote(t["resolution"] or ""), ""]
    out += ["## Timeline", ""]
    for e in d["timeline"]:
        detail = e["detail"] if isinstance(e["detail"], dict) else {}
        brief = ", ".join(f"{k}={_md(v)}" for k, v in detail.items() if k not in ("body",))[:200]
        out.append(f"- {_t(e['at'])} · {_md(e['actor'])} · {e['event']}" + (f" · {brief}" if brief else ""))
    if d["comments"]:
        out += ["", "## Comments", ""]
        for c in d["comments"]:
            out += [f"**{_md(c['author'])}** · {c['kind'].replace('_', ' ')}{' · AI-drafted' if c['ai_drafted'] else ''} · "
                    f"{_t(c['created_at'])}", "", _quote(c["body"]), ""]
    return "\n".join(out) + "\n"


def run_markdown(conn, run_id: str, *, viewer_actor: str) -> str | None:
    r = views.rows(conn, "SELECT run_id::text, ticket_id, kind, prompt, requested_by, finished_at, model, tool_calls, result, "
                         "guard_findings, status FROM ai_runs WHERE run_id = %s", (run_id,))
    if not r or r[0]["status"] != "completed" or (r[0]["ticket_id"] is None and r[0]["requested_by"] != viewer_actor):
        return None
    run = r[0]
    recs = views.rows(conn, "SELECT kind, title, body, rationale, confidence, priority, status, decided_by "
                            "FROM ai_recommendations WHERE run_id = %s ORDER BY priority", (run_id,))
    head = [f"# AI investigation report{(': ' + run['ticket_id']) if run['ticket_id'] else ''}", "",
            "*Produced by the NetSentinel AI Security Agent from read-only tools. Findings are labelled confirmed / "
            "hypothesis / unknown. Nothing in this report was executed.*", ""]
    return "\n".join(head + _run_section(run, recs)) + "\n"

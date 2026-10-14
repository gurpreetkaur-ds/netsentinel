# SOC console, ticketing and the AI Security Agent

The dashboard at `/dashboard` is a full SOC console on top of the existing pipeline (detection →
cases → investigation → risk → response proposals → tickets). It uses the same stack: FastAPI,
server-rendered Jinja pages, Chart.js and PostgreSQL. There is no front-end build step, and the
strict Content-Security-Policy is kept (`script-src 'self'`, no inline scripts or styles).

| Page | What it shows |
|---|---|
| Overview | KPIs (threats, critical/high, open/overdue, MTTA/MTTR, health and assets), threat activity, severity, categories, top sources, incidents, ticket updates, pipeline health, analyst and AI actions. Every KPI and chart mark links to the filtered list. |
| Threat Monitoring | Alerts (correlated cases) with filters, alerts over time, the latest attack detections, and "Create ticket" for untriaged alerts. |
| Tickets | Search, filters, quick filters, sortable columns, pagination and CSV export. Manual creation with duplicate detection. |
| Ticket workspace | Overview, Evidence, Timeline, Collaboration, AI investigation, Response and Resolution tabs, plus a contextual AI agent panel. |
| AI Security Agent | Conversation with or without a ticket, the capability list (including what is *unavailable*), and the run history. |
| Network Map | Inventory assets and zones, connected by real aggregated flows. Demo inventory is labelled. |
| Analytics | Categories and severity over time, MTTA/MTTR, SLA compliance, reopened tickets, AI recommendation outcomes, and the false-positive trend from analyst closure reasons. |
| Reports | Markdown incident and AI reports, CSV exports and the presentation. |
| Settings | Your role, SLA policies, integrations, model, health, action catalog, team and audit log (approvers only). |

**Data honesty.** Every number comes from the database. Flows are attributed to their sender by the
submitting API key (replayed CICIDS-2017 lab traffic, live sensor in shadow mode, other clients),
and the attribution is shown wherever counts appear. Inventory rows tagged `demo:` are labelled as
demo data. Nothing is fabricated to fill an empty state.

## Roles (server-side, from API key scopes)

| Role | Scopes | Can |
|---|---|---|
| viewer | `events:read` | read everything except the audit log |
| analyst | + `tickets:write` | create, edit, assign and transition tickets; comment; attach files; ask the AI agent; accept or reject AI suggestions; propose response actions |
| approver | + `actions:decide` | everything an analyst can, plus approve, reject, simulate, complete and cancel response actions (re-entering their API key), verify executions, and read the audit log |

Grant a scope with `netsentinel keys grant KEY_ID tickets:write`. Every state-changing request checks
the session, the role, the same origin and the CSRF token. Response-action decisions also require the
API key again.

## Ticket lifecycle

`open → acknowledged → investigating → in_progress → resolved → closed`, plus `awaiting_approval`,
which any active state can enter (the Ticket Agent and new proposals use it). The rules are enforced
by a database trigger (`tickets_guard`, migration 0010), so the dashboard, the CLI and the agents
can't skip them:

- any active state → resolved (resolution notes required) or closed (closure reason required: remediated, false positive, duplicate, benign, risk accepted, no action needed, other; a note is required when closing without resolving)
- resolved → investigating (a reopen: reason required and counted) or closed
- closed is final: no edits, comments or attachments
- leaving `open` stamps `acknowledged_at` (for MTTA); tickets can't be deleted

SLA policies (`sla_policies`): critical P1 ack 15 min / resolve 1 h, high P2 30 min / 4 h, medium P3
2 h / 24 h, low P4 8 h / 72 h. Changing severity recalculates the deadlines and locks the severity, so
a pipeline refresh won't overwrite it. A due date can also be set by hand.

Every change writes a `ticket_events` timeline entry and an `audit_log` row (actor, action, object,
client address) in the same transaction. Comments, attachments, timeline entries, AI findings and
the audit log are all append-only.

**Attachments** are stored in the database (the services have read-only filesystems). Limits: 5 MB
each, 25 per ticket. Allowed types: .txt .log .csv .json .md .xml .yaml .pcap .pcapng .png .jpg .pdf.
The content must match the extension (magic bytes, UTF-8 or valid JSON). Files are always served as
`application/octet-stream` downloads with `Content-Security-Policy: sandbox`, and each download is
audited.

## AI Security Agent (`netsentinel/assistant.py`)

- **Where it runs:** a worker thread inside `netsentinel-investigation`, the only service whose
  sandbox allows the Claude runtime. Set `NETSENTINEL_ASSISTANT=off` to disable it, or run it alone
  with `netsentinel agent assistant`. The dashboard queues requests in `ai_runs`. The worker reports
  progress in `ai_run_events`, which the browser streams over server-sent events (with polling as a
  fallback).
- **Model access:** the same keyless server login as the Investigation Agent (`claude login` on the
  server). No API key is stored or needed, and the run refuses to start if one is set. The model is
  `NETSENTINEL_CLAUDE_MODEL` (default `claude-sonnet-5`). Usage counts against the server login's
  subscription limits. When those limits are hit, the run fails with a clear message and nothing
  else is affected.
- **Tool calling:** real tool calls through an in-process MCP server, with six **read-only** tools:
  `get_ticket_details`, `get_related_alerts`, `search_security_logs` (NetSentinel's flow records and
  verdicts), `lookup_ip_reputation` (internal history; external threat intelligence is reported as
  *unavailable*), `get_asset_details` and `get_detection_rule`. There is no shell, SQL, file or
  network tool. IP-scoped tools only accept addresses from the ticket, the analyst's message or
  earlier tool results. Limits per run: 10 tool calls, 240 s.
- **Structured output** validated against a JSON schema: answer, summary, why the alert fired,
  findings labelled *confirmed / hypothesis / unknown* with evidence references, affected items,
  alternative explanations, missing evidence, prioritized recommendations, comment draft and
  resolution draft.
- **Guard:** IPs not present in the evidence mark findings unsupported or drop recommendations.
  Destructive commands are removed. Remediation must use an allowlisted action type and a single IP
  target. Findings citing tools that were never called are marked unsupported.
- **Prompt injection:** ticket text, comments, logs and tool output are fenced and labelled as
  untrusted data. The agent can't write anything, so injected instructions have no lever. Accepting
  a recommendation is a separate human action that goes through the normal checks.
- **Recommendations:** each can be accepted, rejected or dismissed. Accepting applies it through the
  same code as doing it by hand: a comment draft becomes a comment marked AI-drafted, a severity
  change updates the severity, an escalation escalates, and a remediation becomes a response-action
  *proposal* that an approver must still approve. The database refuses decisions by `agent:` actors.
- **Rate limits:** 30 requests per analyst per hour, one active request per ticket, and at most 20
  queued in total.

## Safe remediation (`netsentinel/remediation.py`)

Proposal → approval → execution → verification. Only actions in the Response Agent's allowlisted,
reversible catalog can be proposed. Temporary actions are capped at 72 h. Targets that are too broad,
are loopback, or include this server or an owner address are refused, both at proposal time and
again at execution.

**No firewall, EDR or identity-provider integration is configured**, so `remediation.EXECUTORS` is
empty and every execution is a **simulation**. It records the exact request it *would* send, with
outcome `simulated`, and changes nothing. The database refuses to record a simulation as
`succeeded`. An approver then carries out the action with their own tools, marks it completed, and
records verification (verified or failed, with a note).

To add a live integration, register `EXECUTORS["temporary_block_source"] = fn(target, params) -> dict`
with credentials read from the Security Wall. Executions then run in `live` mode and record
`succeeded` or `failed`.

## Setup and deployment

```bash
# tests (they use the netsentinel_test database through the Wall)
sg wall-netsentinel-clients -c '.venv/bin/pytest'

# production: back up, migrate (0010), restart services, verify
sudo bash ops/deploy/soc-upgrade.sh
```

Migration `0010_soc_workflow.sql` adds `sla_policies`, `ticket_comments`, `ticket_attachments`,
`audit_log`, `ai_runs`, `ai_run_events`, `ai_findings`, `ai_recommendations` and `action_executions`.
It extends `tickets` (manual tickets, lifecycle, SLA, closure, escalation, tags) and `response_actions`
(ticket-level proposals, `cancelled`), and adds the `tickets:write` scope. Existing tickets are kept:
`new` becomes `open`, and categories and IPs are backfilled from their cases.

| Environment variable | Default | Purpose |
|---|---|---|
| `NETSENTINEL_CLAUDE_MODEL` | `claude-sonnet-5` | model for investigations and the AI agent |
| `NETSENTINEL_AI_MODE` | `local` | only the keyless server login is supported |
| `NETSENTINEL_ASSISTANT` | `on` | `off` stops the AI agent worker inside the investigation service |
| `NETSENTINEL_INVESTIGATION_WORKERS` | `2` | parallel pipeline investigations |

No new secrets are required. Optional integrations, none of them configured: external threat
intelligence (AbuseIPDB has a free tier; VirusTotal; MISP), firewall/EDR executors, and Jira or
ServiceNow export. Each would read its credentials from the Wall, never from files or the browser.

## Known limits

- Acknowledge times exist only for tickets acknowledged after this upgrade. Older tickets count as
  missed acknowledge SLAs.
- The network map draws inventory plus observed flows. It does not discover topology or firewalls.
- The AI agent does not read attachment contents, only their metadata.
- Charts cover up to 90 days. CSV exports are capped at 5,000 rows.

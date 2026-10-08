# Agents

```
                 Security Orchestrator  (correlates detections into cases, dispatches work)
                          │
     ┌────────────────────┼──────────────────────┐
     ↓                    ↓                      ↓
Detection Agent    Investigation Agent     Response Agent (next phase: recommend-only, human approval)
(steps 2-7)        (Claude, keyless)              ↑
                          ↓                       │
                 Risk Assessment Agent ───────────┘ (next phase)
                          ↓
                     Ticket Agent (next phase)
```

All agents talk through the Postgres bus (`netsentinel/bus.py`): at-least-once delivery, with
offsets committed in the same transaction as the work.

| Topic | Producer | Consumer |
|---|---|---|
| `detection.attack` | Detection Agent | Orchestrator |
| `model.check_failed` | Detection Agent | (dashboard, alerting) |
| `investigation.requested` | Orchestrator | Investigation Agent |
| `investigation.completed` | Investigation Agent | Risk Assessment Agent (next) |

## Security Orchestrator (`agents/orchestrator.py`)

Groups attack detections by **source IP + attack family** into a case. A case stays `open` while
flows keep arriving, and is dispatched for investigation after 30 s without new flows, 2 minutes
open, or 1,000 flows, so the investigation sees the burst rather than its first flow.
Redelivered messages are not double counted. Run a single instance.

## Investigation Agent (`agents/investigation.py`)

Every investigation stores four labelled sections:

| Label | Source | Can Claude change it? |
|---|---|---|
| **VERIFIED TELEMETRY** | computed from the database: case window, destinations, ports, protocols, flow statistics, the source's other activity ±5 min | no, it is Claude's input |
| **MODEL OUTPUT** | the detector's verdicts, copied verbatim (families, types, p_attack) | no |
| **LLM ANALYSIS** | Claude: summary, observations citing evidence paths, hypotheses, data gaps, "is the telemetry consistent with the model's verdict?" | it is Claude's output |
| **RECOMMENDATION** | Claude: investigative next steps only | it is Claude's output, after the guard |

**Guard** (runs on every answer):
- Any IP address not present in the evidence → `guard_rejected`. The analysis is kept for audit
  but must not be relied on.
- An observation citing an evidence path that doesn't exist → marked `unsupported`.
- Imperative containment steps ("isolate the host", "block …", "terminate the process") →
  removed. Containment is the Response Agent's job, behind human approval.
- Nothing Claude says changes detections, cases or model output. Those tables are append-only.

**Claude access** mirrors Resumate: keyless server login only (refuses if any API key variable
is set or the runtime reports one), no tools, no settings/CLAUDE.md, an isolated working directory,
and a minimal environment (no Wall socket or DB settings). Model: `NETSENTINEL_CLAUDE_MODEL`
(default `claude-sonnet-5`). A failed call is retried once; if Claude is still unavailable, the
investigation is recorded with telemetry, model output and a rule-based checklist
(`llm_status = unavailable`).

Evidence holds only validated values (IPs, ports, numbers, model labels), never client free text,
so there is no path for prompt injection from traffic. Claude is still told to treat evidence as data.

## First live run (2026-10-02)

2,000 held-out flows replayed with real 5-tuples → 17 cases → 17 Claude investigations
(~50-80 s each, sequential). The other 7 cases came from an earlier replay that had no IP data.

- 15 of 17 succeeded on the first attempt. 2 failed with "no valid structured output after 5
  attempts"; the retry added afterwards fixed the one re-run.
- Guard: one false positive ("terminated via RST" matched as a containment verb). The rule was
  narrowed to imperative verbs and covered by tests. No fabricated IPs.
- Example (`172.16.0.1|DoS`, 208 flows to 192.168.10.50:80): Claude called the telemetry
  consistent with an HTTP flood. It noticed the same source hit 108 other ports nearby (the
  PortScan case) and pointed out that the mixed Hulk/GoldenEye/Slowloris labels may be model
  uncertainty rather than four tools. Its next steps and data gaps were all investigative.

Known limitation: replayed flows are timestamped on arrival, so case windows look like
sub-second bursts. Real sensors should send `observed_at`.

## Risk Assessment Agent (`agents/risk.py`)

Deterministic 0-100 score (`risk-rules-v1`). Every factor stores points, reason and provenance:

| Factor | Points | Provenance |
|---|---|---|
| attack family base severity | PortScan 10 … Botnet/Infiltration/Exploit 35; unnamed 25 | MODEL OUTPUT |
| model confidence | +10 if mean p_attack ≥ 0.99, +5 if ≥ 0.9 | MODEL OUTPUT |
| scale | 5·log10(flows), max 15 | VERIFIED TELEMETRY |
| target breadth | +10 for ≥ 10 hosts, +5 for ≥ 3 | VERIFIED TELEMETRY |
| source port fan-out | +5 if the source hit ≥ 100 ports within ±5 min | VERIFIED TELEMETRY |
| targets responded | +5 if most flows got a response | VERIFIED TELEMETRY |
| asset criticality | crit 5 → 20 … 1 → 0; not in inventory → 5 | ASSET INVENTORY |
| internal source | +10 for an internal host doing Botnet/Infiltration/PortScan/BruteForce | ASSET INVENTORY |

Severity: critical ≥ 80, high ≥ 60, medium ≥ 40, else low. **The LLM is never scored.**
`requires_review` is set for critical cases, guard-rejected or missing LLM analysis, an LLM
analysis that disputes the model, or an unnamed family.

The asset inventory and network zones are operator data (`netsentinel assets …`, `netsentinel zones …`).
`assets seed-cicids-lab` loads the published CICIDS-2017 testbed layout, tagged
`demo:cicids-2017-lab`, for replays only.

## Response Agent (`agents/response.py`): recommends, never executes

A fixed playbook maps family × severity × source zone to proposals from a closed catalog of
**reversible** actions. Each has an undo, and destructive operations (delete, wipe, re-image,
kill) aren't in the catalog at all:

`increase_monitoring`, `collect_host_forensics`, `review_target_logs` (non-disruptive) ·
`rate_limit_source`, `temporary_block_source` (24 h), `block_outbound_destination` (24 h),
`isolate_host_for_investigation`, `enable_waf_virtual_patch`, `credential_review` (disruptive)

- Low severity, an unknown source, or an unnamed family → non-disruptive proposals only.
- External source → block/rate-limit the source. Internal source behaving like a scanner, bot or
  intruder → forensics, quarantine VLAN and egress block, never an inbound block of its own IP.
- Cautions are attached when the action touches an inventoried asset or a high-criticality target.
- Only the case's latest risk assessment gets proposals.

**Human approval:** `netsentinel responses list | approve | reject | complete ID --note "…"`.
Decisions are recorded as `human:<user>`. The database refuses any decision whose actor starts
with `agent:`, any change to an action's target or parameters, and any transition other than
proposed → approved/rejected → completed. NetSentinel has no code path that performs an action.

## Ticket Agent (`agents/ticket.py`)

One ticket per case (`NS-000001`…), with priority and SLA from severity (P1 1 h, P2 4 h, P3 24 h,
P4 72 h), a REVIEW flag from the risk agent, a summary with the five labelled sections, and an
append-only timeline of every agent step and human decision.
Status: `awaiting_approval` → `in_progress` once every proposal is decided → `resolved` / `closed`
(by a human: `netsentinel tickets assign | resolve | close`). Closing a ticket closes its case.

## Services

`sudo bash ops/systemd/install.sh` installs and starts the API and the six agents as `linuxuser`
services (not root), with read-only filesystems, a private /tmp, and Wall access through the
`wall-netsentinel-clients` group. The API stays on 127.0.0.1:8200. The script header lists
exactly what changes and how to undo it.

## Resilience (added 2026-10-07)

| Situation | Behaviour |
|---|---|
| A long attack keeps sending flows | Flows of the same source + family within 15 min of the case's last flow join that case, even after it was sent for investigation, so one attack makes one case and one ticket. `netsentinel cases merge-duplicates` repairs older duplicates. |
| Claude down or rate-limited | The case still gets risk, proposals and a ticket, with rule-based next steps and `llm_status = unavailable` (flagged for review). After 15 min the orchestrator retries, at most 3 investigations per case. Observed live: the shared Claude login hit its session limit and every case still reached a ticket within 38 s. |
| Re-investigated / re-assessed case | Proposals identical to ones already proposed or approved for the case are not repeated. |
| Throughput | The Investigation Agent runs `NETSENTINEL_INVESTIGATION_WORKERS` (default 2) Claude investigations in parallel; redelivered requests for finished cases are skipped. |
| Service restart | With `ops/systemd/finalize.sh` applied (`KillMode=mixed`), in-flight investigations finish before the agent exits. |
| Bad model file | Model Check refuses it (hash/schema); the agent pauses scoring and flows wait. Roll back: `netsentinel models activate netsentinel-v1`. |

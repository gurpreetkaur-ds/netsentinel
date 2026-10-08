# NetSentinel internal API

NetSentinel exposes its own ingestion API. Sensors, the replay tool and future adapters (Zeek,
NetFlow) push flow records to it. No external API is assumed.

| Method | Path | Scope | Purpose |
|---|---|---|---|
| GET | `/healthz` | none | liveness + database reachability |
| GET | `/v1/whoami` | any valid key | identifies the calling key |
| POST | `/v1/flows` | `ingest:write` | pipeline step 1 (INGEST): up to 1000 flows per request, 202 Accepted |
| GET | `/v1/flows/{event_id}` | `events:read` | reads back an event **submitted by the same key** |

Send the key as `Authorization: Bearer nsk_…` (or `X-API-Key`). Errors share one shape:
`{"error": {"code", "message", "request_id"}}`. A rejected key always gets the same 401, with no
reason given. After 20 failures in 5 minutes, a client address gets 429 for 5 minutes.

```json
POST /v1/flows
{"source": "cicflowmeter",
 "flows": [{"event_id": "sensor1-000001", "observed_at": "2026-09-30T10:00:00Z",
            "features": {"Dst Port": 80, "Protocol": 6, "Flow Duration": 1234, "Flow Bytes/s": null}}]}
```

`event_id` is optional and makes resubmission idempotent per key (duplicates are counted, not
stored twice). Non-finite numbers are rejected; send `null` for CICFlowMeter's `Infinity`/`NaN`.
Per-feature schema validation (step 2, VALIDATE) arrives with the fixed feature schema.

## API keys: where each copy lives

| Copy | Where | Protection |
|---|---|---|
| The key itself | only on the client's machine (`%USERPROFILE%\.netsentinel\api-key.dpapi`) | Windows DPAPI: readable only by that Windows account |
| SHA-256 digest | table `api_keys` in database `netsentinel` | cannot be reversed (256-bit random secret); table is closed to PUBLIC, owned by `netsentinel_app` whose password OpenBao rotates daily |
| Audit trail | table `api_key_events` | append-only (trigger) |

Database triggers make a key's id and digest immutable, forbid deleting keys, and make
revocation permanent.

1. On your PC: `powershell -ExecutionPolicy Bypass -File new-api-key.ps1` (from `tools/`).
2. On the server, run the printed line (it contains no secret):
   `sg wall-netsentinel-clients -c '.venv/bin/netsentinel keys register --key-id … --sha256 … --name …'`
3. Manage keys: `netsentinel keys list`, `netsentinel keys revoke <key_id> --reason "…"`.

Key management is CLI-only on the server. There is deliberately no admin HTTP endpoint.

**Transport:** the API listens on 127.0.0.1:8200. Before it is reachable from another machine,
it needs TLS (a reverse proxy with a certificate) or an SSH tunnel. Otherwise the key would
cross the network in clear text.

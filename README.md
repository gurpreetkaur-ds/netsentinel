# NetSentinel

API-driven network threat detection and incident response, grown from a CICIDS-2017 anomaly-detection
notebook. Machine learning makes the detection decision; agents correlate, investigate (Claude),
score risk, propose reversible responses for **human approval**, and track tickets.

```
sensor / replay ─► 1 INGEST (API key) ─► 2-4 VALIDATE · NORMALIZE · EXTRACT ─► 5 MODEL CHECK ─► 6 INFERENCE
  ─► 7 EVENT PUBLISH ─► Orchestrator (cases) ─► 8 Investigation (Claude) ─► 9 Risk ─► 10 Response (proposals)
  ─► 11 Ticket ─► 12 Dashboard
```

| Where | What |
|---|---|
| `netsentinel/ml/` | data loading, feature schema, taxonomy, v0 reproduction, v1 hierarchical detector, v2 time-window features |
| `netsentinel/api/` | ingest API (`/v1/…`, loopback) and read-only dashboard (`/dashboard`, HTTPS) |
| `netsentinel/agents/` | detection, orchestrator, investigation, risk, response, ticket |
| `netsentinel/{bus,registry,llm,wall,db}.py` | event bus, model registry + check, Claude client, Security Wall client |
| `netsentinel/migrations/` | PostgreSQL schema (applied by `netsentinel migrate`) |
| `ops/` | systemd units, hardening, TLS, Apache redirect, Security Wall onboarding (root scripts) |
| `original/` | the original notebook, unchanged (read-only) |
| `presentation/NetSentinel.ipynb` | cleaned, runnable story of the project (reads saved results) |
| `docs/` | model reports, agents, API, security review, end-to-end validation |

## Live deployment

| Service | Purpose |
|---|---|
| `netsentinel-api` | ingest API on 127.0.0.1:8200 |
| `netsentinel-detection` / `-orchestrator` / `-investigation` / `-risk` / `-response` / `-ticket` | the agents |
| `netsentinel-sensor` | live capture of this server's traffic (shadow mode: scored, no alerts); see `docs/live-sensor.md` |
| `netsentinel-dashboard` | `https://<domain>:8443/dashboard` (Let's Encrypt; firewall: owner IPs only) |

Active model: **`netsentinel-v2`** (per-flow + per-source 60 s window features, with a per-flow fallback
for flows that arrive without a timestamp or source IP). `netsentinel-v1` is retired and can be
re-activated at any time.

All run as `linuxuser` in a systemd sandbox. Database credentials come from the Security Wall
(OpenBao) and rotate daily; there are no secrets in the repo or environment.

## Site configuration

Copy `config/site.example.json` to `config/site.json` (not committed) and set your domain, server address,
your own IPs and the capture interface. The setup scripts in `ops/` and `netsentinel calibrate` read it.

## Operating it

Prefix server commands with `sg wall-netsentinel-clients -c '…'` from an interactive shell (services have the group already).

| Task | Command |
|---|---|
| Open tickets / one ticket | `netsentinel tickets list` · `netsentinel tickets show NS-000023` |
| Decide on a proposed action | On the dashboard ticket page (needs a key with `actions:decide`; each decision re-asks for the key), or `netsentinel responses approve <id> --note "…"` (or `reject`) |
| Allow a key to decide on the dashboard | `netsentinel keys grant <key_id> actions:decide` |
| Confirm you carried it out | `netsentinel responses complete <id> --note "…"` |
| Close a ticket | `netsentinel tickets resolve|close NS-000023 --resolution "…"` |
| API keys | `netsentinel keys list` · `keys register --key-id … --sha256 …` · `keys revoke <id> --reason "…"` |
| Models | `netsentinel models list` · `register` → `approve` → `activate` (human approval required) |
| Asset context for risk | `netsentinel assets add 10.0.0.5/32 --name db01 --criticality 5` · `netsentinel zones add 10.0.0.0/8 --zone internal` |
| Health | `systemctl status 'netsentinel-*'` · dashboard backlog panel |
| Replay test traffic | `netsentinel replay --limit 2000` (random held-out flows) · `netsentinel replay --slice friday 17:56 1` (a real capture interval, in order: exercises window features) |
| Roll back the model | `netsentinel models activate netsentinel-v1` |
| Full validation | `netsentinel e2e` (exit 0 = every invariant passed) |
| Live-sensor calibration | `netsentinel calibrate --hours 24` (weak labels from firewall + SSH logs) |
| Tests | `.venv/bin/pytest` (uses the `netsentinel_test` database) |

API keys are created **on the client** (`tools/new-api-key.ps1`); the server only stores their SHA-256.
NetSentinel never executes a response action. Approvals record the human's login, and the database
refuses decisions made by agents.

## Retraining

`python -m netsentinel.ml.train v2` → `artifacts/v2/` (needs `data/raw/distrinet`, the corrected
CICIDS-2017 with full timestamps; about 25 min on 2 cores, or `--skip-e2` to repackage only), then
`netsentinel models register netsentinel-v3 artifacts/…` → review → `approve` → `activate`. The detector refuses any model whose file hash or feature schema doesn't match
its registration.

## Documentation

* `docs/model-baseline.md`: the original notebook, reproduced, and why its numbers don't reproduce
* `docs/model-v1.md`: binary vs hierarchical, E1/E2 evaluation, thresholds
* `docs/model-v2.md`: per-source time-window features, the timestamped dataset, live replay validation
* `docs/agents.md`: orchestration, investigation guard, risk factors, response playbook, tickets
* `docs/api.md`: ingest API and API keys
* `docs/live-sensor.md`: live capture, flow-meter fixes, calibration against host logs, why alerting is off
* `docs/security-review.md`: security review findings and fixes
* `docs/e2e-validation.md`: end-to-end validation of the live system

## License

MIT, see [LICENSE](LICENSE). Bundled third-party code keeps its own license: Chart.js
(`netsentinel/api/static/chart.umd.min.js`, MIT). The CICIDS-2017 data (Canadian Institute for
Cybersecurity) and its corrected version (Engelen et al., 2021) are not included; download them from their
publishers under their terms.

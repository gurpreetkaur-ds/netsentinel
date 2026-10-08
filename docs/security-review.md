# Security review (2026-10-07)

| Area | Check | Result |
|---|---|---|
| Secrets in git | tracked key/cert/env files; key, private-key and password patterns across all history | none |
| Secrets in logs | full API keys / DB passwords in all NetSentinel and Wall-proxy journals since 2026-10-01 | 0 |
| TLS private key | `~/.config/netsentinel/tls/key.pem` | 600, dir 700, outside repo |
| Network | non-loopback listeners | NetSentinel: only 8443 (ufw: 3 owner IPs). API 8200 is loopback-only |
| TLS | protocol versions | 1.0/1.1 refused; 1.2 + 1.3 |
| TLS | TLS 1.2 ciphers | **fixed**: CBC suites were accepted, now ECDHE + AES-GCM/ChaCha20 only |
| HTTP headers | dashboard | CSP (no inline/3rd-party), X-Frame-Options DENY, HSTS, nosniff, no-store, no server banner |
| Auth | unauthenticated pages | redirect to sign-in; cross-origin sign-in refused; failures rate-limited per IP |
| Database role | `netsentinel_app` | not superuser / createdb / createrole / bypassrls |
| Database access | PUBLIC grants, CONNECT, schema CREATE | none for PUBLIC; CONNECT only app + openbao (rotation) |
| Audit trail | append-only triggers on 8 audit tables | all present |
| Dependencies | pip-audit (PyPI/OSV advisories) | no known vulnerabilities |
| Service sandbox | systemd-analyze security | **fixing**: 8.5 EXPOSED → 1.6 OK (investigation 3.0) via `ops/systemd/harden.sh` |
| Model integrity | pickle loaded only after SHA-256 match + human approval | in place (tested) |
| LLM | keyless only, no tools, minimal env, guard on output | in place (tested) |

## Accepted / out of scope
- Signing out deletes the session cookie, but a stolen cookie stays valid until it expires (8 h) or the
  key is revoked, which ends all of that key's sessions immediately.
- Ports 80, 8080 (Resumate) and 8123 (esports) belong to other projects and were not changed.
- Ingestion accepts only `Content-Length` bodies; chunked uploads get 411 by design.

## Dashboard decisions (added 2026-10-07)

The dashboard can approve/reject/complete response actions and close tickets. Safeguards (tested):
a separate `actions:decide` permission (signing in needs only `events:read`); every decision re-asks for
the API key, which must be the signed-in key; per-session form tokens plus the same-origin check;
a required note; failures count toward the per-IP lockout. Decisions are recorded as
`human:<key name>@dashboard`, and the database still refuses any decision by an `agent:` actor.
